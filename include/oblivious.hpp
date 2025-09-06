/* Key exchange-based oblivious transfer framework.
   Modified from BDGM19 (https://eprint.iacr.org/2019/726.pdf)
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <crypto/common.h>
#include <exception>
#include <array>

/* xof_trait: Type trait for an extendable output hash function (XOF). Example: SHAKE256 */
/* kem_trait: Type trait for a key exchange mechanism. Example: NTRU LPrime 653 */
/* msg_len: Length of the two messages sent */
/* security_len: The security parameter lambda, used to determine the length of various hashes. In most cases, should be 32 or 64 */
template < typename xof_trait, typename kem_trait, size_t msg_len, size_t security_len >
class bdgm_oblivious_transfer {
public:
  struct bdgm_ot_receiver_state {
    /* Stage 0: Bit b not chosen yet.
       Stage 1: Bit b chosen, waiting for challenge.
       Stage 2: Challenge response sent, waiting for msgs.
       Stage 3: Msg received.
     */
    uint32_t stage;

    /* The chosen bit b */
    bool b;

    /* Random public key diff seed */
    std::array < unsigned char, security_len > seed;

    /* The two public keys pkb, pk(1-b) */
    kem_trait::public_key_t pk, pk_alt;

    /* The private key corresponding to pkb */
    kem_trait::private_key_t sk;

    /* The common exchanged secret */
    std::array < unsigned char, security_len > common_secret;

    bdgm_ot_receiver_state () : stage (0), b (false) { }
  };

  struct bdgm_ot_sender_state {
    /* Stage 0: Waiting for receiver public keys.
       Stage 1: Waiting for receiver challenge response.
       Stage 2: Waiting for message input.
       Stage 3: Msgs sent.
     */
    uint32_t stage;

    /* Random public key diff seed */
    std::array < unsigned char, security_len > seed;

    /* The two received public keys */
    kem_trait::public_key_t pk0, pk1;

    /* The common exchanged secret */
    std::array < unsigned char, security_len > common_secret;

    bdgm_ot_sender_state () : stage (0) { }
  };

  /* Step 1: Receiver gets input bit b.
     It generates a random seed, hashes the seed to a random public key diff,
     and computes pk_b and pk_(1-b), which we call pk and pk_alt.
     It sends to sender seed and pk0.

     This function only provides pk0 output.
     Seed can be read from receiver_state directly.
   */
  static void bdgm_ot_step1 (bool b, kem_trait::public_key_t &pk0_out, bdgm_ot_receiver_state &st) {
    if (st.stage != 0) std::terminate ();
    st.b = b;

    /* Generate pk and sk */
    kem_trait::gen_key (st.sk, st.pk);

    /* Generate random key diff seed */
    getrandom (st.seed.data (), security_len, 0);

    /* Hash seed to get random diff and compute pk_alt */
    {
      std::array < unsigned char, kem_trait::hash_len > hash;
      typename xof_trait::hash_state_t hash_st;
      xof_trait::add_input (st.seed.data (), security_len, hash_st);
      xof_trait::finalize_input (hash_st);
      xof_trait::get_output (kem_trait::hash_len, hash.data (), hash_st);

      typename kem_trait::public_key_diff_t diff;
      kem_trait::gen_public_key_diff_from_hash (hash, diff);
      kem_trait::compute_alt_public_key (st.pk, diff, st.pk_alt, b);
    }

    /* Output pk0 */
    uint32_t b_val = b;
    cond_memcpy (1 - b_val, pk0_out.data (), st.pk.data (), kem_trait::public_key_len);
    cond_memcpy (b_val, pk0_out.data (), st.pk_alt.data (), kem_trait::public_key_len);

    st.stage = 1;
  }

  /* Step 2: Sender receives seed and pk0, computes pk1, and generates a common secret and two ciphertexts.
     The ciphertext consists of an asymmetric part (coming from the KEM) and a symmetric part.
     The plaintext of the symmetric part is secret0 || secret1 || common_secret
     where secret0 and secret1 are the randomness used to generate the two asymmetric ciphertexts.
     The symmetric plaintext is encrypted by XORing with Hash(seed || pk0 || pk1 || 0x00 or 0x01 || 7 bytes of 0x00 || key0 or key1)
     where key0, key1 are the symmetric keys exchanged via the KEM.
     Then sender also provides a hash confirmation of the symmetric plaintext for authentication.
     The confirmation is Hash(seed || pk0 || pk1 || 0x02 || 7 bytes of 0x00 || secret0 || secret1 || common_secret).
   */
  static void bdgm_ot_step2
  (const std::array < unsigned char, security_len > seed,
   const kem_trait::public_key_t &pk0,
   kem_trait::ciphertext_t &ct0_out,
   kem_trait::ciphertext_t &ct1_out,
   std::array < unsigned char, 2 * kem_trait::secret_len + security_len > &symct0_out,
   std::array < unsigned char, 2 * kem_trait::secret_len + security_len > &symct1_out,
   std::array < unsigned char, security_len > &tag_out,
   bdgm_ot_sender_state &st) {
    if (st.stage != 0) std::terminate ();

    /* Save seed and pk0 */
    memcpy (st.seed.data (), seed.data (), security_len);
    memcpy (st.pk0.data (), pk0.data (), kem_trait::public_key_len);

    /* Hash seed to get random diff */
    /* Apply diff to pk0 to get pk1 */
    {
      std::array < unsigned char, kem_trait::hash_len > hash;
      typename xof_trait::hash_state_t hash_st;
      xof_trait::add_input (st.seed.data (), security_len, hash_st);
      xof_trait::finalize_input (hash_st);
      xof_trait::get_output (kem_trait::hash_len, hash.data (), hash_st);

      typename kem_trait::public_key_diff_t diff;
      kem_trait::gen_public_key_diff_from_hash (hash, diff);
      kem_trait::compute_alt_public_key (st.pk0, diff, st.pk1, false);
    }

    /* Generate the common secret */
    getrandom (st.common_secret.data (), security_len, 0);

    /* Generate two secrets for the two ciphertexts */
    typename kem_trait::secret_t secret0, secret1;
    kem_trait::gen_secret (st.pk0, secret0);
    kem_trait::gen_secret (st.pk1, secret1);

    /* Encapsulate the two secrets */
    typename kem_trait::sym_key_t key0, key1;
    kem_trait::encapsulate (st.pk0, secret0, ct0_out, key0);
    kem_trait::encapsulate (st.pk1, secret1, ct1_out, key1);

    /* symct0 <- secret0 || secret1 || common_secret */
    /* symct1 <- secret0 || secret1 || common_secret */
    /* Later, we shall encrypt symct0 and symct1 by XORing with
       mask = Hash(seed || pk0 || pk1 || 0x00 or 0x01 || 7 bytes of 0x00 || key0 or key1).
     */
    memcpy (symct0_out.data (), secret0.data (), kem_trait::secret_len);
    memcpy (symct0_out.data () + kem_trait::secret_len, secret1.data (), kem_trait::secret_len);
    memcpy (symct0_out.data () + 2 * kem_trait::secret_len, st.common_secret.data (), security_len);

    memcpy (symct1_out.data (), secret0.data (), kem_trait::secret_len);
    memcpy (symct1_out.data () + kem_trait::secret_len, secret1.data (), kem_trait::secret_len);
    memcpy (symct1_out.data () + 2 * kem_trait::secret_len, st.common_secret.data (), security_len);

    /* Prepare hash state (seed || pk0 || pk1) to avoid repeated computation */
    typename xof_trait::hash_state_t hash_st_init;
    xof_trait::add_input (st.seed.data (), security_len, hash_st_init);
    xof_trait::add_input (st.pk0.data (), kem_trait::public_key_len, hash_st_init);
    xof_trait::add_input (st.pk1.data (), kem_trait::public_key_len, hash_st_init);

    /* Mask symct0 */
    {
      std::array < unsigned char, security_len + 2 * kem_trait::secret_len > mask0;
      typename xof_trait::hash_state_t hash_st_mask0 = hash_st_init;
      uint64_t ctr = 0;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_mask0);
      xof_trait::add_input (key0.data (), kem_trait::sym_key_len, hash_st_mask0);
      xof_trait::finalize_input (hash_st_mask0);
      xof_trait::get_output (security_len + 2 * kem_trait::secret_len, mask0.data (), hash_st_mask0);

      memxor (symct0_out.data (), mask0.data (), security_len + 2 * kem_trait::secret_len);
    }

    /* Mask symct1 */
    {
      std::array < unsigned char, security_len + 2 * kem_trait::secret_len > mask1;
      typename xof_trait::hash_state_t hash_st_mask1 = hash_st_init;
      uint64_t ctr = 1;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_mask1);
      xof_trait::add_input (key1.data (), kem_trait::sym_key_len, hash_st_mask1);
      xof_trait::finalize_input (hash_st_mask1);
      xof_trait::get_output (security_len + 2 * kem_trait::secret_len, mask1.data (), hash_st_mask1);

      memxor (symct1_out.data (), mask1.data (), security_len + 2 * kem_trait::secret_len);
    }

    /* Compute the confirmation tag */
    {
      typename xof_trait::hash_state_t hash_st_tag = hash_st_init;
      uint64_t ctr = 2;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_tag);
      xof_trait::add_input (secret0.data (), kem_trait::secret_len, hash_st_tag);
      xof_trait::add_input (secret1.data (), kem_trait::secret_len, hash_st_tag);
      xof_trait::add_input (st.common_secret.data (), security_len, hash_st_tag);
      xof_trait::finalize_input (hash_st_tag);
      xof_trait::get_output (security_len, tag_out.data (), hash_st_tag);
    }

    st.stage = 1;
  }

  /* Step 3: Receiver extracts common secret and generates challenge response.
     Receiver should abort the protocol if this step returns false.
   */
  static bool bdgm_ot_step3
  (const kem_trait::ciphertext_t &ct0,
   const kem_trait::ciphertext_t &ct1,
   const std::array < unsigned char, 2 * kem_trait::secret_len + security_len > &symct0,
   const std::array < unsigned char, 2 * kem_trait::secret_len + security_len > &symct1,
   const std::array < unsigned char, security_len > &tag,
   std::array < unsigned char, security_len > &resp_out,
   bdgm_ot_receiver_state &st) {
    if (st.stage != 1) std::terminate ();
    uint32_t b_val = st.b;

    /* ct_b and ct_(1-b) */
    typename kem_trait::ciphertext_t ct, ct_alt;
    std::array < unsigned char, 2 * kem_trait::secret_len + security_len > symct, symct_alt;

    cond_memcpy (1 - b_val, ct.data (), ct0.data (), kem_trait::ciphertext_len);
    cond_memcpy (1 - b_val, symct.data (), symct0.data (), 2 * kem_trait::secret_len + security_len);
    cond_memcpy (b_val, ct.data (), ct1.data (), kem_trait::ciphertext_len);
    cond_memcpy (b_val, symct.data (), symct1.data (), 2 * kem_trait::secret_len + security_len);

    cond_memcpy (b_val, ct_alt.data (), ct0.data (), kem_trait::ciphertext_len);
    cond_memcpy (b_val, symct_alt.data (), symct0.data (), 2 * kem_trait::secret_len + security_len);
    cond_memcpy (1 - b_val, ct_alt.data (), ct1.data (), kem_trait::ciphertext_len);
    cond_memcpy (1 - b_val, symct_alt.data (), symct1.data (), 2 * kem_trait::secret_len + security_len);

    /* Decrypt ct_b */
    typename kem_trait::sym_key_t symkey;
    kem_trait::decapsulate (st.sk, ct, symkey);

    typename kem_trait::public_key_t pk0, pk1;
    cond_memcpy (1 - b_val, pk0.data (), st.pk.data (), kem_trait::public_key_len);
    cond_memcpy (b_val, pk0.data (), st.pk_alt.data (), kem_trait::public_key_len);
    cond_memcpy (b_val, pk1.data (), st.pk.data (), kem_trait::public_key_len);
    cond_memcpy (1 - b_val, pk1.data (), st.pk_alt.data (), kem_trait::public_key_len);

    /* Prepare hash state (seed || pk0 || pk1) to avoid repeated computation */
    typename xof_trait::hash_state_t hash_st_init;
    xof_trait::add_input (st.seed.data (), security_len, hash_st_init);
    xof_trait::add_input (pk0.data (), kem_trait::public_key_len, hash_st_init);
    xof_trait::add_input (pk1.data (), kem_trait::public_key_len, hash_st_init);

    std::array < unsigned char, security_len + 2 * kem_trait::secret_len > plaintext;
    {
      typename xof_trait::hash_state_t hash_st = hash_st_init;
      uint64_t ctr = b_val;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st);
      xof_trait::add_input (symkey.data (), kem_trait::sym_key_len, hash_st);
      xof_trait::finalize_input (hash_st);
      xof_trait::get_output (security_len + 2 * kem_trait::secret_len, plaintext.data (), hash_st);
    }
    memxor (plaintext.data (), symct.data (), security_len + 2 * kem_trait::secret_len);

    /* At this point, plaintext should contain secret0,
       plaintext + kem_trait::secret_len should contain secret1,
       plaintext + 2 * kem_trait::secret_len should contain common_secret.
     */
    memcpy (st.common_secret.data (), plaintext.data () + 2 * kem_trait::secret_len, security_len);

    std::array < unsigned char, kem_trait::secret_len > secret, secret_alt;
    cond_memcpy (1 - b_val, secret.data (), plaintext.data (), kem_trait::secret_len);
    cond_memcpy (b_val, secret.data (), plaintext.data () + kem_trait::secret_len, kem_trait::secret_len);
    cond_memcpy (b_val, secret_alt.data (), plaintext.data (), kem_trait::secret_len);
    cond_memcpy (1 - b_val, secret_alt.data (), plaintext.data () + kem_trait::secret_len, kem_trait::secret_len);

    /* Reencrypt secret_b with pk_b, secret_(1-b) with pk_(1-b) to check that ciphertexts are correct */
    typename kem_trait::ciphertext_t ct_check;
    typename kem_trait::sym_key_t symkey_alt;

    kem_trait::encapsulate (st.pk, secret, ct_check, symkey_alt);
    uint64_t check_flag1 = safe_memcmp (ct.data (), ct_check.data (), kem_trait::ciphertext_len);
    kem_trait::encapsulate (st.pk_alt, secret_alt, ct_check, symkey_alt);
    uint64_t check_flag2 = safe_memcmp (ct_alt.data (), ct_check.data (), kem_trait::ciphertext_len);

    /* To ensure constant-time, we proceed regardless of the flags computed above, but only check them at the end of computation. */

    /* Decrypt the other symmetric ciphertext, and check that the two plaintexts are equal */
    std::array < unsigned char, security_len + 2 * kem_trait::secret_len > plaintext_alt;
    {
      typename xof_trait::hash_state_t hash_st_alt = hash_st_init;
      uint64_t ctr = 1 - b_val;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_alt);
      xof_trait::add_input (symkey_alt.data (), kem_trait::sym_key_len, hash_st_alt);
      xof_trait::finalize_input (hash_st_alt);
      xof_trait::get_output (security_len + 2 * kem_trait::secret_len, plaintext_alt.data (), hash_st_alt);
    }
    memxor (plaintext_alt.data (), symct_alt.data (), security_len + 2 * kem_trait::secret_len);

    uint64_t check_flag3 = safe_memcmp (plaintext.data (), plaintext_alt.data (), security_len + 2 * kem_trait::secret_len);

    /* Check the confirmation tag */
    std::array < unsigned char, security_len + 2 * kem_trait::secret_len > tag_check;
    {
      typename xof_trait::hash_state_t hash_st_tag = hash_st_init;
      uint64_t ctr = 2;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_tag);
      xof_trait::add_input (plaintext.data (), security_len + 2 * kem_trait::secret_len, hash_st_tag);
      xof_trait::finalize_input (hash_st_tag);
      xof_trait::get_output (security_len, tag_check.data (), hash_st_tag);
    }
    uint64_t check_flag4 = safe_memcmp (tag.data (), tag_check.data (), security_len);

    /* The response is Hash(seed || pk0 || pk1 || 0x03 || 7 bytes of 0x00 || common_secret) */
    {
      typename xof_trait::hash_state_t hash_st_resp = hash_st_init;
      uint64_t ctr = 3;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_resp);
      xof_trait::add_input (st.common_secret.data (), security_len, hash_st_resp);
      xof_trait::finalize_input (hash_st_resp);
      xof_trait::get_output (security_len, resp_out.data (), hash_st_resp);
    }

    uint64_t result = 1 - uint64_to_bool (check_flag1 | check_flag2 | check_flag3 | check_flag4);
    st.stage = uint64_cmp_ge_branch (result, 1, 2, 1);
    return result;
  }

  /* Step 4: Sender checks correctness of challenge response.
     Sender should abort the protocol if this step returns false.
   */
  static bool bdgm_ot_step4 (const std::array < unsigned char, security_len > &resp, bdgm_ot_sender_state &st) {
    if (st.stage != 1) std::terminate ();

    std::array < unsigned char, security_len > resp_check;
    {
      typename xof_trait::hash_state_t hash_st_resp;
      xof_trait::add_input (st.seed.data (), security_len, hash_st_resp);
      xof_trait::add_input (st.pk0.data (), kem_trait::public_key_len, hash_st_resp);
      xof_trait::add_input (st.pk1.data (), kem_trait::public_key_len, hash_st_resp);
      uint64_t ctr = 3;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_resp);
      xof_trait::add_input (st.common_secret.data (), security_len, hash_st_resp);
      xof_trait::finalize_input (hash_st_resp);
      xof_trait::get_output (security_len, resp_check.data (), hash_st_resp);
    }

    uint64_t result = safe_memcmp (resp_check.data (), resp.data (), security_len);
    result = 1 - uint64_to_bool (result);
    st.stage = uint64_cmp_ge_branch (result, 1, 2, 1);
    return result;
  }

  /* Step 5: Sender encrypts two messages using the two keys. */
  static void bdgm_ot_step5
  (const std::array < unsigned char, msg_len > &msg0,
   const std::array < unsigned char, msg_len > &msg1,
   kem_trait::ciphertext_t &ct0_out,
   kem_trait::ciphertext_t &ct1_out,
   std::array < unsigned char, msg_len > &symct0_out,
   std::array < unsigned char, msg_len > &symct1_out,
   std::array < unsigned char, security_len > &tag0_out,
   std::array < unsigned char, security_len > &tag1_out,
   bdgm_ot_sender_state &st) {
    if (st.stage != 2) std::terminate ();

    /* Generate two secrets */
    typename kem_trait::secret_t secret0, secret1;
    kem_trait::gen_secret (st.pk0, secret0);
    kem_trait::gen_secret (st.pk1, secret1);

    /* Encapsulate the two secrets */
    typename kem_trait::sym_key_t key0, key1;
    kem_trait::encapsulate (st.pk0, secret0, ct0_out, key0);
    kem_trait::encapsulate (st.pk1, secret1, ct1_out, key1);

    /* Copy the two messages */
    memcpy (symct0_out.data (), msg0.data (), msg_len);
    memcpy (symct1_out.data (), msg1.data (), msg_len);

    /* Prepare hash state (seed || pk0 || pk1) to avoid repeated computation */
    typename xof_trait::hash_state_t hash_st_init;
    xof_trait::add_input (st.seed.data (), security_len, hash_st_init);
    xof_trait::add_input (st.pk0.data (), kem_trait::public_key_len, hash_st_init);
    xof_trait::add_input (st.pk1.data (), kem_trait::public_key_len, hash_st_init);

    /* Mask the two messages.
       Each mask is Hash(seed || pk0 || pk1 || 0x04 or 0x05 || 7 bytes of 0x00 || key0 or key1)
     */
    {
      std::array < unsigned char, msg_len > mask0;
      typename xof_trait::hash_state_t hash_st_mask0 = hash_st_init;
      uint64_t ctr = 4;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_mask0);
      xof_trait::add_input (key0.data (), kem_trait::sym_key_len, hash_st_mask0);
      xof_trait::finalize_input (hash_st_mask0);
      xof_trait::get_output (msg_len, mask0.data (), hash_st_mask0);

      memxor (symct0_out.data (), mask0.data (), msg_len);
    }

    {
      std::array < unsigned char, msg_len > mask1;
      typename xof_trait::hash_state_t hash_st_mask1 = hash_st_init;
      uint64_t ctr = 5;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_mask1);
      xof_trait::add_input (key1.data (), kem_trait::sym_key_len, hash_st_mask1);
      xof_trait::finalize_input (hash_st_mask1);
      xof_trait::get_output (msg_len, mask1.data (), hash_st_mask1);

      memxor (symct1_out.data (), mask1.data (), msg_len);
    }

    /* Compute the authentication tags.
       Each tag is Hash(seed || pk0 || pk1 || 0x06 or 0x07 || 7 bytes of 0x00 || key0 or key1 || msg0 or msg1)
     */
    {
      typename xof_trait::hash_state_t hash_st_tag0 = hash_st_init;
      uint64_t ctr = 6;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_tag0);
      xof_trait::add_input (key0.data (), security_len, hash_st_tag0);
      xof_trait::add_input (msg0.data (), security_len, hash_st_tag0);
      xof_trait::finalize_input (hash_st_tag0);
      xof_trait::get_output (security_len, tag0_out.data (), hash_st_tag0);
    }

    {
      typename xof_trait::hash_state_t hash_st_tag1 = hash_st_init;
      uint64_t ctr = 7;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_tag1);
      xof_trait::add_input (key1.data (), security_len, hash_st_tag1);
      xof_trait::add_input (msg1.data (), security_len, hash_st_tag1);
      xof_trait::finalize_input (hash_st_tag1);
      xof_trait::get_output (security_len, tag1_out.data (), hash_st_tag1);
    }

    st.stage = 3;
  }

  /* Step 6: Receiver decrypts the message */
  static bool bdgm_ot_step6
  (const kem_trait::ciphertext_t &ct0,
   const kem_trait::ciphertext_t &ct1,
   const std::array < unsigned char, msg_len > &symct0,
   const std::array < unsigned char, msg_len > &symct1,
   const std::array < unsigned char, security_len > &tag0,
   const std::array < unsigned char, security_len > &tag1,
   std::array < unsigned char, msg_len > &msg_out,
   bdgm_ot_receiver_state &st) {
    if (st.stage != 2) std::terminate ();

    /* Copy the chosen ct and tag */
    uint32_t b_val = st.b;
    typename kem_trait::ciphertext_t ct;
    std::array < unsigned char, security_len > tag;

    cond_memcpy (1 - b_val, ct.data (), ct0.data (), kem_trait::ciphertext_len);
    cond_memcpy (b_val, ct.data (), ct1.data (), kem_trait::ciphertext_len);
    cond_memcpy (1 - b_val, msg_out.data (), symct0.data (), msg_len);
    cond_memcpy (b_val, msg_out.data (), symct1.data (), msg_len);
    cond_memcpy (1 - b_val, tag.data (), tag0.data (), security_len);
    cond_memcpy (b_val, tag.data (), tag1.data (), security_len);

    /* Decrypt ct */
    typename kem_trait::sym_key_t key;
    kem_trait::decapsulate (st.sk, ct, key);

    /* Prepare hash state (seed || pk0 || pk1) */
    typename xof_trait::hash_state_t hash_st_init;
    {
      typename kem_trait::public_key_t pk0, pk1;
      cond_memcpy (1 - b_val, pk0.data (), st.pk.data (), kem_trait::public_key_len);
      cond_memcpy (b_val, pk0.data (), st.pk_alt.data (), kem_trait::public_key_len);
      cond_memcpy (b_val, pk1.data (), st.pk.data (), kem_trait::public_key_len);
      cond_memcpy (1 - b_val, pk1.data (), st.pk_alt.data (), kem_trait::public_key_len);

      xof_trait::add_input (st.seed.data (), security_len, hash_st_init);
      xof_trait::add_input (pk0.data (), kem_trait::public_key_len, hash_st_init);
      xof_trait::add_input (pk1.data (), kem_trait::public_key_len, hash_st_init);
    }

    /* Compute the mask and decrypt symct */
    std::array < unsigned char, msg_len > mask;
    {
      typename xof_trait::hash_state_t hash_st_mask = hash_st_init;
      uint64_t ctr = 4 + b_val;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_mask);
      xof_trait::add_input (key.data (), kem_trait::sym_key_len, hash_st_mask);
      xof_trait::finalize_input (hash_st_mask);
      xof_trait::get_output (msg_len, mask.data (), hash_st_mask);
    }
    memxor (msg_out.data (), mask.data (), msg_len);

    /* Check the authentication tag */
    std::array < unsigned char, security_len > tag_check;
    {
      typename xof_trait::hash_state_t hash_st_tag = hash_st_init;
      uint64_t ctr = 6 + b_val;
      xof_trait::add_input ((const unsigned char *) &ctr, 8, hash_st_tag);
      xof_trait::add_input (key.data (), kem_trait::sym_key_len, hash_st_tag);
      xof_trait::add_input (msg_out.data (), msg_len, hash_st_tag);
      xof_trait::finalize_input (hash_st_tag);
      xof_trait::get_output (security_len, tag_check.data (), hash_st_tag);
    }

    uint64_t result = 1 - uint64_to_bool (safe_memcmp (tag.data (), tag_check.data (), security_len));
    st.stage = uint64_cmp_ge_branch (result, 1, 3, 2);
    return result;
  }
};
