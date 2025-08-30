#include <stdint.h>
#include <string.h>
#include <ntrulpr_653.hpp>
#include <random.h>
#include <crypto/common.h>
#include <crypto/pk/ntru_lprime/ntru_lprime.h>
#include <crypto/hash/keccak/keccak_p.h>

#define NTRU_LPR_Q 4621
#define NTRU_LPR_ROUND_ENC_LEN 865
#define NTRU_LPR_CT_LEN (NTRU_LPR_ROUND_ENC_LEN + 128 + 32)

void ntrulpr_653_trait::gen_key (ntrulpr_653_trait::private_key_t &sk_out, ntrulpr_653_trait::public_key_t &pk_out) {
  ntrulpr_653_gen_key (sk_out.data (), pk_out.data ());
}

void ntrulpr_653_trait::gen_public_key_diff_from_hash (const std::array < unsigned char, ntrulpr_653_trait::hash_len > &hash, ntrulpr_653_trait::public_key_diff_t &pk_diff_out) {
  /* Seed S for G */
  memcpy (pk_diff_out.first.data (), hash.data (), 32);

  /* round(aG) */
  for (uint32_t i = 0; i < 653; ++i) {
    uint32_t t = 0;
    for (uint32_t j = 0; j < 10; ++j) {
      t = t << 8;
      t = t + hash[32 + i * 10 + j];
      /* Barrett reduction */
      uint32_t quot = (((uint64_t) t) * 43549) >> 26;
      t = t - quot * 1541;
    }
    pk_diff_out.second[i] = t;
  }
}

void ntrulpr_653_trait::compute_alt_public_key (const public_key_t &pk, const public_key_diff_t &pk_diff, public_key_t &pk_out, bool b) {
  /* Seed S for G */
  memcpy (pk_out.data (), pk.data (), 32);
  memxor (pk_out.data (), pk_diff.first.data (), 32);

  /* Convert b to uint32_t, this should be constant-time, in fact a no-op */
  uint32_t b_int = b;

  /* round(aG) */
  uint16_t poly[653];
  ntrulpr_653_decode_poly_round (pk.data () + 32, poly);
  for (uint32_t i = 0; i < 653; ++i) {
    /* Convert to byte-string representation */
    uint32_t s = poly[i];
    s = uint32_cmp_ge_branch (s, (NTRU_LPR_Q + 1) / 2, s - (NTRU_LPR_Q + 1) / 2, s + (NTRU_LPR_Q - 1) / 2);
    /* Add or subtract the difference */
    uint32_t t1 = s + 3 * pk_diff.second[i];
    uint32_t t2 = s + 4623 - 3 * pk_diff.second[i];
    uint32_t t = uint32_cmp_ge_branch (b_int, 1, t2, t1);
    /* Mod against 4623. It is NOT 4621 because the output still needs to be a multiple of 3 */
    t = uint32_cmp_ge_branch (t, 4623, t - 4623, t);
    /* Convert back to [0, Q-1] representation */
    t = uint32_cmp_ge_branch (t, (NTRU_LPR_Q - 1) / 2, t - (NTRU_LPR_Q - 1) / 2, t + (NTRU_LPR_Q + 1) / 2);
    poly[i] = t;
  }
  ntrulpr_653_encode_poly_round (poly, pk_out.data () + 32);
}

void ntrulpr_653_trait::gen_secret ([[maybe_unused]] const public_key_t &pk, secret_t &secret) {
  getrandom (secret.data (), 32, 0);
}

void ntrulpr_653_trait::encapsulate (const public_key_t &pk, const secret_t &secret, ciphertext_t &ct_out, sym_key_t &key_out) {
  ntrulpr_653_encapsulate_internal (pk.data (), secret.data (), NULL, ct_out.data ());

  uint64_t state[25] = {0};
  uint32_t curr_offset = 0;
  uint8_t init_byte = 1;
  sponge_keccak_1600_absorb (state, &curr_offset, &init_byte, 1, 72);
  sponge_keccak_1600_absorb (state, &curr_offset, secret.data (), 32, 72);
  sponge_keccak_1600_absorb (state, &curr_offset, ct_out.data (), NTRU_LPR_CT_LEN, 72);
  sponge_keccak_1600_finalize (state, curr_offset, 2 + 4, 72);
  curr_offset = 0;
  sponge_keccak_1600_squeeze (state, &curr_offset, key_out.data (), 32, 72);
}

void ntrulpr_653_trait::decapsulate (const private_key_t &sk, const ciphertext_t &ct, sym_key_t &key_out) {
  ntrulpr_653_decapsulate (sk.data (), ct.data (), key_out.data ());
}
