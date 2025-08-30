/* Type trait for the NTRU LPrime 653 key exchange mechanism. */

#include <stdint.h>
#include <string.h>
#include <crypto/pk/ntru_lprime/ntru_lprime.h>
#include <utility>
#include <array>

class ntrulpr_653_trait {
public:
  static constexpr size_t public_key_len = 897;
  static constexpr size_t secret_len = 32;
  static constexpr size_t ciphertext_len = 1025;
  static constexpr size_t sym_key_len = 32;

  /* These are guaranteed to be std::array < unsigned char, X_len >.
     This makes serializing these elements easy.
   */
  typedef std::array < unsigned char, public_key_len > public_key_t;
  /* secret_t is the type of the random input used in the encapsulate procedure */
  typedef std::array < unsigned char, secret_len > secret_t;
  /* ciphertext_t is the ciphertext output of the encapsulate procedure */
  typedef std::array < unsigned char, ciphertext_len > ciphertext_t;
  /* key_t is the exchanged symmetric key */
  typedef std::array < unsigned char, sym_key_len > sym_key_t;

  /* The private key type. Since private keys are not sent over the network, it does not need to be serialized, at least in the OT protocol. */
  typedef std::array < unsigned char, 1125 > private_key_t;

  /* The type that is used to represent the "difference" of two public keys. */
  typedef std::pair < std::array < unsigned char, 32 >, std::array < uint16_t, 653 > > public_key_diff_t;

  /* How many random bytes from a hash function is necessary to generate a random public key difference */
  /* For NTRU LPrime, we need 32 bytes for seed S, and 653 elements each between 0 and 1540 (inclusive). */
  /* We shall use 10 random bytes to generate one element between 0 and 1540. */
  /* This brings the statistical difference between our distribution and the uniform distribution down to < 2^-64. */
  static constexpr size_t hash_len = 32 + 653 * 10;

  /* Procedure to generate a keypair */
  static void gen_key (private_key_t &sk_out, public_key_t &pk_out);

  /* Procedure that converts a hash output to a random public key */
  static void gen_public_key_diff_from_hash (const std::array < unsigned char, hash_len > &hash, public_key_diff_t &pk_out);

  /* Procedure that computes pk1 from pk0, or pk0 from pk1.
     The impl must be careful not to leak which is the case.
     If b == false, pk is pk0, and output pk1; otherwise pk is pk1, and output pk0.
   */
  static void compute_alt_public_key (const public_key_t &pk, const public_key_diff_t &pk_diff, public_key_t &pk_out, bool b);

  /* Generate a random secret */
  static void gen_secret (const public_key_t &pk, secret_t &secret);

  /* Encapsulate a given secret using public key */
  static void encapsulate (const public_key_t &pk, const secret_t &secret, ciphertext_t &ct_out, sym_key_t &key_out);

  /* Decapsulate a ciphertext */
  static void decapsulate (const private_key_t &sk, const ciphertext_t &ct, sym_key_t &key_out);
};
