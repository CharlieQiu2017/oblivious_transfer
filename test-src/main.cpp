#include <string.h>
#include <exit.h>
#include <random.h>
#include <oblivious.hpp>
#include <ntrulpr_653.hpp>
#include <shake.hpp>

using kem_trait = ntrulpr_653_trait;
constexpr uint32_t msg_len = 32;
constexpr uint32_t security_len = 32;
using OT = bdgm_oblivious_transfer < shake256_trait, ntrulpr_653_trait, msg_len, security_len >;

extern "C" {
  void main ([[maybe_unused]] void * sp) {
    OT::bdgm_ot_receiver_state receiver;
    OT::bdgm_ot_sender_state sender;

    uint8_t rnd_b;
    getrandom (&rnd_b, 1, 0);
    bool b = rnd_b % 2;

    typename kem_trait::public_key_t pk0;

    OT::bdgm_ot_step1 (b, pk0, receiver);

    typename kem_trait::ciphertext_t ct0, ct1;
    std::array < unsigned char, 2 * kem_trait::secret_len + 2 * security_len > symct0, symct1;
    std::array < unsigned char, security_len > tag;

    OT::bdgm_ot_step2 (receiver.seed, pk0, ct0, ct1, symct0, symct1, tag, sender);

    std::array < unsigned char, security_len > resp;

    bool result1 = OT::bdgm_ot_step3 (ct0, ct1, symct0, symct1, tag, resp, receiver);

    bool result2 = OT::bdgm_ot_step4 (resp, sender);

    std::array < unsigned char, msg_len > msg0, msg1;
    getrandom (msg0.data (), msg_len, 0);
    getrandom (msg1.data (), msg_len, 0);

    kem_trait::ciphertext_t new_ct0, new_ct1;
    std::array < unsigned char, security_len + msg_len > new_symct0, new_symct1;
    std::array < unsigned char, security_len > new_tag0, new_tag1;

    OT::bdgm_ot_step5 (msg0, msg1, new_ct0, new_ct1, new_symct0, new_symct1, new_tag0, new_tag1, sender);

    std::array < unsigned char, msg_len > final_msg;

    bool result3 = OT::bdgm_ot_step6 (new_ct0, new_ct1, new_symct0, new_symct1, new_tag0, new_tag1, final_msg, receiver);

    bool result4 = b ? safe_memcmp (final_msg.data (), msg1.data (), msg_len) == 0 : safe_memcmp (final_msg.data (), msg0.data (), msg_len) == 0;

    exit (! (result1 && result2 && result3 && result4));
  }
}
