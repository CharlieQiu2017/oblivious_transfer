#include <stdint.h>
#include <string.h>
#include <crypto/hash/keccak/keccak_p.h>
#include <shake.hpp>

shake256_trait::shake_internal_state::shake_internal_state () {
  memset (state, 0, 200);
  curr_offset = 0;
}

void shake256_trait::add_input (const unsigned char * input, size_t len, shake256_trait::hash_state_t &st) {
  sponge_keccak_1600_absorb (st.state, &st.curr_offset, input, len, 136);
}

void shake256_trait::finalize_input (shake256_trait::hash_state_t &st) {
  sponge_keccak_1600_finalize (st.state, st.curr_offset, 15 + 16, 136);
  st.curr_offset = 0;
}

void shake256_trait::get_output (size_t len, unsigned char * output, shake256_trait::hash_state_t &st) {
  sponge_keccak_1600_squeeze (st.state, &st.curr_offset, output, len, 136);
}
