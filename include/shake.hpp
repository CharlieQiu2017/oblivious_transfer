/* Type trait for the SHAKE256 extendable output function */

#include <stddef.h>
#include <stdint.h>

class shake256_trait {
public:
  struct shake_internal_state {
    uint64_t state[25];
    uint32_t curr_offset;

    shake_internal_state ();
  };

  /* hash_state_t is assumed to be copyable,
     so that we can avoid duplicated computation when hashing inputs with common prefixes */
  typedef shake_internal_state hash_state_t;

  static void add_input (const unsigned char * input, size_t len, hash_state_t &st);

  /* No input can be added after calling finalize_input */
  static void finalize_input (hash_state_t &st);

  /* Must be called after finalize_input */
  static void get_output (size_t len, unsigned char * output, hash_state_t &st);
};
