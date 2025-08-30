# A C++ Implementation of the BDGM19 Oblivious Transfer Protocol

This repository contains a C++ implementation of an oblivious transfer protocol modified from the paper
"A Framework for Universally Composable Oblivious Transfer from One-Round Key-Exchange"
(https://eprint.iacr.org/2019/726.pdf, cited as BDGM19 below).

## Background

Oblivious transfer (OT) is a cryptographic primitive that, informally speaking, achieves the following functionality:
Alice inputs two messages `msg_0` and `msg_1`.
Bob inputs a bit `b`.
Then Bob learns the message `msg_b`, but learns nothing about `msg_(1-b)`.
Also, Alice learns nothing about the bit `b`.
Alice is called the "sender" as she provides the two messages, while Bob is called the "receiver" as he receives one of the two messages.

OT is considered a very important cryptographic functionality:
* It can be used together with Yao's Garbled Circuit (GC) protocol to achieve two-party secure computation.
See https://en.wikipedia.org/wiki/Garbled_circuit.
* With some additional techniques, it can be used to achieve secure multiparty computation (MPC) for any number of parties.
See https://securecomputation.org/docs/pragmaticmpc.pdf.

As such, there has been a large number of works on designing secure OT protocols.
In this blog post, we look at a specific protocol proposed by Branco et al. (https://eprint.iacr.org/2019/726.pdf) based on key exchange mechanisms (KEM).
We shall call it the BDGM19 protocol.
We will see that BDGM19 actually contains a security flaw.
We describe a modified version of BDGM19 that corrects the issues,
and provide a C++ implementation of the modified BDGM19 protocol.

## Getting Started

This implementation relies on my custom C library (https://github.com/CharlieQiu2017/mini_libc/).
Specifically, it relies on the following functionalities:
* The `getrandom()` syscall interface, which is declared in `<random.h>` in my C library,
but in glibc it is declared in `<sys/random.h>`.
* `cond_memcpy()` which provides cryptographically-safe conditional memcpy.
* `safe_memcmp()` which provides cryptographically-safe memcmp.
* `memxor()` which computes exclusive-or (XOR) of two memory regions, and is cryptographically-safe.
* Some other helper functions for cryptography.
These functions rely on inline AArch64 assembly.
Therefore, this program can only be compiled to an AArch64 target.
* The NTRU-LPrime key exchange algorithm and the SHAKE256 hash algorithm.

BDGM19 is not a "complete" protocol, but rather a "framework".
It depends on a key exchange mechanism, and a random oracle-indifferentiable hash function,
and can be instantiated with various choices of these primitives.
As such, our BDGM19 implementation is provided as a template class in `include/oblivious.hpp`:

```c++
template < typename xof_trait, typename kem_trait, size_t msg_len, size_t security_len >
class bdgm_oblivious_transfer;
```

The class `bdgm_oblivious_transfer` takes two type parameters `xof_trait` and `kem_trait`.
They represent interfaces of a hash function and a key exchange mechanism, respectively.
The hash function is assumed to be an extendable-output function (XOF),
meaning one can obtain an output of arbitrary length from the hash function, rather than a fixed-length output.

The class `bdgm_oblivious_transfer` additionally takes two parameters called `msg_len` and `security_len`.
They represent the length of the messages and the security parameter, respectively.
The security parameter determines the length of initialization vectors (IV) and message authentication codes (MAC) used in the protocol.
In most cases it should be set to 16 (128 bits) or 32 (256 bits).

We provide examples of implementing the `xof_trait` and the `kem_trait` in `include/shake.hpp` and `include/ntrulpr_653.hpp` respectively.
They are wrappers over the SHAKE256 hash function and the NTRU-LPrime 653 key exchange algorithm in my custom C library.
The functions declared in these headers are implemented in `src/shake.cpp` and `src/ntrulpr_653.cpp` respectively.

Finally, we provide an example executable that demonstrates how to use our implementation.
The executable is implemented in `test-src/main.cpp`.
The program instantiates both a receiver and a sender.
The receiver chooses a random bit `b`, while the sender sends two random messages `msg_0` and `msg_1`.
The message received by the receiver should be identical to `msg_b`.
The program exits normally if the protocol completes successfully, and aborts if some step fails.

On a typical Linux environment, please follow these steps to compile the example executable:
1. Install a recent version of the GNU toolchain that targets AArch64.
Since we do not rely on the standard C library, an installation that targets bare metal AArch64 (`aarch64-none-elf`) is sufficient.
Precompiled binaries can be obtained at https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads.
2. Download my custom C library (https://github.com/CharlieQiu2017/mini_libc).
Invoke `make` at the root of the custom C library to build the library.
You should provide the following variables to `make`:
   * `CC`: Absolute path of `gcc`.
   * `AS`: Absolute path of `as` (part of `binutils`).
   * `AR`: Absolute path of `ar` (part of `binutils`).
   * `LD`: Absolute path of `ld` (part of `binutils`).
   * `M4`: Absolute path of `m4` (the m4 macro processor).
   * `LIBGCC`: Absolute path of `libgcc.a` (part of the GCC installation).

   Also provide `debug=1` or `optimize=1` depending on whether you want to debug the library or not.
3. If the custom C library builds successfully, you should see `crt.o`, `libc.a` and `libc_pic.a` at the root of the custom C library.
4. Download this repository.
   Invoke `make` at the root of this repository to build the implementation.
   You should provide the following variables to `make`:
   * `CC`: Absolute path of `gcc`.
   * `CXX`: Absolute path of `g++`.
   * `AS`: Absolute path of `as` (part of `binutils`).
   * `AR`: Absolute path of `ar` (part of `binutils`).
   * `LD`: Absolute path of `ld` (part of `binutils`).
   * `M4`: Absolute path of `m4` (the m4 macro processor).
   * `LIBSUPCXX`: Absolute path of `libsupc++.a` or `libstdc++.a` (part of the GCC installation).
   * `LIBC`: Root of my custom C library.
   * `LIBGCC`: Absolute path of `libgcc.a` (part of the GCC installation).

   The only function we need from `libstdc++` is `std::terminate()`.
   If you provide a custom implementation of this function, the dependency on `libstdc++` (or `libsupc++` in bare metal toolchains) can be removed.

   Like the custom C library, you may specify `debug=1` or `optimize=1` depending on whether you need debug information or not.
5. If the build succeeds, the example executable is located at `test-bin/main`.
6. The example executable provides no output other than exit status.
An exit status of 0 means the protocol executation is successful, while a non-zero exit status indicates some error in the protocol.

## The Theory

BDGM19 relies on a key exchange mechanism (KEM), which consists of the following algorithms:
1. `GenKey()` which returns a *public key* and a *private key*.
2. `GenSecret(pk)` which takes a public key as input and randomly generates a secret `s`.
3. `Encapsulate(pk, s)` which takes a public key `pk` and a secret `s` as input and returns a ciphertext `ct` and a key `k`.
4. `Decapsulate(sk, ct)` which takes a private key `sk` and a ciphertext `ct` as input and returns a key `k`.

We assume the KEM is *perfectly correct*, meaning for every valid keypair `(pk, sk)` generated by `GenKey()` and every possible secret `s` generated by `GenSecret(pk)`,
if `Encapsulate(pk, s) = (ct, k)`, then `Decapsulate(sk, ct) = k`.
Some KEMs like Kyber are not perfectly correct, but only *statistically correct*,
meaning the decryption has a very small but positive probability to fail.
While it is probably fine to use such KEMs in the BDGM19 framework,
the possibility of decryption failure complicates security analysis of the protocol,
and we would like to not deal with such complications.

Moreover, we assume `Encapsulate(pk, s)` is deterministic.
That is, all randomness involved in generating a ciphertext is captured by the secret `s`.
Note that `Decapsulate(sk, ct)` is not required to recover the entire `s`.

We will use the key `k` returned by the `Encapsulate()` and `Decapsulate()` procedures as a symmetric key to encrypt byte-strings.
We assume a symmetric encryption scheme consisting of the following algorithms:
1. `Enc(k, r, M)`: Encrypts message `M` using key `k` and randomness `r` and returns a ciphertext `ct`.
2. `Dec(k, ct)`: Decrypts ciphertext `ct` using key `k`.

Similar to the KEM defined above, we assume `Enc()` and `Dec()` are deterministic.

The basic idea of the BDGM19 protocol is as follows:
1. The receiver provides two random public keys to the sender,
such that the receiver only knows the private key corresponding to one of the two keys;
2. The receiver proves to the sender that it knows the private key corresponding to one (and exactly one) of the two public keys;
3. The sender encrypts its two messages using the two public keys, and sends the ciphertexts to the receiver.

The tricky part is to convince the sender that the receiver can only decrypt one of the two ciphertexts.
Also, the receiver cannot reveal which ciphertext it can decrypt during this process.

BDGM19 assumes that all valid public keys belong to an abelian group `M`.
This means there is a commutative and associative binary operation `a + b` defined over `M`,
such that for every element `x` in `M` there is an *inverse element* `-x` with `a + (x + (-x)) = a` for every `a` in `M`.
Also, a random public key generated by `GenKey()` is assumed to be indistinguishable from a uniformly random element of `M`.

If `pk` is a public key whose corresponding private key is known to the receiver, but `x` is a uniformly random element of `M`,
then `pk + x` (or `pk + (-x)`) is also a uniformly random element of `M`.
Consequently, the receiver is unable to decrypt ciphertexts encrypted using `pk + x`.
The idea of BDGM19 is to use a random oracle to generate `x`.
The receiver provides two public keys `pk_0` and `pk_1` to the sender, such that `pk_1 = pk_0 + x`.
The sender can verify that `x` is indeed a uniformly random element picked by the random oracle,
and so be assured that the receiver may decrypt only one of the two ciphertexts.

To achieve universal composability (UC), the sender must also verify that the receiver can decrypt at least one of the two ciphertexts.
This allows a simulator to extract the bit `b` chosen by the receiver.
BDGM19 describes an elaborate protocol to verify this condition.
As we will see, the approach taken by BDGM19 is in fact flawed, and we adopt a simpler approach that fixes the issues.

### Formal Description of the BDGM19 Protocol

Step 1: The receiver inputs its chosen bit `b`.

```text
Input: bit b
(pk, sk) <- GenKey()
seed <- GetRandom(lambda) // Get lambda random bytes, where lambda is the security parameter.
x <- Hash_1(seed) // Hash functions are modeled as random oracles.
// Hash functions with different subscripts are independent.
// The following statements ensure that pk_1 = pk_0 + Hash_1(seed).
if (b == 0) {
    pk_0 <- pk
    pk_1 <- pk + x
} else {
    pk_0 <- pk + (-x)
    pk_1 <- pk
}
Output: seed, pk_0, sk.
Send seed, pk_0 to the sender.
Store seed, b, sk for future use.
```

Step 2: The sender receives `seed` and `pk_0` rom the receiver, computes `pk_1 = pk_0 + Hash_1(seed)`, and generates a challenge to confirm the receiver can decrypt one of the ciphertexts.

```text
Input: seed, pk_0 from step 1.
pk_1 <- pk_0 + Hash_1(seed)
s_0 <- GenSecret(pk_0)
s_1 <- GenSecret(pk_1)
(ct_0, key_0) <- Encapsulate(pk_0, s_0)
(ct_1, key_1) <- Encapsulate(pk_1, s_1)
// Derive keys from key_0, key_1.
dkey_0 <- Hash_2(key_0)
dkey_1 <- Hash_2(key_1)
(w_0, z_0, w_1, z_1) <- GetRandom(4 * lambda)
// w_0 and w_1 will be used as plaintexts, while z_0 and z_1 will be used as randomness for symmetric encryption.
a_0 <- Enc(dkey_0, z_0, w_0)
a_1 <- Enc(dkey_1, z_1, w_1)
// The receiver should be able to decrypt exactly one of a_0, a_1.
// Derive masks from w_0, w_1.
mask_0 <- Hash_3(w_0)
mask_1 <- Hash_3(w_1)
u_0 <- mask_0 XOR (dkey_1 || z_1 || w_1) // x || y means concatenating x and y.
u_1 <- mask_1 XOR (dkey_0 || z_0 || w_0)
ch <- Hash_4(w_0 || z_0 || w_1 || z_1)
Output: ct_0, ct_1, key_0, key_1, a_0, a_1, u_0, u_1, ch.
Send ct_0, ct_1, a_0, a_1, u_0, u_1 to receiver.
Store key_0, key_1, ch for future use.
```

Step 3: The receiver decrypts one of the two ciphertexts, and retrieves `w_0, z_0, w_1, z_1`.
It computes `Hash_4(w_0 || z_0 || w_1 || z_1)` and sends the result to the sender.

```text
Input: b, sk from step 1; ct_0, ct_1, a_0, a_1, u_0, u_1 from step 2.
ct <- ct_b
a <- a_b
a' <- a_(1-b)
u <- u_b
u' <- u_(1-b)
key <- Decapsulate(sk, ct)
dkey <- Hash_2(key)
w <- Dec(dkey, a)
mask <- Hash_3(w)
(dkey', z', w') <- mask XOR u
Check that a' == Enc(dkey', z', w'). Abort if this step fails.
mask' <- Hash_3(w')
(dkey'', z'', w'') <- mask' XOR u'
Check that a == Enc(dkey'', z'', w'') and (dkey'', w'') == (dkey, w). Abort if this step fails.
if (b == 0) {
    w_0 <- w''
    w_1 <- w'
    z_0 <- z''
    z_1 <- z'
} else {
    w_0 <- w'
    w_1 <- w''
    z_0 <- z'
    z_1 <- z''
}
resp <- Hash_4(w_0, z_0, w_1, z_1)
Output: key, resp.
Send resp to the sender.
Store key for future use.
```

Step 4: The sender checks that `ch == resp`.

```text
Input: ch from step 3; resp from step 4.
Check that ch == resp. Abort if this step fails.
Output: None.
```

Step 5: The sender encrypts the two messages using `key_0` and `key_1`.

```text
Input: msg_0, msg_1; key_0, key_1 from step 2.
(r_0, r_1) <- GetRandom(2 * lambda)
c_0 <- Enc(key_0, r_0, msg_0)
c_1 <- Enc(key_1, r_1, msg_1)
Output: c_0, c_1.
Send c_0, c_1 to the receiver.
```

Step 6: The receiver decrypts one of the ciphertexts.

```text
Input: b from step 1; key from step 3; c_0, c_1 from step 5.
c <- c_b
msg <- Dec(key, c)
Output: msg.
```

In step 3, if the receiver can decrypt one of `a_0, a_1`, then it can obtain all four random values `w_0, z_0, w_1, z_1`.
The various checks are intended to guarantee that, regardless of which ciphertext the receiver decrypts, it will always get the same four values.
Thus the response will not reveal the bit `b` the receiver has chosen.
However, as we will see next, the procedure used by BDGM19 has a flaw.

## A Security Flaw in the BDGM19 Protocol

The flaw of BDGM19 is that in step 3, the receiver never uses the value of `ct_(1-b)`.
This leads to the following attack:
1. The sender prepares the ciphertexts in step 2 as usual.
Just before sending the ciphertexts to the receiver, it replaces one of `ct_0` with a random ciphertext.
2. If the receiver holds `b == 0`, then it will not be able to decrypt `ct_0` and obtain `key_0`. Thus it will abort the protocol.
On the other hand, if the receiver holds `b == 1` then it will ignore the invalid ciphertext `ct_0`, and generate the response as usual.
3. Thus, the sender can recover the bit `b` chosen by the receiver by observing whether it aborts the protocol or not.

## The Modified Protocol

To fix the vulnerability described above, we let the receiver recover the full randomness used to generate the ciphertexts in step 2.
However, this implies that in step 5 we cannot reuse the keys exchanged during step 2 and 3.
Instead, we must generate new secrets and ciphertexts in step 5.

Step 1 remains the same as BDGM19.
The receiver sends `seed` and `pk_0` to the sender.
However, the receiver additionally stores `pk_0, pk_1` for future use.

Step 2 is modified as follows:
```text
Input: seed, pk_0 from step 1.
pk_1 <- pk_0 + Hash_1(seed)
s_0 <- GenSecret(pk_0)
s_1 <- GenSecret(pk_1)
(ct_0, key_0) <- Encapsulate(pk_0, s_0)
(ct_1, key_1) <- Encapsulate(pk_1, s_1)
common_secret <- GetRandom(lambda)
mask_0 <- Hash_2(key_0)
mask_1 <- Hash_3(key_1)
a_0 <- mask_0 XOR (s_0 || s_1 || common_secret)
a_1 <- mask_1 XOR (s_0 || s_1 || common_secret)
tag <- Hash_4(s_0 || s_1 || common_secret)
ch <- Hash_5(s_0 || s_1 || common_secret)
Output: ct_0, ct_1, a_0, a_1, tag, ch, common_secret.
Send ct_0, ct_1, a_0, a_1, tag to the receiver.
Store common_secret, ch for future use.
```

Step 3 is modified as follows:
```text
Input: b, pk_0, pk_1, sk from step 1; ct_0, ct_1, a_0, a_1, tag from step 2.
pk <- pk_b
ct <- ct_b
a <- a_b
key <- Decapsulate(sk, ct)
mask <- Hash_(2+b)(key)
(s_0, s_1, common_secret) <- mask XOR a
Check that Encapsulate(pk, s_b) == ct. Abort if this step fails.
(ct', key') <- Encapsulate(pk_(1-b), s_(1-b))
Check that ct' == ct_(1-b). Abort if this step fails.
mask' <- Hash_(2+(1-b))(key')
(s'_0, s'_1, common_secret') <- mask' XOR a_(1-b)
Check that (s_0, s_1, common_secret) == (s'_0, s'_1, common_secret'). Abort if this step fails.
Check that Hash_4(s_0 || s_1 || common_secret) == tag. Abort if this step fails.
resp <- Hash_5(s_0 || s_1 || common_secret)
Output: common_secret, resp.
Send resp to the sender.
Store common_secret for future use.
```

Step 4 remains the same as BDGM19. The sender checks that `ch == resp`.

Step 5 is modified as follows:
```text
Input: msg_0, msg_1; pk_0, pk_1, common_secret from step 2.
s_0 <- GenSecret(pk_0)
s_1 <- GenSecret(pk_1)
(ct_0, key_0) <- Encapsulate(pk_0, s_0)
(ct_1, key_1) <- Encapsulate(pk_1, s_1)
mask_0 <- Hash_6(common_secret || key_0)
mask_1 <- Hash_7(common_secret || key_1)
a_0 <- mask_0 XOR msg_0
a_1 <- mask_1 XOR msg_1
tag_0 <- Hash_8(common_secret || key_0 || msg_0)
tag_1 <- Hash_9(common_secret || key_1 || msg_1)
Output: ct_0, ct_1, a_0, a_1, tag_0, tag_1.
Send ct_0, ct_1, a_0, a_1, tag_0, tag_1 to the receiver.
```

Step 6 is modified as follows:
```text
Input: b, sk from step 1; common_secret from step 3; ct_0, ct_1, a_0, a_1, tag_0, tag_1 from step 5.
ct <- ct_b
a <- a_b
tag <- tag_b
key <- Decapsulate(sk, ct)
mask <- Hash_(6+b)(common_secret || key)
msg <- mask XOR a
Check thag Hash_(8+b)(common_secret || key || msg) == tag. Abort if this step fails.
Output: msg.
```

## The Implementation

### The KEM Type Trait

We expect users of the library to provide a type argument `kem_trait` that represents the interface of a KEM algorithm.
This class should define the following size parameters of the KEM:
* `static constexpr size_t public_key_len`: Length, in bytes, of a public key returned by `GenKey()`.
* `static constexpr size_t secret_len`: Length, in bytes, of a secret returned by `GenSecret(pk)`.
* `static constexpr size_t ciphertext_len`: Length, in bytes, of a ciphertext returned by `Encapsulate(pk, s)`.
* `static constexpr size_t sym_key_len`: Length, in bytes, of a key returned by `Encapsulate(pk, s)`.

The class should make the following typedefs.
This is to facilitate serializing these values.
* `typedef std::array < unsigned char, public_key_len > public_key_t;`
* `typedef std::array < unsigned char, secret_len > secret_t;`
* `typedef std::array < unsigned char, ciphertext_len > ciphertext_t;`
* `typedef std::array < unsigned char, sym_key_len > sym_key_t;`

Recall that we assume all public keys belong to an abelian group `M`.
In theory, the "difference" of two public keys `pk0, pk1` (defined as `(-pk0) + pk1`) should also be a member of `M`.
To facilitate implementation, we do not require that the difference be represented using the same type as public keys.
The class should define a type `public_key_diff_t` to represent the difference of two public keys,
and specify the number of uniformly random bytes needed to sample a uniformly random element from `M`:
* `typedef /* unspecified */ public_key_diff_t;`
* `static constexpr size_t hash_len = /* unspecified */;`

The class should define the following static functions:
* `static void gen_key (private_key_t &sk_out, public_key_t &pk_out)`: The `GenKey()` procedure.
* `static void gen_public_key_diff_from_hash (const std::array < unsigned char, hash_len > &hash, public_key_diff_t &pk_out)`: Given `hash_len` bytes of uniformly random data, generate a uniformly random element of the abelian group `M`.
The uniformly random bytes will later be supplied by a random oracle.
* `static void compute_alt_public_key (const public_key_t &pk, const public_key_diff_t &pk_diff, public_key_t &pk_out, bool b)`:
Given two elements of the abelian group `M`, represented by `pk` and `pk_diff`, compute `pk + pk_diff` if `b == 0`, and `pk + (-pk_diff)` if `b == 1`.
The implementation must take care not to leak the value of `b`.
* `static void gen_secret (const public_key_t &pk, secret_t &secret)`: The `GenSecret(pk)` procedure.
* `static void encapsulate (const public_key_t &pk, const secret_t &secret, ciphertext_t &ct_out, sym_key_t &key_out)`: The `Encapsulate(pk, s)` procedure.
* `static void decapsulate (const private_key_t &sk, const ciphertext_t &ct, sym_key_t &key_out)`: The `Decapsulate(sk, ct)` procedure.

### The XOF Type Trait

We expect users of the library to provide a type argument `xof_trait` that represents the interface of an extendable-output hash function (XOF).
The interface of `xof_trait` follows the "stateful hash object" (SHO) defined at https://github.com/noiseprotocol/sho_spec/blob/master/sho.md.

The class should define a type `hash_state_t` that represents the internal state of the hash function:
* `typedef /* unspecified */ hash_state_t;`

The type `hash_state_t` should be default-constructible, copy-constructible, and copyable.
If it is default-constructed, it should represent the state where no input has been provided to the hash function.
The state can be modified via the following three static functions:
* `static void add_input (const unsigned char * input, size_t len, hash_state_t &st)`: Provide `len` bytes of input to the hash function.
This function must NOT be called after `finalize_input(st)` is called.
* `static void finalize_input (hash_state_t &st)`: Signal to the hash function that no further input will be provided.
* `static void get_output (size_t len, unsigned char * output, hash_state_t &st)`: Extract `len` bytes of output from the hash function.
This function must NOT be called before `finalize_input(st)` is called.

We assume that all three functions are deterministic.
Moreover, making two consecutive calls to `add_input` is equivalent to making a single call with the two inputs concatenated.
Also, making two consecutive calls to `get_output` is equivalent to making a single call with the two outputs concatenated.

### The Main Algorithm

The class `bdgm_oblivious_transfer` defines two types `bdgm_ot_receiver_state` and `bdgm_ot_sender_state`,
representing the internal state of a receiver and a sender, respectively.
Both types can be default-constructed.

The class exposes the following six static functions representing the six steps of the protocol:
```c++
/* Step 1: The receiver inputs bit b and sends seed, pk_0 to the sender.
   pk_0 is retrieved through the pk0_out parameter.
   seed is retrieved through st.seed.
 */
static void bdgm_ot_step1 (bool b, kem_trait::public_key_t &pk0_out, bdgm_ot_receiver_state &st);

/* Step 2: The sender generates two ciphertexts and an authentication tag.
 */
static void bdgm_ot_step2
  (const std::array < unsigned char, security_len > seed,
   const kem_trait::public_key_t &pk0,
   kem_trait::ciphertext_t &ct0_out,
   kem_trait::ciphertext_t &ct1_out,
   std::array < unsigned char, 2 * kem_trait::secret_len + 2 * security_len > &symct0_out,
   std::array < unsigned char, 2 * kem_trait::secret_len + 2 * security_len > &symct1_out,
   std::array < unsigned char, security_len > &tag_out,
   bdgm_ot_sender_state &st);

/* Step 3: The receiver decrypts one of the ciphertexts and generates the challenge response `resp`.
   The receiver should abort the protocol if this function returns false.
 */
static bool bdgm_ot_step3
  (const kem_trait::ciphertext_t &ct0,
   const kem_trait::ciphertext_t &ct1,
   const std::array < unsigned char, 2 * kem_trait::secret_len + 2 * security_len > &symct0,
   const std::array < unsigned char, 2 * kem_trait::secret_len + 2 * security_len > &symct1,
   const std::array < unsigned char, security_len > &tag,
   std::array < unsigned char, security_len > &resp_out,
   bdgm_ot_receiver_state &st);

/* Step 4: The sender checks correctness of the response.
   The sender should abort the protocol if this function returns false.
 */
static bool bdgm_ot_step4 (const std::array < unsigned char, security_len > &resp, bdgm_ot_sender_state &st);

/* Step 5: The sender encrypts two messages using the two public keys.
 */
  static void bdgm_ot_step5
  (const std::array < unsigned char, msg_len > &msg0,
   const std::array < unsigned char, msg_len > &msg1,
   kem_trait::ciphertext_t &ct0_out,
   kem_trait::ciphertext_t &ct1_out,
   std::array < unsigned char, security_len + msg_len > &symct0_out,
   std::array < unsigned char, security_len + msg_len > &symct1_out,
   std::array < unsigned char, security_len > &tag0_out,
   std::array < unsigned char, security_len > &tag1_out,
   bdgm_ot_sender_state &st);

/* Step 6: The receiver decrypts one of the ciphertexts.
   The receiver should abort the protocol if this function returns false.
 */
static bool bdgm_ot_step6
  (const kem_trait::ciphertext_t &ct0,
   const kem_trait::ciphertext_t &ct1,
   const std::array < unsigned char, security_len + msg_len > &symct0,
   const std::array < unsigned char, security_len + msg_len > &symct1,
   const std::array < unsigned char, security_len > &tag0,
   const std::array < unsigned char, security_len > &tag1,
   std::array < unsigned char, msg_len > &msg_out,
   bdgm_ot_receiver_state &st);