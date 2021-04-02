// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/hash_provider.h"
#include "crypto/key_pair.h"
#include "crypto/mbedtls/hash.h"
#include "crypto/mbedtls/key_pair.h"
#include "crypto/mbedtls/rsa_key_pair.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/key_pair.h"
#include "crypto/openssl/rsa_key_pair.h"

#ifdef INSIDE_ENCLAVE
#  include "ds/logger.h"
std::atomic<std::chrono::milliseconds> logger::config::ms =
  std::chrono::milliseconds::zero();
#  include <crypto_bench_t.h>
#  define PICOBENCH_IMPLEMENT
#else
#  define PICOBENCH_IMPLEMENT_WITH_MAIN
#endif

#include <picobench/picobench.hpp>

using namespace std;
using namespace crypto;

static const string lorem_ipsum =
  "Lorem ipsum dolor sit amet, consectetur adipiscing "
  "elit, sed do eiusmod tempor incididunt ut labore et"
  " dolore magna aliqua. Ut enim ad minim veniam, quis"
  " nostrud exercitation ullamco laboris nisi ut "
  "aliquip ex ea commodo consequat. Duis aute irure "
  "dolor in reprehenderit in voluptate velit esse "
  "cillum dolore eu fugiat nulla pariatur. Excepteur "
  "sint occaecat cupidatat non proident, sunt in culpa "
  "qui officia deserunt mollit anim id est laborum.";

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

template <size_t NBytes>
vector<uint8_t> make_contents()
{
  vector<uint8_t> contents(NBytes);
  size_t written = 0;
  while (written < NBytes)
  {
    const auto write_size = min(lorem_ipsum.size(), NBytes - written);
    memcpy(contents.data() + written, lorem_ipsum.data(), write_size);
    written += write_size;
  }
  return contents;
}

template <typename P, CurveID Curve, size_t NContents>
static void benchmark_sign(picobench::state& s)
{
  P kp(Curve);
  auto contents = make_contents<NContents>();

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto signature = kp.sign(contents);
    do_not_optimize(signature);
    clobber_memory();
  }
  s.stop_timer();
}

template <typename T, typename S, CurveID CID, size_t NContents>
static void benchmark_verify(picobench::state& s)
{
  T kp(CID);
  const auto contents = make_contents<NContents>();
  S pubk(kp.public_key_pem());

  auto signature = kp.sign(contents);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto verified = pubk.verify(contents, signature);
    do_not_optimize(verified);
    clobber_memory();
  }
  s.stop_timer();
}

template <typename P, MDType M, size_t NContents>
static void benchmark_hash(picobench::state& s)
{
  const auto contents = make_contents<NContents>();

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    P hp;
    HashBytes hash = hp.Hash(contents.data(), contents.size(), M);
    do_not_optimize(hash);
    clobber_memory();
  }
  s.stop_timer();
}

#ifdef INSIDE_ENCLAVE
// The clock available in the enclave is very imprecise, so we must run many
// more iterations to get comparable averages.
const std::vector<int> sizes = {1000};
#  define PICO_SUFFIX(CURVE) iterations(sizes)
const std::vector<int> hash_sizes = {10000};
#  define PICO_HASH_SUFFIX() iterations(hash_sizes)
const std::vector<int> rsa_sizes = {100};
#  define PICO_RSA_SUFFIX(CURVE) iterations(sizes)
#else
const std::vector<int> sizes = {10};
#  define PICO_SUFFIX(CURVE) iterations(sizes)
const std::vector<int> hash_sizes = {10};
#  define PICO_HASH_SUFFIX() iterations(hash_sizes)
const std::vector<int> rsa_sizes = {10};
#  define PICO_RSA_SUFFIX(CURVE) iterations(sizes)
#endif

PICOBENCH_SUITE("sign secp384r1");
namespace SIGN_SECP384R1
{
  auto sign_384_mbed_1byte =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP384R1, 1>;
  PICOBENCH(sign_384_mbed_1byte).PICO_SUFFIX(CurveID::SECP384R1);
  auto sign_384_ossl_1byte =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 1>;
  PICOBENCH(sign_384_ossl_1byte).PICO_SUFFIX(CurveID::SECP384R1);

  auto sign_384_mbed_1k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP384R1, 1024>;
  PICOBENCH(sign_384_mbed_1k).PICO_SUFFIX(CurveID::SECP384R1);
  auto sign_384_ossl_1k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 1024>;
  PICOBENCH(sign_384_ossl_1k).PICO_SUFFIX(CurveID::SECP384R1);

  auto sign_384_mbed_100k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP384R1, 102400>;
  PICOBENCH(sign_384_mbed_100k).PICO_SUFFIX(CurveID::SECP384R1);
  auto sign_384_ossl_100k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 102400>;
  PICOBENCH(sign_384_ossl_100k).PICO_SUFFIX(CurveID::SECP384R1);
}

PICOBENCH_SUITE("sign secp256r1");
namespace SIGN_SECP256R1
{
  auto sign_256r1_mbed_1byte =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256R1, 1>;
  PICOBENCH(sign_256r1_mbed_1byte).PICO_SUFFIX(CurveID::SECP256R1);
  auto sign_256r1_ossl_1byte =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 1>;
  PICOBENCH(sign_256r1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256R1);

  auto sign_256r1_mbed_1k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256R1, 1024>;
  PICOBENCH(sign_256r1_mbed_1k).PICO_SUFFIX(CurveID::SECP256R1);
  auto sign_256r1_ossl_1k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 1024>;
  PICOBENCH(sign_256r1_ossl_1k).PICO_SUFFIX(CurveID::SECP256R1);

  auto sign_256r1_mbed_100k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256R1, 102400>;
  PICOBENCH(sign_256r1_mbed_100k).PICO_SUFFIX(CurveID::SECP256R1);
  auto sign_256r1_ossl_100k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 102400>;
  PICOBENCH(sign_256r1_ossl_100k).PICO_SUFFIX(CurveID::SECP256R1);
}

PICOBENCH_SUITE("verify secp384r1");
namespace SECP384R1
{
  auto verify_384_mbed_1byte =
    benchmark_verify<KeyPair_mbedTLS, PublicKey_mbedTLS, CurveID::SECP384R1, 1>;
  PICOBENCH(verify_384_mbed_1byte).PICO_SUFFIX(CurveID::SECP384R1);
  auto verify_384_ossl_1byte =
    benchmark_verify<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP384R1, 1>;
  PICOBENCH(verify_384_ossl_1byte).PICO_SUFFIX(CurveID::SECP384R1);

  auto verify_384_mbed_1k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP384R1,
    1024>;
  PICOBENCH(verify_384_mbed_1k).PICO_SUFFIX(CurveID::SECP384R1);
  auto verify_384_ossl_1k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP384R1,
    1024>;
  PICOBENCH(verify_384_ossl_1k).PICO_SUFFIX(CurveID::SECP384R1);

  auto verify_384_mbed_100k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP384R1,
    102400>;
  PICOBENCH(verify_384_mbed_100k).PICO_SUFFIX(CurveID::SECP384R1);
  auto verify_384_ossl_100k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP384R1,
    102400>;
  PICOBENCH(verify_384_ossl_100k).PICO_SUFFIX(CurveID::SECP384R1);
}

PICOBENCH_SUITE("verify secp256r1");
namespace SECP256R1
{
  auto verify_256r1_mbed_1byte =
    benchmark_verify<KeyPair_mbedTLS, PublicKey_mbedTLS, CurveID::SECP256R1, 1>;
  PICOBENCH(verify_256r1_mbed_1byte).PICO_SUFFIX(CurveID::SECP256R1);
  auto verify_256r1_ossl_1byte =
    benchmark_verify<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP256R1, 1>;
  PICOBENCH(verify_256r1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256R1);

  auto verify_256r1_mbed_1k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP256R1,
    1024>;
  PICOBENCH(verify_256r1_mbed_1k).PICO_SUFFIX(CurveID::SECP256R1);
  auto verify_256r1_ossl_1k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256R1,
    1024>;
  PICOBENCH(verify_256r1_ossl_1k).PICO_SUFFIX(CurveID::SECP256R1);

  auto verify_256r1_mbed_100k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP256R1,
    102400>;
  PICOBENCH(verify_256r1_mbed_100k).PICO_SUFFIX(CurveID::SECP256R1);
  auto verify_256r1_ossl_100k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256R1,
    102400>;
  PICOBENCH(verify_256r1_ossl_100k).PICO_SUFFIX(CurveID::SECP256R1);
}

PICOBENCH_SUITE("sign RSA-2048");
namespace SIGN_RSA2048
{
  template <typename P, size_t KSZ, size_t NContents>
  static void benchmark_sign(picobench::state& s)
  {
    P kp(KSZ);
    auto contents = make_contents<NContents>();

    s.start_timer();
    for (auto _ : s)
    {
      (void)_;
      auto signature = kp.sign(contents, MDType::SHA256);
      do_not_optimize(signature);
      clobber_memory();
    }
    s.stop_timer();
  }

  auto sign_rsa_ossl_1byte = benchmark_sign<RSAKeyPair_OpenSSL, 2048, 1>;
  PICOBENCH(sign_rsa_ossl_1byte).PICO_RSA_SUFFIX();
  auto sign_rsa_mbed_1byte = benchmark_sign<RSAKeyPair_mbedTLS, 2048, 1>;
  PICOBENCH(sign_rsa_mbed_1byte).PICO_RSA_SUFFIX();

  auto sign_rsa_ossl_1k = benchmark_sign<RSAKeyPair_OpenSSL, 2048, 1024>;
  PICOBENCH(sign_rsa_ossl_1k).PICO_RSA_SUFFIX();
  auto sign_rsa_mbed_1k = benchmark_sign<RSAKeyPair_mbedTLS, 2048, 1024>;
  PICOBENCH(sign_rsa_mbed_1k).PICO_RSA_SUFFIX();

  auto sign_rsa_ossl_100k = benchmark_sign<RSAKeyPair_OpenSSL, 2048, 102400>;
  PICOBENCH(sign_rsa_ossl_100k).PICO_RSA_SUFFIX();
  auto sign_rsa_mbed_100k = benchmark_sign<RSAKeyPair_mbedTLS, 2048, 102400>;
  PICOBENCH(sign_rsa_mbed_100k).PICO_RSA_SUFFIX();
}

PICOBENCH_SUITE("verify RSA-2048");
namespace VERIFY_RSA2048
{
  template <typename P, size_t KSZ, size_t NContents>
  static void benchmark_verify(picobench::state& s)
  {
    P kp(KSZ);
    auto contents = make_contents<NContents>();
    auto signature = kp.sign(contents, MDType::SHA256);

    s.start_timer();
    for (auto _ : s)
    {
      (void)_;
      if (!kp.verify(
            contents.data(),
            contents.size(),
            signature.data(),
            signature.size(),
            MDType::SHA256))
      {
        throw std::runtime_error("verification failure");
      }
      do_not_optimize(signature);
      clobber_memory();
    }
    s.stop_timer();
  }

  auto verify_rsa_ossl_1byte = benchmark_verify<RSAKeyPair_OpenSSL, 2048, 1>;
  PICOBENCH(verify_rsa_ossl_1byte).PICO_RSA_SUFFIX();
  auto verify_rsa_mbed_1byte = benchmark_verify<RSAKeyPair_mbedTLS, 2048, 1>;
  PICOBENCH(verify_rsa_mbed_1byte).PICO_RSA_SUFFIX();

  auto verify_rsa_ossl_1k = benchmark_verify<RSAKeyPair_OpenSSL, 2048, 1024>;
  PICOBENCH(verify_rsa_ossl_1k).PICO_RSA_SUFFIX();
  auto verify_rsa_mbed_1k = benchmark_verify<RSAKeyPair_mbedTLS, 2048, 1024>;
  PICOBENCH(verify_rsa_mbed_1k).PICO_RSA_SUFFIX();

  auto verify_rsa_ossl_100k =
    benchmark_verify<RSAKeyPair_OpenSSL, 2048, 102400>;
  PICOBENCH(verify_rsa_ossl_100k).PICO_RSA_SUFFIX();
  auto verify_rsa_mbed_100k =
    benchmark_verify<RSAKeyPair_mbedTLS, 2048, 102400>;
  PICOBENCH(verify_rsa_mbed_100k).PICO_RSA_SUFFIX();
}

PICOBENCH_SUITE("hash");
namespace Hashes
{
  auto sha_384_mbed_1byte = benchmark_hash<MBedHashProvider, MDType::SHA384, 1>;
  PICOBENCH(sha_384_mbed_1byte).PICO_HASH_SUFFIX().baseline();
  auto sha_256_mbed_1byte = benchmark_hash<MBedHashProvider, MDType::SHA256, 1>;
  PICOBENCH(sha_256_mbed_1byte).PICO_HASH_SUFFIX();
  auto sha_512_mbed_1byte = benchmark_hash<MBedHashProvider, MDType::SHA512, 1>;
  PICOBENCH(sha_512_mbed_1byte).PICO_HASH_SUFFIX();

  auto sha_384_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 1>;
  PICOBENCH(sha_384_ossl_1byte).PICO_HASH_SUFFIX();
  auto sha_256_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 1>;
  PICOBENCH(sha_256_ossl_1byte).PICO_HASH_SUFFIX();
  auto sha_512_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 1>;
  PICOBENCH(sha_512_ossl_1byte).PICO_HASH_SUFFIX();

  auto sha_384_mbed_1k = benchmark_hash<MBedHashProvider, MDType::SHA384, 1024>;
  PICOBENCH(sha_384_mbed_1k).PICO_HASH_SUFFIX();
  auto sha_256_mbed_1k = benchmark_hash<MBedHashProvider, MDType::SHA256, 1024>;
  PICOBENCH(sha_256_mbed_1k).PICO_HASH_SUFFIX();
  auto sha_512_mbed_1k = benchmark_hash<MBedHashProvider, MDType::SHA512, 1024>;
  PICOBENCH(sha_512_mbed_1k).PICO_HASH_SUFFIX();

  auto sha_384_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 1024>;
  PICOBENCH(sha_384_ossl_1k).PICO_HASH_SUFFIX();
  auto sha_256_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 1024>;
  PICOBENCH(sha_256_ossl_1k).PICO_HASH_SUFFIX();
  auto sha_512_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 1024>;
  PICOBENCH(sha_512_ossl_1k).PICO_HASH_SUFFIX();

  auto sha_384_mbed_100k =
    benchmark_hash<MBedHashProvider, MDType::SHA384, 102400>;
  PICOBENCH(sha_384_mbed_100k).PICO_HASH_SUFFIX();
  auto sha_256_mbed_100k =
    benchmark_hash<MBedHashProvider, MDType::SHA256, 102400>;
  PICOBENCH(sha_256_mbed_100k).PICO_HASH_SUFFIX();
  auto sha_512_mbed_100k =
    benchmark_hash<MBedHashProvider, MDType::SHA512, 102400>;
  PICOBENCH(sha_512_mbed_100k).PICO_HASH_SUFFIX();

  auto sha_384_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 102400>;
  PICOBENCH(sha_384_ossl_100k).PICO_HASH_SUFFIX();
  auto sha_256_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 102400>;
  PICOBENCH(sha_256_ossl_100k).PICO_HASH_SUFFIX();
  auto sha_512_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 102400>;
  PICOBENCH(sha_512_ossl_100k).PICO_HASH_SUFFIX();
}

#ifdef INSIDE_ENCLAVE
int timespec_get(struct timespec*, int)
{
  return 0;
}

extern "C" int pthread_setaffinity_np(pthread_t, size_t, const cpu_set_t*)
{
  return 0;
}

extern "C" bool run_benchmark()
{
  bool r = false;
  ENGINE_load_rdrand();
  ENGINE* engine = ENGINE_by_id("rdrand");
  ENGINE_init(engine);
  ENGINE_set_default(engine, ENGINE_METHOD_RAND);

  try
  {
    picobench::runner runner;
    runner.set_default_samples(1);
    runner.run();
    r = true;
  }
  catch (...)
  {
    std::cout << "Caught exception" << std::endl;
  }

  ENGINE_finish(engine);
  ENGINE_free(engine);
  ENGINE_cleanup();

  return true;
}
#endif
