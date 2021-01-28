// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <crypto/hash.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string.h>
#include <tls/curve.h>
#include <tls/entropy.h>
#include <tls/key_pair.h>
#include <tls/mbedtls_wrappers.h>
#include <time.h>

#ifdef OE_BUILD_ENCLAVE
#include <signature_bench_t.h>
#define PICOBENCH_IMPLEMENT
#else
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#endif
#include <picobench/picobench.hpp>


using namespace tls;
using namespace crypto;

enum SignatureImpl
{
  SI_MBEDTLS,
  SI_OPENSSL
};

template <SignatureImpl IMPL, CurveImpl CURVE>
static void signature_bench(picobench::state& s)
{
  auto q = picobench::high_res_clock::now();

  std::vector<Sha256Hash> hashes(s.iterations());
  for (int i = 0; i < s.iterations(); i++)
  {
    for (size_t i = 0; i < Sha256Hash::SIZE; ++i)
    {
      hashes.back().h[i] = rand();
    }
  }

  if constexpr (IMPL == SI_MBEDTLS)
  {
    KeyPair kp(get_ec_for_curve_impl(CURVE));

    s.start_timer();
    for (auto& hash : hashes)
    {
      uint8_t signature[MBEDTLS_ECDSA_MAX_LEN];
      size_t signature_size = 0;
      kp.sign_hash(hash.h.data(), hash.SIZE, &signature_size, signature);
    }
  }
  else if constexpr (IMPL == SI_OPENSSL)
  {
    int curve_nid = 0;

    switch (CURVE)
    {
      case CurveImpl::secp384r1:
        curve_nid = NID_secp384r1;
        break;
      case CurveImpl::secp256k1_mbedtls:
      case CurveImpl::secp256k1_bitcoin:
        curve_nid = NID_secp256k1;
        break;
      default:
        throw std::runtime_error("unsupported curve");
    }

    ENGINE_load_rdrand();
    ENGINE* engine = ENGINE_by_id("rdrand");
    ENGINE_init(engine);
    ENGINE_set_default(engine, ENGINE_METHOD_RAND);

    EVP_PKEY_CTX* pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (
      EVP_PKEY_paramgen_init(pkctx) < 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid) < 0 ||
      EVP_PKEY_CTX_set_ec_param_enc(pkctx, OPENSSL_EC_NAMED_CURVE) < 0)
      throw std::runtime_error("could not initialize PK context");

    EVP_PKEY* key = EVP_PKEY_new();
    if (EVP_PKEY_keygen_init(pkctx) < 0 || EVP_PKEY_keygen(pkctx, &key) < 0)
      throw std::runtime_error("could not generate new EC key");
    EVP_PKEY_CTX_free(pkctx);

    s.start_timer();
    for (auto& hash : hashes)
    {
      uint8_t signature[MBEDTLS_ECDSA_MAX_LEN];
      size_t signature_size = sizeof(signature);

      EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
      if (
        EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestSign(
          mdctx, signature, &signature_size, hash.h.data(), hash.SIZE) != 1)
        throw std::runtime_error("could not sign message");
      EVP_MD_CTX_free(mdctx);

#  ifndef NDEBUG
      mdctx = EVP_MD_CTX_new();
      if (
        EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestVerify(
          mdctx, signature, signature_size, hash.h.data(), hash.SIZE) != 1)
        throw std::runtime_error("could not verify signature");
      EVP_MD_CTX_free(mdctx);
#  endif
    }

    EVP_PKEY_free(key);

    ENGINE_finish(engine);
    ENGINE_free(engine);
    ENGINE_cleanup();
  }

  s.stop_timer();
}

const std::vector<int> num_hashes = {100, 250, 1000};

PICOBENCH_SUITE("Signatures");

auto secp384r1_mbedtls =
  signature_bench<SignatureImpl::SI_MBEDTLS, CurveImpl::secp384r1>;
PICOBENCH(secp384r1_mbedtls).iterations(num_hashes).baseline();
auto secp256k1_mbedtls =
  signature_bench<SignatureImpl::SI_MBEDTLS, CurveImpl::secp256k1_mbedtls>;
PICOBENCH(secp256k1_mbedtls).iterations(num_hashes).baseline();
auto secp256k1_bitcoin =
  signature_bench<SignatureImpl::SI_MBEDTLS, CurveImpl::secp256k1_bitcoin>;
PICOBENCH(secp256k1_bitcoin).iterations(num_hashes).baseline();

auto secp384r1_openssl =
  signature_bench<SignatureImpl::SI_OPENSSL, CurveImpl::secp384r1>;
PICOBENCH(secp384r1_openssl).iterations(num_hashes).baseline();
auto secp256k1_openssl =
  signature_bench<SignatureImpl::SI_OPENSSL, CurveImpl::secp256k1_mbedtls>;
PICOBENCH(secp256k1_openssl).iterations(num_hashes).baseline();

#ifdef OE_BUILD_ENCLAVE
int timespec_get(struct timespec* ts, int base)
{
  return 0;
}

extern "C" int pthread_setaffinity_np(pthread_t, size_t, const cpu_set_t *)
{
  return 0;
}

extern "C" bool run_benchmark()
{
  try {
    picobench::runner runner;
    runner.run();
  }
  catch (...) {
    std::cout << "Caught exception" << std::endl;
    return false;
  }
  return true;
}
#endif