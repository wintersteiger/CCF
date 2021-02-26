// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/entropy.h"
#include "crypto/mbedtls/key_pair.h"
#include "crypto/openssl/key_pair.h"
#include "ds/logger.h"
#include "tls/error_string.h"

#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>

namespace tls
{
  class KeyExchangeContextBase
  {
  protected:
    static constexpr size_t len_public = 1024 + 1;
    static constexpr size_t len_shared_secret = 1024;

    std::vector<uint8_t> own_public;

  public:
    KeyExchangeContextBase() : own_public(len_public) {}
    virtual ~KeyExchangeContextBase() = default;

    std::vector<uint8_t> get_own_public()
    {
      // Note that this function returns a vector of bytes
      // where the first byte represents the
      // size of the public key
      return own_public;
    }
  };

  class KeyExchangeContext_mbedTLS : public KeyExchangeContextBase
  {
  private:
    crypto::mbedtls::ECDHContext ctx = nullptr;
    crypto::EntropyPtr entropy;
    static constexpr mbedtls_ecp_group_id domain_parameter =
      MBEDTLS_ECP_DP_SECP384R1;

  public:
    KeyExchangeContext_mbedTLS() :
      KeyExchangeContextBase(),
      entropy(crypto::create_entropy())
    {
      auto tmp_ctx =
        crypto::mbedtls::make_unique<crypto::mbedtls::ECDHContext>();
      size_t len;

      int rc = mbedtls_ecp_group_load(&tmp_ctx->grp, domain_parameter);

      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      rc = mbedtls_ecdh_make_public(
        tmp_ctx.get(),
        &len,
        own_public.data(),
        own_public.size(),
        entropy->get_rng(),
        entropy->get_data());

      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      own_public.resize(len);

      ctx = std::move(tmp_ctx);
    }

    KeyExchangeContext_mbedTLS(
      std::shared_ptr<crypto::KeyPair_mbedTLS> own_kp,
      std::shared_ptr<crypto::PublicKey_mbedTLS> peer_pubk) :
      entropy(crypto::create_entropy())
    {
      auto tmp_ctx =
        crypto::mbedtls::make_unique<crypto::mbedtls::ECDHContext>();

      int rc = mbedtls_ecdh_get_params(
        tmp_ctx.get(),
        mbedtls_pk_ec(*own_kp->get_raw_context()),
        MBEDTLS_ECDH_OURS);
      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      rc = mbedtls_ecdh_get_params(
        tmp_ctx.get(),
        mbedtls_pk_ec(*peer_pubk->get_raw_context()),
        MBEDTLS_ECDH_THEIRS);
      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      ctx = std::move(tmp_ctx);
    }

    void free_ctx()
    {
      // Should only be called when shared secret has been computed.
      ctx.reset();
    }

    virtual ~KeyExchangeContext_mbedTLS()
    {
      free_ctx();
    }

    void load_peer_public(const uint8_t* bytes, size_t size)
    {
      int rc = mbedtls_ecdh_read_public(ctx.get(), bytes, size);
      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }
    }

    std::vector<uint8_t> compute_shared_secret()
    {
      // Should only be called once, when peer public has been loaded.
      std::vector<uint8_t> shared_secret(len_shared_secret);
      size_t len;
      int rc = mbedtls_ecdh_calc_secret(
        ctx.get(),
        &len,
        shared_secret.data(),
        shared_secret.size(),
        entropy->get_rng(),
        entropy->get_data());
      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      shared_secret.resize(len);

      return shared_secret;
    }
  };

  class KeyExchangeContext_OpenSSL : public KeyExchangeContextBase
  {
  public:
    KeyExchangeContext_OpenSSL() = default;

    KeyExchangeContext_OpenSSL(
      std::shared_ptr<crypto::KeyPair_OpenSSL> own_kp,
      std::shared_ptr<crypto::PublicKey_OpenSSL> peer_pubk) :
      KeyExchangeContextBase()
    {}

    virtual ~KeyExchangeContext_OpenSSL() = default;
  };

#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
  using KeyExchangeContext = KeyExchangeContext_mbedTLS;
#else
  using KeyExchangeContext = KeyExchangeContext_OpenSSL;
#endif

  inline std::shared_ptr<KeyExchangeContext> make_key_exchange_context(
    crypto::KeyPairPtr own_kp, crypto::PublicKeyPtr peer_pubk)
  {
    return std::make_shared<KeyExchangeContext>(own_kp, peer_pubk);
  }
}
