// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/curve.h"
#include "crypto/entropy.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/symmetric_key.h"

#include <ccf/entity_id.h>
#include <map>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>
#include <string>
#include <vector>

using namespace crypto;

namespace ByzIdentity
{
  namespace EC
  {
    class Point;
  };

  static inline EC_GROUP* get_openssl_group(crypto::CurveID curve)
  {
    switch (curve)
    {
      case crypto::CurveID::SECP384R1:
        return EC_GROUP_new_by_curve_name(NID_secp384r1);
        break;
      case crypto::CurveID::SECP256R1:
        throw new std::logic_error("SECP256R1 not supported yet");
        return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        break;
      default:
        throw std::logic_error("unsupported curve");
    }
  }

  using namespace crypto::OpenSSL;

  std::vector<uint8_t> serialise_size(size_t sz)
  {
    size_t space = sizeof(sz);
    std::vector<uint8_t> r(space);
    auto data = r.data();
    serialized::write(data, space, sz);
    return r;
  }

  class BigNum
  {
  public:
    BigNum()
    {
      CHECKNULL(b = BN_new());
    }

    BigNum(const BigNum& other)
    {
      CHECKNULL(b = BN_dup(other.b));
    }

    BigNum(const std::string& value)
    {
      CHECKNULL(b = BN_new());
      BN_dec2bn(&b, value.c_str());
    }

    BigNum(unsigned long i)
    {
      CHECKNULL(b = BN_new());
      CHECK1(BN_set_word(b, i));
    }

    BigNum(const BIGNUM* other)
    {
      CHECKNULL(b = BN_dup(other));
    }

    BigNum(const uint8_t*& buf, size_t& sz)
    {
      size_t bsz = serialized::read<size_t>(buf, sz);
      CHECKNULL(b = BN_bin2bn(buf, bsz, NULL));
      buf += bsz;
      sz -= bsz;
    }

    ~BigNum()
    {
      BN_free(b);
    }

    void operator=(const BigNum& other) __attribute__((noinline))
    {
      BN_free(b);
      CHECKNULL(b = BN_dup(other.b));
    }

    bool operator==(const BigNum& other) const
    {
      return BN_cmp(b, other.b) == 0;
    }

    bool operator!=(const BigNum& other) const
    {
      return BN_cmp(b, other.b) != 0;
    }

    bool operator<(const BigNum& other) const
    {
      return BN_cmp(b, other.b) < 0;
    }

    static std::shared_ptr<BigNum> Random(const BigNum& order)
    {
      std::shared_ptr<BigNum> r = std::make_shared<BigNum>();
      CHECK1(BN_rand_range(r->b, order.b));
      return r;
    }

    static std::shared_ptr<BigNum> Zero()
    {
      std::shared_ptr<BigNum> r = std::make_shared<BigNum>();
      BN_zero(r->b);
      return r;
    }

    BigNum mul(const BigNum& other)
    {
      BigNum r;
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      CHECK1(BN_mul(r.b, this->b, other.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    BigNum add(const BigNum& other)
    {
      BigNum r;
      CHECK1(BN_add(r.b, this->b, other.b));
      return r;
    }

    BigNum sub(const BigNum& other)
    {
      BigNum r;
      CHECK1(BN_sub(r.b, this->b, other.b));
      return r;
    }

    static BigNum mod_exp(const BigNum& a, const BigNum& b, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod_exp(r.b, a.b, b.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    static BigNum mod_mul(const BigNum& a, const BigNum& b, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod_mul(r.b, a.b, b.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    static BigNum mod_add(const BigNum& a, const BigNum& b, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod_add(r.b, a.b, b.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    static BigNum mod_sub(const BigNum& a, const BigNum& b, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod_sub(r.b, a.b, b.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    static BigNum mod_inv(const BigNum& a, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      if (!BN_mod_inverse(r.b, a.b, m.b, ctx))
      {
        throw std::runtime_error("OpenSSL error: BN_mod_inverse failed");
      }
      BN_CTX_free(ctx);
      return r;
    }

    static BigNum lagrange_coefficient(
      const std::vector<size_t>& indices,
      size_t i,
      size_t input,
      const BigNum& group_order)
    {
      BigNum r(1);
      BigNum i_bn(indices[i]), input_bn(input);
      for (size_t j = 0; j < indices.size(); j++)
      {
        if (i != j)
        {
          BigNum j_bn(indices[j]);
          auto numerator = BigNum::mod_sub(input_bn, j_bn, group_order);
          auto bottom = BigNum::mod_sub(i_bn, j_bn, group_order);
          auto denominator = BigNum::mod_inv(bottom, group_order);
          auto nd = BigNum::mod_mul(numerator, denominator, group_order);
          r = BigNum::mod_mul(r, nd, group_order);
        }
      }
      return r;
    }

    static BigNum lagrange_interpolate(
      const std::vector<std::shared_ptr<BigNum>>& shares,
      const std::vector<size_t>& indices,
      size_t j,
      const BigNum& group_order)
    {
      assert(shares.size() == indices.size());
      BigNum r((unsigned long)0);
      for (size_t i = 0; i < shares.size(); i++)
      {
        auto coeff_i = lagrange_coefficient(indices, i, j, group_order);
        auto t = BigNum::mod_mul(coeff_i, *shares[i], group_order);
        r = BigNum::mod_add(r, t, group_order);
        // LOG_DEBUG_FMT(
        //   "r={} t={} coeff_i={} *shares[i]={}",
        //   r.to_string(),
        //   t.to_string(),
        //   coeff_i.to_string(),
        //   shares[i]->to_string());
      }
      return r;
    }

    size_t byte_size() const
    {
      return BN_num_bytes(b);
    }

    std::vector<uint8_t> serialise() const
    {
      size_t bsz = byte_size();
      std::vector<uint8_t> r = serialise_size(bsz);
      r.resize(r.size() + bsz);
      BN_bn2bin(b, r.data() + r.size() - bsz);
      return r;
    }

    std::string to_string() const
    {
      char* cs = BN_bn2dec(b);
      CHECKNULL(cs);
      std::string r = cs;
      OPENSSL_free(cs);
      return r;
    }

  protected:
    BIGNUM* b;

    friend class EC::Point;
  };

  namespace EC
  {
    static EC_GROUP* group = get_openssl_group(crypto::CurveID::SECP384R1);

    static std::shared_ptr<BigNum> group_order(
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      EC_GROUP* group = get_openssl_group(curve);
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BIGNUM* group_order = BN_new();
      CHECKNULL(group_order);
      CHECK1(EC_GROUP_get_order(group, group_order, ctx));
      auto r = std::make_shared<BigNum>(group_order);
      BN_free(group_order);
      BN_CTX_free(ctx);
      EC_GROUP_free(group);
      return r;
    }

    typedef std::vector<uint8_t> CompressedPoint;

    class Point
    {
    public:
      Point(crypto::CurveID curve = crypto::CurveID::SECP384R1)
      {
        group = get_openssl_group(curve);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
      }

      Point(const EC_GROUP* group)
      {
        group = EC_GROUP_dup(group);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
      }

      Point(
        const std::string& value,
        bool y_bit /* y=0/1 */,
        crypto::CurveID curve = crypto::CurveID::SECP384R1)
      {
        group = get_openssl_group(curve);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
        BIGNUM* b = BN_new();
        CHECKNULL(b);
        BN_hex2bn(&b, value.c_str());
        CHECK1(EC_POINT_set_compressed_coordinates(group, p, b, y_bit, bn_ctx));
        BN_free(b);
      }

      Point(
        const std::vector<uint8_t>& buf,
        crypto::CurveID curve = crypto::CurveID::SECP384R1)
      {
        group = get_openssl_group(curve);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
        EC_POINT_oct2point(group, p, buf.data(), buf.size(), bn_ctx);
      }

      Point(const Point& other)
      {
        CHECKNULL(group = EC_GROUP_dup(other.group));
        CHECKNULL(p = EC_POINT_dup(other.p, group));
        CHECKNULL(bn_ctx = BN_CTX_new());
      }

      virtual ~Point()
      {
        BN_CTX_free(bn_ctx);
        EC_GROUP_free(group);
        EC_POINT_free(p);
      }

      Point& operator=(const Point& other)
      {
        BN_CTX_free(bn_ctx);
        EC_GROUP_free(group);
        EC_POINT_free(p);
        CHECKNULL(group = EC_GROUP_dup(other.group));
        CHECKNULL(p = EC_POINT_dup(other.p, group));
        CHECKNULL(bn_ctx = BN_CTX_new());
        return *this;
      }

      bool operator==(const Point& other) const
      {
        return EC_POINT_cmp(group, p, other.p, bn_ctx);
      }

      Point mul(const BigNum& b) const
      {
        Point r;
        CHECK1(EC_POINT_mul(group, r.p, NULL, this->p, b.b, bn_ctx));
        return r;
      }

      Point add(const Point& p) const
      {
        Point r;
        CHECK1(EC_POINT_add(group, r.p, this->p, p.p, bn_ctx));
        return r;
      }

      CompressedPoint compress() const
      {
        int sz = EC_POINT_point2oct(
          group, p, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
        std::vector<uint8_t> r(sz);
        if (
          EC_POINT_point2oct(
            group, p, POINT_CONVERSION_COMPRESSED, r.data(), sz, bn_ctx) == 0)
          throw std::runtime_error("could not compress point into buffer");
        return r;
      }

      std::string to_compressed_hex() const
      {
        char* buf =
          EC_POINT_point2hex(group, p, POINT_CONVERSION_COMPRESSED, bn_ctx);
        std::string r = buf;
        OPENSSL_free(buf);
        return r;
      }

    protected:
      BN_CTX* bn_ctx;
      EC_POINT* p;
      EC_GROUP* group;
    };

    EC::Point eval_in_exp(
      const std::vector<CompressedPoint>& commitment,
      size_t j,
      std::shared_ptr<BigNum> group_order)
    {
      size_t degree = commitment.size();
      assert(degree > 0);

      // LOG_TRACE_FMT("c[0]={}", ds::to_hex(commitment[0]));
      EC::Point result(commitment[0]);
      // LOG_TRACE_FMT("result={}", result.to_compressed_hex());
      for (size_t i = 1; i < degree; i++)
      {
        auto t = BigNum::mod_exp(BigNum(j), BigNum(i), *group_order);
        // LOG_TRACE_FMT("t={}", t.to_string());
        // LOG_TRACE_FMT("c[i]={}", ds::to_hex(commitment[i]));
        EC::Point c(commitment[i]);
        // LOG_TRACE_FMT("c={}", c.to_compressed_hex());
        result = result.add(c.mul(t));
        // LOG_TRACE_FMT("result={}", result.to_compressed_hex());
      }
      return result;
    }
  }

  class Polynomial
  {
  public:
    Polynomial(size_t t, crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      group_order = EC::group_order(curve);

      for (size_t i = 0; i < t + 1; i++)
      {
        coefficients.push_back(BigNum::Random(*group_order));
      }
    }

    Polynomial(
      const std::vector<std::shared_ptr<BigNum>>& coefficients,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      coefficients(coefficients)
    {
      if (coefficients.empty())
      {
        throw std::logic_error("no coefficients for polynomial");
      }
      group_order = EC::group_order(curve);
    }

    Polynomial(
      const std::vector<std::string>& coefficient_strings,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      group_order = EC::group_order(curve);

      for (size_t i = 0; i < coefficient_strings.size(); i++)
      {
        coefficients.push_back(
          std::make_shared<BigNum>(coefficient_strings[i]));
      }
    }

    Polynomial(
      const uint8_t*& buf,
      size_t& sz,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      size_t n = serialized::read<size_t>(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        coefficients.push_back(std::make_shared<BigNum>(buf, sz));
      }
    }

    virtual ~Polynomial(){};

    static std::shared_ptr<BigNum> eval(
      const std::vector<std::shared_ptr<BigNum>>& coefficients,
      const std::shared_ptr<BigNum> input,
      crypto::CurveID curve = crypto::CurveID::SECP384R1,
      const std::shared_ptr<BigNum> group_order = nullptr)
    {
      auto go = group_order ? group_order : EC::group_order(curve);
      std::shared_ptr<BigNum> r = BigNum::Zero();
      for (size_t i = 0; i < coefficients.size(); i++)
      {
        auto t1 = BigNum::mod_exp(*input, BigNum(i), *go);
        auto t2 = BigNum::mod_mul(*coefficients[i], t1, *go);
        *r = BigNum::mod_add(*r, t2, *go);
      }
      return r;
    }

    std::shared_ptr<BigNum> eval(
      const std::shared_ptr<BigNum> input,
      crypto::CurveID curve = crypto::CurveID::SECP384R1,
      const std::shared_ptr<BigNum> group_order = nullptr)
    {
      return eval(coefficients, input, curve, group_order);
    }

    static std::shared_ptr<Polynomial> sample_rss(
      size_t t,
      size_t num_coefficients = 0,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      std::vector<std::shared_ptr<BigNum>> coefficients;
      auto go = EC::group_order(curve);

      for (size_t i = 0; i < t + 1; i++)
      {
        coefficients.push_back(BigNum::Random(*go));
      }

      // really num_coefficients+1 or just num_coefficients?
      for (size_t i = t + 1; i < num_coefficients + 1; i++)
      {
        coefficients.push_back(BigNum::Random(*go));
      }

      return std::make_shared<Polynomial>(std::move(coefficients));
    }

    static std::shared_ptr<Polynomial> sample_zss(
      size_t t,
      const std::shared_ptr<BigNum> coeff0 = nullptr,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      assert(t > 0);
      auto r = std::make_shared<Polynomial>(t - 1, curve);
      auto c0 = coeff0;
      if (c0 == nullptr)
        c0 = BigNum::Zero();
      r->coefficients.insert(r->coefficients.begin(), c0);
      return r;
    }

    std::string to_string() const
    {
      std::stringstream r;
      r << "[";
      bool first = true;
      for (const auto& c : coefficients)
      {
        if (first)
        {
          first = false;
        }
        else
        {
          r << ", ";
        }

        r << c->to_string();
      }
      r << "]";
      return r.str();
    }

    std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = serialise_size(coefficients.size());
      for (auto& c : coefficients)
      {
        auto b = c->serialise();
        r.insert(r.end(), b.begin(), b.end());
      }

      // const uint8_t* data = r.data();
      // size_t size = r.size();
      // Polynomial check(data, size);
      // assert(check.coefficients.size() == coefficients.size());
      // for (size_t i = 0; i < coefficients.size(); i++)
      // {
      //   assert(*check.coefficients[i] == *coefficients[i]);
      // }

      return r;
    }

    size_t size() const
    {
      return coefficients.size();
    }

    std::vector<std::shared_ptr<BigNum>> coefficients;

  protected:
    std::shared_ptr<BigNum> group_order;
  };

  class BivariatePolynomial
  {
  public:
    BivariatePolynomial(crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      curve(curve)
    {
      group_order = EC::group_order(curve);
    }

    BivariatePolynomial(
      const uint8_t*& buf,
      size_t& sz,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      group_order = EC::group_order(curve);

      size_t n = serialized::read<size_t>(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        std::vector<std::shared_ptr<BigNum>> t;
        size_t m = serialized::read<size_t>(buf, sz);
        for (size_t j = 0; j < m; j++)
        {
          t.push_back(std::make_shared<BigNum>(buf, sz));
        }
        coefficients.push_back(t);
      }
    }

    virtual ~BivariatePolynomial() {}

    static std::shared_ptr<BivariatePolynomial> sample_rss(
      size_t degree_x,
      size_t degree_y,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      auto r = std::make_shared<BivariatePolynomial>(curve);
      auto go = EC::group_order(curve);

      for (size_t i = 0; i < degree_y + 1; i++)
      {
        std::vector<std::shared_ptr<BigNum>> t;
        for (size_t j = 0; j < degree_x + 1; j++)
        {
          t.push_back(BigNum::Random(*go));
        }
        r->coefficients.push_back(t);
      }

      return r;
    }

    static std::shared_ptr<BivariatePolynomial> sample_zss(
      size_t degree_x,
      size_t degree_y,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      auto r = std::make_shared<BivariatePolynomial>(curve);

      r->coefficients.push_back({});
      for (size_t i = 0; i < degree_x + 1; i++)
      {
        r->coefficients.back().push_back(BigNum::Zero());
      }

      for (size_t i = 0; i < degree_y; i++)
      {
        r->coefficients.push_back({});
        for (size_t j = 0; j < degree_x + 1; j++)
        {
          auto group_order = EC::group_order(curve);
          r->coefficients.back().push_back(BigNum::Random(*group_order));
        }
      }

      return r;
    }

    Polynomial y_coefficients(const std::shared_ptr<BigNum>& x)
    {
      std::vector<std::shared_ptr<BigNum>> r;

      for (size_t i = 0; i < coefficients.size(); i++)
      {
        r.push_back(Polynomial::eval(coefficients[i], x, curve, group_order));
      }

      return Polynomial(r);
    }

    std::string to_string() const
    {
      std::stringstream r;
      r << "[";
      bool first_cc = true;
      for (const auto& cc : coefficients)
      {
        if (first_cc)
        {
          first_cc = false;
        }
        else
        {
          r << ", ";
        }

        r << "[";
        bool first_c = true;
        for (const auto& c : cc)
        {
          if (first_c)
          {
            first_c = false;
          }
          else
          {
            r << ", ";
          }

          r << c->to_string();
        }
        r << "]";
      }
      r << "]";
      return r.str();
    }

    std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = serialise_size(coefficients.size());
      for (auto& cc : coefficients)
      {
        std::vector<uint8_t> rcc = serialise_size(cc.size());
        for (auto& c : cc)
        {
          auto b = c->serialise();
          rcc.insert(rcc.end(), b.begin(), b.end());
        }
        r.insert(r.end(), rcc.begin(), rcc.end());
      }
      return r;
    }

    std::vector<std::vector<std::shared_ptr<BigNum>>> coefficients;

  protected:
    crypto::CurveID curve;
    std::shared_ptr<BigNum> group_order;
  };

  static std::map<crypto::CurveID, std::vector<std::shared_ptr<EC::Point>>>
    bases;

  static void init_bases()
  {
    if (!bases.empty())
      return;

    std::vector<std::string> basis_points_strings = {
      // clang-format off
        "03dba858f075dbbb963b791f4188bca1619697bcf5e042499a8eb9b726e381bbe9649a4dbef5ac0f97188a0da88052711e",
        "033953e90a2a1508e2b5328fa49a3fc08cee8a6e9982805c6609eb87963a188050b0cf9c66184f6289e7ede96bcd690c07",
        "025917d93be7e10f27624d54fc4a1ff3d2bc39a63880720d8e04d7dc847cd47569b873604b076ec95e2f2a9cecb227c4aa",
        "03568b906382ef59651f8467c20c6363cfe8020255f3594f37c857f5e630b06ee5b380d24708f19b5f7111e5975fc77c45",
        "02de35c607f96e2aa67448d8adfbf65d2cf5ca141304bece5af5cb1858f0f7aa0c2d8332edbae2408100c1ded076ee7c75",
        "0393b22ab6ba93ead24d09a5ea9f7009c5465a3cd399913b92d44ddd21d53a20ae5673955e907c3590f53478c32b0e738c",
        "03a68f392cbdc24fcc170fb66e20bbaea19e4ae2945fa0443b6845a815b417df674eef61775693776ec92b848ec98a859c",
        "026303eb4c2b07422a2e8f553ec5095dde4da22eb735e2535feb52d4d5a25bd482dbfc08e96ef5980e7d4dc3cad30b385f",
        "0369ba45307acaec23595d1ed1eea86408bcb71d5e3589499474fa4d00ed28d0e11403c7fc042c5a4abba511bba9abb5a1",
        "03985ba2bee0c0c8b4003cd53574356999c7ee02edf90aff9143494474dec9232810b017beacd60aa88215a1e3146e609e",
        "03add81d8a9664ea7bc4702cf85449cd392328d7c315725f4f275b334f7417d1ec5d27b2d62e73777deeaee4a88e1200cb",
        "036a54335a7ff3a6f84609a00d38bbd076272fbadf8233d75a953a4e1f8e5ad097d559e05b378bce135864949a57e1fd00",
        "024fca965946d12265d8b6d097d2d2441bfd807ac7d3726150535811acc0d80720169e1c40ead8d6b3bac22d415532c0bf",
      // clang-format on
    };
    // ADD crypto::CurveID::SECP256R1
    for (auto s : basis_points_strings)
    {
      bases[crypto::CurveID::SECP384R1].push_back(
        std::make_shared<EC::Point>(s.substr(2), s.substr(0, 2) != "02"));
    }
  }

  EC::Point commit_multi(
    size_t start,
    const std::vector<std::shared_ptr<BigNum>>& msgs,
    crypto::CurveID curve = crypto::CurveID::SECP384R1)
  {
    init_bases();
    auto basis = bases[curve];
    assert(
      0 <= start and start + msgs.size() < basis.size() and msgs.size() > 0);
    EC::Point r = basis[start]->mul(*msgs[0]);
    for (size_t i = 1; i < msgs.size(); i++)
    {
      r = r.add(basis[start + i]->mul(*msgs[i]));
    }
    return r;
  }

  inline EC::CompressedPoint compress(
    size_t start,
    const std::vector<std::shared_ptr<BigNum>>& msgs,
    crypto::CurveID curve = crypto::CurveID::SECP384R1)
  {
    return commit_multi(start, msgs, curve).compress();
  }

  inline EC::CompressedPoint compress_x_wx(
    std::shared_ptr<BigNum> x,
    std::shared_ptr<BigNum> wx,
    crypto::CurveID curve = crypto::CurveID::SECP384R1)
  {
    return compress(0, {x, wx}, curve);
  }

  class SharePolynomials
  {
  public:
    Polynomial q;
    Polynomial q_witness;

    SharePolynomials(const Polynomial& q, const Polynomial& q_witness) :
      q(q),
      q_witness(q_witness)
    {}

    SharePolynomials(const uint8_t*& buf, size_t& sz) :
      q(buf, sz),
      q_witness(buf, sz)
    {}

    std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = q.serialise();
      std::vector<uint8_t> rw = q_witness.serialise();
      r.insert(r.end(), rw.begin(), rw.end());
      return r;
    }

    std::string to_string() const
    {
      std::stringstream ss;
      ss << "[" << q.to_string() << ", " << q_witness.to_string() << "]";
      return ss.str();
    }
  };

  std::vector<std::vector<std::shared_ptr<BigNum>>> sum_share_polys(
    const std::vector<SharePolynomials>& deals,
    std::shared_ptr<BigNum> group_order)
  {
    assert(deals.size() > 0);
    std::vector<std::vector<std::shared_ptr<BigNum>>> r;

    for (size_t p = 0; p < 2; p++)
    {
      std::vector<std::shared_ptr<BigNum>> jt;

      const auto& poly0 = p == 0 ? deals[0].q : deals[0].q_witness;
      for (size_t u = 0; u < poly0.coefficients.size(); u++)
      {
        auto sum = BigNum::Zero();
        LOG_DEBUG_FMT("sum={}", sum->to_string());
        for (size_t k = 0; k < deals.size(); k++)
        {
          const auto& poly_k = p == 0 ? deals[k].q : deals[k].q_witness;
          auto& c = poly_k.coefficients[u];
          LOG_DEBUG_FMT("+c={}", c->to_string());
          *sum = BigNum::mod_add(*sum, *c, *group_order);
          LOG_DEBUG_FMT("sum={}", sum->to_string());
        }
        jt.push_back(sum);
      }
      r.push_back(jt);
    }

    return r;
  }

  class Deal
  {
  public:
    Deal(
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      defensive(defensive),
      curve(curve)
    {}

    virtual ~Deal() {}

  protected:
    bool defensive;
    crypto::CurveID curve;
  };

  class SigningDeal : public Deal
  {
  public:
    SigningDeal(
      size_t t,
      const std::vector<size_t>& indices,
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      Deal(defensive, curve),
      t(t),
      defensive(defensive),
      indices_(indices)
    {
      sample();
      compute_shares();

      if (defensive)
      {
        compute_commits();
        compute_proof();
      }
    }

    SigningDeal(const uint8_t*& buf, size_t& sz)
    {
      size_t n = serialized::read<size_t>(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        std::vector<std::shared_ptr<BigNum>> t;
        size_t m = serialized::read<size_t>(buf, sz);
        for (size_t j = 0; j < m; j++)
        {
          t.push_back(std::make_shared<BigNum>(buf, sz));
        }
        shares_.push_back(t);
      }

      // TODO: load commitments
    }

    virtual ~SigningDeal() {}

    void load(const std::vector<std::vector<std::string>>& ss)
    {
      sharings.clear();
      for (const std::vector<std::string>& s : ss)
      {
        sharings.push_back(std::make_shared<Polynomial>(s, curve));
      }
      compute_shares();
      if (defensive)
      {
        compute_commits();
      }
    }

    const std::shared_ptr<Polynomial>& k() const
    {
      return sharings[0];
    }

    const std::shared_ptr<Polynomial>& a() const
    {
      return sharings[1];
    }

    const std::shared_ptr<Polynomial>& z() const
    {
      return sharings[2];
    }

    const std::shared_ptr<Polynomial>& y() const
    {
      return sharings[3];
    }

    const std::shared_ptr<Polynomial>& w() const
    {
      return sharings[4];
    }

    const std::vector<std::vector<std::shared_ptr<BigNum>>>& shares() const
    {
      return shares_;
    }

    const std::vector<EC::CompressedPoint>& commitments() const
    {
      // n compressed points
      return commitments_;
    }

    std::vector<std::string> proof()
    {
      return proof_;
    }

    std::string to_string() const
    {
      std::stringstream r;
      r << "sharings={";
      bool first = true;
      for (const auto& s : sharings)
      {
        if (first)
          first = false;
        else
          r << ", ";
        r << s->to_string() << std::endl;
      }
      r << "}";
      r << std::endl;
      r << "shares={";
      first = true;
      for (const auto& s : shares_)
      {
        if (first)
          first = false;
        else
          r << ", ";
        for (auto& si : s)
        {
          for (auto& ni : s)
          {
            r << ni->to_string();
          }
        }
      }
      r << "}";
      return r.str();
    }

    std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = serialise_size(shares_.size());
      for (auto& s : shares_)
      {
        std::vector<uint8_t> b = serialise_size(s.size());
        for (auto& si : s)
        {
          auto bi = si->serialise();
          b.insert(b.end(), bi.begin(), bi.end());
        }
        r.insert(r.end(), b.begin(), b.end());
      }
      std::vector<uint8_t> rc = serialise_size(commitments_.size());
      for (auto& c : commitments_)
      {
        std::vector<uint8_t> rcsz = serialise_size(c.size());
        rc.insert(rc.end(), rcsz.begin(), rcsz.end());
        rc.insert(rc.end(), c.begin(), c.end());
      }
      r.insert(r.end(), rc.begin(), rc.end());
      return r;
    }

  protected:
    size_t t;
    bool defensive;
    std::vector<size_t> indices_;
    std::vector<std::vector<std::shared_ptr<BigNum>>> shares_;
    std::vector<std::vector<uint8_t>> commitments_;
    std::vector<std::string> proof_;
    std::vector<std::shared_ptr<Polynomial>> sharings;

    void sample()
    {
      sharings.push_back(Polynomial::sample_rss(t, 2 * t, curve));
      sharings.push_back(Polynomial::sample_rss(t, 2 * t, curve));
      sharings.push_back(Polynomial::sample_zss(2 * t, nullptr, curve));
      sharings.push_back(Polynomial::sample_zss(2 * t, nullptr, curve));
      if (defensive)
      {
        sharings.push_back(Polynomial::sample_rss(2 * t, 0, curve));
      }
    }

    void compute_shares()
    {
      shares_.clear();
      for (auto index : indices_)
      {
        auto input = std::make_shared<BigNum>(index);
        std::vector<std::shared_ptr<BigNum>> t;
        for (auto s : sharings)
        {
          t.push_back(Polynomial::eval(s->coefficients, input, curve));
        }
        shares_.push_back(t);
      }
    }

    void compute_commits()
    {
      commitments_.clear();
      for (size_t i = 0; i < 2 * t + 1; i++)
      {
        std::vector<std::shared_ptr<BigNum>> sc_i;
        for (auto s : sharings)
        {
          sc_i.push_back(s->coefficients[i]);
        }
        commitments_.push_back({commit_multi(2, sc_i).compress()});
      }
    }

    void compute_proof()
    {
      // TODO
    }
  };

  class ResharingDeal : public Deal
  {
  public:
    ResharingDeal(
      const std::vector<size_t>& indices,
      const std::vector<size_t>& next_indices,
      crypto::CurveID curve = crypto::CurveID::SECP384R1,
      bool init = true) :
      Deal(false, curve)
    {
      if (init)
      {
        sample(indices, next_indices);
        compute_share_polynomials(indices);
        compute_commits();
      }
    }

    ResharingDeal(
      const uint8_t*& buf,
      size_t& sz,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      Deal(false, curve)
    {
      size_t n = serialized::read<size_t>(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        share_polynomials.push_back(SharePolynomials(buf, sz));
      }

      n = serialized::read<size_t>(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        size_t m = serialized::read<size_t>(buf, sz);
        std::vector<std::vector<uint8_t>> cs;
        for (size_t j = 0; j < m; j++)
        {
          size_t vs = serialized::read<size_t>(buf, sz);
          cs.push_back(std::vector<uint8_t>(buf, buf + vs));
          assert(cs.back().size() == vs);
          buf += vs;
          sz -= vs;
        }
        commitments_.push_back(cs);
      }
    }

    virtual ~ResharingDeal() {}

    virtual std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = serialise_size(share_polynomials.size());
      for (auto& share : share_polynomials)
      {
        auto b = share.q.serialise();
        r.insert(r.end(), b.begin(), b.end());
        b = share.q_witness.serialise();
        r.insert(r.end(), b.begin(), b.end());
      }

      auto num_commitments = serialise_size(commitments_.size());
      r.insert(r.end(), num_commitments.begin(), num_commitments.end());

      for (auto& commit : commitments_)
      {
        auto commit_size = serialise_size(commit.size());
        r.insert(r.end(), commit_size.begin(), commit_size.end());
        for (auto& c : commit)
        {
          auto c_size = serialise_size(c.size());
          r.insert(r.end(), c_size.begin(), c_size.end());
          r.insert(r.end(), c.begin(), c.end());
        }
      }

      return r;
    }

    const std::vector<SharePolynomials>& shares() const
    {
      return share_polynomials;
    }

    const std::vector<std::vector<EC::CompressedPoint>>& commitments() const
    {
      // n*n compressed points
      return commitments_;
    }

  protected:
    std::vector<std::shared_ptr<BivariatePolynomial>> sharings;
    std::vector<std::vector<std::vector<uint8_t>>> commitments_;
    std::vector<SharePolynomials> share_polynomials;

    virtual void sample(
      const std::vector<size_t>& indices,
      const std::vector<size_t>& next_indices)
    {
      auto t0 = (indices.size() - 1) / 3;
      auto t1 = (next_indices.size() - 1) / 3;

      sharings.clear();
      auto q = BivariatePolynomial::sample_zss(t0, t1);
      auto q_witness = BivariatePolynomial::sample_zss(t0, t1);
      sharings.push_back(q);
      sharings.push_back(q_witness);

      LOG_TRACE_FMT(
        "BYID: resharing deal sharings q={} q_witness={}",
        q->to_string(),
        q_witness->to_string());
    }

    void compute_share_polynomials(const std::vector<size_t>& indices)
    {
      if (sharings.size() != 2)
        throw std::logic_error("missing sharings");

      share_polynomials.clear();

      const auto& q = sharings[0];
      const auto& q_witness = sharings[1];
      for (auto i : indices)
      {
        const auto index_i = std::make_shared<BigNum>(i);
        auto share_poly_i = q->y_coefficients(index_i);
        auto witness_poly_i = q_witness->y_coefficients(index_i);
        LOG_TRACE_FMT(
          "BYID: share_polynomials for {}: [{}, {}]",
          i,
          share_poly_i.to_string(),
          witness_poly_i.to_string());

        share_polynomials.push_back(
          SharePolynomials({share_poly_i, witness_poly_i}));
      }
    }

    void compute_commits()
    {
      const auto& q = sharings[0];
      const auto& q_witness = sharings[1];
      size_t degree_y = q->coefficients.size();
      size_t degree_x = q->coefficients[0].size();

      commitments_.clear();

      std::stringstream ss;

      ss << "[";
      for (size_t i = 0; i < degree_y; i++)
      {
        const auto& qv = q->coefficients[i];
        const auto& qv_witness = q_witness->coefficients[i];

        ss << "[";
        std::vector<std::vector<uint8_t>> c;
        for (size_t j = 0; j < degree_x; j++)
        {
          c.push_back(compress_x_wx(qv[j], qv_witness[j], curve));
          ss << ds::to_hex(c.back()) << ", ";
        }
        ss << "]";

        commitments_.push_back(c);
      }
      ss << "]";

      LOG_TRACE_FMT("BYID: commits: {}", ss.str());
    }
  };

  class SamplingDeal : public ResharingDeal
  {
  public:
    SamplingDeal(
      const std::vector<size_t>& indices,
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      ResharingDeal(indices, indices, curve, false)
    {
      sample(indices, indices);
      compute_share_polynomials(indices);
      compute_commits();
    }

    SamplingDeal(
      const uint8_t*& buf,
      size_t& sz,
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      ResharingDeal(buf, sz, curve)
    {}

    virtual ~SamplingDeal() {}

  protected:
    virtual void sample(
      const std::vector<size_t>& indices,
      const std::vector<size_t>& next_indices) override
    {
      size_t t0 = (indices.size() - 1) / 3;
      sharings.clear();
      auto r = BivariatePolynomial::sample_rss(t0, t0);
      auto r_witness = BivariatePolynomial::sample_rss(t0, t0);
      sharings.push_back(r);
      sharings.push_back(r_witness);

      LOG_TRACE_FMT(
        "BYID: sampling deal sharings r={}, r_witness={}]",
        r->to_string(),
        r_witness->to_string());
    }
  };

  class Session
  {
  public:
    Session(
      size_t id,
      size_t t,
      const std::vector<ccf::NodeId>& config,
      const std::vector<ccf::NodeId>& next_config,
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      id(id),
      t(t),
      defensive(defensive),
      curve(curve),
      config(config),
      next_config(config),
      max_node_index(0)
    {
      for (auto& nid : config)
      {
        indices.push_back(get_node_index(nid, false));
        sharing_indices.push_back(get_sharing_index(nid, false));
        max_node_index = std::max(max_node_index, indices.back());
      }
      for (auto& nid : next_config)
      {
        next_indices.push_back(get_node_index(nid, true));
      }

      group_order = EC::group_order(curve);
    }

    virtual ~Session() {}

    size_t id, t;
    bool defensive = false;
    std::string subprotocol;
    CurveID curve;
    std::shared_ptr<BigNum> group_order;

    std::map<ccf::NodeId, std::vector<std::vector<uint8_t>>> resharings;

    std::vector<ccf::NodeId> config;
    std::vector<ccf::NodeId> next_config;
    std::vector<size_t> indices, next_indices;
    std::vector<size_t> sharing_indices;
    size_t max_node_index;
    std::vector<EC::CompressedPoint> x_commits; // session-wide; in kv store?

    size_t get_node_index(const ccf::NodeId& nid, bool next = false) const
    {
      size_t r = -1;
      auto& cfg = next ? next_config : config;
      for (auto& n : cfg)
      {
        r++;
        if (n == nid)
        {
          return r;
        }
      }
      throw std::logic_error("unknown nid");
    }

    size_t get_sharing_index(const ccf::NodeId& nid, bool next = false) const
    {
      return get_node_index(nid, next) + 1;
    }

    std::map<ccf::NodeId, std::map<ccf::NodeId, std::vector<uint8_t>>>
      all_encrypted_shares;

    struct Blame
    {
      ccf::NodeId id;
      std::vector<uint8_t> verifiable_symmetric_key;
    };
  };

  class SamplingSession : public Session
  {
  public:
    SamplingSession(
      size_t id,
      size_t t,
      const std::vector<ccf::NodeId>& config,
      bool defensive = false) :
      Session(id, t, config, config, defensive)
    {}

    virtual ~SamplingSession() {}

    struct NodeState
    {
      ccf::NodeId nid;
      std::map<
        ccf::NodeId,
        std::map<ccf::NodeId, std::shared_ptr<crypto::KeyAesGcm>>>
        keys;
      const std::vector<uint8_t> iv = std::vector<uint8_t>(GCM_SIZE_IV, 0);
      std::vector<uint8_t> tag = std::vector<uint8_t>(GCM_SIZE_TAG, 0);

      std::shared_ptr<SamplingDeal> deal;
      std::shared_ptr<BigNum> x = BigNum::Zero(); // Private key share
      std::shared_ptr<BigNum> x_witness = BigNum::Zero(); // Public key share

      std::map<ccf::NodeId, std::vector<uint8_t>> decrypted_shares;
      typedef std::vector<std::vector<uint8_t>> Reshare;
      std::map<ccf::NodeId, Reshare> reshares;
      std::vector<Blame> blames;
      std::vector<EC::CompressedPoint> x_commits; // local - just a copy?
      std::vector<std::vector<EC::CompressedPoint>>
        batched_commits; // Different type during signing

      void encrypt_shares(
        const std::vector<ccf::NodeId>& nids,
        std::map<ccf::NodeId, std::map<ccf::NodeId, std::vector<uint8_t>>>&
          encrypted_shares)
      {
        for (auto onid : nids)
        {
          if (nid != onid)
          {
            auto plain = deal->serialise();
            std::vector<uint8_t> iv(GCM_SIZE_IV, 0);
            std::vector<uint8_t> tag(GCM_SIZE_TAG, 0);
            std::vector<uint8_t> cipher(plain.size());
            keys[nid][onid]->encrypt(iv, plain, {}, cipher.data(), tag.data());
            cipher.insert(cipher.end(), tag.begin(), tag.end());
            encrypted_shares[nid][onid] = cipher;
          }
        }
      }

      void decrypt_shares(
        const std::vector<ccf::NodeId>& nids,
        std::map<ccf::NodeId, std::map<ccf::NodeId, std::vector<uint8_t>>>&
          encrypted_shares)
      {
        for (auto onid : nids)
        {
          if (nid != onid)
          {
            if (encrypted_shares.find(onid) != encrypted_shares.end())
            {
              auto cipher = encrypted_shares[onid][nid];
              tag =
                std::vector<uint8_t>(cipher.end() - GCM_SIZE_TAG, cipher.end());
              cipher.erase(cipher.end() - GCM_SIZE_TAG, cipher.end());
              std::vector<uint8_t> decrypted(cipher.size());
              assert(keys[onid][nid]->decrypt(
                iv, tag.data(), cipher, {}, decrypted.data()));
              decrypted_shares[onid] = decrypted;
            }
          }
          else if (deal)
          {
            decrypted_shares[onid] = deal->serialise();
          }
        }
      }

      void batch_commits(SamplingSession& s)
      {
        if (decrypted_shares.size() != s.t + 1)
        {
          throw std::logic_error("incorrect number of deals");
        }

        batched_commits.clear();

        std::vector<std::vector<std::vector<EC::CompressedPoint>>> commits;
        size_t y_dim = decrypted_shares.size();
        size_t x_dim = 0;
        for (const auto& [nid, ds] : decrypted_shares) // not in index order!
        {
          auto data = ds.data();
          auto sz = ds.size();
          SamplingDeal deal(data, sz);
          auto& cs = deal.commitments();
          assert(!cs[0].empty());
          assert(x_dim == 0 || x_dim == cs[0].size());
          x_dim = cs[0].size();
          commits.push_back(cs);
        }

        assert(x_dim != 0);

        for (size_t y = 0; y < y_dim; y++)
        {
          std::vector<std::vector<uint8_t>> xt;
          for (size_t x = 0; x < x_dim; x++)
          {
            EC::Point p(crypto::CurveID::SECP384R1);
            for (auto ci : commits)
            {
              assert(ci.size() > x);
              assert(ci[0].size() > y);
              p = p.add(EC::Point(ci[y][x]));
            }
            xt.push_back(p.compress());
          }
          batched_commits.push_back(xt);
        }

        std::stringstream ss;
        for (auto cc : batched_commits)
        {
          ss << "[";
          for (auto c : cc)
          {
            ss << ds::to_hex(c) << ", ";
          }
          ss << "],";
        }
        LOG_TRACE_FMT("BYID: batched commits: [{}]", ss.str());
      }

      std::vector<std::vector<std::shared_ptr<BigNum>>> sum_polynomials(
        Session& s)
      {
        if (decrypted_shares.size() == 0)
          throw std::logic_error("no decrypted shares/deals");

        std::vector<SharePolynomials> polys;
        auto index = s.get_node_index(nid);
        for (auto& [_, ds] : decrypted_shares)
        {
          const uint8_t* data = ds.data();
          size_t sz = ds.size();
          SamplingDeal d(data, sz);
          auto share_i = d.shares()[index];
          polys.push_back(share_i);
          LOG_TRACE_FMT("BYID: {} share_i={}", nid, share_i.to_string());
          assert(*polys.back().q.coefficients[0] != *BigNum::Zero());
        }

        return sum_share_polys(polys, s.group_order);
      }

      void verify_shares(
        const Session& s,
        const std::vector<std::vector<std::shared_ptr<BigNum>>>&
          share_polynomials)
      {
        size_t degree_y = batched_commits.size();
        size_t degree_x = batched_commits[0].size();
        auto shares = share_polynomials[0];
        auto witnesses = share_polynomials[1];

        assert(shares.size() == 2);

        LOG_TRACE_FMT(
          "shares (verification) {}: [{}, {}]",
          nid,
          shares[0]->to_string(),
          shares[1]->to_string());

        LOG_TRACE_FMT(
          "witnesses (verification) {}: [{}, {}]",
          nid,
          witnesses[0]->to_string(),
          witnesses[1]->to_string());

        std::stringstream ss;
        for (auto cc : batched_commits)
        {
          ss << "[";
          for (auto c : cc)
          {
            ss << ds::to_hex(c) << ", ";
          }
          ss << "],";
        }
        LOG_TRACE_FMT("batched commits (verification) {}: [{}]", nid, ss.str());

        auto index = s.get_sharing_index(nid);
        for (size_t i = 0; i < degree_y; i++)
        {
          // Recompute commitment from received shares and check that they
          // match.
          EC::Point computed =
            EC::eval_in_exp(batched_commits[i], index, s.group_order);
          LOG_TRACE_FMT(
            "BYID: shares[i]={}, witnesses[i]={}",
            shares[i]->to_string(),
            witnesses[i]->to_string());
          auto received = compress_x_wx(shares[i], witnesses[i]);
          auto compressed = computed.compress();
          LOG_TRACE_FMT(
            "BYID: compressed={} received={}",
            ds::to_hex(compressed),
            ds::to_hex(received));
          if (compressed != received)
          {
            throw std::logic_error("shares do not correspond to commitments");
          }
        }
      }

      std::vector<std::vector<uint8_t>> compute_resharing(
        Session& s,
        const std::vector<std::vector<std::shared_ptr<BigNum>>>&
          share_polynomials)
      {
        assert(share_polynomials.size() == 2);
        auto share_polynomial = Polynomial(share_polynomials[0]);
        auto witness_polynomial = Polynomial(share_polynomials[1]);
        std::vector<std::vector<uint8_t>> r;
        for (auto nid : s.next_config)
        {
          size_t i = s.get_sharing_index(nid);
          std::vector<uint8_t> ri;

          auto bi = std::make_shared<BigNum>(i);

          auto x_eval = share_polynomial.eval(bi);
          auto xk = std::make_shared<BigNum>(
            BigNum::mod_add(*x, *x_eval, *s.group_order));
          std::vector<uint8_t> xks = xk->serialise();
          ri.insert(ri.end(), xks.begin(), xks.end());
          LOG_TRACE_FMT("BYID: xk={}", xk->to_string());

          auto wk = std::make_shared<BigNum>(BigNum::mod_add(
            *x_witness, *witness_polynomial.eval(bi), *s.group_order));
          std::vector<uint8_t> wks = wk->serialise();
          ri.insert(ri.end(), wks.begin(), wks.end());
          LOG_TRACE_FMT("BYID: wk={}", wk->to_string());

          r.push_back(ri);
        }
        return r;
      }

      void add_reshare(
        SamplingSession& s,
        const ccf::NodeId& from,
        const std::vector<std::vector<uint8_t>>& reshare)
      {
        if (decrypted_shares.size() < s.t + 1)
          throw std::logic_error("not enough deals");

        if (reshares.size() >= 2 * s.t + 1)
          throw std::logic_error("too many reshares");

        if (!blames.empty())
          throw std::logic_error("already have blames");

        if (reshares.find(from) != reshares.end())
          throw std::logic_error("duplicate reshare");

        reshares[from] = reshare;

        if (reshares.size() == 2 * s.t + 1)
        {
          s.x_commits.clear();
          for (size_t i = 0; i < batched_commits.size(); i++)
          {
            s.x_commits.push_back(batched_commits[i][0]);
          }
        }
      }

      void compute_x_wx_shares(const SamplingSession& s)
      {
        std::vector<std::shared_ptr<BigNum>> shares, witnesses;
        std::vector<size_t> indices;

        size_t index = s.get_node_index(nid, true);
        for (auto& [onid, reshare] : s.resharings)
        {
          auto ri = reshare[index];
          // decrypt: NYI

          const uint8_t* data = ri.data();
          size_t sz = ri.size();
          auto x_jk = std::make_shared<BigNum>(data, sz);
          auto wx_jk = std::make_shared<BigNum>(data, sz);

          if (nid != onid)
            s.verify_transfer_shares(
              batched_commits, x_commits, nid, onid, x_jk, wx_jk);
          shares.push_back(x_jk);
          witnesses.push_back(wx_jk);
          indices.push_back(s.get_sharing_index(onid, false));

          if (shares.size() > s.t)
          {
            x = std::make_shared<BigNum>(
              BigNum::lagrange_interpolate(shares, indices, 0, *s.group_order));
            LOG_DEBUG_FMT("x={}", x->to_string());
            assert(*x != *BigNum::Zero());
            x_witness = std::make_shared<BigNum>(BigNum::lagrange_interpolate(
              witnesses, indices, 0, *s.group_order));
            LOG_DEBUG_FMT("BYID: share and witness successfully interpolated");
            break;
          }
        }
      }
    };

    std::vector<NodeState> nodes;

    void verify_transfer_shares(
      const std::vector<std::vector<EC::CompressedPoint>>& q_commits,
      const std::vector<EC::CompressedPoint>& x_commits,
      const ccf::NodeId& nid,
      const ccf::NodeId& onid,
      std::shared_ptr<BigNum> x_jk,
      std::shared_ptr<BigNum> wx_jk) const
    {
      size_t j = get_sharing_index(onid, false);
      size_t k = get_sharing_index(nid, true);
      LOG_TRACE_FMT("j={} k={}", j, k);
      std::vector<EC::CompressedPoint> qj_commits;
      for (auto& q : q_commits)
      {
        for (size_t i = 0; i < q.size(); i++)
        {
          LOG_TRACE_FMT("q[{}]={}", i, ds::to_hex(q[i]));
        }
        auto q_eval = EC::eval_in_exp(q, j, group_order);
        LOG_TRACE_FMT("q-eval={}", q_eval.to_compressed_hex());
        qj_commits.push_back(q_eval.compress());
      }
      auto eval1 = EC::eval_in_exp(x_commits, j, group_order);
      auto eval2 = EC::eval_in_exp(qj_commits, k, group_order);
      LOG_TRACE_FMT("eval1={}", eval1.to_compressed_hex());
      LOG_TRACE_FMT("eval2={}", eval2.to_compressed_hex());
      LOG_TRACE_FMT("x_jk={} wx_jk={}", x_jk->to_string(), wx_jk->to_string());
      auto computed = eval1.add(eval2).compress();
      auto received = compress_x_wx(x_jk, wx_jk);
      LOG_DEBUG_FMT("{} =?= {}", ds::to_hex(computed), ds::to_hex(received));
      if (computed != received)
      {
        throw std::runtime_error("invalid commitment");
      }
    }
  };
}