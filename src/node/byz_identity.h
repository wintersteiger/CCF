// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/curve.h"
#include "crypto/openssl/openssl_wrappers.h"

#include <map>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>
#include <string>
#include <vector>

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

    std::string to_string() const
    {
      char* cs = BN_bn2dec(b);
      CHECKNULL(cs);
      std::string r = cs;
      OPENSSL_free(b);
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

      std::vector<uint8_t> compress() const
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
  }

  class Polynomial
  {
  public:
    Polynomial(const Polynomial&) = delete;

    Polynomial(size_t t, crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      group_order = EC::group_order(curve);

      for (size_t i = 0; i < t + 1; i++)
      {
        coefficients.push_back(BigNum::Random(*group_order));
      }
    }

    Polynomial(
      size_t t,
      const std::vector<std::string>& coefficient_strings = {},
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      group_order = EC::group_order(curve);

      if (coefficient_strings.size() > 0)
      {
        for (size_t i = 0; i < coefficient_strings.size(); i++)
        {
          coefficients.push_back(
            std::make_shared<BigNum>(coefficient_strings[i]));
        }
      }
      else
      {
        for (size_t i = 0; i < t + 1; i++)
        {
          coefficients.push_back(BigNum::Random(*group_order));
        }
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

    static std::shared_ptr<Polynomial> sample_rss(
      size_t t,
      size_t num_coefficients = 0,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      std::shared_ptr<Polynomial> r = std::make_shared<Polynomial>(t, curve);

      if (num_coefficients > t)
      {
        // really num_coefficients+1 or just num_coefficients?
        for (size_t i = t + 1; i < num_coefficients + 1; i++)
        {
          r->coefficients.push_back(BigNum::Zero());
        }
      }

      return r;
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

    std::string to_string()
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

    std::vector<std::shared_ptr<BigNum>> coefficients;

  protected:
    std::shared_ptr<BigNum> group_order;
  };

  class BivariatePolynomial
  {
  public:
    BivariatePolynomial(crypto::CurveID curve) : curve(curve)
    {
      group_order = EC::group_order(curve);
    }

    virtual ~BivariatePolynomial() {}

    static std::shared_ptr<BivariatePolynomial> sample_rss(
      size_t degree_x,
      size_t degree_y,
      crypto::CurveID curve = crypto::CurveID::SECP384R1)
    {
      auto r = std::make_shared<BivariatePolynomial>(curve);

      for (size_t i = 0; i < degree_y + 1; i++)
      {
        r->coefficients.push_back({});
        for (size_t j = 0; j < degree_x + 1; j++)
        {
          r->coefficients.back().push_back(std::make_shared<BigNum>());
        }
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

    std::vector<std::shared_ptr<BigNum>> y_coefficients(
      const std::shared_ptr<BigNum>& x)
    {
      std::vector<std::shared_ptr<BigNum>> r;

      for (size_t i = 0; i < coefficients.size(); i++)
      {
        r.push_back(Polynomial::eval(coefficients[i], x, curve, group_order));
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

  inline std::vector<uint8_t> compress(
    size_t start,
    const std::vector<std::shared_ptr<BigNum>>& msgs,
    crypto::CurveID curve = crypto::CurveID::SECP384R1)
  {
    return commit_multi(start, msgs, curve).compress();
  }

  inline std::vector<uint8_t> compress_x_wx(
    std::shared_ptr<BigNum> x,
    std::shared_ptr<BigNum> wx,
    crypto::CurveID curve = crypto::CurveID::SECP384R1)
  {
    return compress(0, {x, wx}, curve);
  }

  typedef std::vector<std::shared_ptr<BigNum>> Share;
  typedef std::vector<std::vector<uint8_t>> Commitment;
  class Deal
  {
  public:
    Deal(crypto::CurveID curve = crypto::CurveID::SECP384R1) : curve(curve) {}
    virtual ~Deal() {}

    const std::vector<Share>& shares()
    {
      return shares_;
    }

    const std::vector<Commitment>& commitments()
    {
      return commitments_;
    }

  protected:
    crypto::CurveID curve;
    std::vector<Share> shares_;
    std::vector<Commitment> commitments_;
  };

  class SigningDeal : public Deal
  {
  public:
    SigningDeal(
      size_t t,
      const std::vector<size_t>& indices,
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      Deal(curve),
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

    virtual ~SigningDeal() {}

    void load(const std::vector<std::vector<std::string>>& ss)
    {
      sharings.clear();
      for (const std::vector<std::string>& s : ss)
      {
        sharings.push_back(std::make_shared<Polynomial>(t, s, curve));
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
        for (const auto& p : s)
        {
          r << p->to_string();
        }
      }
      r << "}";
      return r.str();
    }

  protected:
    size_t t;
    bool defensive;
    std::vector<size_t> indices_;
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
        shares_.push_back({});
        for (auto s : sharings)
        {
          shares_.back().push_back(
            Polynomial::eval(s->coefficients, input, curve));
        }
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
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      Deal(curve),
      indices_(indices),
      next_indices_(next_indices)
    {
      sample();
      compute_shares();
      compute_commits();
    }

    virtual ~ResharingDeal() {}

  protected:
    std::vector<size_t> indices_, next_indices_;
    std::vector<std::shared_ptr<BivariatePolynomial>> sharings;

    virtual void sample()
    {
      auto t0 = (indices_.size() - 1) / 3;
      auto t1 = (next_indices_.size() - 1) / 3;

      sharings.clear();
      auto q = BivariatePolynomial::sample_zss(t0, t1);
      auto q_witness = BivariatePolynomial::sample_zss(t0, t1);
      sharings.push_back(q);
      sharings.push_back(q_witness);
    }

    void compute_shares()
    {
      if (sharings.size() != 2)
        throw std::logic_error("missing sharings");
      auto q = sharings[0];
      auto q_witness = sharings[1];
      for (auto i : indices_)
      {
        auto index_i = std::make_shared<BigNum>(i);
        auto share_poly_i = q->y_coefficients(index_i);
        auto witness_poly_i = q_witness->y_coefficients(index_i);
        shares_.push_back(share_poly_i);
        shares_.push_back(witness_poly_i);
      }
    }

    void compute_commits()
    {
      auto q = sharings[0];
      auto q_witness = sharings[1];
      size_t degree_y = q->coefficients.size();
      size_t degree_x = q->coefficients[0].size();
      commitments_.clear();
      for (size_t i = 0; i < degree_y; i++)
      {
        auto qv = q->coefficients[i];
        auto qv_witness = q_witness->coefficients[i];
        std::vector<std::vector<uint8_t>> c;
        for (size_t j = 0; j < degree_x; j++)
        {
          c.push_back(compress_x_wx(qv[j], qv_witness[j], curve));
        }
        commitments_.push_back(c);
      }
    }
  };

  class SamplingDeal : public ResharingDeal
  {
  public:
    SamplingDeal(
      const std::vector<size_t>& indices,
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      ResharingDeal(indices, indices, curve)
    {
      sample();
      compute_shares();
      compute_commits();
    }

    virtual ~SamplingDeal() {}

  protected:
    virtual void sample() override
    {
      size_t t0 = (indices_.size() - 1) / 3;
      sharings.clear();
      auto r = BivariatePolynomial::sample_rss(t0, t0);
      auto r_witness = BivariatePolynomial::sample_rss(t0, t0);
      sharings.push_back(r);
      sharings.push_back(r_witness);
    }
  };

  class Session
  {
  public:
    Session(size_t id) : id(id) {}
    ~Session() {}

    size_t id;
    std::string subprotocol;
    std::map<ccf::NodeId, std::shared_ptr<Deal>> deals;
    std::map<ccf::NodeId, std::map<ccf::NodeId, std::vector<uint8_t>>>
      encrypted_shares;
  };

  class SamplingSession : public Session
  {
  public:
    using Session::deals;

    SamplingSession(size_t id) : Session(id) {}
    virtual ~SamplingSession() {}

    std::vector<Commitment> batched_commits;

    void batch_commits()
    {
      batched_commits.clear();

      if (deals.size() == 0)
        throw std::logic_error("no deals");

      std::vector<std::vector<Commitment>> commits;

      size_t y_dim = deals.size();
      size_t x_dim = 0;
      for (const auto& [_, d] : deals)
      {
        auto& cs = d->commitments();
        assert(cs.size() > 0);
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
            auto c = ci[y][x];
            p.add(EC::Point(c));
          }
          xt.push_back(p.compress());
        }
        batched_commits.push_back(xt);
      }
    }

    std::vector<std::vector<std::shared_ptr<BigNum>>> sum_shares()
    {
      if (deals.size() == 0)
        throw std::logic_error("no deals");

      std::vector<Share> summed_polynomials;
      auto& deal0 = deals.begin()->second;
      size_t num_poly = deal0->shares().size();
      std::vector<std::vector<std::shared_ptr<BigNum>>> r;
      for (size_t i = 0; i < num_poly; i++)
      {
        std::vector<std::shared_ptr<BigNum>> jt;
        for (size_t j = 0; j < deal0->shares()[i].size(); j++)
        {
          auto s = BigNum::Zero();
          for (auto& [_, d] : deals)
          {
            s->add(*(*d).shares()[i][j]);
          }
          jt.push_back(s);
        }
        r.push_back(jt);
      }
      return r;
    }

    EC::Point eval_in_exp(const Commitment& commitment, size_t j)
    {
      size_t degree = commitment.size();
      EC::Point result(commitment[0]);

      for (size_t i = 1; i < degree; i++)
      {
        result.add(EC::Point(commitment[i]).mul(std::pow(j, i)));
      }

      return result;
    }

    void verify_shares(
      size_t node_index,
      const std::vector<std::vector<std::shared_ptr<BigNum>>>&
        share_polynomials,
      const std::vector<Commitment>& commits)
    {
      size_t degree_y = commits.size();
      size_t degree_x = commits[0].size();
      auto shares = share_polynomials[0];
      auto witnesses = share_polynomials[1];

      for (size_t i = 0; i < degree_y; i++)
      {
        // Recompute commitment from received shares and check that they match.
        auto commits_i = commits[i];
        EC::Point computed = eval_in_exp(commits_i, node_index);
        auto received = compress_x_wx(shares[i], witnesses[i]);
        if (computed.compress() != received)
        {
          throw std::logic_error("shares do not correspond to commitments");
        }
      }
    }
  };
}