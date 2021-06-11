// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/curve.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <string>
#include <vector>

namespace ByzIdentity
{
  static inline EC_GROUP* get_openssl_group(crypto::CurveID curve)
  {
    switch (curve)
    {
      case crypto::CurveID::SECP384R1:
        return EC_GROUP_new_by_curve_name(NID_secp384r1);
        break;
      case crypto::CurveID::SECP256R1:
        return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        break;
      default:
        throw std::logic_error("unsupported curve");
    }
  }

  class Polynomial
  {
  public:
    Polynomial(const Polynomial&) = delete;

    Polynomial(
      crypto::CurveID curve,
      size_t t,
      const std::vector<std::string>& coefficient_strings = {})
    {
      ctx = BN_CTX_new();

      group = get_openssl_group(curve);
      group_order = BN_new();
      EC_GROUP_get_order(group, group_order, ctx);

      if (coefficient_strings.size() > 0)
      {
        for (size_t i = 0; i < coefficient_strings.size(); i++)
        {
          coefficients.push_back(BN_new());
          BN_dec2bn(&coefficients[i], coefficient_strings[i].c_str());
        }
      }
      else
      {
        for (size_t i = 0; i < t + 1; i++)
        {
          BIGNUM* x = BN_new();
          BN_rand_range(x, group_order);
          coefficients.push_back(x);
        }
      }
    }

    virtual ~Polynomial()
    {
      for (auto c : coefficients)
      {
        BN_free(c);
      }
      BN_free(group_order);
      EC_GROUP_free(group);
      BN_CTX_free(ctx);
    };

    static BIGNUM* eval(
      const BIGNUM* group_order,
      BN_CTX* ctx,
      const std::vector<BIGNUM*>& coefficients,
      BIGNUM* input)
    {
      BIGNUM* result = BN_new();
      BIGNUM *t1 = BN_new(), *t2 = BN_new();
      for (size_t i = 0; i < coefficients.size(); i++)
      {
        BIGNUM* t0 = BN_new();
        BN_set_word(t0, i);
        BN_mod_exp(t1, input, t0, group_order, ctx);
        BN_mod_mul(t2, coefficients[i], t1, group_order, ctx);
        BN_mod_add(result, result, t2, group_order, ctx);
        BN_free(t0);
      }
      BN_free(t2);
      BN_free(t1);
      return result;
    }

    BIGNUM* eval(BIGNUM* input) const
    {
      return eval(group_order, ctx, coefficients, input);
    }

    static Polynomial* sample_rss(
      crypto::CurveID curve, size_t t, size_t num_coefficients = 0)
    {
      Polynomial* r = new Polynomial(curve, t);

      if (num_coefficients > t)
      {
        // really num_coefficients+1 or just num_coefficients?
        for (size_t i = t + 1; i < num_coefficients + 1; i++)
        {
          BIGNUM* zero = BN_new();
          BN_zero(zero);
          r->coefficients.push_back(zero);
        }
      }

      return r;
    }

    static Polynomial* sample_zss(
      crypto::CurveID curve, size_t t, BIGNUM* coeff0 = nullptr)
    {
      assert(t > 0);
      Polynomial* r = new Polynomial(curve, t - 1);
      if (!coeff0)
      {
        coeff0 = BN_new();
        BN_zero(coeff0);
      }
      r->coefficients.insert(r->coefficients.begin(), coeff0);
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
        char* cs = BN_bn2dec(c);
        r << cs;
        OPENSSL_free(cs);
      }
      r << "]";
      return r.str();
    }

    std::vector<BIGNUM*> coefficients;

  protected:
    BN_CTX* ctx;
    EC_GROUP* group;
    BIGNUM* group_order;
  };

  class BivariatePolynomial
  {
  public:
    BivariatePolynomial(crypto::CurveID curve)
    {
      group = get_openssl_group(curve);
      group_order = BN_new();
      EC_GROUP_get_order(group, group_order, ctx);
    }

    virtual ~BivariatePolynomial() {}

    static BivariatePolynomial* sample_rss(size_t degree_x, size_t degree_y)
    {
      BivariatePolynomial* r = new BivariatePolynomial({});

      for (size_t i = 0; i < degree_y + 1; i++)
      {
        r->coefficients.push_back({});
        for (size_t j = 0; j < degree_x + 1; j++)
        {
          BIGNUM* x = BN_new();
          BN_rand_range(x, r->group_order);
          r->coefficients.back().push_back(x);
        }
      }

      return r;
    }

    static BivariatePolynomial* sample_zss(size_t degree_x, size_t degree_y)
    {
      BivariatePolynomial* r = new BivariatePolynomial({});

      r->coefficients.push_back({});
      for (size_t i = 0; i < degree_x + 1; i++)
      {
        BIGNUM* x = BN_new();
        BN_set_word(x, 0);
        r->coefficients.back().push_back(x);
      }

      for (size_t i = 0; i < degree_y; i++)
      {
        r->coefficients.push_back({});
        for (size_t j = 0; j < degree_x + 1; j++)
        {
          BIGNUM* x = BN_new();
          BN_rand_range(x, r->group_order);
          r->coefficients.back().push_back(x);
        }
      }

      return r;
    }

    std::vector<BIGNUM*> y_coefficients(BIGNUM* x)
    {
      std::vector<BIGNUM*> r;

      for (size_t i = 0; i < coefficients.size(); i++)
      {
        r.push_back(Polynomial::eval(group_order, ctx, coefficients[i], x));
      }

      return r;
    }

    std::vector<std::vector<BIGNUM*>> coefficients;

  protected:
    BN_CTX* ctx;
    EC_GROUP* group;
    BIGNUM* group_order;
  };

  namespace EC
  {
    static std::map<EC_GROUP*, std::vector<EC_POINT*>> bases;

    void init_basis()
    {
      for (auto curve :
           {crypto::CurveID::SECP256R1, crypto::CurveID::SECP384R1})
      {
        for (size_t i = 0; i < 13; i++)
        {
          // TODO
        }
      }
    }

    EC_POINT* commit_multi(
      EC_GROUP* group, size_t start, const std::vector<const BIGNUM*>& msgs)
    {
      auto basis = bases[group];
      assert(
        0 <= start and start + msgs.size() < basis.size() and msgs.size() > 0);
      auto ctx = BN_CTX_new();
      EC_POINT* c = EC_POINT_new(group);
      EC_POINT_mul(group, c, NULL, basis[start], msgs[0], ctx);
      for (size_t i = 1; i < msgs.size(); i++)
      {
        EC_POINT* t = EC_POINT_new(group);
        EC_POINT_mul(group, t, NULL, basis[start + i], msgs[i], ctx);
        EC_POINT_add(group, c, c, t, ctx);
      }
      BN_CTX_free(ctx);
      return c;
    }

    std::vector<uint8_t> compress(
      EC_GROUP* group, size_t start, const std::vector<const BIGNUM*>& msgs)
    {
      auto ctx = BN_CTX_new();
      EC_POINT* p = commit_multi(group, start, msgs);
      unsigned char* buf;
      size_t n =
        EC_POINT_point2buf(group, p, POINT_CONVERSION_COMPRESSED, &buf, ctx);
      BN_CTX_free(ctx);
      std::vector<uint8_t> r = {buf, buf + n};
      EC_POINT_free(p);
      return r;
    }

    std::vector<uint8_t> compress_x_wx(
      EC_GROUP* group, const BIGNUM* x, const BIGNUM* wx)
    {
      return compress(group, 0, {x, wx});
    }
  };

  typedef std::vector<BIGNUM*> Share;

  class SigningDeal
  {
  public:
    SigningDeal(
      size_t t,
      const std::vector<size_t>& indices,
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      curve(curve),
      t(t),
      defensive(defensive),
      indices_(indices)
    {
      sample();
      compute_shares();

      if (defensive)
      {
        // commits = [ compress(commit.multi(2, deal.coefficients(u))) for u in
        // range(2*t+1) ] c0 = deal.coefficients(0) non_zero_shares = c0[0:2] +
        // [ c0[4] ] proof = zkp.prove_zeroes(commits[0], non_zero_shares),
        // zkp.prove_456(commits[t+1:2*t+1], deal.higher_coefficients(t))
      }
    }

    virtual ~SigningDeal()
    {
      delete_sharings();
      delete_shares();
    }

    void load(const std::vector<std::vector<std::string>>& ss)
    {
      delete_sharings();
      for (const std::vector<std::string>& s : ss)
      {
        sharings.push_back(new Polynomial(curve, t, s));
      }
      compute_shares();
    }

    const Polynomial* k() const
    {
      return sharings[0];
    }
    const Polynomial* a() const
    {
      return sharings[1];
    }
    const Polynomial* z() const
    {
      return sharings[2];
    }
    const Polynomial* y() const
    {
      return sharings[3];
    }
    const Polynomial* w() const
    {
      return sharings[4];
    }

    std::vector<Share> shares()
    {
      return shares_;
    }
    std::vector<uint8_t> commits()
    {
      return commits_;
    }
    std::vector<uint8_t> proof()
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
        BIGNUM* tmp = BN_new();
        for (const auto& p : s)
        {
          char* ps = BN_bn2dec(p);
          r << ps;
          OPENSSL_free(ps);
        }
        BN_free(tmp);
      }
      r << "}";
      return r.str();
    }

  protected:
    crypto::CurveID curve;
    size_t t;
    bool defensive;
    std::vector<size_t> indices_;
    std::vector<Share> shares_;
    std::vector<uint8_t> commits_, proof_;
    std::vector<Polynomial*> sharings;

    void sample()
    {
      sharings.push_back(Polynomial::sample_rss(curve, t, 2 * t));
      sharings.push_back(Polynomial::sample_rss(curve, t, 2 * t));
      sharings.push_back(Polynomial::sample_zss(curve, 2 * t));
      sharings.push_back(Polynomial::sample_zss(curve, 2 * t));
      if (defensive)
      {
        sharings.push_back(Polynomial::sample_rss(curve, 2 * t));
      }
    }

    void delete_sharings()
    {
      for (auto p : sharings)
      {
        delete p;
      }
      sharings.clear();
    }

    void delete_shares()
    {
      for (auto& share : shares_)
      {
        for (BIGNUM* bn : share)
        {
          BN_free(bn);
        }
      }
      shares_.clear();
    }

    void compute_shares()
    {
      delete_shares();
      for (auto index : indices_)
      {
        BIGNUM* input = BN_new();
        BN_set_word(input, index);
        shares_.push_back({});
        for (auto s : sharings)
        {
          shares_.back().push_back(s->eval(input));
        }
        BN_free(input);
      }
    }
  };

  class SamplingDeal
  {
  public:
    SamplingDeal(
      const std::vector<size_t>& indices,
      bool defensive = false,
      crypto::CurveID curve = crypto::CurveID::SECP384R1) :
      curve(curve),
      defensive(defensive),
      indices_(indices)
    {
      group = get_openssl_group(curve);
      t = (indices.size() - 1) / 3;
      sample();
      compute_shares();
    }

    virtual ~SamplingDeal() {}

    std::vector<Share> shares()
    {
      return shares_;
    }

    std::vector<std::vector<uint8_t>> commits()
    {
      return commits_;
    }

  protected:
    crypto::CurveID curve;
    size_t t;
    bool defensive;
    EC_GROUP* group;
    std::vector<size_t> indices_;
    std::vector<Share> shares_;
    std::vector<std::vector<uint8_t>> commits_;
    std::vector<BivariatePolynomial*> sharings;

    void sample()
    {
      sharings.clear();
      auto r = BivariatePolynomial::sample_rss(t, t);
      auto r_witness = BivariatePolynomial::sample_rss(t, t);
      sharings.push_back(r);
      sharings.push_back(r_witness);
    }

    void compute_shares()
    {
      auto q = sharings[0];
      auto q_witness = sharings[1];
      for (auto i : indices_)
      {
        BIGNUM* index_i = BN_new();
        BN_set_word(index_i, i);
        auto share_poly_i = q->y_coefficients(index_i);
        auto witness_poly_i = q_witness->y_coefficients(index_i);
        shares_.push_back(share_poly_i);
        shares_.push_back(witness_poly_i);
        BN_free(index_i);
      }
    }

    void commit_coefficients()
    {
      auto q = sharings[0];
      auto q_witness = sharings[1];
      size_t degree_y = q->coefficients.size();
      size_t degree_x = q->coefficients[0].size();
      commits_.clear();
      for (size_t i = 0; i < degree_y; i++)
      {
        auto qv = q->coefficients[i];
        auto qv_witness = q_witness->coefficients[i];
        std::vector<uint8_t> c;
        for (size_t j = 0; j < degree_x; j++)
        {
          c = EC::compress_x_wx(group, qv[j], qv_witness[j]);
        }
        commits_.push_back(c);
      }
    }
  };

}
