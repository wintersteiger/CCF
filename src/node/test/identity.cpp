// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_types.h"
#include "node/byz_identity.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace crypto;
using namespace ByzIdentity;

TEST_CASE("Debug signing deal")
{
  size_t t = 2;
  std::vector<size_t> indices = {2, 5, 7};
  SigningDeal deal(t, indices, false);

  // clang-format off
  deal.load({
    { "10014884927522895850327356177777625667978260337939389002110941575532553449296052180537322023555523813228576607014520",
      "16341302935712828055939570400053371625442944138326862601309546139321868278170469229016276949582840172941386133934238",
      "22733325687411215076796313729157744702163634859070151867248808792760888847980819625421343878626948678252216382474849",
      "0",
      "0"},
    { "11971040240021253050855990733199357635264196602076534095139749962191011218714097886800203842464169762930539838981047",
      "30266522339766330547875209837816374563136257208888330801420119685406168349405731716334307208652403104319846043578207",
      "12833249415650484131911965264874336946692530010710652062211180234551822035172024552641821338390106873090080256466796",
      "0",
      "0"},
    { "0",
      "13205794569199814472461093117211428820752412125765014907879295308183638919356155487359875604880043216475786674000347",
      "34685344325380327964522083139003084435536306270999210711520074143743902170655670161491578907007091186639185307431684",
      "37639340622829321449596249844298857577682454924769540346973809852196699371678357930162248040236232354807684319526556",
      "6644660354369846524921448351859610398683307692243094993327170051671951633341461233013940975251333834595136764613802"},
    { "0",
      "30134393016483678268202705920662787806702929734540798373077032206049520195946227699361337750381791453786194458434954",
      "12847305610441416543274060940241723347866315369337480715735914830432962510600885905904575194059939024246355508660685",
      "39230436614667971035442643960925254786422087350648162248200488457081460325107010130294392673080943010276921843742880",
      "13370229149470308411214868724733664915736295307991931318216659880585842740848512916194692080062648886982658994040987"},
    { "37224616507411555438010701434640303823301245501366136207464259578561594034994592609033007855712496695382479867095728",
      "19607885985106249555562436727104543113555475738870997075409383775047480625454757535395098560141892903494018293441562",
      "17932138509996119236010145888837752011369384395140876275723775364518873491524504241197898792017477605547227198389377",
      "32207904579103540016219868188033273552381026460328589666178735109463097167278377132610280560603020370937575938331145",
      "14575218702365232574685903037462414017020863264884773918261013636785026093261895872237206718006461150584426313012233"}
    });

  std::vector<std::vector<const char*>> expected_shares = {
    { "15424774959409974632554631594084506312279470239477381669884553186336867200220478432058382512772114131456913442954463",
      "5631063992972413037417151167898613133067613251299463942983994432327657860873868821839234688872518723267251990176716",
      "20954170342950347826617129772569229112926262023056461979607412920880476040639544818621718449567522581729906212563708",
      "8993068641290058176016065283135325066752716352040571999017705005813506502916069613427890012216546661624791143029192",
      "8603579245968905421444910945567389905995930153009588795633743176954693696607258550909051186557015684539915299298960"},
    { "29622442649055745653468409804690280468008024178880352002728407617121565653856671850769002806706723017369978375474647",
      "11310812973381258540682690342416288457301861668699129642156990897485491055684207451729797647651318149128572621230266",
      "19295343609495686105592049675131727719768551576501482877773334606413410181291178167141800839421048159780037702464121",
      "20154244250614175489382546333576839200368753110142924223733476981980446522034402902065907540682233606924050180129006",
      "7169114203779879449143499359297170193231816046324995217557936929873817757447325889658444049276036917053777646036949"},
    { "16874772072433375424273478602428689494625060016236022000115331727611743575038327777929465170634747937989439013599854",
      "25223787860975225891808915473740600058477442909342420726543408380892622006604888023211517412948035089940287978105997",
      "1384957605588707963627717129332315118212548008822339547498466018241422426027059844341847314502562477260297450126001",
      "22257379580037686129144416330342364539137835662438161680059452077356003923739768576714345163541869281354807539145059",
      "10168575713000123602259968848472340438785757710205718293243014176955755855823983470602512563918937778902648570761918"}
    };
  // clang-format on

  const auto& ss = deal.shares();
  REQUIRE(ss.size() == expected_shares.size());
  for (size_t i = 0; i < ss.size(); i++)
  {
    for (size_t j = 0; j < ss[i].size(); j++)
    {
      REQUIRE(*ss[i][j] == BigNum(expected_shares[i][j]));
    }
  }
}

TEST_CASE("Compute signature")
{
  const char* message_to_sign = "Hello";
  size_t t = 1;

  auto group_order = EC::group_order();
  auto x = BigNum::Random(*group_order);

  // bypassing Byzantine sampling of the private signing key.
  auto xp = Polynomial::sample_zss(t, x);
  // auto x_commits = [ (commit.basis[0] * xp.coefficients[u]).compress() for u
  // in range(t+1) ];

  // sharing_indices = [ j + 1 for j in range(2*t+1) ]

  // # (1) DEALING: deals is a list of (shares, commits, proof) triples
  // # we skip the elaboration/encryption of DEAL messages to carry it
  // # and their allocation to a signining session
  // deals = [ SigningDeal.deal(t, sharing_indices, defensive=defensive) for i
  // in range(t+1)] commits = None if defensive:
  //     # normally re-computed by every replica
  //     dealer_commits = [ deals[i][1] for i in range(t+1) ]
  //     commits = [ batch_commit(dealer_commits,u) for u in range(2*t+1) ]

  // # (2) After accepting the deals, every replica aggregates their shares
  // # and sends their OpenK message.
  // def core_session(j):
  //     session = SignSession()
  //     session.defensive = defensive
  //     session.shares = sum_shares([ deals[i][0][j] for i in range(t+1) ])
  //     session.batched_commits = commits
  //     if defensive:
  //         verify_shares_signing(j+1,session.shares,commits)
  //     return session
  // session = [ core_session(j) for j in range(2*t+1) ]
  // openKs = [ compute_OpenK(session[j]) for j in range(2*t+1) ]

  // K_shares = [ openKs[j][0] for j in range(2*t+1)]
  // if defensive:
  //     # normally verified by every replica
  //     # note the defensive protocol only need t+1 verified messages
  //     for j in range(2*t+1):
  //         Cx = K_shares[j]
  //         Cj = compute_C_at_j(commits,j+1)
  //         proof = openKs[j][1]
  //         assert zkp.verify_OpenK((Cx,Cj), proof)

  // # (3) After receiving the OpenKs, every replica computes r, then their
  // shares of the signature # Only this last "online" step of signing depends
  // on the message and shared private key

  // K = interpolate_and_check(K_shares, sharing_indices, t)
  // r = int((Point.decompress(K).x) % order)
  // for j in range(2*t+1):
  //     session[j].txt = txt
  //     session[j].r = r
  // # sig_shares is a list of (ak_share, s_share, proof)
  // sig_shares = [ compute_signature_shares_core(session[j], xp.eval(j+1), 0)
  // for j in range(2*t+1) ]

  // # (4) Anyone can then aggregate the shares and interpolate the signature
  // ak_shares = [ sig_shares[j][0] for j in range(2*t+1)]
  // s_shares = [ sig_shares[j][1] for j in range(2*t+1)]

  // if defensive:
  //     for j in range(2*t+1):
  //         m = int(crypto_provider.hash_msg(session[j].txt))
  //         Cy_pv = compress(
  //             Point.decompress(compute_C_at_j(x_commits, j+1)) +
  //             Point.decompress(compute_C_at_j(session[j].batched_commits,
  //             j+1)))
  //         proof = sig_shares[j][2]
  //         assert zkp.verify_mult(Cy_pv,m,session[j].r,ak_shares[j],
  //         s_shares[j], proof)
  // # these 5 lines should be factored out of keying
  // ak = lagrange_interpolate(ak_shares, sharing_indices, 0)
  // s1 = lagrange_interpolate(s_shares, sharing_indices, 0)
  // s = (s1 * inv(ak)) % order
  // signature = encode_dss_signature(session[0].r, s)

  // # check signing succeeded using another, plain ECDSA implementation
  // # (the call to verify may fail with an InvalidSignature exception)
  // # crypto_provider.ecdsa_verify(X, signature, message_to_sign)
  // // VK verification key is the public part of `x`
  // VK.verify(signature, bytes(txt, "utf-8"), ec.ECDSA(hashes.SHA256()))
}

std::map<ccf::NodeId, std::map<ccf::NodeId, std::shared_ptr<crypto::KeyAesGcm>>>
make_node_keys(const std::vector<ccf::NodeId>& nids)
{
  EntropyPtr entropy = create_entropy();
  std::
    map<ccf::NodeId, std::map<ccf::NodeId, std::shared_ptr<crypto::KeyAesGcm>>>
      r;
  for (auto nid_from : nids)
  {
    for (auto nid_to : nids)
    {
      if (nid_from != nid_to)
      {
        r[nid_from][nid_to] = crypto::make_key_aes_gcm(entropy->random(32));
      }
    }
  }
  return r;
}

TEST_CASE("Establish Byzantine identity")
{
  size_t t = 4;

  std::vector<ccf::NodeId> nids;
  for (size_t i = 0; i < 3 * t + 1; i++)
  {
    nids.push_back(ccf::NodeId(std::to_string(i)));
  }

  SamplingSession s(0, t, nids, false);

  auto keys = make_node_keys(nids);

  for (size_t i = 0; i < 3 * t + 1; i++)
  {
    s.nodes.push_back({nids[i], s.indices[i], keys});
  }

  // Prepare t+1 deals
  for (size_t i = 0; i < t + 1; i++)
  {
    s.nodes[i].deal = std::make_shared<SamplingDeal>(s.indices);
  }

  // Dealers encrypt shares for each other node
  for (size_t i = 0; i < t + 1; i++)
  {
    s.nodes[i].encrypt_shares(nids, s.all_encrypted_shares);
  }

  // Nodes decrypt all shares
  for (auto& n : s.nodes)
  {
    n.decrypt_shares(nids, s.all_encrypted_shares);
  }

  for (auto& from : s.nodes)
  {
    if (from.deal)
    {
      auto plain = from.deal->serialise();

      for (auto& to : s.nodes)
      {
        if (from.nid != to.nid)
        {
          REQUIRE(plain == to.decrypted_shares[from.nid]);
        }
      }
    }
  }

  // All nodes validate the shares (sum_shares_reshare) and reply with
  // "reshares" for each node (evaluations of the sharing/witness polynomials at
  // each sharing index; this includes all 3*t+1 nodes). All reshares are also
  // encrypted by the node-to-node keys.

  for (auto& node : s.nodes)
  {
    node.batch_commits(s); // Only primary, shared in start message?

    // Sum shares and verify them.
    auto sum = node.sum_polynomials(s);
    try
    {
      node.verify_shares(sum, node.batched_commits);
    }
    catch (std::exception& ex)
    {
      // --> Blame
    }

    s.resharings[node.nid] = node.compute_resharing(s, sum);
    // encryption of resharings NYI
  }

  for (auto& node : s.nodes)
  {
    for (auto& id : nids)
    {
      auto srid = s.resharings[id];
      node.add_reshare(s, id, srid);

      if (node.reshares.size() >= 2 * t + 1)
      {
        node.compute_x_wx_shares(s);
        // send OpenKey
        break;
      }
    }
  }
}
