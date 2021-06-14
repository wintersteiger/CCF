// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/byz_identity.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace crypto;
using namespace ByzIdentity;

TEST_CASE("Debug signing deal")
{
  ByzIdentity::init_bases();

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
      {"11971040240021253050855990733199357635264196602076534095139749962191011218714097886800203842464169762930539838981047",
      "30266522339766330547875209837816374563136257208888330801420119685406168349405731716334307208652403104319846043578207",
      "12833249415650484131911965264874336946692530010710652062211180234551822035172024552641821338390106873090080256466796",
      "0",
      "0"},
      {"0",
      "13205794569199814472461093117211428820752412125765014907879295308183638919356155487359875604880043216475786674000347",
      "34685344325380327964522083139003084435536306270999210711520074143743902170655670161491578907007091186639185307431684",
      "37639340622829321449596249844298857577682454924769540346973809852196699371678357930162248040236232354807684319526556",
      "6644660354369846524921448351859610398683307692243094993327170051671951633341461233013940975251333834595136764613802"},
      {"0",
      "30134393016483678268202705920662787806702929734540798373077032206049520195946227699361337750381791453786194458434954",
      "12847305610441416543274060940241723347866315369337480715735914830432962510600885905904575194059939024246355508660685",
      "39230436614667971035442643960925254786422087350648162248200488457081460325107010130294392673080943010276921843742880",
      "13370229149470308411214868724733664915736295307991931318216659880585842740848512916194692080062648886982658994040987"},
      {"37224616507411555438010701434640303823301245501366136207464259578561594034994592609033007855712496695382479867095728",
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
    {"29622442649055745653468409804690280468008024178880352002728407617121565653856671850769002806706723017369978375474647",
      "11310812973381258540682690342416288457301861668699129642156990897485491055684207451729797647651318149128572621230266",
      "19295343609495686105592049675131727719768551576501482877773334606413410181291178167141800839421048159780037702464121",
      "20154244250614175489382546333576839200368753110142924223733476981980446522034402902065907540682233606924050180129006",
      "7169114203779879449143499359297170193231816046324995217557936929873817757447325889658444049276036917053777646036949"},
    {"16874772072433375424273478602428689494625060016236022000115331727611743575038327777929465170634747937989439013599854",
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

  ByzIdentity::clear_bases();
}

TEST_CASE("Establish Byzantine identity of 4-node network")
{
  ByzIdentity::init_bases();
  size_t t = 2;
  bool defensive = false;
  std::vector<size_t> indices = {2, 5, 7, 9};
  SigningDeal deal(t, indices, defensive);
  ByzIdentity::clear_bases();
}
