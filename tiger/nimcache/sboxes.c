/* Generated by Nim Compiler v0.11.2 */
/*   (c) 2015 Andreas Rumpf */
/* The generated code is subject to the original license. */
/* Compiled for: Windows, amd64, gcc */
/* Command for C compiler:
   gcc.exe -c  -w  -IC:\Users\apens_000\Downloads\nim-original\lib -o c:\users\apens_000\documents\nimcode\nimdigest\tiger\nimcache\sboxes.o c:\users\apens_000\documents\nimcode\nimdigest\tiger\nimcache\sboxes.c */
#define NIM_INTBITS 64
#include "nimbase.h"
typedef NU64 TY89006[256];
static N_INLINE(void, nimFrame)(TFrame* s);
N_NOINLINE(void, stackoverflow_19801)(void);
static N_INLINE(void, popFrame)(void);
NIM_CONST TY89006 Table1_89005 = {192161084409973854ULL,
12412566003039578348ULL,
8272369121297300691ULL,
7854730284916899642ULL,
14815005489349235091ULL,
8463286011307239906ULL,
12782397079979459523ULL,
5082381371487377520ULL,
16910140313379794150ULL,
14213758138097816412ULL,
5541490850629862524ULL,
766444128913191948ULL,
1204553577021685498ULL,
14325024777722506090ULL,
1401289229890216703ULL,
1893918052108309022ULL,
5461170853188208586ULL,
2807403890869420487ULL,
9624326389127268278ULL,
5699452412975025298ULL,
15532482038911174219ULL,
10247451172578640253ULL,
7624427211800470465ULL,
13116673706182362478ULL,
9043806901924967914ULL,
7231827479902542914ULL,
13778939497803891424ULL,
6875646691050945796ULL,
17492696646193712838ULL,
7786398710221814956ULL,
8167597339425066981ULL,
1830707105885056415ULL,
18253814936157636059ULL,
14445834393465872395ULL,
9656360342964607310ULL,
11887624205054558387ULL,
10399800464770430483ULL,
15811522062611479537ULL,
1783120314242633559ULL,
248005612187258982ULL,
7688500634458409525ULL,
17647688304275301531ULL,
8591138587399736033ULL,
15633037317611203077ULL,
13643301300320350067ULL,
5042603696143252264ULL,
2053990370701680515ULL,
10011753445593162089ULL,
3741955435321465241ULL,
4334407786093429776ULL,
13046945900594209529ULL,
1449859124008718907ULL,
18187146081364455764ULL,
16146959651762660871ULL,
9821796187408409551ULL,
10596140432474060285ULL,
3847074041673952000ULL,
4649400157396704725ULL,
14173244547020241484ULL,
14606001508420839982ULL,
2909491499011162061ULL,
4458122598401901638ULL,
7071481730398905774ULL,
6725294491764459774ULL,
12245192337599078954ULL,
14074214025701625255ULL,
1226483701329067140ULL,
15924709066658687059ULL,
14770628265263427446ULL,
13470993037325816321ULL,
16615015929427450229ULL,
10714085159597194772ULL,
479582384021555544ULL,
8040612334407127321ULL,
15648517004018321088ULL,
17112515522038886866ULL,
8751740296797632830ULL,
6603430683508552489ULL,
8942924799792477540ULL,
3573742753214737511ULL,
16027224499883949314ULL,
6349030933445924429ULL,
15944798094267651441ULL,
12269290567006146658ULL,
10560886376429385824ULL,
5194369709296555225ULL,
7174555471952375656ULL,
7982812746821821468ULL,
9739074967177125163ULL,
3232013613859041307ULL,
12699367828500449645ULL,
16215284685696605295ULL,
3112410413624570453ULL,
16110141331589860284ULL,
6658792778814911418ULL,
6126246269502162262ULL,
12375791606097406863ULL,
4721051187472420532ULL,
12913124649239600434ULL,
13593718485625264257ULL,
2663576151211431276ULL,
928112258657309258ULL,
5664920977038299994ULL,
2704699625848084345ULL,
2312925355491498803ULL,
17917931256736142540ULL,
2964761606854114992ULL,
4148718494125202372ULL,
4082542483235864459ULL,
5171535286737311423ULL,
2166137813939512309ULL,
8844224567096109974ULL,
12073497029628754377ULL,
10313129584137200909ULL,
7053919794999990929ULL,
5576291611870337032ULL,
17071918333241912043ULL,
17712290504455390414ULL,
17740771901396443681ULL,
11758017946897781732ULL,
10978122417803504804ULL,
14919163634504077233ULL,
11490461953836997027ULL,
12165654920579776535ULL,
853355433004222246ULL,
16522522127453838137ULL,
2124075034376372323ULL,
5881355904936746717ULL,
1033318428544969251ULL,
1692585388818821524ULL,
17200759021255085090ULL,
1107424405919510210ULL,
9235073569857586017ULL,
12471487353192899638ULL,
963191604767572015ULL,
4506934758573727688ULL,
11934771386322515838ULL,
11732209241253279301ULL,
7421261837586505858ULL,
3318186242040429129ULL,
14044682965315173317ULL,
1910808081503ULL,
4771413979138012118ULL,
15088778931977875125ULL,
11635083951108444120ULL,
3247421105326436348ULL,
17436899165275233567ULL,
8353265116968520410ULL,
12565337778774156881ULL,
10871874290690996106ULL,
6528592316425799439ULL,
15397071475010590000ULL,
15142762107613549607ULL,
7320455443630736945ULL,
11094769083352733519ULL,
2539802313181221187ULL,
11139220281097600151ULL,
6084456898448652712ULL,
1615327116689102472ULL,
8126548348642832045ULL,
17352529224806255890ULL,
6320848846662414801ULL,
17282944389244390251ULL,
3439926484095136410ULL,
11228441527149633512ULL,
4583261464596863494ULL,
5278432013075676693ULL,
672210957064462075ULL,
13025854346008288483ULL,
14498696732057183809ULL,
3753742208681096767ULL,
13261228611926580032ULL,
17986491732842022258ULL,
111470777923844445ULL,
1951374535466601971ULL,
9571400392277455661ULL,
13953014824866208278ULL,
4830799035278983864ULL,
13222015508416504078ULL,
6842302225500364445ULL,
11335550205397804100ULL,
15716824796288558584ULL,
12864465832706149959ULL,
18320322304522000518ULL,
14411022707054136303ULL,
16460574793555246339ULL,
3977519900599801820ULL,
9148781857317432677ULL,
6468933130968205401ULL,
8516219711084257782ULL,
1539015908620793624ULL,
7527026033758878374ULL,
16798794393021101279ULL,
3088835283432281588ULL,
3651919061693825289ULL,
9461488011709396048ULL,
18023579054726214285ULL,
11414687284771824631ULL,
308165109378616703ULL,
8884692927086426203ULL,
2438838841395254149ULL,
14896570625953598117ULL,
2823241734971430590ULL,
3896218688877146334ULL,
393786506094771122ULL,
15328770503170608105ULL,
10473175056012527227ULL,
10077980508395331620ULL,
6934559736714979565ULL,
17857395910652154129ULL,
10891890112678993536ULL,
11568068034921390039ULL,
14648678256067979723ULL,
9344782632198616737ULL,
13887300970038794941ULL,
10781369878360680786ULL,
10110669637513019833ULL,
4236391428300945648ULL,
555138268555536248ULL,
5351590591369890935ULL,
4306521946498657944ULL,
11295261863032656012ULL,
4901816398460471456ULL,
9412954593909222793ULL,
7485939926152528684ULL,
13340749930154375154ULL,
6245128712556390173ULL,
13728064239465473455ULL,
18121470962401429929ULL,
7772052866533484500ULL,
639373189613950878ULL,
2515940555210603828ULL,
16388058205984530442ULL,
9187445612742136046ULL,
12674756240461064247ULL,
16320932256496599612ULL,
15242008505997455568ULL,
15052846203706837274ULL,
1313621308117380133ULL,
3526835097255131285ULL,
13493710469666597351ULL,
8704164972314360376ULL,
17526606163846348700ULL,
5969067443919232116ULL,
5791404459833380522ULL,
16764031247701565831ULL,
6001456072058810555ULL,
10172882867408301456ULL,
2241175407069758350ULL,
15484192582789326408ULL,
8359644330926224055ULL,
9923258301097833899ULL,
18441560808156168866ULL,
16657473437411103805ULL,
11975088000835799072ULL,
16988008119788939130ULL}
;
NIM_CONST TY89006 Table2_89011 = {16620180768708174136ULL,
13087780087216503960ULL,
6213947727727520144ULL,
5496303794639560149ULL,
15650762814559589428ULL,
642450021946863605ULL,
15520994653159001329ULL,
14194067837486075289ULL,
16073846824652113554ULL,
15991021072757504790ULL,
8011611286970690052ULL,
5372247966639775667ULL,
11956475335693613649ULL,
18180761396468528926ULL,
16734845874302321705ULL,
15893194850365545698ULL,
14791316918028724237ULL,
1788379855404599063ULL,
3792259505844355329ULL,
857793142685420274ULL,
2176386753693503798ULL,
16165556464122449145ULL,
18433866172389203220ULL,
6070247714570225101ULL,
7358743242340641331ULL,
9743228014385134454ULL,
1522910625901990663ULL,
16311896314355823354ULL,
5235630359010597374ULL,
12672095911739354858ULL,
277273466943670671ULL,
3580831169916433691ULL,
17414337388161447897ULL,
4657750985732713388ULL,
1177149711660596421ULL,
8685721698255572101ULL,
15219111713807365290ULL,
12097333842433196187ULL,
13637243492043779536ULL,
10523434303980543600ULL,
11720003357325288028ULL,
13858952002212630691ULL,
17788473056595710763ULL,
3834592178494549117ULL,
14592892671379561684ULL,
9581455899396743388ULL,
8774750272303345432ULL,
10018717713484244012ULL,
15042560872303683366ULL,
6519077675840655372ULL,
1009372798613472243ULL,
13941815458558040098ULL,
7670504156571609794ULL,
9378295951984427608ULL,
7481699948221361317ULL,
2131352009749933493ULL,
7854556580946198495ULL,
5848046147829288198ULL,
6811751916476253359ULL,
17810787299410161198ULL,
13709208837769715866ULL,
16831935031467898469ULL,
8245611441321613668ULL,
8087057586628171618ULL,
5058061449640751271ULL,
13294825889344038590ULL,
7212395796113148780ULL,
8872633840395976086ULL,
8602726521519041395ULL,
12561253256920036340ULL,
6042660761688602872ULL,
1642367900117110883ULL,
25924001596622557ULL,
7531865058110106323ULL,
4223621278438660202ULL,
3926684511422013614ULL,
16382380113756205527ULL,
5939130201053773422ULL,
8312208923375399755ULL,
5278156969609628584ULL,
12734421984402844485ULL,
3610014133393185213ULL,
9596519943885996947ULL,
10457528947283767525ULL,
7953444341930717599ULL,
13374154748713552676ULL,
14768757517560628423ULL,
5127306049615917691ULL,
9121210965518562125ULL,
8462056263389103903ULL,
17703039091829532745ULL,
5658738406708581754ULL,
3084862250275496789ULL,
15607266543450182998ULL,
14480359564937826262ULL,
14959210002597418810ULL,
18322749590590308156ULL,
17101137515031609645ULL,
9446964496815386772ULL,
14254958291267920036ULL,
1116769798908306816ULL,
1871732813531574911ULL,
12807515078363457603ULL,
2050857069623328786ULL,
942713319182180155ULL,
9890976159808040074ULL,
16508030273321291366ULL,
7028952989422544417ULL,
9018945159409650955ULL,
9348172371089358427ULL,
512456053301416255ULL,
14393200364208532887ULL,
14115843866838292311ULL,
16933948646436594152ULL,
15343759105510392346ULL,
11057037641413621675ULL,
11808547772908125699ULL,
11334024907024538672ULL,
4569666897377300404ULL,
11295294635916036800ULL,
4462677101358564049ULL,
3679240545963649394ULL,
14317631520548985665ULL,
776201060342576796ULL,
17243909456190059557ULL,
17604610864827148760ULL,
10001446825249529526ULL,
3458390008116962295ULL,
10339343346676942200ULL,
6618311662604863029ULL,
4790267690900900096ULL,
1716087693007726108ULL,
4148457837926911568ULL,
13027786587857474755ULL,
8968309666649857421ULL,
15835383998547979361ULL,
6968029403465067289ULL,
14862556481213186354ULL,
500987773930853904ULL,
10278571274613639408ULL,
2355660670689429871ULL,
3178293543037890097ULL,
12863151040160441096ULL,
12149618985794982607ULL,
894835714693979080ULL,
13140917299619429091ULL,
18098692892679743463ULL,
352461093517089771ULL,
5441805419015688358ULL,
15397362850185904124ULL,
3501129463520285556ULL,
13466617900358153333ULL,
10143225092775386885ULL,
11000396338623494503ULL,
2615208954064994172ULL,
17924140821443864558ULL,
2237558221535645089ULL,
14534824473151846839ULL,
13236032612028143522ULL,
7102368496127332321ULL,
10727377356684633597ULL,
399232473491847935ULL,
7140013836546489399ULL,
10212002790465040192ULL,
16215351210583878990ULL,
11386546581606838557ULL,
5038446221635409553ULL,
6294769326316815049ULL,
18058941983678306709ULL,
15096697943663711592ULL,
15779936050728011823ULL,
12285020473469085899ULL,
2783168786742146440ULL,
1986639352536355296ULL,
16458016955501249014ULL,
8799325730492140254ULL,
7305467695957075406ULL,
2551364576700533681ULL,
12365742766643545018ULL,
13556939551025923470ULL,
11121884478320942796ULL,
11560995779659109437ULL,
5760535140236403614ULL,
1501217875009212803ULL,
17155111980276651522ULL,
10740590121652346377ULL,
6454505253869455699ULL,
4319683495060363885ULL,
12201821765133472647ULL,
11627976249930647428ULL,
2960027307368769952ULL,
8570410701452901115ULL,
160427886842421800ULL,
13476805212888794763ULL,
13819301442714769089ULL,
15161096039636807203ULL,
10840625911376688560ULL,
6176075057452006273ULL,
7582622308322968760ULL,
6649763778434249567ULL,
18263287368680645066ULL,
2699628156079216836ULL,
16679512126457685165ULL,
2945653313023238585ULL,
2813841150172635667ULL,
8163160757531991904ULL,
11234321609599741815ULL,
12522125344893058495ULL,
649720531103423106ULL,
6394120152722619742ULL,
17511778262592440498ULL,
4753049982369101610ULL,
2408845162401379802ULL,
1253140645631747605ULL,
10647695429742646567ULL,
16862477982545442873ULL,
17990741204064412777ULL,
8367255505928917714ULL,
91400768704631494ULL,
13982368817729209682ULL,
1938401838693046941ULL,
10926450282100227564ULL,
9810146466437985312ULL,
3990523136699180870ULL,
7731749711829208666ULL,
4875740361372990282ULL,
9173201802070489451ULL,
7834799413446679311ULL,
12013351936531834174ULL,
3325271250982575439ULL,
9716135266257811596ULL,
16057385208373506132ULL,
9237091451614363741ULL,
4359958813756723849ULL,
4539467735137059035ULL,
12938212395927242823ULL,
1312945880979454078ULL,
17499315598292792898ULL,
4958176066159770025ULL,
1374196081931091686ULL,
11528309388770592584ULL,
17351559514427848379ULL,
17035274631238963172ULL,
3145683508650593868ULL,
12407221208356893421ULL,
14642276899857517585ULL,
11883033819604736188ULL,
6868326517302426863ULL,
6758043032196830276ULL,
5827167051130463242ULL,
4074828688890126937ULL,
3293442170241026694ULL,
10380983089625111273ULL,
5618223731912049521ULL,
15432198388343861625ULL,
2520538699101199374ULL}
;
NIM_CONST TY89006 Table3_89017 = {17627031972844598171ULL,
5224129141031473793ULL,
16763249281696835647ULL,
3214246200928423523ULL,
15726560327778417602ULL,
3432136347919366758ULL,
11602366076889764820ULL,
13748905236245012081ULL,
14966620937599181975ULL,
13189541385867841559ULL,
15286072487566162144ULL,
10303139529070577017ULL,
10864531730823556037ULL,
7399204607179264370ULL,
2410740665327626235ULL,
12915425045000683329ULL,
17314732200908842661ULL,
10202635360025484021ULL,
10346713243535852126ULL,
17581701249550998855ULL,
17040480865221710045ULL,
17702999974772413585ULL,
11191718324395673746ULL,
5293216666010209768ULL,
11760393922366610529ULL,
505172698323928814ULL,
9942580208356683160ULL,
12407545700111804674ULL,
2102395425312436973ULL,
16966062287010644749ULL,
6364975572501938982ULL,
11411085932076284862ULL,
10424236436870678051ULL,
13966310405599776871ULL,
2328871106231838244ULL,
1378680973804076623ULL,
14859971753385412708ULL,
15691716086439804087ULL,
7519553577929664460ULL,
460638964809724379ULL,
18346923196617292268ULL,
6562793443469826132ULL,
1580997072160885165ULL,
859005579845670993ULL,
15387787899692562424ULL,
15066929237798940388ULL,
14509772897067631359ULL,
9722885996444150946ULL,
3784640730692549981ULL,
15931797558562408746ULL,
17728532885004413945ULL,
5877026246039211124ULL,
9823170296600362018ULL,
12063115411652128397ULL,
4036482174343220762ULL,
11995118481713087914ULL,
12472271790989499929ULL,
14327130824154426887ULL,
14241938299045681464ULL,
1637614953354483776ULL,
1768420517056302872ULL,
12383262458672579103ULL,
4469119677486524438ULL,
6862084742702193339ULL,
2666591392741323510ULL,
1958911907595193257ULL,
2078226524874004819ULL,
9182514826368667184ULL,
12779288295799455805ULL,
11485631769479599801ULL,
7984583406477441100ULL,
5152724216922222472ULL,
16434817050700023809ULL,
18234510019709827509ULL,
4838452819165657451ULL,
10009107659229344338ULL,
14082648967264690522ULL,
9603180932220791817ULL,
17494196096204240005ULL,
7192165871822020282ULL,
9489155661644977250ULL,
4293149567017494192ULL,
6266031685674981260ULL,
3297360663327026118ULL,
11022523844556058157ULL,
1848411117523063487ULL,
4803542876947788811ULL,
11932736566254486873ULL,
3918859449562378630ULL,
7730455268829558643ULL,
2300310138214025757ULL,
5073098731442674389ULL,
16579416859534749813ULL,
13327030148229826424ULL,
2481833961960165662ULL,
3483465760582650171ULL,
14647584793672228655ULL,
15832567204901745934ULL,
3683901813415452623ULL,
11860503814910655190ULL,
12166547435894244330ULL,
11567973332241571036ULL,
9797215346402413073ULL,
1263269478536931145ULL,
11026752283992642452ULL,
12676928707863290380ULL,
7280608515770959015ULL,
7790930297845911262ULL,
13387369097968848820ULL,
11741684142390913187ULL,
8900403996915095151ULL,
8816891275549542045ULL,
17970260734629539600ULL,
17214461913506212373ULL,
3119849171172694992ULL,
7662494604586420558ULL,
149203013753700084ULL,
5530308158539891708ULL,
4143436129840869576ULL,
15035120613856864378ULL,
17420391663083337065ULL,
10122251552433275289ULL,
6707891355510602429ULL,
5715986277202524800ULL,
18053537085616071129ULL,
4600951196636466039ULL,
13853232418390755104ULL,
9065747437067558111ULL,
9545093663071697752ULL,
2592076422926394627ULL,
228032410479194937ULL,
6667480117540136779ULL,
588648581915253038ULL,
16109793598716311100ULL,
3634608293302267354ULL,
1202024298738736502ULL,
6299068367672194603ULL,
1932346445954743183ULL,
7573861666572117031ULL,
18384928506924659011ULL,
3549459440654955014ULL,
8158286332358861718ULL,
10776371282861455089ULL,
17930787456663004470ULL,
14483524995628130770ULL,
8464707252757847009ULL,
397230465775035974ULL,
13489606539521972333ULL,
675316509725923312ULL,
2628613740627889320ULL,
15914532455247542225ULL,
5345232712238813773ULL,
13670086066823634667ULL,
3062009004852183467ULL,
16065515842120794365ULL,
74184876899443393ULL,
16563765655732577159ULL,
9131956796466541322ULL,
8604540880985875509ULL,
22099178757704754ULL,
16690920901523858194ULL,
11331521809212514546ULL,
2945473010562318822ULL,
15182352039751412520ULL,
2789803412788518275ULL,
13422792374992604543ULL,
15567727576646958478ULL,
1017933909609308228ULL,
16309966615540910654ULL,
8230916861376446652ULL,
14396504241698491859ULL,
8983610917420146076ULL,
8543542228473779244ULL,
1721876046845854392ULL,
16194459883656067231ULL,
5559864569757380000ULL,
4937681992884682033ULL,
13005489746079912805ULL,
9379902043379058579ULL,
5670390740934713304ULL,
2219071780988037499ULL,
7008521987288882964ULL,
6028345117330418825ULL,
10946567170512804608ULL,
7071075452076274675ULL,
16842568984047522312ULL,
1445978213955986826ULL,
10467709131392737444ULL,
951333080223670799ULL,
6099155138413436065ULL,
14140843974652577825ULL,
12209974622899604911ULL,
15533845830470436847ULL,
16381003300289283813ULL,
14619566180652406020ULL,
1340472571717533606ULL,
14798380781942060739ULL,
12690176289563455943ULL,
4461163794677446508ULL,
12598027068668226835ULL,
3341940384398866564ULL,
13564145691162448073ULL,
3829921822543532494ULL,
899996630714791418ULL,
6478536468284266291ULL,
2994597028103565543ULL,
6124895672834828926ULL,
10070201468809780037ULL,
14034091836647305274ULL,
10722043131897179970ULL,
728866099714851926ULL,
339635816873858970ULL,
17293171257415384160ULL,
17854528813163386564ULL,
11296654129530459363ULL,
8700134485486622004ULL,
12894110748725224554ULL,
17148226315594415145ULL,
8749621007278605595ULL,
12313167596287644540ULL,
4199955888901663150ULL,
13105311278491538903ULL,
18206853885491773239ULL,
8106773277103211697ULL,
16217424015630281360ULL,
5930619164422717276ULL,
4368075505682949467ULL,
4623369983466747106ULL,
8403817438537116875ULL,
13118988004869881546ULL,
1151085119119418028ULL,
6933250016240323664ULL,
6814675599201764477ULL,
15451253908724655102ULL,
5778917359701360712ULL,
11112271228158943598ULL,
9234396265040989002ULL,
10660000026621187831ULL,
4025584697920591189ULL,
5446500518121291045ULL,
10580078819325063104ULL,
18093856480622414774ULL,
8290028954029701554ULL,
9359194341002304104ULL,
7234639242841923679ULL,
2860911103167493259ULL,
14729974056387769779ULL,
7444204691177324181ULL,
8012224255291120002ULL,
6549509778060988165ULL,
13790479014885986647ULL,
16914047268224035561ULL,
4993489137437819341ULL,
4727924503904151836ULL,
15266142735205863280ULL,
7858325008468642462ULL}
;
NIM_CONST TY89006 Table4_89023 = {6561287832113134677ULL,
1893413629145602549ULL,
12241423297023873018ULL,
7334764389497132503ULL,
421942495471316930ULL,
9361514122259283269ULL,
5948965432456907277ULL,
11573866571256030207ULL,
4831763938021002582ULL,
14173855499281032303ULL,
5678704711006605406ULL,
4536654317168965104ULL,
802439540090739142ULL,
1728614842704535657ULL,
7852250862810361152ULL,
15476660523196402343ULL,
6999787169451700297ULL,
327545298748531618ULL,
15682530895364148274ULL,
9213801181845131435ULL,
12496725194737746507ULL,
16259867463176200084ULL,
15345880568547961059ULL,
18251822138640095379ULL,
2629011484744925146ULL,
679658461659738748ULL,
15377935326821115525ULL,
2845612796809381245ULL,
10724645847535636471ULL,
7273530125705028225ULL,
4410076014410041819ULL,
16142531744609233649ULL,
18400807702465453034ULL,
12734021026892126223ULL,
8922873767131958175ULL,
15064444873285696908ULL,
15209927617758412081ULL,
14409996395411159111ULL,
5226125132195873799ULL,
2940247444995640068ULL,
14028725908667580799ULL,
6671397049608501367ULL,
8821388386505911040ULL,
14866556336909964964ULL,
16999697712800573186ULL,
2147098610462912262ULL,
16490478192134913802ULL,
15589826239460328034ULL,
5141735866072457044ULL,
3265027362719053310ULL,
11995823427747035680ULL,
6017965846669640613ULL,
4287051124723328232ULL,
8655371236021312991ULL,
17289896101590403443ULL,
2365060307249772354ULL,
1630631832073154105ULL,
1828719980936758421ULL,
2674037562503248056ULL,
11151127292458434926ULL,
17083602979237295729ULL,
204405347605452144ULL,
5797523068258732423ULL,
8122903338174012641ULL,
8739821670855295734ULL,
961841682317282412ULL,
3487881148722869326ULL,
10451359914320687899ULL,
7665614591556333409ULL,
10615335048481936743ULL,
17623836910915152341ULL,
16755608983150617741ULL,
3797048810173566205ULL,
15867839772959253853ULL,
15036032900410842080ULL,
577633178325057199ULL,
11067531136919120693ULL,
9410969925345319376ULL,
2754939666238358593ULL,
8444132705799138470ULL,
10552522441266611941ULL,
3065464070595795438ULL,
11836294715923403837ULL,
3184382822055416328ULL,
5740274767717360273ULL,
6179930651821454089ULL,
13620591815564702195ULL,
5115645765347262247ULL,
4602739923119569497ULL,
14980942922478280335ULL,
12087144524938010904ULL,
16520591415739429341ULL,
9977754778323748670ULL,
11946163567554916583ULL,
4125629484990072616ULL,
11612073089940694572ULL,
13601564719816443589ULL,
4230689665262407186ULL,
16597059646647655223ULL,
9047540561879224854ULL,
1112218670439199625ULL,
8426162753992594376ULL,
12455974392228691485ULL,
15942953649737145623ULL,
4028912247909671416ULL,
18037587660758276778ULL,
10068912122063836921ULL,
17294173404640996964ULL,
12119325820894234776ULL,
14721184867647846348ULL,
1964465731879646024ULL,
16004983352460288019ULL,
6946242362685775318ULL,
15147764321093464775ULL,
11210460518370038227ULL,
17027551023089054838ULL,
18353008346233291053ULL,
12541344992679135386ULL,
2507248404937789251ULL,
7581261321693772141ULL,
9610178040610218018ULL,
520172056875071564ULL,
3738403388662150470ULL,
16089237235933099576ULL,
13444004222476132682ULL,
930169001927683533ULL,
6889748805645999668ULL,
17415394646893863865ULL,
7941113837267854943ULL,
17203533056638157852ULL,
16292115423603831981ULL,
6332043450707792835ULL,
3386824618901547762ULL,
7130458179308482168ULL,
1271522336860346025ULL,
17449709749372114003ULL,
4823850509807911142ULL,
3107332511049695348ULL,
5437793788182680416ULL,
10131116070914134461ULL,
1494290439970088554ULL,
9837305513065677719ULL,
10238790748255110929ULL,
13014122770789771601ULL,
1159256241058966379ULL,
1026141471931805870ULL,
10231135287654865684ULL,
17837053010959982172ULL,
7511556330643118785ULL,
14530951735809871833ULL,
3932170512244996561ULL,
6834333685245251200ULL,
4355290964656419152ULL,
6487547078612259600ULL,
6267880520331323438ULL,
16901268206404951963ULL,
8190919284549556346ULL,
3366895789332200348ULL,
2444540809879438627ULL,
6459524513146455969ULL,
4077716903750958194ULL,
12277814504276850140ULL,
11473260408293916814ULL,
13249302657669755564ULL,
7734160491610189202ULL,
7910254887717195099ULL,
3836881802794822270ULL,
8311228008842563790ULL,
730509642500215940ULL,
17796343913904606621ULL,
13322520308326068757ULL,
3579688877020158541ULL,
8591780283260295173ULL,
5028082178778891827ULL,
17947929312755564086ULL,
15737034618683411560ULL,
5487541034902828271ULL,
8530400576707172340ULL,
10842208886204497163ULL,
17577087322588800898ULL,
4656569414526204412ULL,
491061932033469878ULL,
8035458231926703496ULL,
137019260109594401ULL,
7421708309958176805ULL,
8223709417363553275ULL,
5401705824239018731ULL,
11284135823146617054ULL,
5308870500428712900ULL,
12937794336414209978ULL,
1376856236535589493ULL,
12790835156597546584ULL,
11346069089450335244ULL,
1332977380922036690ULL,
3015788518022419172ULL,
11727889587379563708ULL,
6396540069380292132ULL,
2034188120276215631ULL,
16791609835598348582ULL,
17937002894199062475ULL,
3623665942510192329ULL,
9281808803060841315ULL,
1765784450088366494ULL,
5837777785993897047ULL,
1564973338399864744ULL,
15841348874649115855ULL,
4964475598524693274ULL,
13134700095219650201ULL,
6706291041494563888ULL,
17656797450059587882ULL,
10355440293737830067ULL,
7456716478970921562ULL,
18111480716034354357ULL,
9931395181607471617ULL,
11397947510903519547ULL,
18213715995450361897ULL,
284725780453796946ULL,
14614670887385324978ULL,
13525508979215740547ULL,
13357650568845892272ULL,
12839204429038201151ULL,
9535062457613112024ULL,
13702844559136150558ULL,
10782422547259353446ULL,
13847462387142919467ULL,
2560491659082246267ULL,
8971180328015050686ULL,
2265540171276805379ULL,
6093561527083620308ULL,
12169565841013306ULL,
9128413284208255679ULL,
14268022017174275008ULL,
9486595659187961990ULL,
14229791298934897290ULL,
13071773666531600249ULL,
11777955427119840489ULL,
15499833483678125794ULL,
9771890684304357024ULL,
10910763655887102767ULL,
12331386150595254155ULL,
10380906726741623612ULL,
10959706799060127120ULL,
16385370526716955323ULL,
12663551718386818228ULL,
7153300451507295513ULL,
9667256041923175882ULL,
2187906506867626476ULL,
5612681432830855607ULL,
13793523891730566065ULL,
4688837593722596333ULL,
14631077022245992099ULL,
16667000290047189060ULL,
14796252507804280846ULL,
13917690577461137509ULL,
14425632076328529814ULL,
14096329984509715743ULL}
;
extern TFrame* frameptr_17042;

static N_INLINE(void, nimFrame)(TFrame* s) {
	NI LOC1;
	LOC1 = 0;
	{
		if (!(frameptr_17042 == NIM_NIL)) goto LA4;
		LOC1 = ((NI) 0);
	}
	goto LA2;
	LA4: ;
	{
		LOC1 = ((NI) ((NI16)((*frameptr_17042).calldepth + ((NI16) 1))));
	}
	LA2: ;
	(*s).calldepth = ((NI16) (LOC1));
	(*s).prev = frameptr_17042;
	frameptr_17042 = s;
	{
		if (!((*s).calldepth == ((NI16) 2000))) goto LA9;
		stackoverflow_19801();
	}
	LA9: ;
}

static N_INLINE(void, popFrame)(void) {
	frameptr_17042 = (*frameptr_17042).prev;
}
NIM_EXTERNC N_NOINLINE(void, HEX00_sboxesInit)(void) {
	nimfr("sboxes", "sboxes.nim")
	popFrame();
}

NIM_EXTERNC N_NOINLINE(void, HEX00_sboxesDatInit)(void) {
}

