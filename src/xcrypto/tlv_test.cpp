#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <common/base58.h>
#include "xcrypto.h"
#include "ringct/rctTypes.h"
#include "tlvserializer.hpp"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_core.h"
#include "string_tools.h"
#include "ringct/rctSigs.h"
#define RR(x) (rand()%x)




void rctsigForTest(rct::rctSig &rctsig) {
      std::string blob="02000202000bf28701969803befc01a64fa92c32fd02dd011b4809d029f06c765d7e0995c9948b20b42a8b192c37de4a9ee04b6fdf673d45e316a602000bc666ba9c0298bd01d9068a029a8b018ba401860dd918032e760eb40d7242a8168c91c2e2d860145c5a83f2ffcfa6cdcc0b97db05f0ae3588020002e16e8a6b0dc56757e327f6d1b1f6bce047c2257e29251876add99b8956c6bf200002585752b03393c6ae30726a51431cf1d9e6dac206a4bab0535a43ff3d589b4ea72c020901c98df59ad654002d016e4ccfaa013ee9383f2725b11799ffa15f914456ade60bc6abbfa2c7f7d790a50490eafe426623b4dd0a4d75eee11814e168e1058a16ddaff6ddee2ceef0bf07fdb5b38326c5cfc379a6979f295588d49f977c3728907d07c3c8d127cbdf3215a8bccf81a6e64351a5ac85a1e7276653c2fc73c4210195647eb6cd4f4069772856993834342b7f690f59eed1f301f283e8b14405363f6b6165b145168b27067b5c0d818eed9a30cccde64992e54173e93dead100cf7055c57232820320b96461891139e66ce1db32c619a60f2025bfc8c548541e83983bb482fa82c45c48b4eb97d6209e84a5f0cb162b89bba6faa6ec4e902584e90ed66c860c3aefc2ab1b0cf313322301d7e8f3708fdc0c3357a96c90001cbd030413bca9af218a7b338f545ce41207a569bc2782a287579c540bc5512fa1df160c070e8c4d421ba587014396c7b6a4d2d8f712e36b1e77ab6c7a7af392323730de47076f2b793683ed05185a84f709f68e2d690cd23f173c34644a0d671e6b2c4f11f8d7f6e2daab96fd7af323c6ee151726160e4909ca8daf41eacfca18284b7ae0a739997085ca3edae4626e071f4fedce3932d588d3b50a3243ad477363c954f4528c36c85da0f9d2bc9717d1dcc8c32d87dae876828d7a0efb613692165378fd4a0aa4c991d3fb8d43ddc09ae38fe997a639021ad59809655e07822f800a294b56432f98804f3cfcaf8e01b0754f6238edfb2a3acdccd9ce0d467c77002f6e2407b6568f296b10a8d1013f2678318696d0e8ee789a8068d58132b3d23cf33ebfa1aef046121dafb1ab0b413f9af87e2fa5d778ff1672ea5a4cd35816dcb3a785e59a6bd083d81492bd6eabba028453d9f135ecd89eed568986570c2e2d5ede91933a0e619c330e2e4115eb6d058bebf325488a41e0baf244079506f49a143c557ec1e91c8453be0d937940612f0f12791bbf88b792997ba1992f5cccad2966f76acf789a52460ff1849068528f5703c06776003e7986b83377f1cedb990e18f1b9931a749bbc369277d2fc5d19ff815c61c28868437ccc6e5e27e357227785086e759d97bf74dd6d7764a33f81a8a0877a4d390937c531eefdedbb4ee7353d4905040a261a96e8505eec140dd99bc08be9feb8ab19eca1fa0a595671666f656b01fd8f60033729870acc31d32fb7a5592f869d2f697c80f0e1f8c3826f85559406b0ebd47583a3ad53b2c5e81c9dd57db73c6edc4607832396f1f4ea90600d2f038d10c7b11cd3e490d32caeb0d6d8a7621f2cd7356ffc0378e6e706eeb4dcc80cdb28fd9f00488191bee2263995c447688b755c6ed311df1d04177ff064ecc90a15b5176ee4624259aea0259ed3b21f7a62dc40d3afeef57321cd4caf007fbb078b29beecfb269c92ed44d995f2340d21cf8b308f4a7359741c1702999c8cb00b5f829dfb14dc6a5322b3b2225519f888d2623a8a71f7d02dfc5217917b5e5408cca9dfbfd690d6be02706e539d0e1adefbc861bf7b1ec326a0d301557600c10867aa00b4dc7c5c819cfd888ebea6dd421f50ffab5275b46845166d59b78167075e1259fa6088a8e69e1657c4614773a2323be77fae59d67d920989bece554305696b91d3bd87dc054cc9fa9b67bb9cb5aad0ba68f7202f5a57141d730a43f707ff6f07493bbaa2dd4a1b875e1ae171a87678c0c51f1dc56fb9b1dad531b88403c847078f863fb9efd9ba55ba57821fe4e96566d2e8fc2ca28dc20d928ddf0907df73ba3960b13e17918d8ba08bbfad13bd40b190ee9662ee5ba2d82c5ed5e70a4ae985bbe2d05c141a9a9a68c99d6e44be113fbd158e3f18674bad5f101e810c2acd98b64ee1675eb122a6d19fab9ddb6e52096b53e8bb03ed4ec06ab55f3e0a633fc00b33fc5bb4e91308065899531ee9366cdf0c392520234866fa7e5c1b0000fb5ecb25e9504e631b51d6b04f39c10145bd105e1a54f170cedc8e188ef20a865245a3da0a41028da0e936bf2ae50b2a677363f00f6ffbcc2e79ecf284ad065cac81d78877264e736fdbcb3b901d01f8733c30175eaecddc81d13b6238a101ed8faa8b51d710c35c3e6667e77376c990fae88bad4e7bce336abe6678b0a60f4a4b14da38fd62320fd2ce10c2139293850a4224d0266c8aa925fe1a6bc178061c9cbd1b1f0a0f1d93654f7aed566e77e636c3e51dde45aa9d5eb551ef609e090a3186b128926e9e0eb312c53142b18f60ba8599e24684a1bc5246be7a86f80813a89af5f38d8b17cd508c4cb2173697aeb23b704f078c442b721aa713c34809f6369c5b253c09866cc370a21bd1c776de7ff3dc83313392cd3741be7387e7033a2a45491bbe76eaecbc640ef8048323fe056f362705288bc606dd7dbbd41e09628217cb73aee63b97d624752340f011cde10f947532bb42aa3dd8ff639e970aa5e0d679b0aba29057ae7e3f9892311fd26a34f34862e72d55fda84db4ade10ea02fab4f6d1e2055619bcc696b980966106576e16e8bea66588c81398fe5e302a570b7ba4137be56437cd7f3e1b79e2783e7e9f2f5313e7b20f705e14dbf480801d5d60b45bed35b78a1d24c6e0820d7849323afac56b88509f2a050af8a830e7a3d2c7dcfc51bdfd13c3ce7b9f0dd67f0a6dd87941fffca344f2f2e982cab066754d22db9a0859a79636bf679eb8822aa11a81e7510624395aa4eaa94fcac09ed9a8b1fbcd385e72706f7d043650722398fa6e94f2994efae1bcd64d553350e7a5e346b498b08f217b37314013b7355bad9cf2ff3a063e4b2962057b86aaf01b73f30ace6e20d1d6402dbffe05e053046e9ad1bd095877153b26290983e7f0c2e55a7f0a83d6569e110444f84f2e79c56fbbc44159d2f1c04b291fa27341a078e24c1701fb9e031c78591f717a1e3faf024b49c0c685cd3bcbddf4ca19f2805f0c29cc3470f94dcda18b5e3cbe1bec892b633a54994a73fc5083aba5ed98603873a50b23bc2e3ed486cab83c612bc7bc943b82b0744f2849639f11789c63907495a80fccb670da171ddc21befc169cebe45bd8cb2b28e0a99d2cb00af751a097c453f220b9e4de474ef4e2443214707727b7e0825b96177261cb3bfdaa2d90955246206cb3598c365410e1c462df41eeefec1b4aa347e0e5204f4e613816d0d61789c0472886b4a93e3cf53fda42f6a81a22c96a4f78104e8e4a7ef4baa840931d501ae8e06dfd216c204350df8f95bc69eb3e473c3553112a660bc26f9b4079cef8a2152d4109aeb4268fcb6cab98834c628c878271a086609e2716cea5c0a6e16f915e0c5c45f1569f201de7e28e6d667bf261cc8669a2b6cc228e312f3f7229e3884291a9af85ec085131db25ed24c84042432332a6eb46ee5827ceb70a3";

    cryptonote::transaction tx;
    std::string tx_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(blob, tx_blob)) {
        printf("parse_hexstr_to_binbuff fail\n");
        return;
    }
    bool parseres = cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx);
    printf("parseres==%d\n", parseres);

    unsigned char mes[32] = {25, 15, 184, 52, 135, 221, 0, 36, 2, 123, 121, 179, 196, 164, 211, 38, 206, 125, 82, 57,
                             123, 84, 128, 216, 22, 67, 176, 231, 151, 51, 179, 58};
    memcpy(tx.rct_signatures.message.bytes, mes, 32);
    unsigned char mm[2][11][2][32] = {
            {
                    {{191, 106, 61, 16,  27,  205, 154, 179, 20, 74,  153, 245, 60, 147, 226, 119, 91, 87,  96,  247, 21,  79,  251, 241, 188, 61,  206, 122, 110, 222, 72,  99,}, {224, 99, 57,  131, 42, 137, 71, 62,  118, 246, 63,  141, 83, 195, 40,  70, 234, 7,   145, 208, 182, 171, 44,  28,  231, 35,  153, 213, 163, 50,  207, 226}},
                    {{139, 77,  189, 180, 37,  241, 187, 94,  61,  232, 71, 9,  170, 120, 192, 233, 1,   8,   189, 2,  56, 23, 195, 217, 134, 162, 255, 154, 80, 128, 88,  167,}, {173, 190, 4,  158, 54, 219, 41, 106, 233, 135, 113, 115, 236, 142, 133, 155, 78,  184, 197, 227, 200, 78,  39,  250, 250, 142, 111, 42, 79,  109, 239, 57}},
                    {{210, 102, 211, 101, 247, 92, 184, 222, 202, 163, 13,  218, 88,  164, 123, 242, 89,  152, 133, 216, 214, 124, 137, 174, 3,  28,  23,  51,  87, 134, 154, 2,},  {195, 188, 86, 161, 255, 169, 204, 219, 75,  208, 130, 148, 28,  206, 17,  148, 156, 96,  64,  194, 25,  155, 228, 119, 103, 59, 247, 117, 177, 95, 51, 137}},
                    {{11,  1, 173, 171, 65,  114, 209, 100, 196, 217, 56,  187, 165, 196, 209, 46,  115, 66,  104, 253, 134, 72,  47,  157, 185, 118, 220, 2,   217, 116, 215, 94,},  {56,  201, 82, 79,  207, 129, 22,  96, 118, 41,  219, 9,   103, 10, 3,   109, 47, 195, 235, 52, 84,  255, 74,  212, 203, 33, 162, 206, 219, 85, 229, 183}},
                    {{49, 119, 211, 36, 87, 40, 124, 88, 200, 135, 252, 185, 2,   175, 111, 41,  38, 159, 216, 111, 28,  139, 105, 80,  9,  195, 91, 65, 50, 34,  56,  218,}, {61,  24, 113, 42,  22,  146, 152, 244, 127, 71,  149, 242, 184, 52,  147, 21,  219, 33,  198, 42,  45, 138, 238, 225, 86,  185, 44,  196, 76,  133, 163, 0}},
                    {{3,   103, 53,  107, 59, 21, 167, 252, 164, 0,   212, 26, 176, 163, 76,  133, 23,  73, 94,  13,  34, 62,  4,   213, 50,  136, 39,  26,  237, 194, 10,  170,}, {6,   9,   18, 202, 0,  161, 249, 221, 23,  41,  6,   199, 236, 200, 177, 32, 206, 181, 186, 4,   184, 188, 13, 189, 16,  3,   120, 29,  209, 185, 208, 250}},
                    {{224, 113, 124, 72, 210, 71,  82,  70,  134, 182, 40,  155, 163, 173, 131, 12,  119, 56, 166, 192, 239, 43, 144, 189, 223, 145, 132, 188, 242, 153, 62,  172,}, {17,  199, 75, 38, 219, 220, 31,  135, 137, 64,  76, 55,  109, 148, 98, 214, 49,  166, 92, 40,  33, 73,  119, 228, 125, 210, 85,  122, 52, 33,  56,  194}},
                    {{47,  125, 54,  39,  93, 85, 193, 230, 197, 198, 129, 229, 95,  83,  71,  83,  23, 166, 89, 207, 125, 48,  235, 236, 61, 203, 30,  1,  230, 72, 200, 135,}, {46,  102, 164, 13,  15,  16,  81, 194, 150, 165, 158, 20,  118, 126, 192, 191, 143, 155, 162, 164, 254, 4,   108, 12,  234, 237, 30,  66,  170, 220, 240, 165}},
                    {{28,  119, 123, 243, 165, 20,  4,  32, 229, 13, 217, 25,  83,  18, 68, 71,  181, 246, 48,  21,  194, 80, 83,  92, 31,  60,  234, 170, 210, 67, 1,   155,}, {86,  223, 17,  236, 251, 100, 5,  19,  218, 8,   185, 107, 171, 195, 142, 245, 217, 202, 8,   154, 214, 26,  174, 178, 26, 245, 42,  164, 152, 159, 64,  4}},
                    {{120, 163, 243, 180, 139, 203, 12,  177, 184, 45, 252, 86, 181, 16, 154, 169, 171, 147, 145, 122, 162, 198, 231, 212, 200, 80,  143, 156, 218, 169, 232, 184,}, {197, 206, 204, 189, 222, 4,   169, 178, 164, 209, 255, 26, 135, 218, 183, 86,  19, 217, 179, 234, 177, 67,  28, 181, 38,  35,  193, 64,  74,  203, 140, 77}},
                    {{220, 145, 117, 210, 42,  173, 189, 127, 220, 9,   197, 113, 151, 121, 124, 151, 230, 37,  244, 147, 44, 108, 194, 152, 82,  135, 125, 170, 83, 145, 53, 182,}, {32,  165, 59, 6,   170, 141, 121, 224, 241, 46,  75,  213, 187, 230, 93, 166, 153, 90, 219, 68,  45, 231, 178, 228, 122, 34,  43, 133, 29, 252, 241, 7}}
            },


            {
                    {{115, 226, 61, 109, 227, 250, 2,   112, 90, 140, 86,  81,  26, 174, 241, 154, 47, 231, 137, 122, 120, 238, 234, 220, 236, 219, 50,  154, 39,  177, 122, 6,},  {72,  33, 192, 16,  86, 250, 1,  157, 76,  176, 231, 49,  89, 135, 103, 29, 2,   239, 105, 254, 160, 43,  248, 219, 81,  237, 251, 148, 180, 105, 39,  25}},
                    {{176, 221, 118, 108, 183, 83,  221, 127, 242, 146, 30, 39, 176, 162, 233, 82,  138, 245, 147, 98, 13, 35, 137, 194, 96,  176, 209, 188, 10, 18,  117, 181,}, {204, 31,  27, 222, 33, 246, 87, 202, 235, 53,  102, 74,  75,  1,   158, 163, 237, 31,  95,  227, 249, 186, 221, 210, 249, 160, 110, 13, 253, 133, 8,   200}},
                    {{17,  139, 231, 160, 130, 57, 92,  71,  14,  72,  142, 99,  102, 201, 49,  229, 180, 107, 134, 202, 168, 186, 101, 156, 79, 149, 167, 216, 72, 70,  183, 80,}, {229, 19,  71, 242, 30,  91,  215, 141, 230, 243, 74,  121, 146, 118, 100, 92,  150, 201, 171, 128, 219, 203, 190, 98,  94,  90, 4,   14,  186, 52, 18, 62}},
                    {{237, 4, 226, 33,  232, 81,  213, 204, 76,  164, 151, 195, 158, 255, 247, 190, 22,  161, 225, 63,  195, 161, 231, 119, 26,  2,   98,  103, 156, 255, 247, 241,}, {173, 119, 64, 116, 17,  240, 128, 10, 116, 227, 192, 228, 112, 28, 249, 246, 74, 46,  76,  16, 209, 238, 133, 205, 235, 67, 153, 160, 113, 4,  146, 205}},
                    {{55, 129, 166, 8,  80, 80, 115, 44, 60,  227, 229, 67,  218, 74,  179, 126, 70, 209, 162, 40,  194, 185, 53,  103, 64, 5,   71, 28, 7,  240, 155, 128,}, {123, 21, 184, 174, 209, 211, 220, 12,  205, 255, 213, 98,  136, 173, 179, 112, 253, 194, 9,   240, 49, 27,  21,  83,  169, 206, 246, 152, 217, 250, 43,  91}},
                    {{117, 91,  215, 207, 65, 46, 252, 214, 87,  204, 246, 72, 204, 40,  157, 41,  106, 43, 162, 139, 44, 130, 166, 188, 104, 69,  134, 232, 68,  137, 211, 29,},  {191, 186, 89, 19,  22, 164, 126, 128, 151, 107, 153, 41,  234, 239, 164, 98, 175, 174, 221, 250, 2,   98,  90, 141, 126, 115, 220, 223, 224, 244, 135, 17}},
                    {{199, 57,  137, 55, 39,  212, 164, 114, 133, 188, 245, 68,  191, 99,  112, 148, 151, 68, 155, 187, 110, 10, 157, 67,  41,  54,  142, 5,   49,  73,  145, 187,}, {167, 51,  65, 19, 173, 0,   186, 204, 186, 207, 12, 129, 149, 206, 20, 28,  100, 228, 17, 146, 30, 139, 248, 140, 76,  134, 115, 69,  4,  208, 242, 140}},
                    {{160, 137, 245, 131, 0,  63, 85,  99,  108, 215, 95,  236, 134, 187, 174, 107, 87, 237, 59, 98,  66,  120, 113, 188, 73, 107, 232, 57, 3,   75, 52,  13,},  {111, 163, 46,  235, 215, 246, 45, 121, 175, 177, 170, 107, 230, 81,  189, 225, 212, 53,  116, 176, 92,  167, 192, 138, 216, 48,  203, 216, 156, 4,   84,  58}},
                    {{137, 41,  126, 171, 48,  231, 34, 43, 86,  77, 218, 202, 122, 14, 62, 181, 22,  186, 157, 186, 149, 73, 131, 11, 187, 247, 53,  157, 31,  90, 232, 52,},  {129, 0,   224, 239, 84,  50,  73, 109, 189, 125, 161, 177, 77,  218, 240, 192, 108, 69,  188, 159, 88,  111, 81,  30,  54, 25,  105, 145, 100, 43,  247, 66}},
                    {{146, 156, 138, 46,  195, 113, 106, 124, 30,  8,  10,  30, 47,  58, 177, 102, 23,  89,  241, 26,  63,  23,  209, 193, 33,  231, 116, 180, 86,  234, 169, 40,},  {245, 250, 115, 119, 36,  105, 215, 24,  160, 199, 210, 80, 245, 13,  1,   229, 54, 145, 218, 51,  22,  211, 62, 146, 140, 186, 212, 175, 164, 112, 229, 11}},
                    {{141, 190, 151, 164, 205, 246, 60,  111, 167, 198, 230, 39,  16,  9,   44,  133, 146, 153, 240, 250, 14, 134, 238, 135, 102, 39,  30,  143, 66, 247, 81, 189,}, {160, 94,  18, 158, 51,  1,   68,  143, 186, 251, 196, 38,  179, 13,  54, 254, 214, 67, 99,  237, 75, 247, 94,  112, 110, 186, 24, 198, 93, 227, 236, 52}}
            }
    };
    rct::ctkey mkey[2][11];
    // tx.rct_signatures.mixRing.resize(tx.rct_signatures.p.pseudoOuts.size());
    tx.rct_signatures.mixRing.resize(2);
    for (int m = 0; m < 2; ++m) {
        tx.rct_signatures.mixRing[m].clear();
        for (int j = 0; j < 11; j++) {
            memcpy(mkey[m][j].dest.bytes, mm[m][j][0], 32);
            memcpy(mkey[m][j].mask.bytes, mm[m][j][1], 32);
            tx.rct_signatures.mixRing[m].push_back(mkey[m][j]);
        }
    }
    unsigned char ii[2][32] = {
             {208,41,240,108,118,93,126,9,149,201,148,139,32,180,42,139,25,44,55,222,74,158,224,75,111,223,103,61,69,227,22,166}
            ,{118,14,180,13,114,66,168,22,140,145,194,226,216,96,20,92,90,131,242,255,207,166,205,204,11,151,219,5,240,174,53,136}
    };
    rct::key iikey[2];
    for (size_t i = 0;i< tx.vin.size();i++) {
        memcpy(iikey[i].bytes, ii[i], 32);
        tx.rct_signatures.p.MGs[i].II.clear();
        tx.rct_signatures.p.MGs[i].II.push_back(iikey[i]);
    }
    rctsig = tx.rct_signatures;

    return ;

}

int xcToi(char from){
   if (from >= 'a'&&from <= 'f'){
       return from-'a'+10;
   }else{
       return from - '0';
   }
}
void sTox(char *from,unsigned char *data, int len){
    for(int i = 0;i < 2*len;i+=2){
       data[i/2] = (xcToi(from[i])*16) + xcToi(from[i+1]);
    }
}
void printKeyRaw(unsigned char *data, int len) {
    printf("{");
    for (int i = 0; i < len; i++) {
        printf(i == 0 ? "%d" : ",%d", data[i]);
    }
    printf("}");
}

void printKey(unsigned char *data, int len) {
    printf("0x");
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}
void printKey(rct::key &key) {
    printKey(key.bytes,32);
}

void printKeyV(rct::keyV &b) {
    printf("[");
    int len = b.size();
    for (int i = 0; i < len; i++) {
        printKeyRaw(b[i].bytes, 32);
        printf(",");
    }
    printf("]");
}

void printKeyM(rct::keyM &b) {
    printf("[");
    int len = b.size();
    for (int i = 0; i < len; i++) {
        printKeyV(b[i]);
        printf(",");
    }
    printf("]");
}

void printCtKey(rct::ctkey &a) {
    printf("{");
    printKey(a.dest.bytes, 32);
    printf(",");
    printKey(a.mask.bytes, 32);
    printf("}");
}
void printCtKeyM(rct::ctkeyM &a) {
    printf("[");
    for (size_t i = 0; i < a.size(); i++) {
        printf("[");
        for (size_t j = 0; j < a[i].size(); j++) {
            printCtKey(a[i][j]);
        }
        printf("],");
    }
    printf("]");
}
void printMultisigKLRki(rct::multisig_kLRki &a) {
    printf("{");
    printKey(a.k);printf(",");
    printKey(a.ki);printf(",");
    printKey(a.L);printf(",");
    printKey(a.R);
    printf("}");
}


bool keyvEqual(rct::keyV &a, rct::keyV &b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); i++) {
        if (!(a[i] == b[i])) {
            return false;
        }
    }
    return true;
}

bool keyMEqual(rct::keyM &a, rct::keyM &b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); i++) {
        if (!keyvEqual(a[i], b[i])) {
            return false;
        }
    }
    return true;
}

bool rctKeyEqual(rct::ctkey &a, rct::ctkey &b) {
    if (a.mask == b.mask && a.dest == b.dest) {
        return true;
    }
    return false;
}

bool rctKeyVEqual(rct::ctkeyV &a, rct::ctkeyV &b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); i++) {
        if (!rctKeyEqual(a[i], b[i])) {
            return false;
        }
    }
    return true;
}

bool rctKeyMEqual(rct::ctkeyM &a, rct::ctkeyM &b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); i++) {
        if (!rctKeyVEqual(a[i], b[i])) {
            return false;
        }
    }
    return true;
}
bool multisigKLRkiEqual(rct::multisig_kLRki &a, rct::multisig_kLRki &b) {
  if (a.k == b.k&&a.ki==b.ki&&a.L==b.L&&a.R==b.R){
      return true;
  }
    return false;
}
void createRandomKey(rct::key &a) {
    a.bytes[0] = 0;
    a.bytes[1] = 0xff;
    a.bytes[2] = 0;
    a.bytes[3] = 0;
    srand(time(NULL));
    for (int i = 4; i < 32; i++) {
        a.bytes[i] = (unsigned char) (RR(256));
    }
}

void createRandomKeyv(rct::keyV &a, int size) {
    for (int i = 0; i < size; i++) {
        rct::key key;
        createRandomKey(key);
        a.push_back(key);
    }
}

void createRandomKeyM(rct::keyM &a, int size) {
    for (int i = 0; i < size; i++) {
        rct::keyV keyv;
        createRandomKeyv(keyv, (i % 3) + 2);
        a.push_back(keyv);
    }
}

void createRandomctKey(rct::ctkey &a) {
    createRandomKey(a.dest);
    createRandomKey(a.mask);
}

void createRandomctKeyV(rct::ctkeyV &a, int size) {
    for (int i = 0; i < size; i++) {
        rct::ctkey key;
        createRandomctKey(key);
        a.push_back(key);
    }
}

void createRandomctKeyM(rct::ctkeyM &a, int size) {
    for (int i = 0; i < size; i++) {
        rct::ctkeyV keyv;
        createRandomctKeyV(keyv, (i % 3) + 2);
        a.push_back(keyv);
    }
}

int testKeyV() {
    rct::keyV keyv;
    unsigned char ii[2][32] = {
            {208, 41, 240, 108, 118, 93, 126, 9,  149, 201, 148, 139, 32,  180, 42, 139, 25, 44,  55,  222, 74,  158, 224, 75,  111, 223, 103, 61, 69,  227, 22, 166},
            {118, 14, 180, 13,  114, 66, 168, 22, 140, 145, 194, 226, 216, 96,  20, 92,  90, 131, 242, 255, 207, 166, 205, 204, 11,  151, 219, 5,  240, 174, 53, 136}
    };
    for (int i = 0; i < 2; i++) {
        rct::key k;
        memcpy(k.bytes, ii[i], 32);
        keyv.push_back(k);
    }
    int size = tlv_keyv_size(keyv);
    unsigned char *encodeByte = (unsigned char *) malloc(size);
    int encodeLen = tlv_keyv_encode(keyv, encodeByte, size);
    printf("encodeLen=%d\n", encodeLen);
    if (encodeLen == -1) {
        return -1;
    }
    //   printKeyRaw(encodeByte,encodeLen);printf("\n");
    printKey(encodeByte, encodeLen);
    printf("\n");
    rct::keyV keyv2;
    if (false == tlv_keyv_decode(keyv2, encodeByte, encodeLen)) {
        printf("decode fail\n");
        return -1;
    }
    if (!keyvEqual(keyv, keyv2)) {
        return -1;
    }

    return 0;
}

int testKeyM() {
    rct::keyM from;
    createRandomKeyM(from, 2);

    int size = tlv_keym_size(from);
    unsigned char *encodeByte = (unsigned char *) malloc(size);
    int encodeLen = tlv_keym_encode(from, encodeByte, size);
    printf("testKeyM encodeLen=%d\n", encodeLen);
    if (encodeLen == -1) {
        free(encodeByte);
        return -1;
    }
    //   printKeyRaw(encodeByte,encodeLen);printf("\n");
    //  printKey(encodeByte, encodeLen);printf("\n");

    rct::keyM to;
    if (false == tlv_keym_decode(to, encodeByte, encodeLen)) {
        free(encodeByte);
        printf("decode fail\n");
        printKeyM(from);
        printf("\n");
        printKeyM(to);
        return -1;
    }
    if (!keyMEqual(from, to)) {
        printKeyM(from);
        printf("\n");
        printKeyM(to);
        printf("\n");
        free(encodeByte);
        return -1;
    }
    return 0;
}

int testRctkey() {
    rct::ctkey from;
    createRandomKey(from.dest);
    createRandomKey(from.mask);

    int size = tlv_ctkey_size();
    unsigned char *encodeByte = (unsigned char *) malloc(size);
    int encodeLen = tlv_ctkey_encode(from, encodeByte, size);
    printf("testRctkey encodeLen=%d\n", encodeLen);
    if (encodeLen == -1) {
        free(encodeByte);
        return -1;
    }


    rct::ctkey to;
    if (false == tlv_ctkey_decode(to, encodeByte, encodeLen)) {
        free(encodeByte);
        printCtKey(from);
        printCtKey(to);
        printf("\n");
        return -1;
    }
    if (!rctKeyEqual(from, to)) {
        printCtKey(from);
        printCtKey(to);
        printf("\n");
        free(encodeByte);
        return -1;
    }
    return 0;
}

int testRctMkey() {
    rct::ctkeyM from;
    createRandomctKeyM(from, 3);

    int size = tlv_ctkeym_size(from);
    unsigned char *encodeByte = (unsigned char *) malloc(size);
    int encodeLen = tlv_ctkeym_encode(from, encodeByte, size);
    printf("testRctMkey encodeLen=%d\n", encodeLen);
    if (encodeLen == -1) {
        free(encodeByte);
        printf("size=%d\n",size);
        printCtKeyM(from);
        printf("\n");
        return -1;
    }
    //   printKeyRaw(encodeByte,encodeLen);printf("\n");
    //  printKey(encodeByte, encodeLen);printf("\n");

    rct::ctkeyM to;
    if (false == tlv_ctkeym_decode(to, encodeByte, encodeLen)) {
        free(encodeByte);
        printf("decode fail\n");
        printCtKeyM(from);
        printf("\n");
        printCtKeyM(to);
        printf("\n");
        return -1;
    }
    if (!rctKeyMEqual(from, to)) {
        printCtKeyM(from);
        printf("\n");
        printCtKeyM(to);
        printf("\n");
        printf("\n");
        free(encodeByte);
        return -1;
    }
    return 0;
}

int testMultisigKLRki() {
    rct::multisig_kLRki from;
    createRandomKey(from.k);
    createRandomKey(from.ki);
    createRandomKey(from.L);
    createRandomKey(from.R);

    int size = tlv_multisig_kLRki_size(from);
    unsigned char *encodeByte = (unsigned char *) malloc(size);
    int encodeLen = tlv_multisig_kLRki_encode(from, encodeByte, size);
    printf("testMultisigKLRki encodeLen=%d\n", encodeLen);
    if (encodeLen == -1) {
        free(encodeByte);
        return -1;
    }
    //   printKeyRaw(encodeByte,encodeLen);printf("\n");
    //  printKey(encodeByte, encodeLen);printf("\n");

    rct::multisig_kLRki to;
    if (false == tlv_multisig_kLRki_decode(to, encodeByte, encodeLen)) {
        free(encodeByte);
        printMultisigKLRki(from);
        printf("\n");
        printMultisigKLRki(to);
        printf("\n");
        return -1;
    }
    if (!multisigKLRkiEqual(from, to)) {
        printMultisigKLRki(from);
        printf("\n");
        printMultisigKLRki(to);
        printf("\n");
        free(encodeByte);
        return -1;
    }
    return 0;
}
int testEcdhTuple() {
    std::vector<rct::ecdhTuple> from;
    for (int i = 0;i < 3;i++) {
        rct::ecdhTuple item;
        createRandomKey(item.amount);
        createRandomKey(item.mask);
        from.push_back(item);
    }

    int size = tlv_ecdhTuplev_size(from);
    unsigned char *encodeByte = (unsigned char *) malloc(size);
    int encodeLen = tlv_ecdhTuplev_encode(from, encodeByte, size);
    printf("testEcdhTuple encodeLen=%d\n", encodeLen);
    if (encodeLen == -1) {
        free(encodeByte);
        return -1;
    }
    std::vector<rct::ecdhTuple> to;
    if (false == tlv_ecdhTuplev_decode(to, encodeByte, encodeLen)) {
        free(encodeByte);
        printf("testEcdhTuple tlv_ecdhTuplev_decode fail");
        return -1;
    }
    if (from.size() != to.size()){
        free(encodeByte);
        return -1;
    }
    for (int i = 0;i < 3;i++) {
        if(!(from[i].mask==to[i].mask &&from[i].amount==to[i].amount)){
            return -1;
        }
    }
    return 0;
}
int testRctsig(){
    rct::rctSig from;
    rctsigForTest(from);

//    printf("verRctSemanticsSimple=%d\n", rct::verRctSemanticsSimple(from));
//    printf("verRctNonSemanticsSimple=%d\n", rct::verRctNonSemanticsSimple(from));
    int size = tlv_rctSig_size(from);
    printf("testRctsig size = %d\n",size);
    unsigned char *encodeByte = (unsigned char *) malloc(size);
    int encodeLen = tlv_rctSig_encode(from, encodeByte, size);
    printf("rctSig encodeLen=%d\n", encodeLen);
    if (encodeLen == -1) {
        free(encodeByte);
        return -1;
    }
  //  printf("rctSig encode=");printKey(encodeByte,encodeLen);printf("\n");
    rct::rctSig to;
    if (false == tlv_rctSig_decode(to, encodeByte, encodeLen)) {
        free(encodeByte);
        printf("testRctsig tlv_rctSig_decode fail\n");
        return -1;
    }

    if (rct::verRctSemanticsSimple(from) != rct::verRctSemanticsSimple(to)){
        free(encodeByte);
        return -1;
    }
    if (rct::verRctNonSemanticsSimple(from) != rct::verRctNonSemanticsSimple(to)){
        free(encodeByte);
        return -1;
    }
    return 0;
}
int testRctsigSimple(){
    rct::rctSig from;
    from.txnFee=0xffffffffffffffff;
    from.type=0xff;
    int size = tlv_rctSig_size(from);
    printf("testRctsigSimple size = %d\n",size);
    unsigned char *encodeByte = (unsigned char *) malloc(size);
    int encodeLen = tlv_rctSig_encode(from, encodeByte, size);
    printf("testRctsigSimple encodeLen=%d\n", encodeLen);
    if (encodeLen == -1) {
        free(encodeByte);
        return -1;
    }
      printf("testRctsigSimple encode=");printKey(encodeByte,encodeLen);printf("\n");
    rct::rctSig to;
    if (false == tlv_rctSig_decode(to, encodeByte, encodeLen)) {
        free(encodeByte);
        printf("testRctsigSimple decode fail\n");
        return -1;
    }
    if(to.txnFee!=0xffffffffffffffff || to.type != 0xff){
        return -1;
    }
    return 0;
}
void bul(){
    hw::device &dev = hw::get_device("default");
    rct::keyV C;
    rct::keyV masks;
    // rct::keyV amounts;
    std::vector<uint64_t> amounts;
    rct::keyV sk;
    rct::key key;
    key ={59,173,27,112,149,59,198,233,243,11,237,185,50,159,46,83,39,91,225,183,137,12,66,59,133,65,187,13,248,171,85,7};
    sk.push_back(key);
    key ={36,173,90,206,188,160,166,80,251,173,97,206,160,31,217,251,142,12,154,59,120,35,2,253,214,248,226,249,89,238,204,14};
    sk.push_back(key);
    amounts.push_back(100000000);
    amounts.push_back(35075991376858);
    rct::Bulletproof bulletproof = rct::proveRangeBulletproof(C, masks, amounts, sk, dev);

    for (int i = 0;i < (int)C.size();i++){
        printf("C[%d]=",i);printKey(C[i]);
    }
    printf("\n");
    for (int i = 0;i < (int)masks.size();i++){
        printf("masks[%d]=",i);printKey(masks[i]);
    }
    printf("\n");
    printf("bp.a="); printKey(bulletproof.A);printf("\n");
    printf("bp.s="); printKey(bulletproof.S);printf("\n");
    printf("bp.T1="); printKey(bulletproof.T1);printf("\n");
    printf("bp.T2="); printKey(bulletproof.T2);printf("\n");
    rct::rctSig rctsig;
    rctsigForTest(rctsig);
    key = rct::get_pre_mlsag_hash(rctsig, dev);
    printf("get_pre_mlsag_hash="); printKey(key);printf("\n");

}
int testRctsigCompatibleWithGo(){
    char s[] = "01001c0a0100000002005403000050030200200095647eb6cd4f4069772856993834342b7f690f59eed1f301f283e8b14405363f030020006b6165b145168b27067b5c0d818eed9a30cccde64992e54173e93dead100cf700400200055c57232820320b96461891139e66ce1db32c619a60f2025bfc8c548541e839806002000d66c860c3aefc2ab1b0cf313322301d7e8f3708fdc0c3357a96c90001cbd03040b002000040a261a96e8505eec140dd99bc08be9feb8ab19eca1fa0a595671666f656b010c002000fd8f60033729870acc31d32fb7a5592f869d2f697c80f0e1f8c3826f855594060100400079c99414a5e10825ba75ef0003944cf15637267bb623737e4c38babf1750b1311a93e5a7d7f2c72fe710e9e3f2b24659f8f8cf8a361110b06bf765b14d3a2594050020003bb482fa82c45c48b4eb97d6209e84a5f0cb162b89bba6faa6ec4e902584e90e0700200013bca9af218a7b338f545ce41207a569bc2782a287579c540bc5512fa1df160c0800e0000e8c4d421ba587014396c7b6a4d2d8f712e36b1e77ab6c7a7af392323730de47076f2b793683ed05185a84f709f68e2d690cd23f173c34644a0d671e6b2c4f11f8d7f6e2daab96fd7af323c6ee151726160e4909ca8daf41eacfca18284b7ae0a739997085ca3edae4626e071f4fedce3932d588d3b50a3243ad477363c954f4528c36c85da0f9d2bc9717d1dcc8c32d87dae876828d7a0efb613692165378fd4a0aa4c991d3fb8d43ddc09ae38fe997a639021ad59809655e07822f800a294b56432f98804f3cfcaf8e01b0754f6238edfb2a3acdccd9ce0d467c77002f6e240900e000b6568f296b10a8d1013f2678318696d0e8ee789a8068d58132b3d23cf33ebfa1aef046121dafb1ab0b413f9af87e2fa5d778ff1672ea5a4cd35816dcb3a785e59a6bd083d81492bd6eabba028453d9f135ecd89eed568986570c2e2d5ede91933a0e619c330e2e4115eb6d058bebf325488a41e0baf244079506f49a143c557ec1e91c8453be0d937940612f0f12791bbf88b792997ba1992f5cccad2966f76acf789a52460ff1849068528f5703c06776003e7986b83377f1cedb990e18f1b9931a749bbc369277d2fc5d19ff815c61c28868437ccc6e5e27e357227785086e0a002000759d97bf74dd6d7764a33f81a8a0877a4d390937c531eefdedbb4ee7353d49050300780600003803010020000a3186b128926e9e0eb312c53142b18f60ba8599e24684a1bc5246be7a86f80802002000d029f06c765d7e0995c9948b20b42a8b192c37de4a9ee04b6fdf673d45e316a60300ec0200004000b0ebd47583a3ad53b2c5e81c9dd57db73c6edc4607832396f1f4ea90600d2f038d10c7b11cd3e490d32caeb0d6d8a7621f2cd7356ffc0378e6e706eeb4dcc80c01004000db28fd9f00488191bee2263995c447688b755c6ed311df1d04177ff064ecc90a15b5176ee4624259aea0259ed3b21f7a62dc40d3afeef57321cd4caf007fbb07020040008b29beecfb269c92ed44d995f2340d21cf8b308f4a7359741c1702999c8cb00b5f829dfb14dc6a5322b3b2225519f888d2623a8a71f7d02dfc5217917b5e540803004000cca9dfbfd690d6be02706e539d0e1adefbc861bf7b1ec326a0d301557600c10867aa00b4dc7c5c819cfd888ebea6dd421f50ffab5275b46845166d59b7816707040040005e1259fa6088a8e69e1657c4614773a2323be77fae59d67d920989bece554305696b91d3bd87dc054cc9fa9b67bb9cb5aad0ba68f7202f5a57141d730a43f70705004000ff6f07493bbaa2dd4a1b875e1ae171a87678c0c51f1dc56fb9b1dad531b88403c847078f863fb9efd9ba55ba57821fe4e96566d2e8fc2ca28dc20d928ddf090706004000df73ba3960b13e17918d8ba08bbfad13bd40b190ee9662ee5ba2d82c5ed5e70a4ae985bbe2d05c141a9a9a68c99d6e44be113fbd158e3f18674bad5f101e810c070040002acd98b64ee1675eb122a6d19fab9ddb6e52096b53e8bb03ed4ec06ab55f3e0a633fc00b33fc5bb4e91308065899531ee9366cdf0c392520234866fa7e5c1b000800400000fb5ecb25e9504e631b51d6b04f39c10145bd105e1a54f170cedc8e188ef20a865245a3da0a41028da0e936bf2ae50b2a677363f00f6ffbcc2e79ecf284ad06090040005cac81d78877264e736fdbcb3b901d01f8733c30175eaecddc81d13b6238a101ed8faa8b51d710c35c3e6667e77376c990fae88bad4e7bce336abe6678b0a60f0a0040004a4b14da38fd62320fd2ce10c2139293850a4224d0266c8aa925fe1a6bc178061c9cbd1b1f0a0f1d93654f7aed566e77e636c3e51dde45aa9d5eb551ef609e09010038030300ec020000400013a89af5f38d8b17cd508c4cb2173697aeb23b704f078c442b721aa713c34809f6369c5b253c09866cc370a21bd1c776de7ff3dc83313392cd3741be7387e703010040003a2a45491bbe76eaecbc640ef8048323fe056f362705288bc606dd7dbbd41e09628217cb73aee63b97d624752340f011cde10f947532bb42aa3dd8ff639e970a02004000a5e0d679b0aba29057ae7e3f9892311fd26a34f34862e72d55fda84db4ade10ea02fab4f6d1e2055619bcc696b980966106576e16e8bea66588c81398fe5e30203004000a570b7ba4137be56437cd7f3e1b79e2783e7e9f2f5313e7b20f705e14dbf480801d5d60b45bed35b78a1d24c6e0820d7849323afac56b88509f2a050af8a830e040040007a3d2c7dcfc51bdfd13c3ce7b9f0dd67f0a6dd87941fffca344f2f2e982cab066754d22db9a0859a79636bf679eb8822aa11a81e7510624395aa4eaa94fcac0905004000ed9a8b1fbcd385e72706f7d043650722398fa6e94f2994efae1bcd64d553350e7a5e346b498b08f217b37314013b7355bad9cf2ff3a063e4b2962057b86aaf0106004000b73f30ace6e20d1d6402dbffe05e053046e9ad1bd095877153b26290983e7f0c2e55a7f0a83d6569e110444f84f2e79c56fbbc44159d2f1c04b291fa27341a07070040008e24c1701fb9e031c78591f717a1e3faf024b49c0c685cd3bcbddf4ca19f2805f0c29cc3470f94dcda18b5e3cbe1bec892b633a54994a73fc5083aba5ed9860308004000873a50b23bc2e3ed486cab83c612bc7bc943b82b0744f2849639f11789c63907495a80fccb670da171ddc21befc169cebe45bd8cb2b28e0a99d2cb00af751a09090040007c453f220b9e4de474ef4e2443214707727b7e0825b96177261cb3bfdaa2d90955246206cb3598c365410e1c462df41eeefec1b4aa347e0e5204f4e613816d0d0a00400061789c0472886b4a93e3cf53fda42f6a81a22c96a4f78104e8e4a7ef4baa840931d501ae8e06dfd216c204350df8f95bc69eb3e473c3553112a660bc26f9b407010020009cef8a2152d4109aeb4268fcb6cab98834c628c878271a086609e2716cea5c0a02002000760eb40d7242a8168c91c2e2d860145c5a83f2ffcfa6cdcc0b97db05f0ae3588040040006e16f915e0c5c45f1569f201de7e28e6d667bf261cc8669a2b6cc228e312f3f7229e3884291a9af85ec085131db25ed24c84042432332a6eb46ee5827ceb70a30200e50702002000190fb83487dd0024027b79b3c4a4d326ce7d52397b5480d81643b0e79733b33a030038060000180301002000bf6a3d101bcd9ab3144a99f53c93e2775b5760f7154ffbf1bc3dce7a6ede486302002000e06339832a89473e76f63f8d53c32846ea0791d0b6ab2c1ce72399d5a332cfe2010020008b4dbdb425f1bb5e3de84709aa78c0e90108bd023817c3d986a2ff9a508058a702002000adbe049e36db296ae9877173ec8e859b4eb8c5e3c84e27fafa8e6f2a4f6def3901002000d266d365f75cb8decaa30dda58a47bf2599885d8d67c89ae031c173357869a0202002000c3bc56a1ffa9ccdb4bd082941cce11949c6040c2199be477673bf775b15f33890200200038c9524fcf8116607629db09670a036d2fc3eb3454ff4ad4cb21a2cedb55e5b7010020000b01adab4172d164c4d938bba5c4d12e734268fd86482f9db976dc02d974d75e010020003177d32457287c58c887fcb902af6f29269fd86f1c8b695009c35b41322238da020020003d18712a169298f47f4795f2b8349315db21c62a2d8aeee156b92cc44c85a300010020000367356b3b15a7fca400d41ab0a34c8517495e0d223e04d53288271aedc20aaa02002000060912ca00a1f9dd172906c7ecc8b120ceb5ba04b8bc0dbd1003781dd1b9d0fa01002000e0717c48d247524686b6289ba3ad830c7738a6c0ef2b90bddf9184bcf2993eac0200200011c74b26dbdc1f8789404c376d9462d631a65c28214977e47dd2557a342138c2010020002f7d36275d55c1e6c5c681e55f53475317a659cf7d30ebec3dcb1e01e648c887020020002e66a40d0f1051c296a59e14767ec0bf8f9ba2a4fe046c0ceaed1e42aadcf0a5010020001c777bf3a5140420e50dd91953124447b5f63015c250535c1f3ceaaad243019b0200200056df11ecfb640513da08b96babc38ef5d9ca089ad61aaeb21af52aa4989f40040100200078a3f3b48bcb0cb1b82dfc56b5109aa9ab93917aa2c6e7d4c8508f9cdaa9e8b802002000c5ceccbdde04a9b2a4d1ff1a87dab75613d9b3eab1431cb52623c1404acb8c4d01002000dc9175d22aadbd7fdc09c57197797c97e625f4932c6cc29852877daa539135b60200200020a53b06aa8d79e0f12e4bd5bbe65da6995adb442de7b2e47a222b851dfcf107010018030100200073e23d6de3fa02705a8c56511aaef19a2fe7897a78eeeadcecdb329a27b17a06020020004821c01056fa019d4cb0e7315987671d02ef69fea02bf8db51edfb94b469271901002000b0dd766cb753dd7ff2921e27b0a2e9528af593620d2389c260b0d1bc0a1275b502002000cc1f1bde21f657caeb35664a4b019ea3ed1f5fe3f9baddd2f9a06e0dfd8508c801002000118be7a082395c470e488e6366c931e5b46b86caa8ba659c4f95a7d84846b75002002000e51347f21e5bd78de6f34a799276645c96c9ab80dbcbbe625e5a040eba34123e01002000ed04e221e851d5cc4ca497c39efff7be16a1e13fc3a1e7771a0262679cfff7f102002000ad77407411f0800a74e3c0e4701cf9f64a2e4c10d1ee85cdeb4399a0710492cd010020003781a6085050732c3ce3e543da4ab37e46d1a228c2b935674005471c07f09b80020020007b15b8aed1d3dc0ccdffd56288adb370fdc209f0311b1553a9cef698d9fa2b5b01002000755bd7cf412efcd657ccf648cc289d296a2ba28b2c82a6bc684586e84489d31d02002000bfba591316a47e80976b9929eaefa462afaeddfa02625a8d7e73dcdfe0f4871101002000c739893727d4a47285bcf544bf63709497449bbb6e0a9d4329368e05314991bb02002000a7334113ad00baccbacf0c8195ce141c64e411921e8bf88c4c86734504d0f28c01002000a089f583003f55636cd75fec86bbae6b57ed3b62427871bc496be839034b340d020020006fa32eebd7f62d79afb1aa6be651bde1d43574b05ca7c08ad830cbd89c04543a020020008100e0ef5432496dbd7da1b14ddaf0c06c45bc9f586f511e36196991642bf7420100200089297eab30e7222b564ddaca7a0e3eb516ba9dba9549830bbbf7359d1f5ae83401002000929c8a2ec3716a7c1e080a1e2f3ab1661759f11a3f17d1c121e774b456eaa92802002000f5fa73772469d718a0c7d250f50d01e53691da3316d33e928cbad4afa470e50b010020008dbe97a4cdf63c6fa7c6e62710092c859299f0fa0e86ee8766271e8f42f751bd02002000a05e129e3301448fbafbc426b30d36fed64363ed4bf75e706eba18c65de3ec34040000000500d800010020000000000000000000000000000000000000000000000000000000000000000000020020006623b4dd0a4d75ee00000000000000000000000000000000000000000000000003002000000000000000000000000000000000000000000000000000000000000000000001002000000000000000000000000000000000000000000000000000000000000000000002002000e11814e168e1058a0000000000000000000000000000000000000000000000000300200000000000000000000000000000000000000000000000000000000000000000000600900001002000e16e8a6b0dc56757e327f6d1b1f6bce047c2257e29251876add99b8956c6bf200200200016ddaff6ddee2ceef0bf07fdb5b38326c5cfc379a6979f295588d49f977c372801002000585752b03393c6ae30726a51431cf1d9e6dac206a4bab0535a43ff3d589b4ea702002000907d07c3c8d127cbdf3215a8bccf81a6e64351a5ac85a1e7276653c2fc73c4210700080000000000085fb5100100010004";
    int encodeLen = strlen(s)/2;
    unsigned char *encodeByte = (unsigned char *)malloc(encodeLen);
    sTox(s,encodeByte,encodeLen);
    rct::rctSig to;
    if (false == tlv_rctSig_decode(to, encodeByte, encodeLen)) {
        free(encodeByte);
        printf("testRctsigCompatibleWithGo decode fail\n");
        return -1;
    }

    if (!rct::verRctSemanticsSimple(to)){
        free(encodeByte);
        return -1;
    }
    if (!rct::verRctNonSemanticsSimple(to)){
        free(encodeByte);
        return -1;
    }
    return 0;
}
//void tmpTest(){
//    uint64_t tag = 0xff;
//    char addr[] = "3f2771523a6a4b83f25cb65192b8db29b4d68b6f7a5ae424f09bd312e3ab123c91e23f3e2da4093f82ef9e43c07602f9efca833063f0597ba3a1a3b3cdb28401b40d906bc8";
//    std::string data(addr);
//    printf("addr = %s\n",data.c_str());
//    std::string ret = tools::base58::encode_addr(tag,data);
//    printf("ret = %s tag=%lld data=%s\n",ret.c_str(),tag,data.c_str());
//}
int main(int argc, char **argv) {
    if (-1 == testKeyV()) {
        printf("testKeyV fail\n");
    }

    if (-1 == testKeyM()) {
        printf("testKeyM fail\n");
    }
    if (-1 == testRctkey()) {
        printf("testRctkey fail\n");
    }
    if (-1 == testRctMkey()) {
        printf("testRctMkey fail\n");
    }
    if (-1 == testMultisigKLRki()) {
        printf("testMultisigKLRki fail\n");
    }
    if (-1 == testEcdhTuple()) {
        printf("testEcdhTuple fail\n");
    }
    if (-1 == testRctsig()) {
        printf("testRctsig fail\n");
    }
    if (-1 == testRctsigSimple()) {
        printf("testRctsigSimple fail\n");
    }
    if (-1 == testRctsigCompatibleWithGo()) {
        printf("testRctsigCompatibleWithGo fail\n");
    }
//    tmpTest();
    return 0;
}