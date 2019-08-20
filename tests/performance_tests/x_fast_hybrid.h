// Copyright (c) 2014-2017, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "ringct/rctSigs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "string_tools.h"
#include "single_tx_test_base.h"
#include "device/device.hpp"
#include "crypto/crypto.h"
std::string fast_hybrid_list[]={
        "check_key_false",
        "check_key_true",
        "scalarmultBase",
        "scalarmultKey",
        "skpkGen",
        "scalarmultH",
        "zeroCommit",
        "scalarmult8",
        "sc_add",
        "sc_sub",
        "skGen",
        "genC",
        "addKeys",
        "AddKeyV",
        "AddKeys2"
};
template<size_t functag>
class x_test_fast_hybrid {
public:
    static const size_t loop_count = 10000;
    bool init() {
        char s1[] = "c2cb3cf3840aa9893e00ec77093d3d44dba7da840b51c48462072d58d8efd183";
        char s2[] = "bd85a61bae0c101d826cbed54b1290f941d26e70607a07fc6f0ad611eb8f70a6";
        char s3[] = "9cef8a2152d4109aeb4268fcb6cab98834c628c878271a086609e2716cea5c0a";
        char s4[] = "a570b7ba4137be56437cd7f3e1b79e2783e7e9f2f5313e7b20f705e14dbf4808";
        char s5[] = "a570b7ba4137be56437cd7f3e1b79e2783e7e9f2f5313e7b20f705e14dbf4808";
        sTox(s1,(unsigned char *)pk1.data,32);
        sTox(s2,(unsigned char *)pk2.data,32);

        sTox(s3,(unsigned char *)k1.bytes,32);
        sTox(s4,(unsigned char *)k2.bytes,32);
        sTox(s5,(unsigned char *)k3.bytes,32);
        kv1.clear();
        for (int i =0;i < 4;i++) {
            kv1.push_back(k1);
            kv1.push_back(k2);
            kv1.push_back(k3);
        }
        amount = 0xfffffff123;
        unsigned char sc[2][32] ={{225, 110, 138, 107, 13, 197, 103, 87, 227, 39, 246, 209, 177, 246, 188, 224, 71, 194, 37, 126, 41, 37, 24, 118, 173, 217, 155, 137, 86, 198, 191, 32},
                                  {22, 221, 175, 246, 221, 238, 44, 238, 240, 191, 7, 253, 181, 179, 131, 38, 197, 207, 195, 121, 166, 151, 159, 41, 85, 136, 212, 159, 151, 124, 55, 40}};
        memcpy(scalar1.data,(char *)sc[0],32);
        memcpy(scalar2.data,(char *)sc[1],32);
        printf("\nready %s call\n",fast_hybrid_list[functag].c_str());
        return true;
    }

    bool test() {
        rct::key tmp1,tmp2;
        crypto::ec_scalar ts1;
        switch (functag){
            case 0:
                crypto::check_key(pk1);
                break;
            case 1:
                crypto::check_key(pk2);
                break;
            case 2:
                rct::scalarmultBase(k1);
                break;
            case 3:
                rct::scalarmultKey(k1,k2);
                break;
            case 4:
                rct::skpkGen(tmp1,tmp2);
                break;
            case 5:
                rct::scalarmultH(k1);
                break;
            case 6:
                rct::zeroCommit(amount);
                break;
            case 7:
                rct::scalarmult8(k1);
                break;
            case 8:
                sc_add((unsigned char *) (ts1.data), (unsigned char *) (scalar1.data), (unsigned char *) (scalar2.data));
                break;
            case 9:
                sc_sub((unsigned char *) (ts1.data), (unsigned char *) (scalar1.data), (unsigned char *) (scalar2.data));
                break;
            case 10:
                rct::skGen();
                break;
            case 11:
                rct::genC(k1,k2,amount);
                break;
            case 12:
                rct::addKeys(tmp1,k1,k2);
                break;
            case 13:
                rct::addKeys(kv1);
                break;
            case 14:
                rct::addKeys2(tmp1,k1,k2,k3);
                break;

        }
        return true;
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

private:
    crypto::public_key pk1,pk2;
    rct::key k1,k2,k3;
    rct::keyV kv1;
    crypto::ec_scalar scalar1,scalar2;
    long long unsigned amount;
};
