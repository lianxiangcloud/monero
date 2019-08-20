//
// Created by lulu on 2019-07-04.
//

#ifndef MONERO_TLVSERIALIZER_CPP
#define MONERO_TLVSERIALIZER_CPP


#include "xcrypto.h"
#include <stdio.h>
#include "ringct/rctTypes.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/account.h"
#include <vector>


const int TLV_TAGSIZE = 2;
const int TLV_LENSIZE = 2;
const int TLV_TAGOFFSET = 0;

const int TLV_LENOFFSET = TLV_TAGSIZE;
const int TLV_HEADSIZE = TLV_TAGSIZE + TLV_LENSIZE;
const int TLV_VOFFSET = TLV_HEADSIZE;

union Endian {
    int a;
    char b;
} ed;

bool isbig_endian() {
    ed.a = 1;
    return ed.b != 1;
}

const bool GigEndian = isbig_endian();

#define TLV_ENCODE_T(target, tag, data, offset, inc, len, encoder) if(len - offset - TLV_HEADSIZE < 0)return -1;\
setTagOrLen(tag, data + offset + TLV_TAGOFFSET);\
inc = encoder(target, data + offset + TLV_HEADSIZE, len - offset - TLV_HEADSIZE);\
if (inc < 0) {\
printf("inc < 0 %d %s\n",tag,#encoder);\
return -1;\
}\
setTagOrLen(inc, data + offset + TLV_LENOFFSET);\
offset += inc + TLV_HEADSIZE;


#define TLV_DECODE_T(target, data, len, decoder) int offset = 0;while (offset < len) {\
int tag = parseTagOrLen(data + offset + TLV_TAGOFFSET);\
int inc = parseTagOrLen(data + offset + TLV_LENOFFSET);\
if (offset + TLV_HEADSIZE + inc > len) {\
return false;\
}\
bool flag = decoder(tag,target,data+offset,inc);\
if (flag == false) {\
return false;\
}\
offset += inc + TLV_HEADSIZE;\
}\
if (offset != len) {\
return false;\
}


#define TLV_VECTOR_ENCODE_T(name, t, encoder, constSize) int tlv_##name(std::vector<t> &target, unsigned char *data, int len) {\
    int vlen = target.size();\
    int offset = 0;\
    int inc = 0;\
    for (int i = 0; i < vlen; i++) {\
        if (offset >= len) {\
        printf("offset>=len  offset=%d len=%d %s\n",offset,len,#encoder);\
            return -1;\
        }\
        if (constSize>0){\
            inc = encoder(target[i], data + offset, len - offset);\
            if (inc == -1 || inc == 0) {\
            printf("inc <=0  offset=%d inc=%d %s\n",offset,inc,#encoder);\
                return -1;\
            }\
            offset += constSize;\
        }\
        else{\
            inc = encoder(target[i], data + offset + TLV_VOFFSET, len - offset - TLV_VOFFSET);\
            if (inc == -1 || inc == 0) {\
            printf("inc <=0  offset=%d inc=%d %s\n",offset,inc,#encoder);\
                return -1;\
            }\
            setTagOrLen(i, data + offset + TLV_TAGOFFSET);\
            setTagOrLen(inc, data + offset + TLV_LENOFFSET);\
            offset += inc + TLV_HEADSIZE;\
        }\
    }\
    return offset;\
}

#define TLV_VECTOR_DECODE_T(name, t, decoder, constSize) bool tlv_##name(std::vector<t> &target, unsigned char *data, int len) {\
    int offset = 0;\
    int inc = 0;\
    while (offset < len) {\
        t item;\
        if (constSize>0) {\
            if (false == decoder(item, data + offset, constSize)) {\
                return false;\
            }\
            offset += constSize;\
        }else{\
            int vlen = parseTagOrLen(data + offset + TLV_LENOFFSET);\
            if (offset + TLV_VOFFSET + vlen > len) {\
                return false;\
            }\
            if (false == decoder(item, data + offset + TLV_VOFFSET, vlen)) {\
                return false;\
            }\
            offset += vlen + TLV_HEADSIZE;\
        }\
        target.push_back(item);\
    }\
    if (offset != len) {\
        return false;\
    }\
    return true;\
}



int parseTagOrLen(unsigned char *data);

int parseTagOrLen(unsigned char *data) {
    return (int(data[0]) + (((int) data[1]) << 8));
}

void setTagOrLen(int val, unsigned char *data) {
    data[0] = (unsigned char) (val & ((1 << 8) - 1));
    data[1] = (unsigned char) ((val >> 8) & ((1 << 8) - 1));
}

int parseArrayLenFromData(unsigned char *data, int datalen, int eleSize) {
    if (datalen == 0) {
        return 0;
    }
    if (eleSize <= 0) {
        int offset = 0;
        int ret = 0;
        while (offset < datalen) {
            int inc = parseTagOrLen(data + offset + TLV_LENOFFSET);
            offset += inc + TLV_HEADSIZE;
            ret++;
        }
        if (offset != datalen) {
            return -1;
        }
        return ret;
    } else {
        if (datalen % eleSize != 0) {
            return -1;
        } else {
            return datalen / eleSize;
        }
    }

}

//char
int tlv_char_size() {
    return 1;
}

int tlv_char_encode(char target, unsigned char *data, int len) {
    if (len < tlv_char_size()) {
        return -1;
    }
    data[0] = target;
    return 1;
}

bool tlv_char_decode(char *target, unsigned char *data, int len) {
    if (len != 1) {
        return false;
    }
    *target = data[0];
    return true;
}

//char  4 bytes
int tlv_char4_size() {
    return 4;
}

int tlv_char4_encode(char *target, unsigned char *data, int len) {
    if (len < tlv_char_size()) {
        return -1;
    }
    if (GigEndian) {
        memcpy(data, (unsigned char *) target, 4);
    } else {
        for (int i = 0; i < 4; i++) {
            data[i] = target[3 - i];
        }
    }

    return 4;
}

bool tlv_char4_decode(char *target, unsigned char *data, int len) {
    if (len != 4) {
        return false;
    }
    if (GigEndian) {
        memcpy(target, (char *) data, 4);
    } else {
        for (int i = 0; i < 4; i++) {
            target[i] = data[3 - i];
        }
    }
    return true;
}

//char  8 bytes
int tlv_char8_size() {
    return 8;
}

int tlv_char8_encode(char *target, unsigned char *data, int len) {
    int charlen = tlv_char8_size();
    if (len != charlen) {
        return -1;
    }

    if (GigEndian) {
        memcpy(data, (unsigned char *) target, charlen);
    } else {
        for (int i = 0; i < charlen; i++) {
            data[i] = target[charlen - 1 - i];
        }
    }
    return charlen;
}

bool tlv_char8_decode(char *target, unsigned char *data, int len) {
    int charlen = tlv_char8_size();
    if (len != charlen) {
        return false;
    }
    if (GigEndian) {
        memcpy(target, (char *) data, charlen);
    } else {
        for (int i = 0; i < charlen; i++) {
            target[i] = data[charlen - 1 - i];
        }
    }
    return true;
}


//key
int tlv_key_size() {
    return 32;
}

int tlv_key_encode(rct::key &key, unsigned char *data, int len) {
    if (len < 32) {
        return -1;
    }
    memcpy(data, key.bytes, 32);
    return 32;
}

bool tlv_key_decode(rct::key &key, unsigned char *data, int len) {
    if (len != 32) {
        printf("tlv_key_decode keylen=%d\n", len);
        return false;
    }
    memcpy(key.bytes, data, 32);
    return true;
}

//keyv------------------------------------------------------------------
int tlv_keyv_size(rct::keyV &keyv) {
    return keyv.size() * 32;
}

int tlv_keyv_encode(rct::keyV &target, unsigned char *data, int len) {
    if (len < tlv_keyv_size(target)) {
        return false;
    }
    int vlen = target.size();
    int offset = 0;
    int inc = 0;
    for (int i = 0; i < vlen; i++) {
        if (offset >= len) {
            return -1;
        }
        inc = tlv_key_encode(target[i], data + offset, len - offset);
        if (inc == -1 || inc == 0) {
            return -1;
        }
        offset += inc;
    }
    return offset;
}

bool tlv_keyv_decode(rct::keyV &target, unsigned char *data, int len) {

    rct::key key;

    int offset = 0;
    int inc = tlv_key_size();
    while (offset < len) {
        if (false == tlv_key_decode(key, data + offset, inc)) {
            return false;
        }
        target.push_back(key);
        offset += inc;
    }
    if (offset != len) {
        return false;
    }
    return true;
}

//keym------------------------------------------------------------------
int tlv_keym_size(rct::keyM &keym) {
    int ret = 0;
    int mlen = keym.size();
    for (int i = 0; i < mlen; i++) {
        ret += tlv_keyv_size(keym[i]) + TLV_HEADSIZE;
    }
    return ret;
}

int tlv_keym_encode(rct::keyM &target, unsigned char *data, int len) {
    if (len < tlv_keym_size(target)) {
        return -1;
    }
    int vlen = target.size();
    int offset = 0;
    int inc = 0;
    for (int i = 0; i < vlen; i++) {
        if (offset >= len) {
            return -1;
        }
        inc = tlv_keyv_encode(target[i], data + offset + TLV_VOFFSET, len - offset - TLV_VOFFSET);
        if (inc == -1 || inc == 0) {
            return -1;
        }
        setTagOrLen(i, data + offset + TLV_TAGOFFSET);
        setTagOrLen(inc, data + offset + TLV_LENOFFSET);
        offset += inc + TLV_HEADSIZE;
    }
    return offset;
}

bool tlv_keym_decode(rct::keyM &target, unsigned char *data, int len) {

    int offset = 0;
    while (offset < len) {
        int vlen = parseTagOrLen(data + offset + TLV_LENOFFSET);
        if (offset + TLV_VOFFSET + vlen > len) {
            return false;
        }
        rct::keyV keyv;
        if (false == tlv_keyv_decode(keyv, data + offset + TLV_VOFFSET, vlen)) {
            return false;
        }
        target.push_back(keyv);
        offset += vlen + TLV_HEADSIZE;
    }
    if (offset != len) {
        return false;
    }
    return true;
}


//ctkey------------------------------------------------------------------
int tlv_ctkey_size() {
    return 2 * (tlv_key_size() + TLV_HEADSIZE);
}

int tlv_ctkey_encode(rct::ctkey &target, unsigned char *data, int len) {
    if (len < tlv_ctkey_size()) {
        return -1;
    }
    //dest
    int offset = 0;
    int inc = 0;
    setTagOrLen(1, data + offset + TLV_TAGOFFSET);
    inc = tlv_key_encode(target.dest, data + offset + TLV_HEADSIZE, len - offset - TLV_HEADSIZE);
    if (inc < 0) {
        return -1;
    }
    setTagOrLen(inc, data + offset + TLV_LENOFFSET);
    offset += inc + TLV_HEADSIZE;


    //mask
    setTagOrLen(2, data + offset + TLV_TAGOFFSET);
    inc = tlv_key_encode(target.mask, data + offset + TLV_HEADSIZE, len - offset - TLV_HEADSIZE);
    if (inc < 0 || offset + inc + TLV_HEADSIZE > len) {
        return -1;
    }
    setTagOrLen(inc, data + offset + TLV_LENOFFSET);
    offset += inc + TLV_HEADSIZE;

    return offset;
}

bool tlv_ctkey_decode(rct::ctkey &target, unsigned char *data, int len) {
    int offset = 0;
    while (offset < len) {
        int tag = parseTagOrLen(data + offset + TLV_TAGOFFSET);
        int inc = parseTagOrLen(data + offset + TLV_LENOFFSET);
        if (offset + TLV_HEADSIZE + inc > len) {
            return false;
        }
        bool flag = true;
        switch (tag) {
            case 1:
                flag = tlv_key_decode(target.dest, data + offset + TLV_VOFFSET, inc);
                break;
            case 2:
                flag = tlv_key_decode(target.mask, data + offset + TLV_VOFFSET, inc);
                break;
        }
        if (flag == false) {
            return false;
        }
        offset += inc + TLV_HEADSIZE;
    }
    if (offset != len) {
        return false;
    }
    return true;
}


//ctkeyv------------------------------------------------------------------
int tlv_ctkeyv_size(std::vector<rct::ctkey> &target) {
    return target.size() * tlv_ctkey_size();
}

int tlv_ctkeyv_encode(std::vector<rct::ctkey> &target, unsigned char *data, int len) {

    int vlen = target.size();
    int offset = 0;
    int inc = 0;
    for (int i = 0; i < vlen; i++) {
        if (offset >= len) {
            return -1;
        }
        inc = tlv_ctkey_encode(target[i], data + offset, len - offset);
        if (inc == -1 || inc == 0) {
            return -1;
        }
        offset += inc;
    }
    return offset;
}

bool tlv_ctkeyv_decode(std::vector<rct::ctkey> &target, unsigned char *data, int len) {

    rct::ctkey key;

    int offset = 0;
    int inc = tlv_ctkey_size();
    while (offset < len) {
        if (false == tlv_ctkey_decode(key, data + offset, inc)) {
            return false;
        }
        target.push_back(key);
        offset += inc;
    }
    if (offset != len) {
        return false;
    }
    return true;
}

//ctkeyM------------------------------------------------------------------
int tlv_ctkeym_size(rct::ctkeyM &target) {
    int size = target.size();
    int ret = 0;
    for (int i = 0; i < size; i++) {
        ret += tlv_ctkeyv_size(target[i]) + TLV_HEADSIZE;
    }
    return ret;
}

int tlv_ctkeym_encode(rct::ctkeyM &target, unsigned char *data, int len) {
    int vlen = target.size();
    int offset = 0;
    int inc = 0;
    for (int i = 0; i < vlen; i++) {
        if (offset >= len) {
            return -1;
        }
        inc = tlv_ctkeyv_encode(target[i], data + offset + TLV_VOFFSET, len - offset - TLV_VOFFSET);
        if (inc == -1 || inc == 0) {
            return -1;
        }
        setTagOrLen(i, data + offset + TLV_TAGOFFSET);
        setTagOrLen(inc, data + offset + TLV_LENOFFSET);
        offset += inc + TLV_HEADSIZE;
    }
    return offset;
}

bool tlv_ctkeym_decode(rct::ctkeyM &target, unsigned char *data, int len) {

    int offset = 0;
    while (offset < len) {
        int vlen = parseTagOrLen(data + offset + TLV_LENOFFSET);
        if (offset + TLV_VOFFSET + vlen > len) {
            return false;
        }
        rct::ctkeyV obj;
        if (false == tlv_ctkeyv_decode(obj, data + offset + TLV_VOFFSET, vlen)) {
            return false;
        }
        target.push_back(obj);
        offset += vlen + TLV_VOFFSET;
    }
    if (offset != len) {
        return false;
    }
    return true;
}


//multisig_kLRki
int tlv_multisig_kLRki_size(rct::multisig_kLRki &target) {
    return 4 * (tlv_key_size() + TLV_HEADSIZE);
}

int tlv_multisig_kLRki_encode(rct::multisig_kLRki &target, unsigned char *data, int len) {

    int offset = 0;
    int inc = 0;

// 1 -> k
    TLV_ENCODE_T(target.k, 1, data, offset, inc, len, tlv_key_encode)
// 2 -> ki
    TLV_ENCODE_T(target.ki, 2, data, offset, inc, len, tlv_key_encode)
// 3 -> L
    TLV_ENCODE_T(target.L, 3, data, offset, inc, len, tlv_key_encode)
// 4 -> R
    TLV_ENCODE_T(target.R, 4, data, offset, inc, len, tlv_key_encode)

    return offset;
}

bool tlv_multisig_kLRki_decode_tag(int tag, rct::multisig_kLRki &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_key_decode(target.k, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_key_decode(target.ki, data + TLV_VOFFSET, inc);
            break;
        case 3:
            flag = tlv_key_decode(target.L, data + TLV_VOFFSET, inc);
            break;
        case 4:
            flag = tlv_key_decode(target.R, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_multisig_kLRki_decode(rct::multisig_kLRki &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_multisig_kLRki_decode_tag)
    return true;
}


//multisig_out

int tlv_multisig_out_size(rct::multisig_out &target) {
    int ret = target.c.size() * tlv_key_size() + TLV_HEADSIZE;
    return ret;
}

int tlv_multisig_out_encode(rct::multisig_out &target, unsigned char *data, int len) {

    int offset = 0;
    int inc = 0;
// 1 -> c
    TLV_ENCODE_T(target.c, 1, data, offset, inc, len, tlv_keyv_encode)

    return offset;
}

bool tlv_multisig_out_decode_tag(int tag, rct::multisig_out &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_keyv_decode(target.c, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_multisig_out_decode(rct::multisig_out &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_multisig_out_decode_tag)
    return true;
}


//ecdhTuple
int tlv_ecdhTuple_size() {
    int ret = 3 * (tlv_key_size() + TLV_HEADSIZE);
    return ret;
}

int tlv_ecdhTuple_encode(rct::ecdhTuple &target, unsigned char *data, int len) {

    int offset = 0;
    int inc = 0;
// 1 -> mast
    TLV_ENCODE_T(target.mask, 1, data, offset, inc, len, tlv_key_encode)
// 2 -> mast
    TLV_ENCODE_T(target.amount, 2, data, offset, inc, len, tlv_key_encode)
    return offset;
}

bool tlv_ecdhTuple_decode_tag(int tag, rct::ecdhTuple &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_key_decode(target.mask, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_key_decode(target.amount, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_ecdhTuple_decode(rct::ecdhTuple &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_ecdhTuple_decode_tag)

    return true;
}

//ecdhTuple verctor
int tlv_ecdhTuplev_size(std::vector<rct::ecdhTuple> &target) {
    int ret = 0;
    int vlen = target.size();
    for (int i = 0; i < vlen; i++) {
        ret += tlv_ecdhTuple_size();
    }
    return ret;
}

TLV_VECTOR_ENCODE_T(ecdhTuplev_encode, rct::ecdhTuple, tlv_ecdhTuple_encode, tlv_ecdhTuple_size())

TLV_VECTOR_DECODE_T(ecdhTuplev_decode, rct::ecdhTuple, tlv_ecdhTuple_decode, tlv_ecdhTuple_size())


//key64
int tlv_key64_size() {
    int ret = 64 * tlv_key_size();
    return ret;
}

int tlv_key64_encode(rct::key64 &target, unsigned char *data, int len) {
    if (len < tlv_key64_size()) {
        return -1;
    }
    int offset = 0, inc = tlv_key_size();
    for (int i = 0; i < 64; i++, offset += inc) {
        if (-1 == tlv_key_encode(target[i], data + offset, len - offset)) {
            return -1;
        }
    }
    return 64 * tlv_key_size();
}

bool tlv_key64_decode(rct::key64 &target, unsigned char *data, int len) {
    if (len != tlv_key64_size()) {
        return false;
    }
    int offset = 0, inc = tlv_key_size();
    for (int i = 0; i < 64; i++) {
        if (offset + inc > len) {
            return false;
        }
        if (!tlv_key_decode(target[i], data + offset, inc)) {
            return false;
        }
        offset += inc;
    }
    if (offset != len) {
        return false;
    }
    return true;
}


//boroSig

int tlv_boroSig_size(rct::boroSig &target) {
    int ret = tlv_key64_size() + TLV_HEADSIZE;
    ret += tlv_key64_size() + TLV_HEADSIZE;
    ret += tlv_key_size() + TLV_HEADSIZE;
    return ret;
}

int tlv_boroSig_encode(rct::boroSig &target, unsigned char *data, int len) {

    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.ee, 1, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.s0, 2, data, offset, inc, len, tlv_key64_encode)
    TLV_ENCODE_T(target.s1, 3, data, offset, inc, len, tlv_key64_encode)
    return offset;
}

bool tlv_boroSig_decode_tag(int tag, rct::boroSig &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_key_decode(target.ee, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_key64_decode(target.s0, data + TLV_VOFFSET, inc);
            break;
        case 3:
            flag = tlv_key64_decode(target.s1, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_boroSig_decode(rct::boroSig &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_boroSig_decode_tag)
    return true;
}


//mgSig
int tlv_mgSig_size(rct::mgSig &target) {
    int ret = tlv_keym_size(target.ss) + TLV_HEADSIZE;
    ret += tlv_key_size() + TLV_HEADSIZE;
    ret += tlv_keyv_size(target.II) + TLV_HEADSIZE;
    return ret;
}

int tlv_mgSig_encode(rct::mgSig &target, unsigned char *data, int len) {

    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.cc, 1, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.II, 2, data, offset, inc, len, tlv_keyv_encode)
    TLV_ENCODE_T(target.ss, 3, data, offset, inc, len, tlv_keym_encode)
    return offset;
}

bool tlv_mgSig_decode_tag(int tag, rct::mgSig &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_key_decode(target.cc, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_keyv_decode(target.II, data + TLV_VOFFSET, inc);
            break;
        case 3:
            flag = tlv_keym_decode(target.ss, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_mgSig_decode(rct::mgSig &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_mgSig_decode_tag)
    return true;
}

//mgSig vector
int tlv_mgSigv_size(std::vector<rct::mgSig> &target) {
    int ret = 0;
    int vlen = target.size();
    for (int i = 0; i < vlen; i++) {
        ret += tlv_mgSig_size(target[i]) + TLV_HEADSIZE;
    }
    return ret;
}

TLV_VECTOR_ENCODE_T(mgSigv_encode, rct::mgSig, tlv_mgSig_encode, 0)

TLV_VECTOR_DECODE_T(mgSigv_decode, rct::mgSig, tlv_mgSig_decode, 0)

//rangeSig
int tlv_rangeSig_size(rct::rangeSig &target) {
    int ret = tlv_boroSig_size(target.asig) + TLV_HEADSIZE;
    ret += tlv_key64_size() + TLV_HEADSIZE;

    return ret;
}

int tlv_rangeSig_encode(rct::rangeSig &target, unsigned char *data, int len) {

    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.asig, 1, data, offset, inc, len, tlv_boroSig_encode)
    TLV_ENCODE_T(target.Ci, 2, data, offset, inc, len, tlv_key64_encode)
    return offset;
}

bool tlv_rangeSig_decode_tag(int tag, rct::rangeSig &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_boroSig_decode(target.asig, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_key64_decode(target.Ci, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_rangeSig_decode(rct::rangeSig &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_rangeSig_decode_tag)
    return true;
}

//rangeSig vector
int tlv_rangeSigv_size(std::vector<rct::rangeSig> &target) {
    int ret = 0;
    int vlen = target.size();
    for (int i = 0; i < vlen; i++) {
        ret += tlv_rangeSig_size(target[i]) + TLV_HEADSIZE;
    }
    return ret;
}

TLV_VECTOR_ENCODE_T(rangeSigv_encode, rct::rangeSig, tlv_rangeSig_encode, 0)

TLV_VECTOR_DECODE_T(rangeSigv_decode, rct::rangeSig, tlv_rangeSig_decode, 0)

//Bulletproof
int tlv_bulletproof_size(rct::Bulletproof &target) {
    //A, S, T1, T2,taux, mu,a,b,t;
    int ret = 9 * (tlv_key_size() + TLV_HEADSIZE);
    ret += tlv_keyv_size(target.V) + TLV_HEADSIZE;
    ret += tlv_keyv_size(target.L) + TLV_HEADSIZE;
    ret += tlv_keyv_size(target.R) + TLV_HEADSIZE;
    return ret;
}

int tlv_bulletproof_encode(rct::Bulletproof &target, unsigned char *data, int len) {
    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.V, 1, data, offset, inc, len, tlv_keyv_encode)
    TLV_ENCODE_T(target.A, 2, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.S, 3, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.T1, 4, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.T2, 5, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.taux, 6, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.mu, 7, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.L, 8, data, offset, inc, len, tlv_keyv_encode)
    TLV_ENCODE_T(target.R, 9, data, offset, inc, len, tlv_keyv_encode)
    TLV_ENCODE_T(target.a, 10, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.b, 11, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.t, 12, data, offset, inc, len, tlv_key_encode)

    return offset;
}

bool tlv_bulletproof_decode_tag(int tag, rct::Bulletproof &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_keyv_decode(target.V, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_key_decode(target.A, data + TLV_VOFFSET, inc);
            break;
        case 3:
            flag = tlv_key_decode(target.S, data + TLV_VOFFSET, inc);
            break;
        case 4:
            flag = tlv_key_decode(target.T1, data + TLV_VOFFSET, inc);
            break;
        case 5:
            flag = tlv_key_decode(target.T2, data + TLV_VOFFSET, inc);
            break;
        case 6:
            flag = tlv_key_decode(target.taux, data + TLV_VOFFSET, inc);
            break;
        case 7:
            flag = tlv_key_decode(target.mu, data + TLV_VOFFSET, inc);
            break;
        case 8:
            flag = tlv_keyv_decode(target.L, data + TLV_VOFFSET, inc);
            break;
        case 9:
            flag = tlv_keyv_decode(target.R, data + TLV_VOFFSET, inc);
            break;
        case 10:
            flag = tlv_key_decode(target.a, data + TLV_VOFFSET, inc);
            break;
        case 11:
            flag = tlv_key_decode(target.b, data + TLV_VOFFSET, inc);
            break;
        case 12:
            flag = tlv_key_decode(target.t, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_bulletproof_decode(rct::Bulletproof &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_bulletproof_decode_tag)
    return true;
}

//Bulletproof vector
int tlv_bulletproofv_size(std::vector<rct::Bulletproof> &target) {
    int ret = 0;
    int vlen = target.size();
    for (int i = 0; i < vlen; i++) {
        ret += tlv_bulletproof_size(target[i]) + TLV_HEADSIZE;
    }
    return ret;
}

TLV_VECTOR_ENCODE_T(bulletproofv_encode, rct::Bulletproof, tlv_bulletproof_encode, 0)

TLV_VECTOR_DECODE_T(bulletproofv_decode, rct::Bulletproof, tlv_bulletproof_decode, 0)

//rctSigBase
int tlv_rctSigBase_size(rct::rctSigBase &target) {
    //message
    int ret = tlv_key_size() + TLV_HEADSIZE;

    ret += tlv_char_size() + TLV_HEADSIZE;
    ret += tlv_ctkeym_size(target.mixRing) + TLV_HEADSIZE;
    ret += tlv_keyv_size(target.pseudoOuts) + TLV_HEADSIZE;
    ret += tlv_ecdhTuplev_size(target.ecdhInfo) + TLV_HEADSIZE;
    ret += tlv_ctkeyv_size(target.outPk)+ TLV_HEADSIZE;
    ret += tlv_char8_size() + TLV_HEADSIZE;

    return ret;
}

int tlv_rctSigBase_encode(rct::rctSigBase &target, unsigned char *data, int len) {
    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.type, 1, data, offset, inc, len, tlv_char_encode)
    TLV_ENCODE_T(target.message, 2, data, offset, inc, len, tlv_key_encode)
    TLV_ENCODE_T(target.mixRing, 3, data, offset, inc, len, tlv_ctkeym_encode)
    TLV_ENCODE_T(target.pseudoOuts, 4, data, offset, inc, len, tlv_keyv_encode)
    TLV_ENCODE_T(target.ecdhInfo, 5, data, offset, inc, len, tlv_ecdhTuplev_encode)
    TLV_ENCODE_T(target.outPk, 6, data, offset, inc, len, tlv_ctkeyv_encode)
    TLV_ENCODE_T(((char *) (&target.txnFee)), 7, data, offset, inc, len, tlv_char8_encode)
    return offset;
}

bool tlv_rctSigBase_decode_tag(int tag, rct::rctSigBase &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_char_decode((char *) (&(target.type)), data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_key_decode(target.message, data + TLV_VOFFSET, inc);
            break;
        case 3:
            flag = tlv_ctkeym_decode(target.mixRing, data + TLV_VOFFSET, inc);
            break;
        case 4:
            flag = tlv_keyv_decode(target.pseudoOuts, data + TLV_VOFFSET, inc);
            break;
        case 5:
            flag = tlv_ecdhTuplev_decode(target.ecdhInfo, data + TLV_VOFFSET, inc);
            break;
        case 6:
            flag = tlv_ctkeyv_decode(target.outPk, data + TLV_VOFFSET, inc);
            break;
        case 7:
            flag = tlv_char8_decode((char *)(&(target.txnFee)), data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_rctSigBase_decode(rct::rctSigBase &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_rctSigBase_decode_tag)
    return true;
}


//rctSigPrunable
int tlv_rctSigPrunable_size(rct::rctSigPrunable &target) {
    //message
    int ret = tlv_keyv_size(target.pseudoOuts) + TLV_HEADSIZE;
    ret += tlv_rangeSigv_size(target.rangeSigs) + TLV_HEADSIZE;
    ret += tlv_bulletproofv_size(target.bulletproofs) + TLV_HEADSIZE;
    ret += tlv_mgSigv_size(target.MGs) + TLV_HEADSIZE;

    return ret;
}

int tlv_rctSigPrunable_encode(rct::rctSigPrunable &target, unsigned char *data, int len) {
    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.rangeSigs, 1, data, offset, inc, len, tlv_rangeSigv_encode)
    TLV_ENCODE_T(target.bulletproofs, 2, data, offset, inc, len, tlv_bulletproofv_encode)
    TLV_ENCODE_T(target.MGs, 3, data, offset, inc, len, tlv_mgSigv_encode)
    TLV_ENCODE_T(target.pseudoOuts, 4, data, offset, inc, len, tlv_keyv_encode)
    return offset;
}

bool tlv_rctSigPrunable_decode_tag(int tag, rct::rctSigPrunable &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_rangeSigv_decode(target.rangeSigs, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_bulletproofv_decode(target.bulletproofs, data + TLV_VOFFSET, inc);
            break;
        case 3:
            flag = tlv_mgSigv_decode(target.MGs, data + TLV_VOFFSET, inc);
            break;
        case 4:
            flag = tlv_keyv_decode(target.pseudoOuts, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_rctSigPrunable_decode(rct::rctSigPrunable &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_rctSigPrunable_decode_tag)
    return true;
}


//rctSig
int tlv_rctSig_size(rct::rctSig &target) {
    int ret = tlv_rctSigPrunable_size(target.p) + TLV_HEADSIZE;
    ret += tlv_rctSigBase_size(target) + TLV_HEADSIZE;
    return ret;
}

int tlv_rctSig_encode(rct::rctSig &target, unsigned char *data, int len) {
    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.p, 1, data, offset, inc, len, tlv_rctSigPrunable_encode)
    TLV_ENCODE_T(target, 2, data, offset, inc, len, tlv_rctSigBase_encode)
    return offset;
}

bool tlv_rctSig_decode_tag(int tag, rct::rctSig &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_rctSigPrunable_decode(target.p, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_rctSigBase_decode(target, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_rctSig_decode(rct::rctSig &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_rctSig_decode_tag)
    return true;
}


//secret_key
int tlv_secret_key_size() {
    return 32;
}

int tlv_secret_key_encode(crypto::secret_key &key, unsigned char *data, int len) {
    if (len < 32) {
        return -1;
    }
    memcpy(data, key.data, 32);
    return 32;
}

bool tlv_secret_key_decode(crypto::secret_key &key, unsigned char *data, int len) {
    if (len != 32) {
        printf("tlv_secret_key_decode keylen=%d\n", len);
        return false;
    }
    memcpy(key.data, data, 32);
    return true;
}
//public_key
int tlv_public_key_size() {
    return 32;
}

int tlv_public_key_encode(crypto::public_key &key, unsigned char *data, int len) {
    if (len < 32) {
        return -1;
    }
    memcpy(data, key.data, 32);
    return 32;
}

bool tlv_public_key_decode(crypto::public_key &key, unsigned char *data, int len) {
    if (len != 32) {
        printf("tlv_public_key_decode keylen=%d\n", len);
        return false;
    }
    memcpy(key.data, data, 32);
    return true;
}
//cryptonote::account_public_address
int tlv_account_public_address_size() {
    int ret = tlv_public_key_size() + TLV_HEADSIZE;
    ret += tlv_public_key_size() + TLV_HEADSIZE;
    return ret;
}

int tlv_account_public_address_encode(cryptonote::account_public_address &target, unsigned char *data, int len) {
    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.m_spend_public_key, 1, data, offset, inc, len, tlv_public_key_encode)
    TLV_ENCODE_T(target.m_view_public_key, 2, data, offset, inc, len, tlv_public_key_encode)
    return offset;
}

bool tlv_account_public_address_decode_tag(int tag, cryptonote::account_public_address &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_public_key_decode(target.m_spend_public_key, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_public_key_decode(target.m_view_public_key, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_account_public_address_decode(cryptonote::account_public_address &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_account_public_address_decode_tag)
    return true;
}


//cryptonote::account_keys
int tlv_account_keys_size(cryptonote::account_keys &target) {
    int ret = tlv_account_public_address_size() + TLV_HEADSIZE;
    ret += tlv_secret_key_size() + TLV_HEADSIZE;
    ret += tlv_secret_key_size() + TLV_HEADSIZE;
    return ret;
}

int tlv_account_keys_encode(cryptonote::account_keys &target, unsigned char *data, int len) {
    int offset = 0;
    int inc = 0;
    TLV_ENCODE_T(target.m_account_address, 1, data, offset, inc, len, tlv_account_public_address_encode)
    TLV_ENCODE_T(target.m_spend_secret_key, 2, data, offset, inc, len, tlv_secret_key_encode)
    TLV_ENCODE_T(target.m_view_secret_key, 3, data, offset, inc, len, tlv_secret_key_encode)
    return offset;
}

bool tlv_account_keys_decode_tag(int tag, cryptonote::account_keys &target, unsigned char *data, int inc) {
    bool flag = true;
    switch (tag) {
        case 1:
            flag = tlv_account_public_address_decode(target.m_account_address, data + TLV_VOFFSET, inc);
            break;
        case 2:
            flag = tlv_secret_key_decode(target.m_spend_secret_key, data + TLV_VOFFSET, inc);
            break;
        case 3:
            flag = tlv_secret_key_decode(target.m_view_secret_key, data + TLV_VOFFSET, inc);
            break;
    }
    return flag;
}

bool tlv_account_keys_decode(cryptonote::account_keys &target, unsigned char *data, int len) {
    TLV_DECODE_T(target, data, len, tlv_account_keys_decode_tag)
    return true;
}
#endif //MONERO_TLVSERIALIZER_CPP
