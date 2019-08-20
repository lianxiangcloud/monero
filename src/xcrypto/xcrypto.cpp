
#include <errno.h>
#include <vector>
#include <iostream>
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "device/device.hpp"
#include "mnemonics/electrum-words.h"
#include "cryptonote_basic/subaddress_index.h"
#include "common/base58.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "crypto/crypto-ops.h"

using namespace epee;

#include "convert.hpp"
#include "xcrypto.h"
#include "tlvserializer.hpp"

#define MAX_PUBKEY_COUNT (12)

// std::cerr << "xcrypto exception at " << __FUNCTION__  << " : " << e.what() << std::endl
#define EXCEPTION(e) errno = EINVAL; printf("xcrypto exception at %s() : %s\n", __FUNCTION__, e.what())
#define UNKNOW_EXCEPTION() errno = EINVAL; printf("xcrypto exception at %s()\n", __FUNCTION__)

static void fastLog0(std::string str, rct::key k) {
        // MLOG(el::Level::Info, str << (int)k[0] << (int)k[1] << (int)k[2] << (int)k[3]<< (int)k[4] << (int)k[5] << (int)k[6] << (int)k[7]<< (int)k[8] << (int)k[9] << (int)k[10] << (int)k[11]<< (int)k[12] << (int)k[13] << (int)k[14] << (int)k[15]<< (int)k[16] << (int)k[17] << (int)k[18] << (int)k[19]<< (int)k[20] << (int)k[21] << (int)k[22] << (int)k[23]<< (int)k[24] << (int)k[25] << (int)k[26] << (int)k[27]<< (int)k[28] << (int)k[29] << (int)k[30] << (int)k[31]);
        std::cout << str << (int)k[0] << (int)k[1] << (int)k[2] << (int)k[3]<< (int)k[4] << (int)k[5] << (int)k[6] << (int)k[7]<< (int)k[8] << (int)k[9] << (int)k[10] << (int)k[11]<< (int)k[12] << (int)k[13] << (int)k[14] << (int)k[15]<< (int)k[16] << (int)k[17] << (int)k[18] << (int)k[19]<< (int)k[20] << (int)k[21] << (int)k[22] << (int)k[23]<< (int)k[24] << (int)k[25] << (int)k[26] << (int)k[27]<< (int)k[28] << (int)k[29] << (int)k[30] << (int)k[31] << std::endl;
    }

//int crypto_ops::check_ring_signature(const hash &prefix_hash, const key_image &image,
//    const public_key *const *pubs, size_t pubs_count,
//    const signature *sig) {

int x_check_ring_signature(hash_t prefix_hash, key_image_t image, rct_keyV_t *pubs, signature_t *sig) {
    if (pubs->nums >= MAX_PUBKEY_COUNT) {
        return -2;
    }

    crypto::hash _prefix_hash;
    crypto::key_image _image;
    crypto::signature _sig;
    crypto::public_key _pubs[MAX_PUBKEY_COUNT];

    memcpy(_prefix_hash.data, (const void *) prefix_hash, X_HASH_SIZE);
    memcpy(_image.data, (const void *) image, X_HASH_SIZE);
    memcpy((void *) &_sig.c, (const void *) sig->c, X_HASH_SIZE);
    memcpy((void *) &_sig.r, (const void *) sig->r, X_HASH_SIZE);

    int i;
    for (i = 0; i < pubs->nums; i++) {
        memcpy(_pubs[i].data, pubs->v[i], X_HASH_SIZE);
    }

    std::vector<const crypto::public_key *> _pubs_v;
    for (i = 0; i < pubs->nums; i++) {
        _pubs_v.push_back((const crypto::public_key *) (&_pubs[i]));
    }

    if (crypto::check_ring_signature(_prefix_hash, _image, _pubs_v, &_sig))
        return 0;

    return -1;
}

//   void crypto_ops::generate_ring_signature(const hash &prefix_hash, const key_image &image,
//     const public_key *const *pubs, size_t pubs_count,
//     const secret_key &sec, size_t sec_index,
//     signature *sig) {

int x_generate_ring_signature(hash_t prefix_hash, key_image_t image, rct_keyV_t *pubs, p_rct_key_t sec, size_t sec_index, signature_t *sig) {
    if (pubs->nums == 0) {
        return -2;
    }

    crypto::hash _prefix_hash;
    crypto::key_image _image;
    crypto::public_key _pubs[MAX_PUBKEY_COUNT];
    crypto::secret_key _sec;
    crypto::signature _sig;

    memcpy(_prefix_hash.data, (const void *) prefix_hash, X_HASH_SIZE);
    memcpy(_image.data, (const void *) image, X_HASH_SIZE);
    memcpy(_sec.data, sec, X_HASH_SIZE);

    int i;
    crypto::public_key _pub;
    for (i = 0; i < pubs->nums; i++) {
        memcpy(_pubs[i].data, pubs->v[i], X_HASH_SIZE);
    }
    std::vector<const crypto::public_key *> _pubs_v;
    for (i = 0; i < pubs->nums; i++) {
        _pubs_v.push_back((const crypto::public_key *) (&_pubs[i]));
    }

    crypto::generate_ring_signature(_prefix_hash, _image, _pubs_v, _sec, sec_index, &_sig);
    memcpy((void *) sig->c, (const void *) &_sig.c, X_HASH_SIZE);
    memcpy((void *) sig->r, (const void *) &_sig.r,X_HASH_SIZE);
    return 0;
}

int x_cn_fast_hash(void *data, int len, hash_t result) {
    crypto::hash _result;
    crypto::cn_fast_hash(data, len, _result);
    memcpy((void *) result, (const void *) _result.data, X_HASH_SIZE);
    return 0;
}


int x_verRctNonSemanticsSimple(rct_sig_t *rv) {
    rct::rctSig _rv;
    x_from_rct_sig(rv, &_rv);

    int ret = rct::verRctNonSemanticsSimple(_rv);
    x_free_rct_sig(rv);
    return (ret ? 0 : -1);
}

int x_verRctSemanticsSimple(rct_sig_t *rv) {
    rct::rctSig _rv;
    x_from_rct_sig(rv, &_rv);

    if (rct::verRctSemanticsSimple(_rv))
        return 0;

    return -1;
}

int x_verRctSimple(rct_sig_t *rv) {
    rct::rctSig _rv;
    x_from_rct_sig(rv, &_rv);

    if (rct::verRctSimple(_rv))
        return 0;
    return -1;
}

//RingCT protocol
//genRct: 
//   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
//   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
//   Also contains masked "amount" and "mask" so the receiver can see how much they received
//verRct:
//   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
//decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
//   uses the attached ecdh info to find the amounts represented by each output commitment 
//   must know the destination private key to find the correct amount, else will return a random number    
int x_verRctWithSemantics(rct_sig *rv, int semantics) {
    rct::rctSig _rv;
    x_from_rct_sig(rv, &_rv);

    int ret = rct::verRct(_rv, (semantics == 0) ? false : true);
    x_free_rct_sig(rv);
    return (ret ? 0 : -1);
}

int x_verRct(rct_sig_t *rv) {
    rct::rctSig _rv;
    x_from_rct_sig(rv, &_rv);
    if (rct::verRct(_rv))
        return 0;

    return -1;
}

void x_zeroCommit(rct_key_t ret, long long unsigned amount) {
    try {
        rct::key _ret = rct::zeroCommit(amount);
        x_to_rct_key(ret, _ret);
    } catch(const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
}

int x_is_rct_bulletproof(int type) {
    return rct::is_rct_bulletproof(type) ? 0 : -1;
}

extern "C" void slow_hash_allocate_state();

void x_slow_hash_allocate_state(void) {
    slow_hash_allocate_state();
}

extern "C" void slow_hash_free_state();

void x_slow_hash_free_state(void) {
    slow_hash_free_state();
}

void x_cn_slow_hash(const void *data, int length, hash_t hash, int variant, uint64_t height) {
    crypto::hash _hash;
    crypto::cn_slow_hash(data, length, _hash, variant, height);
    memcpy((void *) hash, (const void *) _hash.data, X_HASH_SIZE);
}

void x_cn_slow_hash_prehashed(const void *data, int length, hash_t hash, int variant, uint64_t height) {
    crypto::hash _hash;
    crypto::cn_slow_hash_prehashed(data, length, _hash, variant, height);
    memcpy((void *) hash, (const void *) _hash.data, X_HASH_SIZE);
}

void x_scalarmultBase(rct_key_t aG, rct_key_t a) {
    rct::key _aG, _a;

    x_from_rct_key(a, _a);
    rct::scalarmultBase(_aG, _a);
    x_to_rct_key(aG, _aG);
}

void x_scalarmultKey(rct_key_t aP, rct_key_t P, rct_key_t a) {
    rct::key _aP, _P, _a;
    x_from_rct_key(P, _P);
    x_from_rct_key(a, _a);

    try {
        rct::scalarmultKey(_aP, _P, _a);
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
    x_to_rct_key(aP, _aP);
}

void x_scalarmultH(rct_key_t aH, rct_key_t a) {
    rct::key _ah, _a;

    x_from_rct_key(a, _a);
    _ah = rct::scalarmultH(_a);
    x_to_rct_key(aH, _ah);
}

void x_addKeys(rct_key_t ab, rct_key_t a, rct_key_t b) {
    rct::key _ab, _a, _b;
    x_from_rct_key(a, _a);
    x_from_rct_key(b, _b);

    try {
        rct::addKeys(_ab, _a, _b);
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
    x_to_rct_key(ab, _ab);
}

void x_addKeys2(rct_key_t aGbB, rct_key_t a, rct_key_t b,rct_key_t B){
    rct::key _aGbB, _a, _b,_B;
    x_from_rct_key(a, _a);
    x_from_rct_key(b, _b);
    x_from_rct_key(B, _B);

    try {
        rct::addKeys2(_aGbB,_a,_b,_B);
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
    x_to_rct_key(aGbB, _aGbB);
}

void x_skpkGen(rct_key_t sk, rct_key_t pk) {
    rct::key _sk, _pk;
    rct::skpkGen(_sk, _pk);
    x_to_rct_key(sk, _sk);
    x_to_rct_key(pk, _pk);
}

int x_checkKey(p_rct_key_t pk) {
    crypto::public_key _pk;
    x_from_public_key(pk, _pk);
    return crypto::check_key(_pk) ? 0 : -1;
}

// rctSig genRct(const key &message, const ctkeyV & inSk, const keyV & destinations, const vector<xmr_amount> & amounts, const ctkeyM &mixRing, 
// const keyV &amount_keys, const multisig_kLRki *kLRki, multisig_out *msout, unsigned int index, ctkeyV &outSk, const RCTConfig &rct_config, hw::device &hwdev) {

static inline hw::device &get_default_device() {
    static hw::device &dev = hw::get_device("default");
    return dev;
}

void
x_genRct(rct_key_t message, rct_ctkeyV_t *inSk, rct_keyV_t *destinations, amountV_t *amounts, rct_ctkeyM_t *mixRing,
         rct_keyV_t *amount_keys, rct_multisig_kLRki_t *kLRki, rct_multisig_out_t *msout, unsigned int index,
         rct_ctkeyV_t *outSk, RCTConfig_t *rct_config,
         rct_sig_t *rctSig) {
    rct::key _message;
    rct::ctkeyV _inSk;
    rct::keyV _destinations;
    std::vector<rct::xmr_amount> _amounts;
    rct::ctkeyM _mixRing;
    rct::keyV _amount_keys;
    rct::multisig_kLRki _kLRki;
    rct::multisig_out _msout;
    rct::ctkeyV _outSk;
    rct::RCTConfig _rct_config;

    hw::device &_hwdev = get_default_device();

    x_from_rct_key(message, _message);
    x_from_rct_ctkeyV(inSk, _inSk);
    x_from_rct_keyV(destinations, _destinations);
    if ((amounts != NULL) && (amounts->nums > 0)) {
        _amounts.reserve(amounts->nums);
        for (int index = 0; index < amounts->nums; index++) {
            _amounts.push_back((rct::xmr_amount) (amounts->v[index]));
        }
    }
    x_from_rct_ctkeyM(mixRing, _mixRing);
    x_from_rct_keyV(amount_keys, _amount_keys);
    x_from_rct_multisig_kLRki(kLRki, _kLRki);
    x_from_rct_keyV(msout, _msout.c);
    x_from_rct_ctkeyV(outSk, _outSk);
    _rct_config.bp_version = rct_config->bp_version;
    _rct_config.range_proof_type = (rct::RangeProofType) rct_config->range_proof_type;

    try {
        rct::rctSig _rctSig = rct::genRct(_message, _inSk, _destinations, _amounts, _mixRing, _amount_keys, &_kLRki,
                                        &_msout, index, _outSk, _rct_config, _hwdev);
        x_to_rct_sig(rctSig, &_rctSig);
        rctSig->cb(rctSig);
    } catch (const std::exception &e) {
        EXCEPTION(e);
        goto __finally;
    } catch (...) {
        UNKNOW_EXCEPTION();
        goto __finally;
    }

__finally:
    // @Note: release memory
    x_free_rct_sig(rctSig);
    x_free_rct_ctkeyV(inSk);
    x_free_rct_keyV(destinations);
    x_free_amountV(amounts);
    x_free_rct_ctkeyM(mixRing);
    x_free_rct_keyV(amount_keys);
}


// rctSig genRctSimple(const key &message, const ctkeyV & inSk, const keyV & destinations, const vector<xmr_amount> &inamounts, const vector<xmr_amount> &outamounts, 
//  xmr_amount txnFee, const ctkeyM & mixRing, const keyV &amount_keys, const std::vector<multisig_kLRki> *kLRki, multisig_out *msout, 
//  const std::vector<unsigned int> & index, ctkeyV &outSk, const RCTConfig &rct_config, hw::device &hwdev) {

void x_genRctSimple(rct_key_t message, rct_ctkeyV_t *inSk, rct_keyV_t *destinations, amountV_t *inamounts,
                    amountV_t *outamounts, uint64_t txnFee, rct_ctkeyM_t *mixRing, rct_keyV_t *amount_keys,
                    rct_multisig_kLRkiV_t *kLRki, rct_multisig_out_t *msout, indexV_t *index, rct_ctkeyV_t *outSk,
                    RCTConfig_t *rct_config, rct_sig_t *rctSig) {
    rct::key _message;
    rct::ctkeyV _inSk;
    rct::keyV _destinations;
    std::vector<rct::xmr_amount> _inamounts;
    std::vector<rct::xmr_amount> _outamounts;
    rct::xmr_amount _txnFee;
    rct::ctkeyM _mixRing;
    rct::keyV _amount_keys;
    std::vector<rct::multisig_kLRki> _kLRki;
    rct::multisig_out _msout; // out
    std::vector<unsigned int> _index;
    rct::ctkeyV _outSk; // out
    rct::RCTConfig _rct_config;

    hw::device &_hwdev = get_default_device();

    x_from_rct_key(message, _message);
    x_from_rct_ctkeyV(inSk, _inSk);
    x_from_rct_keyV(destinations, _destinations);
    x_from_amountV(inamounts, _inamounts);
    x_from_amountV(outamounts, _outamounts);
    _txnFee = txnFee;
    x_from_rct_ctkeyM(mixRing, _mixRing);
    x_from_rct_keyV(amount_keys, _amount_keys);
    // x_from_rct_multisig_kLRkiV(kLRki, _kLRki);
    // x_from_rct_keyV(msout, _msout.c);
    x_from_indexV(index, _index);
    x_from_rct_ctkeyV(outSk, _outSk);
    _rct_config.bp_version = rct_config->bp_version;
    _rct_config.range_proof_type = (rct::RangeProofType) rct_config->range_proof_type;

    try {
        rct::rctSig _rctSig = rct::genRctSimple(_message, _inSk, _destinations, _inamounts, _outamounts, _txnFee, _mixRing,
                                                _amount_keys, NULL, NULL, _index, _outSk, _rct_config, _hwdev);
        x_to_rct_sig(rctSig, &_rctSig);
        rctSig->cb(rctSig);
        x_to_rct_ctkeyV(outSk, _outSk);
    } catch (const std::exception &e) {
        EXCEPTION(e);
        goto __finally;
    } catch (...) {
        UNKNOW_EXCEPTION();
        goto __finally;
    }

__finally:
    // @Note: release memory
    x_free_rct_sig(rctSig);
    x_free_rct_ctkeyV(inSk);
    x_free_rct_keyV(destinations);
    x_free_amountV(inamounts);
    x_free_amountV(outamounts);
    x_free_rct_ctkeyM(mixRing);
    x_free_rct_keyV(amount_keys);
}

void x_free_rct_keyV(rct_keyV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

void x_free_rct_ctkeyV(rct_ctkeyV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

// bool words_to_bytes(const epee::wipeable_string &words, crypto::secret_key& dst, std::string &language_name)
int x_words_to_bytes(char *words, p_secret_key_t dst) {
    epee::wipeable_string _words((const char *) words);
    crypto::secret_key _dst;
    std::string _lang;
    if (!crypto::ElectrumWords::words_to_bytes(_words, _dst, _lang))
        return -1;
    x_to_secret_key(dst, _dst);
    return 0;
}

// bool bytes_to_words(const char *src, size_t len, epee::wipeable_string& words, const std::string &language_name);
int x_bytes_to_words(p_secret_key_t src, char **words, char *language_name) {
    epee::wipeable_string _words;
    std::string _lang(language_name);
    if (!crypto::ElectrumWords::bytes_to_words((char *) src, X_HASH_SIZE, _words, _lang))
        return -1;

    *words = (char *) malloc(_words.length());
    strcpy(*words, _words.data());
    return 0;
}


//   inline secret_key generate_keys(public_key &pub, secret_key &sec, const secret_key& recovery_key = secret_key(), bool recover = false)
void x_generate_keys(p_public_key_t pub, p_secret_key_t sec, p_secret_key_t recover_key) {
    crypto::public_key _pub;
    crypto::secret_key _sec;
    crypto::secret_key _recover_key;

    x_from_secret_key(recover_key, _recover_key);
    crypto::generate_keys(_pub, _sec, _recover_key, true);
    x_to_public_key(pub, _pub);
    x_to_secret_key(sec, _sec);
}

// bool  sc_secret_add(crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) override;
void x_sc_secret_add(p_secret_key_t r, p_secret_key_t a, p_secret_key_t b) {
    crypto::secret_key _r, _a, _b;
    x_from_secret_key(a, _a);
    x_from_secret_key(b, _b);
    get_default_device().sc_secret_add(_r, _a, _b);
    x_to_secret_key(r, _r);
}


//crypto::secret_key  get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) override;
void x_get_subaddress_secret_key(p_secret_key_t sec, uint32_t begin, p_secret_key_t sub_sec) {
    crypto::secret_key _sec;
    cryptonote::subaddress_index _index = {0, begin};

    x_from_secret_key(sec, _sec);
    crypto::secret_key _sub = get_default_device().get_subaddress_secret_key(_sec, _index);
    x_to_secret_key(sub_sec, _sub);
}


// cryptonote::account_public_address device_default::get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index)
void x_get_subaddress(account_keys_t *keys, uint32_t index, account_public_address_t *pub) {
    cryptonote::account_keys _keys;
    cryptonote::subaddress_index _index = {0, index};

    x_from_account_keys(keys, _keys);
    try {
        cryptonote::account_public_address _pub = get_default_device().get_subaddress(_keys, _index);
        x_to_account_public_address(pub, _pub);
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
}

// std::vector<crypto::public_key>  device_default::get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end)
void x_get_subaddress_spend_public_keys(account_keys_t *keys, uint32_t begin, uint32_t end, p_public_key_t *pubs) {
    cryptonote::account_keys _keys;
    x_from_account_keys(keys, _keys);

    try {
        std::vector<crypto::public_key> _pubs = get_default_device().get_subaddress_spend_public_keys(_keys, 0, begin, end);
        for (size_t i = 0; i < _pubs.size(); i++) {
            x_to_public_key(pubs[i], _pubs[i]);
        }
    } catch (const std::exception &e) {
        EXCEPTION(e);
    }
}

// std::string encode(const std::string& data);
char *x_base58_encode(char *data, int len) {
    std::string _data;
    _data.assign(data, len);
    std::string addr = tools::base58::encode(_data);
    char *p = (char *) malloc(addr.length());
    strcpy(p, addr.data());
    return p;
}

//bool decode(const std::string& enc, std::string& data);
char *x_base58_decode(char *addr, int *len) {
    std::string data;
    if (tools::base58::decode(std::string(addr), data)) {
        char *p = (char *) malloc(data.length());
        *len = data.length();
        memcpy(p, data.data(), data.length());
        return p;
    }

    return NULL;
}

//std::string encode_addr(uint64_t tag, const std::string& data);
char *x_base58_encode_addr(unsigned long long tag ,char *data, int len) {
    std::string _data;
    _data.assign(data, len);
    std::string addr = tools::base58::encode_addr(tag,_data);
    if (addr.length() == 0){
        return NULL;
    }
    char *p = (char *) malloc(addr.length());
    strcpy(p, addr.data());
    return p;
}
//std::string encode_addr(uint64_t tag, const std::string& data);
char *x_base58_decode_addr(unsigned long long *tag ,char *addr, int *len) {
    std::string _data;
    uint64_t _tag = (uint64_t)(*tag);
    if (tools::base58::decode_addr(std::string(addr),_tag,_data)){
        char *p = (char *) malloc(_data.length());
        *len = _data.length();
        memcpy(p, _data.data(), _data.length());
        *tag = _tag;
        return p;
    }
    return NULL;
}

//   inline bool generate_key_derivation(const public_key &key1, const secret_key &key2, key_derivation &derivation) {
int x_generate_key_derivation(p_public_key_t key1, p_secret_key_t key2, p_ec_point_t derivation) {
    crypto::public_key _key1;
    crypto::secret_key _key2;
    crypto::key_derivation _derivation;

    x_from_public_key(key1, _key1);
    x_from_secret_key(key2, _key2);
    if (!get_default_device().generate_key_derivation(_key1, _key2, _derivation)) {
        return -1;
    }

    x_to(derivation, (void *) (&_derivation.data[0]), X_HASH_SIZE);
    return 0;
}

// bool  derive_subaddress_public_key(const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index,  crypto::public_key &derived_pub) override;
int x_derive_subaddress_public_key(p_public_key_t pub, p_ec_point_t derivation, size_t output_index,
                                   p_public_key_t derived_pub) {
    crypto::public_key _pub;
    crypto::key_derivation _derivation;
    crypto::public_key _derived_pub;

    x_from_public_key(pub, _pub);
    x_from(derivation, (void *) (&_derivation.data[0]), X_HASH_SIZE);
    if (!get_default_device().derive_subaddress_public_key(_pub, _derivation, output_index, _derived_pub)) {
        return -1;
    }

    x_to_public_key(derived_pub, _derived_pub);
    return 0;
}


// bool  derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec,  crypto::secret_key &derived_sec) override;
int x_derive_secret_key(p_ec_point_t derivation, size_t output_index, p_secret_key_t sec, p_secret_key_t derived_sec) {
    crypto::key_derivation _derivation;
    crypto::secret_key _sec;
    crypto::secret_key _derived_sec;

    x_from(derivation, (void *) (&_derivation.data[0]), X_HASH_SIZE);
    x_from_secret_key(sec, _sec);
    if (!get_default_device().derive_secret_key(_derivation, output_index, _sec, _derived_sec))
        return -1;

    x_to(derived_sec, (void *) (&_derived_sec.data[0]), X_HASH_SIZE);
    return 0;
}

// bool  derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub,  crypto::public_key &derived_pub) override;
int x_derive_public_key(p_ec_point_t derivation, size_t output_index, p_public_key_t pub, p_public_key_t derived_pub) {
    crypto::key_derivation _derivation;
    crypto::public_key _pub;
    crypto::public_key _derived_pub;

    x_from(derivation, (void *) (&_derivation.data[0]), X_HASH_SIZE);
    x_from_public_key(pub, _pub);
    if (!get_default_device().derive_public_key(_derivation, output_index, _pub, _derived_pub))
        return -1;

    x_to_public_key(derived_pub, _derived_pub);
    return 0;
}

// bool  secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) override;
int x_secret_key_to_public_key(p_secret_key_t sec, p_public_key_t pub) {
    crypto::secret_key _sec;
    crypto::public_key _pub;

    x_from_secret_key(sec, _sec);
    if (!get_default_device().secret_key_to_public_key(_sec, _pub))
        return -1;

    x_to_public_key(pub, _pub);
    return 0;
}

// key hash_to_scalar(const keyV &keys)
void x_hash_to_scalar(rct_keyV_t *keys, p_rct_key_t key) {
    rct::keyV _keys;

    x_from_rct_keyV(keys, _keys);
    rct::key _key = rct::hash_to_scalar(_keys);
    x_to_rct_key(key, _key);
    x_free_rct_keyV(keys);
}

// bool  generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image) override;
int x_generate_key_image(p_public_key_t pub, p_secret_key_t sec, p_key_image_t image) {
    crypto::public_key _pub;
    crypto::secret_key _sec;
    crypto::key_image _image;

    x_from_public_key(pub, _pub);
    x_from_secret_key(sec, _sec);
    if (!get_default_device().generate_key_image(_pub, _sec, _image))
        return -1;

    x_to(image, (void *) (&_image.data[0]), X_HASH_SIZE);
    return 0;
}

// bool  derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) override;
int x_derivation_to_scalar(p_ec_point_t derivation, size_t output_index, p_ec_scalar_t res) {
    crypto::key_derivation _derivation;
    crypto::ec_scalar _res;

    x_from(derivation, (void *) (&_derivation.data[0]), X_HASH_SIZE);
    if (!get_default_device().derivation_to_scalar(_derivation, output_index, _res))
        return -1;

    x_to(res, (void *) (&_res.data[0]), X_HASH_SIZE);
    return 0;
}

// bool  ecdhDecode(rct::ecdhTuple & masked, const rct::key & sharedSec, bool short_amount)
int x_ecdh_decode(rct_ecdhTuple_t *masked, p_rct_key_t sharedSec, int short_amount) {
    rct::ecdhTuple _masked;
    rct::key _sharedSec;
    bool _short_amount = (short_amount == 0) ? false : true;

    x_from_rct_ecdhTuple(masked, _masked);
    x_from_rct_key(sharedSec, _sharedSec);
    if (!get_default_device().ecdhDecode(_masked, _sharedSec, _short_amount))
        return -1;

    x_to_rct_ecdhTuple(masked, _masked);
    return 0;
}

void x_scalarmult8(rct_key_t p, rct_key_t ret) {
    rct::key _p, _ret;
    x_from_rct_key(p, _p);
    try {
        _ret = rct::scalarmult8(_p);
        x_to_rct_key(ret, _ret);
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
}

void x_sc_add(ec_scalar_t s, ec_scalar_t a, ec_scalar_t b) {
    crypto::ec_scalar _s, _a, _b;
    x_from_ec_scalar_t(a, _a);
    x_from_ec_scalar_t(b, _b);
    sc_add((unsigned char *) (_s.data), (unsigned char *) (_a.data), (unsigned char *) (_b.data));
    x_to_ec_scalar_t(s, _s);
}

void x_sc_sub(ec_scalar_t s, ec_scalar_t a, ec_scalar_t b) {
    crypto::ec_scalar _s, _a, _b;
    x_from_ec_scalar_t(a, _a);
    x_from_ec_scalar_t(b, _b);
    sc_sub((unsigned char *) (_s.data), (unsigned char *) (_a.data), (unsigned char *) (_b.data));
    x_to_ec_scalar_t(s, _s);
}

void x_skGen(rct_key_t key) {
    rct::key k = rct::skGen();
    x_to_rct_key(key, k);
}

void x_genC(rct_key_t c, rct_key_t a, unsigned long long amount) {
    rct::key _c, _a;
    x_from_rct_key(a, _a);
    try {
        rct::genC(_c, _a, (rct::xmr_amount) amount);
        x_to_rct_key(c, _c);
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
}

int x_ecdh_encode(rct_ecdhTuple_t *unmasked, p_rct_key_t sharedSec, int short_amount) {
    rct::ecdhTuple _unmasked;
    rct::key _sharedSec;
    bool _short_amount = (short_amount == 0) ? false : true;

    x_from_rct_ecdhTuple(unmasked, _unmasked);
    x_from_rct_key(sharedSec, _sharedSec);
    if (!get_default_device().ecdhEncode(_unmasked, _sharedSec, _short_amount))
        return -1;
    x_to_rct_ecdhTuple(unmasked, _unmasked);
    return 0;
}
void x_get_pre_mlsag_hash(rct_key_t key,rct_sig_t *rv){
    rct::rctSig _rv;
    x_from_rct_sig(rv, &_rv);
    hw::device &_hwdev = get_default_device();

    try {
        rct::key _k = rct::get_pre_mlsag_hash(_rv, _hwdev);
        x_to_rct_key(key, _k);
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
}

//tlv-----------------------------------------------------
int tlv_verRctNotSemanticsSimple(unsigned char *raw, int in_len) {
    rct::rctSig _rv;
    if (!tlv_rctSig_decode(_rv, raw, in_len)) {
        return -1;
    }

    int ret = rct::verRctNonSemanticsSimple(_rv);
    return (ret ? 0 : -1);
}

int tlv_verRctSimple(unsigned char *raw, int in_len) {
    rct::rctSig rctSig;
    if (!tlv_rctSig_decode(rctSig, raw, in_len)) {
        return -1;
    }
    if (rct::verRctSimple(rctSig))
        return 1;
    return 0;
}

int tlv_ecdhEncode(unsigned char *raw, int in_len, unsigned char **out) {
    rct::ecdhTuple unmasked;
    rct::key sharedSec;
    bool short_amount;
    int offset = 0;
    while (offset < in_len) {
        int tag = parseTagOrLen(raw + offset + TLV_TAGOFFSET);
        int inc = parseTagOrLen(raw + offset + TLV_LENOFFSET);
        bool flag = true;
        switch (tag) {
            case 1:
                flag = tlv_ecdhTuple_decode(unmasked, raw + offset + TLV_VOFFSET, inc);
                break;
            case 2:
                flag = tlv_key_decode(sharedSec, raw + offset + TLV_VOFFSET, inc);
                break;
            case 3:
                flag = tlv_char_decode((char *) (&short_amount), raw + offset + TLV_VOFFSET, inc);
                break;
        }
        if (!flag) {
            return -1;
        }
        offset += TLV_HEADSIZE + inc;
    }
    if (offset != in_len) {
        return -1;
    }
    rct::ecdhEncode(unmasked, sharedSec, short_amount);
    int datalen = tlv_ecdhTuple_size();
    *out = (unsigned char *) malloc(datalen);
    if (-1 == tlv_ecdhTuple_encode(unmasked, *out, datalen)) {
        free(*out);
        return -1;
    }
    return datalen;
}

//keyV &C, keyV &masks, const std::vector<key> &amounts, const std::vector<key> &sk, hw::device &hwdev
int tlv_proveRangeBulletproof(unsigned char *raw, int in_len, unsigned char **out) {
    rct::keyV amounts;
    rct::keyV sk;
    rct::keyV C;
    rct::keyV masks;
    hw::device &_hwdev = get_default_device();
    int offset = 0;
    int inc = 0;
    while (offset < in_len) {
        int tag = parseTagOrLen(raw + offset + TLV_TAGOFFSET);
        inc = parseTagOrLen(raw + offset + TLV_LENOFFSET);
        bool flag = true;
        switch (tag) {
            case 1:
                flag = tlv_keyv_decode(amounts, raw + offset + TLV_VOFFSET, inc);
                break;
            case 2:
                flag = tlv_keyv_decode(sk, raw + offset + TLV_VOFFSET, inc);
                break;
        }
        if (!flag) {
            return -1;
        }
        offset += TLV_HEADSIZE + inc;
    }
    if (offset != in_len) {
        return -1;
    }

    int size = -1;
    try {
        rct::Bulletproof bulletproof = rct::proveRangeBulletproof(C, masks, amounts, sk, _hwdev);
        size =
              tlv_bulletproof_size(bulletproof) + TLV_HEADSIZE + tlv_keyv_size(C) + TLV_HEADSIZE + tlv_keyv_size(masks) +
              TLV_HEADSIZE;
        *out = (unsigned char *) malloc(size);
        offset = 0;
        inc = 0;
        TLV_ENCODE_T(C, 1, *out, offset, inc, size, tlv_keyv_encode)
        TLV_ENCODE_T(masks, 2, *out, offset, inc, size, tlv_keyv_encode)
        TLV_ENCODE_T(bulletproof, 3, *out, offset, inc, size, tlv_bulletproof_encode)
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }

    return size;
}

//keyV &C, keyV &masks, const std::vector<key> &amounts, const std::vector<key> &sk, hw::device &hwdev
int tlv_proveRangeBulletproof128(unsigned char *raw, int in_len, unsigned char **out) {
    rct::keyV amounts;
    rct::keyV sk;
    rct::keyV C;
    rct::keyV masks;
    hw::device &_hwdev = get_default_device();
    int offset = 0;
    int inc = 0;
    while (offset < in_len) {
        int tag = parseTagOrLen(raw + offset + TLV_TAGOFFSET);
        inc = parseTagOrLen(raw + offset + TLV_LENOFFSET);
        bool flag = true;
        switch (tag) {
            case 1:
                flag = tlv_keyv_decode(amounts, raw + offset + TLV_VOFFSET, inc);
                break;
            case 2:
                flag = tlv_keyv_decode(sk, raw + offset + TLV_VOFFSET, inc);
                break;
        }
        if (!flag) {
            return -1;
        }
        offset += TLV_HEADSIZE + inc;
    }
    if (offset != in_len) {
        return -1;
    }

    int size = -1;
    try {
        rct::Bulletproof bulletproof = rct::proveRangeBulletproof128(C, masks, amounts, sk, _hwdev);
        size =
            tlv_bulletproof_size(bulletproof) + TLV_HEADSIZE + tlv_keyv_size(C) + TLV_HEADSIZE + tlv_keyv_size(masks) +
            TLV_HEADSIZE;
        *out = (unsigned char *) malloc(size);
        offset = 0;
        inc = 0;
        TLV_ENCODE_T(C, 1, *out, offset, inc, size, tlv_keyv_encode)
        TLV_ENCODE_T(masks, 2, *out, offset, inc, size, tlv_keyv_encode)
        TLV_ENCODE_T(bulletproof, 3, *out, offset, inc, size, tlv_bulletproof_encode)
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }

    return size;
}

//mgSig proveRctMGSimple(const key & message, const ctkeyV & pubs, const ctkey & inSk, const key &a , const key &Cout, const multisig_kLRki *kLRki, key *mscout, unsigned int index, hw::device &hwdev);
int tlv_proveRctMGSimple(rct_key_t mscout, unsigned int index, unsigned char *raw, int in_len, unsigned char **out) {
    rct::key message;
    rct::ctkeyV pubs;
    rct::ctkey inSk;
    rct::key a;
    rct::key Cout;

    rct::key _mscout;
    rct::key *_mscout_p = NULL;
    rct::multisig_kLRki _kLRki;
    rct::multisig_kLRki *_kLRki_p = NULL;

    if (mscout != NULL) {
        x_from_rct_key(mscout, _mscout);
        _mscout_p = &_mscout;
    }

    hw::device &_hwdev = get_default_device();
    int offset = 0;
    int inc = 0;
    while (offset < in_len) {
        int tag = parseTagOrLen(raw + offset + TLV_TAGOFFSET);
        inc = parseTagOrLen(raw + offset + TLV_LENOFFSET);
        bool flag = true;
        switch (tag) {
            case 1:
                flag = tlv_key_decode(message, raw + offset + TLV_VOFFSET, inc);
                break;
            case 2:
                flag = tlv_ctkeyv_decode(pubs, raw + offset + TLV_VOFFSET, inc);
                break;
            case 3:
                flag = tlv_ctkey_decode(inSk, raw + offset + TLV_VOFFSET, inc);
                break;
            case 4:
                flag = tlv_key_decode(a, raw + offset + TLV_VOFFSET, inc);
                break;
            case 5:
                flag = tlv_key_decode(Cout, raw + offset + TLV_VOFFSET, inc);
                break;
            case 6:
                flag = tlv_multisig_kLRki_decode(_kLRki, raw + offset + TLV_VOFFSET, inc);
                _kLRki_p = &_kLRki;
                break;
        }
        if (!flag) {
            return -1;
        }
        offset += TLV_HEADSIZE + inc;
    }
    if (offset != in_len) {
        return -1;
    }

    try {
        rct::mgSig mgsig = rct::proveRctMGSimple(message, pubs, inSk, a, Cout, _kLRki_p, _mscout_p, index, _hwdev);
        int size = tlv_mgSig_size(mgsig);
        *out = (unsigned char *) malloc(size);
        if (-1 == tlv_mgSig_encode(mgsig, *out, size)) {
            free(*out);
            return -1;
        }
        if (_mscout_p != NULL) {
            x_to_rct_key(mscout, _mscout);
        }
        return size;
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
    return -1;
}

int tlv_get_pre_mlsag_hash(rct_key_t key, unsigned char *raw, int in_len) {
    rct::rctSig rctSig;
    if (!tlv_rctSig_decode(rctSig, raw, in_len)) {
        return -1;
    }

    try {
        hw::device &_hwdev = get_default_device();
        rct::key _k = rct::get_pre_mlsag_hash(rctSig, _hwdev);
        x_to_rct_key(key, _k);
        return 0;
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
    return -1;
}

int tlv_addKeyV(rct_key_t sum, unsigned char *raw, int in_len){
    rct::keyV _a;
    if (!tlv_keyv_decode(_a, raw, in_len)) {
        return -1;
    }

    try {
        rct::key _sum = rct::addKeys(_a);
        x_to_rct_key(sum, _sum);
        return 0;
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
    return -1;
}

int tlv_verBulletproof(unsigned char *raw, int in_len){
    rct::Bulletproof _a;
    if (!tlv_bulletproof_decode(_a, raw, in_len)) {
        return -1;
    }
    if (rct::verBulletproof(_a)){
        return 1;
    }else{
        return 0;
    }
}

int tlv_verBulletproof128(unsigned char *raw, int in_len){
    rct::Bulletproof _a;
    if (!tlv_bulletproof_decode(_a, raw, in_len)) {
        return -1;
    }
    if (rct::verBulletproof128(_a)){
        return 1;
    }else{
        return 0;
    }
}

int test_tlv_keyV(unsigned char *keyv_in, int keyv_in_len, unsigned char **keyv_out) {
    rct::keyV keyv;
    if (!tlv_keyv_decode(keyv, keyv_in, keyv_in_len)) {
        return -1;
    }
    int size = tlv_keyv_size(keyv);
    *keyv_out = (unsigned char *) malloc(size);
    if (-1 == tlv_keyv_encode(keyv, *keyv_out, size)) {
        return -1;
    }
    return size;
}

int test_tlv_rctsig(unsigned char *raw, int in_len, unsigned char **out) {
    rct::rctSig rctSig;
    if (!tlv_rctSig_decode(rctSig, raw, in_len)) {
        return -1;
    }
    int size = tlv_rctSig_size(rctSig);
    *out = (unsigned char *) malloc(size);
    if (-1 == tlv_rctSig_encode(rctSig, *out, size)) {
        return -1;
    }
    return size;
}

// cryptonote::account_public_address device_default::get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index)
int tlv_get_subaddress(uint32_t index, unsigned char *raw, int in_len, unsigned char **out) {
    cryptonote::account_keys _keys;
    cryptonote::subaddress_index _index = {0, index};
    tlv_account_keys_decode(_keys, raw, in_len);

    try {
        cryptonote::account_public_address _pub = get_default_device().get_subaddress(_keys, _index);
        int size = tlv_account_public_address_size();
        *out = (unsigned char *) malloc(size);
        if (-1 == tlv_account_public_address_encode(_pub, *out, size)) {
            free(*out);
            return -1;
        }
        return size;
    } catch (const std::exception &e) {
        EXCEPTION(e);
    } catch (...) {
        UNKNOW_EXCEPTION();
    }
    return -1;
}
