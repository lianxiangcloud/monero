#ifndef _X_CRYPTO_CONVERT_H_
#define _X_CRYPTO_CONVERT_H_

#include "xcrypto.h"
#include "ringct/rctTypes.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/account.h"
#include <vector>
#include "crypto/crypto.h"

inline void x_to(void *to, void *from, size_t n) {
    memcpy(to, from, n);
}

inline void x_from(void *from, void *to, size_t n) {
    memcpy(to, from, n);
}


inline void x_to_public_key(p_public_key_t to, crypto::public_key &from) {
    memcpy(to, (const void *)from.data, X_HASH_SIZE); 
}

inline void x_to_p_public_key_t(p_public_key_t *to, crypto::public_key &from) {
    *to = (char *)(&from.data[0]);
}

inline void x_from_public_key(p_public_key_t from, crypto::public_key &to) {
    memcpy((void *)to.data, (const void *)from, X_HASH_SIZE);
}

inline void x_to_secret_key(p_secret_key_t to, crypto::secret_key &from) {
    memcpy(to, (const void *)from.data, X_HASH_SIZE);
}

inline void x_from_secret_key(p_secret_key_t from, crypto::secret_key &to) {
    memcpy((void *)to.data, (const void *)from, X_HASH_SIZE);
}

inline void x_to_rct_key(rct_key_t to, rct::key &from) {
    memcpy((void *)to, (const void *)from.bytes, X_HASH_SIZE);
}
inline void x_to_ec_scalar_t(ec_scalar_t to, crypto::ec_scalar &from) {
    memcpy((void *)to, (const void *)from.data, X_HASH_SIZE);
}
inline void x_from_ec_scalar_t(ec_scalar_t from, crypto::ec_scalar &to) {
    memcpy((void *)to.data,(const void *)from,  X_HASH_SIZE);
}
inline void x_to_account_public_address(account_public_address_t *to, cryptonote::account_public_address &from) {
    x_to_public_key(to->spend, from.m_spend_public_key);
    x_to_public_key(to->view, from.m_view_public_key);
}

inline void x_from_account_keys(account_keys_t *from, cryptonote::account_keys& to) {
    x_from_public_key(from->address.spend, to.m_account_address.m_spend_public_key);
    x_from_public_key(from->address.view, to.m_account_address.m_view_public_key);
    x_from_secret_key(from->spend, to.m_spend_secret_key);
    x_from_secret_key(from->view, to.m_view_secret_key);
}

// @Note: todo ywh.
inline void x_to_p_rct_key(p_rct_key_t *to, rct::key &from) {
    *to = (char *)(&from.bytes[0]);
}

inline void x_from_rct_key(rct_key_t from, rct::key &to) {
    memcpy((void *)to.bytes, (const void *)from, X_HASH_SIZE);
}

inline void x_free_rct_key(rct_key_t xx) {}

// --------------------------------------------------------

inline void x_to_rct_key64(rct_key64_t to, rct::key64 from) {
    for (int i = 0; i < 64; i++) {
        x_to_p_rct_key(&to[i], from[i]);
    }
}

inline void x_from_rct_key64(rct_key64_t from, rct::key64 to) {
    for (int i = 0; i < 64; i++) {
        x_from_rct_key(from[i], to[i]);
    }
}

inline void x_free_rct_key64(rct_key64_t xx) {}

// --------------------------------------------------------

inline void x_to_rct_keyV(rct_keyV_t *to, rct::keyV &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (p_rct_key_t *)malloc(to->nums * sizeof(p_rct_key_t));

        int index = 0;
        for (index = 0; index < to->nums; index++) {
            x_to_p_rct_key(&to->v[index], from[index]);
            // to->v[index] = (p_rct_key_t)&from[index]; 
        }
    }
}

inline void x_from_rct_keyV(rct_keyV_t *from, rct::keyV &to) {
    to.reserve(from->nums);
    rct::key tmp;
    for (int index = 0; index < from->nums; index++) {
        x_from_rct_key(from->v[index], tmp);
        to.push_back(tmp);
    }
}

// inline void x_free_rct_keyV(rct_keyV_t *xx) {
//     if (xx->nums > 0)
//         free(xx->v);
// }

// --------------------------------------------------------

inline void x_to_rct_keyM(rct_keyM_t *to, rct::keyM &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->m = (rct_keyV_t *)malloc(to->nums * sizeof(rct_keyV_t));

        int index = 0;
        for (index = 0; index < to->nums; index++) {
            x_to_rct_keyV(&to->m[index], from[index]);
        }
    }
}

inline void x_from_rct_keyM(rct_keyM_t *from, rct::keyM &to) {
    to.reserve(from->nums);
    for (int index = 0; index < from->nums; index++) {
        rct::keyV tmp;
        x_from_rct_keyV(&from->m[index], tmp);
        to.push_back(tmp);
    }
}

inline void x_free_rct_keyM(rct_keyM_t *xx) {
    if (xx->nums > 0) {
        for (int index = 0; index < xx->nums; index++) {
            x_free_rct_keyV(&xx->m[index]);
        }
        free(xx->m);
    }
}

// --------------------------------------------------------

inline void x_to_rct_ctkey(rct_ctkey_t *to, rct::ctkey &from) {
/*
    rct_key_t dest;
    rct_key_t mask; //C here if public
 */
    x_to_p_rct_key(&to->dest, from.dest);
    x_to_p_rct_key(&to->mask, from.mask);
}

inline void x_from_rct_ctkey(rct_ctkey_t *from, rct::ctkey &to) {
    x_from_rct_key(from->dest, to.dest);
    x_from_rct_key(from->mask, to.mask);
}

inline void x_free_rct_ctkey(rct_ctkey_t *xx) {
    // x_free_rct_key(xx->dest);
    // x_free_rct_key(xx->mask);
}

// --------------------------------------------------------

inline void x_to_rct_ctkeyV(rct_ctkeyV_t *to, rct::ctkeyV &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (rct_ctkey_t *)malloc(to->nums * sizeof(rct_ctkey_t));

        int index = 0;
        for (index = 0; index < to->nums; index++) {
            x_to_rct_ctkey(&to->v[index], from[index]);
            // to->v[index] = (rct_ctkey_t *)&from[index];
        }
    }
}

inline void x_from_rct_ctkeyV(rct_ctkeyV_t *from, rct::ctkeyV &to) {
    to.reserve(from->nums);
    rct::ctkey tmp;
    for (int index = 0; index < from->nums; index++) {
        x_from_rct_ctkey(&from->v[index], tmp);
        to.push_back(tmp);
    }
}

// inline void x_free_rct_ctkeyV(rct_ctkeyV_t *xx) {
//     if (xx->nums > 0)
//         free(xx->v);
// }

// --------------------------------------------------------

inline void x_to_rct_ctkeyM(rct_ctkeyM_t *to, rct::ctkeyM &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->m = (rct_ctkeyV_t *)malloc(to->nums * sizeof(rct_ctkeyV_t));

        int index = 0;
        for (index = 0; index < to->nums; index++) {
            x_to_rct_ctkeyV(&to->m[index], from[index]);
        }
    }
}

inline void x_from_rct_ctkeyM(rct_ctkeyM_t *from, rct::ctkeyM &to) {
    to.reserve(from->nums);
    for (int index = 0; index < from->nums; index++) {
        rct::ctkeyV tmp;
        x_from_rct_ctkeyV(&from->m[index], tmp);
        to.push_back(tmp);
    }
}

inline void x_free_rct_ctkeyM(rct_ctkeyM_t *xx) {
    if (xx->nums > 0) {
        for (int index = 0; index < xx->nums; index++) {
            x_free_rct_ctkeyV(&xx->m[index]);
        }
        free(xx->m);
    }
}

// --------------------------------------------------------

inline void x_to_rct_ecdhTuple(rct_ecdhTuple_t *to, rct::ecdhTuple &from) {
/*
    rct_key_t mask;
    rct_key_t amount;
 */
    x_to_rct_key(to->mask, from.mask);
    x_to_rct_key(to->amount, from.amount);
}

inline void x_from_rct_ecdhTuple(rct_ecdhTuple_t *from, rct::ecdhTuple &to) {
    x_from_rct_key(from->mask, to.mask);
    x_from_rct_key(from->amount, to.amount);
}

inline void x_free_rct_ecdhTuple(rct_ecdhTuple_t *xx) {
    // x_free_rct_key(xx->mask);
    // x_free_rct_key(xx->amount);
}

// --------------------------------------------------------

inline void x_to_rct_ecdhTupleV(rct_ecdhTupleV_t *to, std::vector<rct::ecdhTuple> &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (rct_ecdhTuple_t *)malloc(to->nums * sizeof(rct_ecdhTuple_t));

        int index = 0;
        for (index = 0; index < to->nums; index++) {
            x_to_rct_ecdhTuple(&to->v[index], from[index]);
            // to->v[index] = (rct_ecdhTuple_t *)&from[index];
        }
    }
}

inline void x_from_rct_ecdhTupleV(rct_ecdhTupleV_t *from, std::vector<rct::ecdhTuple> &to) {
    to.reserve(from->nums);
    rct::ecdhTuple tmp;
    for (int index = 0; index < from->nums; index++) {
        x_from_rct_ecdhTuple(&from->v[index], tmp);
        to.push_back(tmp);
    }
}

inline void x_free_rct_ecdhTupleV(rct_ecdhTupleV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

// --------------------------------------------------------

inline void x_to_rct_base(rct_sigbase_t *to, rct::rctSigBase *from) {
/*
    uint8_t type;
    rct_key_t message;
    rct_ctkeyM_t mixRing; //the set of all pubkeys / copy
    //pairs that you mix with
    rct_keyV_t pseudoOuts; //C - for simple rct
    rct_ecdhTypleV_t ecdhInfo;
    rct_ctkeyV_t outPk;
    uint64_t txnFee; // contains b

 */
    to->Type = from->type;
    x_to_p_rct_key(&to->message, from->message);
    x_to_rct_ctkeyM(&to->mixRing, from->mixRing);

    x_to_rct_keyV(&to->pseudoOuts, from->pseudoOuts);
    x_to_rct_ecdhTupleV(&to->ecdhInfo, from->ecdhInfo);
    x_to_rct_ctkeyV(&to->outPk, from->outPk);
    to->txnFee = from->txnFee;
}

inline void x_from_rct_base(rct_sigbase_t *from, rct::rctSigBase *to) {
    to->type = from->Type;
    x_from_rct_key(from->message, to->message);
    x_from_rct_ctkeyM(&from->mixRing, to->mixRing);

    x_from_rct_keyV(&from->pseudoOuts, to->pseudoOuts);
    x_from_rct_ecdhTupleV(&from->ecdhInfo, to->ecdhInfo);
    x_from_rct_ctkeyV(&from->outPk, to->outPk);
    to->txnFee = from->txnFee;
}

inline void x_free_rct_base(rct_sigbase_t *xx) {
    x_free_rct_key(xx->message);
    x_free_rct_ctkeyM(&xx->mixRing);

    x_free_rct_keyV(&xx->pseudoOuts);
    x_free_rct_ecdhTupleV(&xx->ecdhInfo);
    x_free_rct_ctkeyV(&xx->outPk);
}

// --------------------------------------------------------

inline void x_to_rct_boroSig(rct_boroSig_t *to, rct::boroSig &from) {
/*
    rct_key64_t s0;
    rct_key64_t s1;
    rct_key_t ee;
 */

    x_to_rct_key64(to->s0, from.s0);
    x_to_rct_key64(to->s1, from.s1);
    x_to_p_rct_key(&to->ee, from.ee);
}

inline void x_from_rct_boroSig(rct_boroSig_t *from, rct::boroSig &to) {
    x_from_rct_key64(from->s0, to.s0);
    x_from_rct_key64(from->s1, to.s1);
    x_from_rct_key(from->ee, to.ee);
}

inline void x_free_rct_boroSig(rct_boroSig_t *xx) {
    x_free_rct_key64(xx->s0);
    x_free_rct_key64(xx->s1);
    x_free_rct_key(xx->ee);
}

// --------------------------------------------------------

inline void x_to_rct_rangeSig(rct_rangeSig_t *to, rct::rangeSig &from) {
/*
    rct_boroSig_t asig;
    rct_key64_t Ci;
*/
    x_to_rct_boroSig(&to->asig, from.asig);
    x_to_rct_key64(to->Ci, from.Ci);
}

inline void x_from_rct_rangeSig(rct_rangeSig_t *from, rct::rangeSig &to) {
    x_from_rct_boroSig(&from->asig, to.asig);
    x_from_rct_key64(from->Ci, to.Ci);
}

inline void x_free_rct_rangeSig(rct_rangeSig_t *xx) {
    x_free_rct_boroSig(&xx->asig);
    x_free_rct_key64(xx->Ci);
}

// --------------------------------------------------------

inline void x_to_rct_rangeSigV(rct_rangeSigV_t *to, std::vector<rct::rangeSig> &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (rct_rangeSig_t *)malloc(to->nums * sizeof(rct_rangeSig_t));

        int index = 0;
        for (index = 0; index < to->nums; index++) {
            x_to_rct_rangeSig(&to->v[index], from[index]);
        }
    }
}

inline void x_from_rct_rangeSigV(rct_rangeSigV_t *from, std::vector<rct::rangeSig> &to) {
    to.reserve(from->nums);
    for (int index = 0; index < from->nums; index++) {
        rct::rangeSig tmp;
        x_from_rct_rangeSig(&from->v[index], tmp);
        to.push_back(tmp);
    }
}

inline void x_free_rct_rangeSigV(rct_rangeSigV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

// --------------------------------------------------------

inline void x_to_rct_bulletproof(rct_bulletproof_t *to, rct::Bulletproof &from) {
/*
    rct_keyV_t V;
    rct_key_t A, S, T1, T2;
    rct_key_t taux, mu;
    rct_keyV_t L, R;
    rct_key_t a, b, t;
*/

    x_to_rct_keyV(&to->V, from.V);
    x_to_p_rct_key(&to->A, from.A);
    x_to_p_rct_key(&to->S, from.S);
    x_to_p_rct_key(&to->T1, from.T1);
    x_to_p_rct_key(&to->T2, from.T2);
    x_to_p_rct_key(&to->taux, from.taux);
    x_to_p_rct_key(&to->mu, from.mu);

    x_to_rct_keyV(&to->L, from.L);
    x_to_rct_keyV(&to->R, from.R);

    x_to_p_rct_key(&to->a, from.a);
    x_to_p_rct_key(&to->b, from.b);
    x_to_p_rct_key(&to->t, from.t);
}

inline void x_from_rct_bulletproof(rct_bulletproof_t *from, rct::Bulletproof &to) {
    x_from_rct_keyV(&from->V, to.V);
    x_from_rct_key(from->A, to.A);
    x_from_rct_key(from->S, to.S);
    x_from_rct_key(from->T1, to.T1);
    x_from_rct_key(from->T2, to.T2);
    x_from_rct_key(from->taux, to.taux);
    x_from_rct_key(from->mu, to.mu);

    x_from_rct_keyV(&from->L, to.L);
    x_from_rct_keyV(&from->R, to.R);

    x_from_rct_key(from->a, to.a);
    x_from_rct_key(from->b, to.b);
    x_from_rct_key(from->t, to.t);
}

inline void x_free_rct_bulletproof(rct_bulletproof_t *xx) {
    x_free_rct_keyV(&xx->V);
    x_free_rct_keyV(&xx->L);
    x_free_rct_keyV(&xx->R);
}

// --------------------------------------------------------

inline void x_to_rct_bulletproofV(rct_bulletproofV_t *to, std::vector<rct::Bulletproof> &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (rct_bulletproof_t *)malloc(to->nums * sizeof(rct_bulletproof_t));

        for (int index = 0; index < to->nums; index++) {
            x_to_rct_bulletproof(&to->v[index], from[index]);
        } 
    }
}

inline void x_from_rct_bulletproofV(rct_bulletproofV_t *from, std::vector<rct::Bulletproof> &to) {
    to.reserve(from->nums);
    for (int index = 0; index < from->nums; index++) {
        rct::Bulletproof tmp;
        x_from_rct_bulletproof(&from->v[index], tmp);
        to.push_back(tmp);
    }
}

inline void x_free_rct_bulletproofV(rct_bulletproofV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

// --------------------------------------------------------

inline void x_to_rct_mgSig(rct_mgSig_t *to, rct::mgSig &from) {
/*
    rct_keyM_t ss;
    rct_key_t cc;
    rct_keyV_t II;
*/
    x_to_rct_keyM(&to->ss, from.ss);
    x_to_p_rct_key(&to->cc, from.cc);
    x_to_rct_keyV(&to->II, from.II);
}

inline void x_from_rct_mgSig(rct_mgSig_t *from, rct::mgSig &to) {
    x_from_rct_keyM(&from->ss, to.ss);
    x_from_rct_key(from->cc, to.cc);
    x_from_rct_keyV(&from->II, to.II);
}

inline void x_free_rct_mgSig(rct_mgSig_t *xx) {
    x_free_rct_keyM(&xx->ss);
    x_free_rct_keyV(&xx->II);
}

// --------------------------------------------------------

inline void x_to_rct_mgSigV(rct_mgSigV_t *to, std::vector<rct::mgSig> &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (rct_mgSig_t *)malloc(to->nums * (sizeof(rct_mgSig_t)));

        int index = 0;
        for (index = 0; index < to->nums; index++) {
            x_to_rct_mgSig(&to->v[index], from[index]);
        }
    }
}

inline void x_from_rct_mgSigV(rct_mgSigV_t *from, std::vector<rct::mgSig> &to) {
    to.reserve(from->nums);
    for (int index = 0; index < from->nums; index++) {
        rct::mgSig tmp;
        x_from_rct_mgSig(&from->v[index], tmp);
        to.push_back(tmp);
    }
}

inline void x_free_rct_mgSigV(rct_mgSigV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

// --------------------------------------------------------

inline void x_to_rct_sig_prunable(rct_sig_prunable_t *to, rct::rctSigPrunable &from) {
/* 
    rct_rangeSigV_t rangeSigs;
    rct_bulletproofV_t bulletproofs;
    rct_mgSigV_t MGs; // simple rct has N, full has 1
    rct_keyV_t pseudoOuts; //C - for simple rct
 */

    x_to_rct_rangeSigV(&to->rangeSigs, from.rangeSigs);
    x_to_rct_bulletproofV(&to->bulletproofs, from.bulletproofs);
    x_to_rct_mgSigV(&to->MGs, from.MGs);
    x_to_rct_keyV(&to->pseudoOuts, from.pseudoOuts);
}

inline void x_from_rct_sig_prunable(rct_sig_prunable_t *from, rct::rctSigPrunable &to) {
    x_from_rct_rangeSigV(&from->rangeSigs, to.rangeSigs);
    x_from_rct_bulletproofV(&from->bulletproofs, to.bulletproofs);
    x_from_rct_mgSigV(&from->MGs, to.MGs);
    x_from_rct_keyV(&from->pseudoOuts, to.pseudoOuts);
}

inline void x_free_rct_sig_prunable(rct_sig_prunable_t *xx) {
    x_free_rct_rangeSigV(&xx->rangeSigs);
    x_free_rct_bulletproofV(&xx->bulletproofs);
    x_free_rct_mgSigV(&xx->MGs);
    x_free_rct_keyV(&xx->pseudoOuts);
}

// --------------------------------------------------------

inline void x_to_rct_sig(rct_sig_t *to, rct::rctSig *from) {
    x_to_rct_base(&to->base, (rct::rctSigBase *)from);
    x_to_rct_sig_prunable(&to->p, from->p);
}

inline void x_from_rct_sig(rct_sig_t *from, rct::rctSig *to) {
    x_from_rct_base(&from->base, (rct::rctSigBase *)to);
    x_from_rct_sig_prunable(&from->p, to->p);
}

inline void x_free_rct_sig(rct_sig_t *xx) {
    x_free_rct_base(&xx->base);
    x_free_rct_sig_prunable(&xx->p);
}

// --------------------------------------------------------

inline void x_to_rct_multisig_kLRki(rct_multisig_kLRki_t *to, rct::multisig_kLRki &from) {
/*
    rct_key_t k;
    rct_key_t L;
    rct_key_t R;
    rct_key_t ki;

 */
    x_to_p_rct_key(&to->k, from.k);
    x_to_p_rct_key(&to->L, from.L);
    x_to_p_rct_key(&to->R, from.R);
    x_to_p_rct_key(&to->ki, from.ki);
}

inline void x_from_rct_multisig_kLRki(rct_multisig_kLRki_t *from, rct::multisig_kLRki &to) {
    x_from_rct_key(from->k, to.k);
    x_from_rct_key(from->L, to.L);
    x_from_rct_key(from->R, to.R);
    x_from_rct_key(from->ki, to.ki);
}

// ---------------------------------------------------------

inline void x_to_rct_multisig_kLRkiV(rct_multisig_kLRkiV_t *to, std::vector<rct::multisig_kLRki>& from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (rct_multisig_kLRki_t *)malloc(to->nums * sizeof(rct_multisig_kLRki_t));
        for (int index = 0; index < to->nums; index++) {
            x_to_rct_multisig_kLRki(&to->v[index], from[index]);
        }
    }
}

inline void x_from_rct_multisig_kLRkiV(rct_multisig_kLRkiV_t *from, std::vector<rct::multisig_kLRki>& to) {
    to.reserve(from->nums);
    for (int index = 0; index < from->nums; index++) {
        rct::multisig_kLRki tmp;
        x_from_rct_multisig_kLRki(&from->v[index], tmp);
        to.push_back(tmp);
    }
}

inline void x_free_rct_multisig_kLRkiV(rct_multisig_kLRkiV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

// --------------------------------------------------------

inline void x_to_amountV(amountV_t *to, std::vector<rct::xmr_amount> &from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (uint64_t *)malloc(to->nums * sizeof(uint64_t));
        for (int index = 0; index < to->nums; index++) {
            to->v[index] = from[index];
        }
    }
}

inline void x_from_amountV(amountV_t *from, std::vector<rct::xmr_amount> &to) {
    to.reserve(from->nums);
    for (int index = 0; index < from->nums; index++) {
        to.push_back(from->v[index]);
    }
}

inline void x_free_amountV(amountV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

// --------------------------------------------------------

inline void x_to_indexV(indexV_t *to, std::vector<unsigned int>& from) {
    to->nums = from.size();
    if (to->nums > 0) {
        to->v = (unsigned int *)malloc(to->nums * sizeof(unsigned int));
        for (int index = 0; index < to->nums; index++) {
            to->v[index] = from[index];
        }
    }
}

inline void x_from_indexV(indexV_t *from, std::vector<unsigned int>& to) {
    to.reserve(from->nums);
    for (int index = 0; index < from->nums; index++) {
        to.push_back(from->v[index]);
    }
}

inline void x_free_indexV(indexV_t *xx) {
    if (xx->nums > 0)
        free(xx->v);
}

// --------------------------------------------------------

#endif