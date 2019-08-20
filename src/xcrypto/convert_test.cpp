#include "convert.hpp"
void testc_rct_key(rct_key_t from, test_rct_key_t *to) {
    rct::key tmp;
    x_from_rct_key(from, tmp);
    x_to_p_rct_key(&to->data, tmp);
    to->cb(to);

    x_free_rct_key(from);
    x_free_rct_key(to->data);
}

void testc_rct_keyV(rct_keyV_t *from, test_rct_keyV_t *to) {
    rct::keyV tmp;
    x_from_rct_keyV(from, tmp);
    x_to_rct_keyV(&to->data, tmp);
    to->cb(to);

    x_free_rct_keyV(from);
    x_free_rct_keyV(&to->data);
}

void testc_rct_keyM(rct_keyM_t *from, test_rct_keyM_t *to) {
    rct::keyM tmp;
    x_from_rct_keyM(from, tmp);
    x_to_rct_keyM(&to->data, tmp);
    to->cb(to);

    x_free_rct_keyM(from);
    x_free_rct_keyM(&to->data);
}

void testc_rct_ctkey(rct_ctkey_t *from, test_rct_ctkey_t *to) {
    rct::ctkey tmp;
    x_from_rct_ctkey(from, tmp);
    x_to_rct_ctkey(&to->data, tmp);
    to->cb(to);

    x_free_rct_ctkey(from);
    x_free_rct_ctkey(&to->data);
}

void testc_rct_ctkeyV(rct_ctkeyV_t *from, test_rct_ctkeyV_t *to) {
    rct::ctkeyV tmp;
    x_from_rct_ctkeyV(from, tmp);
    x_to_rct_ctkeyV(&to->data, tmp);
    to->cb(to);

    x_free_rct_ctkeyV(from);
    x_free_rct_ctkeyV(&to->data);
}

void testc_rct_ctkeyM(rct_ctkeyM_t *from, test_rct_ctkeyM_t *to) {
    rct::ctkeyM tmp;
    x_from_rct_ctkeyM(from, tmp);
    x_to_rct_ctkeyM(&to->data, tmp);
    to->cb(to);

    x_free_rct_ctkeyM(from);
    x_free_rct_ctkeyM(&to->data);
}

void testc_rct_sigbase(rct_sigbase_t *from, test_rct_sigbase_t *to) {
    rct::rctSigBase tmp;
    x_from_rct_base(from, &tmp);
    x_to_rct_base(&to->data, &tmp);
    to->cb(to);
}

void testc_rct_sig_prunable(rct_sig_prunable_t *from, test_rct_sig_prunable_t *to) {
    rct::rctSigPrunable tmp;
    x_from_rct_sig_prunable(from, tmp);
    x_to_rct_sig_prunable(&to->data, tmp);
    to->cb(to);

    x_free_rct_sig_prunable(from);
    x_free_rct_sig_prunable(&to->data);
}

void testc_rct_multisig_kLRkiV(rct_multisig_kLRkiV_t *from, test_rct_multisig_kLRkiV_t *to) {
    std::vector<rct::multisig_kLRki> tmp;
    x_from_rct_multisig_kLRkiV(from, tmp);
    x_to_rct_multisig_kLRkiV(&to->data, tmp);
    to->cb(to);

    x_free_rct_multisig_kLRkiV(from);
    x_free_rct_multisig_kLRkiV(&to->data);
}

void testc_rct_sig(rct_sig_t *from, rct_sig_t *to) {
    rct::rctSig tmp;
    x_from_rct_sig(from, &tmp);
    x_to_rct_sig(to, &tmp);
    to->cb(to);

    x_free_rct_sig(from);
    x_free_rct_sig(to);
}

