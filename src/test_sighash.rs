//! Unit tests for input sighash classification (`is_all_anyonecanpay_input`).
//!
//! Signature *validity* is never checked (the miniscript interpreter runs with
//! `iter_assume_sigs`), so fixtures use structurally valid but cryptographically
//! meaningless signatures: any DER-parseable ECDSA sig and any 64-byte schnorr
//! sig works. Taproot script-path fixtures must still be structurally real
//! because the interpreter verifies the control block commitment against the
//! prevout script_pubkey.

use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGADD, OP_EQUAL, OP_EQUALVERIFY, OP_NUMEQUAL, OP_SHA256, OP_SIZE,
};
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::secp256k1::{
    Keypair, PublicKey as SecpPublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bdk_wallet::bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bdk_wallet::bitcoin::{OutPoint, PublicKey, ScriptBuf, Sequence, TxIn, Witness};

use crate::is_all_anyonecanpay_input;

/// SIGHASH_ALL (0x01) | SIGHASH_ANYONECANPAY (0x80)
const ALL_ACP: u8 = 0x81;
/// SIGHASH_ALL without ANYONECANPAY
const ALL: u8 = 0x01;

/// DER-encoded ECDSA signature (r=1, s=1) with the given sighash byte appended.
fn ecdsa_sig(sighash: u8) -> [u8; 9] {
    [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, sighash]
}

/// 64-byte schnorr signature with an optional explicit sighash byte.
fn schnorr_sig(sighash: Option<u8>) -> Vec<u8> {
    let mut sig = vec![0x42; 64];
    if let Some(byte) = sighash {
        sig.push(byte);
    }
    sig
}

fn txin(script_sig: ScriptBuf, witness: Vec<Vec<u8>>) -> TxIn {
    TxIn {
        previous_output: OutPoint::null(),
        script_sig,
        witness: Witness::from_slice(&witness),
        sequence: Sequence::MAX,
    }
}

fn check(input: &TxIn, spk: &ScriptBuf) -> bool {
    is_all_anyonecanpay_input(input, spk, LockTime::ZERO)
}

fn pubkey(seed: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    PublicKey::new(SecpPublicKey::from_secret_key(&secp, &sk))
}

fn xonly_pubkey(seed: u8) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &sk);
    XOnlyPublicKey::from_keypair(&keypair).0
}

/// Builds (prevout_spk, control_block, tapscript) for a P2TR output with a
/// single tapscript leaf, so fixtures can spend it via the script path.
fn p2tr_script_path(tapscript: ScriptBuf) -> (ScriptBuf, Vec<u8>, ScriptBuf) {
    let secp = Secp256k1::new();
    let internal_key = xonly_pubkey(0xaa);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();
    let control_block = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .unwrap();
    let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    (spk, control_block.serialize(), tapscript)
}

/// Tapscript `pk(key)`: <x-only key> CHECKSIG
fn pk_tapscript(seed: u8) -> ScriptBuf {
    ScriptBuf::builder()
        .push_x_only_key(&xonly_pubkey(seed))
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Tapscript `multi_a(2, k1, k2, k3)` with k1, k3 from the given seeds.
fn multi_a_tapscript() -> ScriptBuf {
    ScriptBuf::builder()
        .push_x_only_key(&xonly_pubkey(1))
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&xonly_pubkey(2))
        .push_opcode(OP_CHECKSIGADD)
        .push_x_only_key(&xonly_pubkey(3))
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script()
}

#[test]
fn p2wpkh_all_anyonecanpay() {
    let key = pubkey(1);
    let spk = ScriptBuf::new_p2wpkh(&key.wpubkey_hash().unwrap());
    let input = txin(
        ScriptBuf::new(),
        vec![ecdsa_sig(ALL_ACP).to_vec(), key.to_bytes()],
    );
    assert!(check(&input, &spk));
}

#[test]
fn p2wpkh_all_only_rejected() {
    let key = pubkey(1);
    let spk = ScriptBuf::new_p2wpkh(&key.wpubkey_hash().unwrap());
    let input = txin(
        ScriptBuf::new(),
        vec![ecdsa_sig(ALL).to_vec(), key.to_bytes()],
    );
    assert!(!check(&input, &spk));
}

#[test]
fn p2pkh_all_anyonecanpay() {
    let key = pubkey(1);
    let spk = ScriptBuf::new_p2pkh(&key.pubkey_hash());
    let script_sig = ScriptBuf::builder()
        .push_slice(ecdsa_sig(ALL_ACP))
        .push_key(&key)
        .into_script();
    assert!(check(&txin(script_sig, vec![]), &spk));
}

#[test]
fn p2pkh_all_only_rejected() {
    let key = pubkey(1);
    let spk = ScriptBuf::new_p2pkh(&key.pubkey_hash());
    let script_sig = ScriptBuf::builder()
        .push_slice(ecdsa_sig(ALL))
        .push_key(&key)
        .into_script();
    assert!(!check(&txin(script_sig, vec![]), &spk));
}

#[test]
fn p2tr_key_path_all_anyonecanpay() {
    let secp = Secp256k1::new();
    let spk = ScriptBuf::new_p2tr(&secp, xonly_pubkey(1), None);
    let input = txin(ScriptBuf::new(), vec![schnorr_sig(Some(ALL_ACP))]);
    assert!(check(&input, &spk));
}

/// 64-byte schnorr signature means SIGHASH_DEFAULT, not ALL|ANYONECANPAY.
#[test]
fn p2tr_key_path_default_rejected() {
    let secp = Secp256k1::new();
    let spk = ScriptBuf::new_p2tr(&secp, xonly_pubkey(1), None);
    let input = txin(ScriptBuf::new(), vec![schnorr_sig(None)]);
    assert!(!check(&input, &spk));
}

#[test]
fn p2tr_key_path_all_only_rejected() {
    let secp = Secp256k1::new();
    let spk = ScriptBuf::new_p2tr(&secp, xonly_pubkey(1), None);
    let input = txin(ScriptBuf::new(), vec![schnorr_sig(Some(ALL))]);
    assert!(!check(&input, &spk));
}

/// A 65-byte schnorr signature with a 0x00 sighash byte is invalid per BIP-341.
#[test]
fn p2tr_key_path_invalid_sighash_byte_rejected() {
    let secp = Secp256k1::new();
    let spk = ScriptBuf::new_p2tr(&secp, xonly_pubkey(1), None);
    let input = txin(ScriptBuf::new(), vec![schnorr_sig(Some(0x00))]);
    assert!(!check(&input, &spk));
}

/// Script-path spend of a `pk` leaf: witness is <sig> <tapscript> <control block>.
#[test]
fn p2tr_script_path_pk_all_anyonecanpay() {
    let (spk, control_block, tapscript) = p2tr_script_path(pk_tapscript(1));
    let witness = vec![
        schnorr_sig(Some(ALL_ACP)),
        tapscript.into_bytes(),
        control_block,
    ];
    assert!(check(&txin(ScriptBuf::new(), witness), &spk));
}

#[test]
fn p2tr_script_path_pk_all_only_rejected() {
    let (spk, control_block, tapscript) = p2tr_script_path(pk_tapscript(1));
    let witness = vec![
        schnorr_sig(Some(ALL)),
        tapscript.into_bytes(),
        control_block,
    ];
    assert!(!check(&txin(ScriptBuf::new(), witness), &spk));
}

/// Script-path `multi_a(2, k1, k2, k3)` satisfied by k1 and k3: the unused k2
/// slot is an empty stack element and CHECKSIGADD multisig has no OP_0 dummy,
/// so the witness is <sig_k3> <> <sig_k1> <tapscript> <control block>.
#[test]
fn p2tr_script_path_multi_a_with_empty_slot() {
    let (spk, control_block, tapscript) = p2tr_script_path(multi_a_tapscript());
    let witness = vec![
        schnorr_sig(Some(ALL_ACP)),
        vec![],
        schnorr_sig(Some(ALL_ACP)),
        tapscript.into_bytes(),
        control_block,
    ];
    assert!(check(&txin(ScriptBuf::new(), witness), &spk));
}

/// One bad sighash in a multi-sig input fails the whole input.
#[test]
fn p2tr_script_path_multi_a_one_bad_sighash_rejected() {
    let (spk, control_block, tapscript) = p2tr_script_path(multi_a_tapscript());
    let witness = vec![
        schnorr_sig(Some(ALL_ACP)),
        vec![],
        schnorr_sig(Some(ALL)),
        tapscript.into_bytes(),
        control_block,
    ];
    assert!(!check(&txin(ScriptBuf::new(), witness), &spk));
}

/// P2WSH `pk(key)` single-sig: the two-item witness <sig> <witness script> has
/// no OP_0 dummy, so the signature is at index 0.
#[test]
fn p2wsh_pk_all_anyonecanpay() {
    let key = pubkey(1);
    let witness_script = ScriptBuf::builder()
        .push_key(&key)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let spk = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
    let witness = vec![ecdsa_sig(ALL_ACP).to_vec(), witness_script.into_bytes()];
    assert!(check(&txin(ScriptBuf::new(), witness), &spk));
}

#[test]
fn p2wsh_pk_all_only_rejected() {
    let key = pubkey(1);
    let witness_script = ScriptBuf::builder()
        .push_key(&key)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let spk = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
    let witness = vec![ecdsa_sig(ALL).to_vec(), witness_script.into_bytes()];
    assert!(!check(&txin(ScriptBuf::new(), witness), &spk));
}

/// P2SH-wrapped P2WPKH: redeemScript in scriptSig, signature in the witness.
#[test]
fn p2sh_p2wpkh_all_anyonecanpay() {
    let key = pubkey(1);
    let wpkh_spk = ScriptBuf::new_p2wpkh(&key.wpubkey_hash().unwrap());
    let spk = ScriptBuf::new_p2sh(&wpkh_spk.script_hash());
    let script_sig = ScriptBuf::builder()
        .push_slice(PushBytesBuf::try_from(wpkh_spk.into_bytes()).unwrap())
        .into_script();
    let witness = vec![ecdsa_sig(ALL_ACP).to_vec(), key.to_bytes()];
    assert!(check(&txin(script_sig, witness), &spk));
}

/// A hashlock-only input carries no signatures and must be rejected.
#[test]
fn wsh_hashlock_without_signature_rejected() {
    let preimage = [0x07; 32];
    let hash = sha256::Hash::hash(&preimage);
    let witness_script = ScriptBuf::builder()
        .push_opcode(OP_SIZE)
        .push_int(32)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(hash.to_byte_array())
        .push_opcode(OP_EQUAL)
        .into_script();
    let spk = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
    let witness = vec![preimage.to_vec(), witness_script.into_bytes()];
    assert!(!check(&txin(ScriptBuf::new(), witness), &spk));
}

/// An input with no witness and no scriptSig cannot be interpreted.
#[test]
fn empty_input_rejected() {
    let key = pubkey(1);
    let spk = ScriptBuf::new_p2wpkh(&key.wpubkey_hash().unwrap());
    assert!(!check(&txin(ScriptBuf::new(), vec![]), &spk));
}
