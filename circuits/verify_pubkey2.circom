pragma circom 2.0.6;
include "./circom-ecdsa-circuits/bigint_func.circom";
include "./circom-ecdsa-circuits/ecdsa.circom";
include "./circom-ecdsa-circuits/zk-identity/eth.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/*
    VerifyPubkey2 Proof
    -------------------
    Verifies that pubKey2 is correctly derived from the original pubKey, and that 
    the claimed posiedonHash is the Poseidon hash of the inputted message and a 
    private salt. 
    
    Note that as Ethereum wallets attach a prefix to inputted data and keccak256 
    hash it before signing, the actual signed msg is keccakHash. It being correctly 
    derived from poseidonHash is checked outside of the SNARK.

    msgHash and salt are both built of k n-bit registers to avoid any overflow 
    in the field used by circom. Thus the Poseidon hash takes 2*k inputs.

    Public inputs:
    modInvRMultPubkey2[2][k]    r^-1 * pubKey2, computed outside SNARK
    negInvR[k]                  -r^-1, computed outside SNARK
    msghash[k]                  hash of the message being attested to
    poseidonHash                claimed Poseidon(salt[k], msghash[k])
    keccakHashMsg[k]            actual data signed by wallet, computed outside SNARK 

    Private inputs:
    salt[k]                     private salt used to keep signed message secret
    pubkey[2][k]                actual pubkey

    Outputs:
    result                      1 if pubKey2 was correctly derived, 0 if not
*/
// pubkey =  pubkey2 * r^-1 - msg * r^-1 * G
template VerifyPubkey2(n, k) {
    signal input modInvRMultPubkey2[2][k];
    signal input negInvR[k];
    signal input msghash[k];
    signal input poseidonHash;
    signal input keccakHashMsg[k];

    signal input salt[k];
    signal input pubkey[2][k];

    signal output result;

    // verify poseidonHash = Poseidon(salt[k], msgHash[k])
    component hasher = Poseidon(2*k);
    for (var idx = 0; idx < k; idx++) {
        hasher.inputs[idx] <== salt[idx];
        hasher.inputs[k+idx] <== msghash[idx];
    }
    poseidonHash === hasher.out;

    // compute (msg * -r^-1) mod n
    var order[100] = get_secp256k1_order(n, k);
    component g_coeff = BigMultModP(n, k);
    for (var idx = 0; idx < k; idx++) {
        g_coeff.a[idx] <== keccakHashMsg[idx];
        g_coeff.b[idx] <== negInvR[idx];
        g_coeff.p[idx] <== order[idx];
    }

    // -(msg * r^-1) * G
    component negMsgMultModInvRMultG = ECDSAPrivToPub(n, k);
    for (var i = 0; i < k; i++) {
        negMsgMultModInvRMultG.privkey[i] <== g_coeff.out[i];
    }

    // -(msg * r^-1) * G + r^-1 * pubKey2
    component computedPubkey = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        computedPubkey.a[0][i] <== negMsgMultModInvRMultG.pubkey[0][i];
        computedPubkey.a[1][i] <== negMsgMultModInvRMultG.pubkey[1][i];
        computedPubkey.b[0][i] <== modInvRMultPubkey2[0][i];
        computedPubkey.b[1][i] <== modInvRMultPubkey2[1][i];
    }

    // compare pubkey and computedPubkey
    component compare[2][k];
    signal num_equal[k];

    for (var idx = 0; idx < k; idx++) {
        compare[0][idx] = IsEqual();
        compare[0][idx].in[0] <== pubkey[0][idx];
        compare[0][idx].in[1] <== computedPubkey.out[0][idx];

        compare[1][idx] = IsEqual();
        compare[1][idx].in[0] <== pubkey[1][idx];
        compare[1][idx].in[1] <== computedPubkey.out[1][idx];

        if (idx == 0) {
            num_equal[0] <== compare[0][0].out + compare[1][0].out;
        } else {
            num_equal[idx] <== num_equal[idx - 1] + compare[0][idx].out + compare[1][idx].out;
        }
    }

    component res_comp = IsEqual();
    res_comp.in[0] <== 2*k;
    res_comp.in[1] <== num_equal[k-1];
    result <== res_comp.out;
}

component main { public [modInvRMultPubkey2, negInvR, msghash, poseidonHash, keccakHashMsg] } = VerifyPubkey2(64, 4);