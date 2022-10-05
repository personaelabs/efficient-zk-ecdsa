pragma circom 2.0.6;
include "./circom-ecdsa-circuits/bigint_func.circom";
include "./circom-ecdsa-circuits/ecdsa.circom";
include "./circom-ecdsa-circuits/zk-identity/eth.circom";

// Compute the public key and its corresponding address by computing the follwoing:
// pubKey =  pubKey2 * r^-1 - msg * r^-1 * G
template PubKeyFromSecretMessage(n, k) {
    signal input modInvRMultPubKey2[2][k]; // r^-1 * pubKey2
    signal input negMsgMultModInvR[k]; // -(msg * r^-1)

    // The address should be hidden in real-world applications.
    // This circuit outputs the address only for demonstration purposes.
    // signal output addr;

    // -(msg * r^-1) * G
    component negMsgMultModInvRMultG = ECDSAPrivToPub(n, k);

    for (var i = 0; i < k; i++) {
        negMsgMultModInvRMultG.privkey[i] <== negMsgMultModInvR[i];
    }


    // -(msg * r^-1) * G + r^-1 * pubKey2
    component pubKey = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        pubKey.a[0][i] <== negMsgMultModInvRMultG.pubkey[0][i];
        pubKey.a[1][i] <== negMsgMultModInvRMultG.pubkey[1][i];
        pubKey.b[0][i] <== modInvRMultPubKey2[0][i];
        pubKey.b[1][i] <== modInvRMultPubKey2[1][i];
    }

    // component flattenPub = FlattenPubkey(n, k);
    // for (var i = 0; i < k; i++) {
    //     flattenPub.chunkedPubkey[0][i] <== pubKey.out[0][i];
    //     flattenPub.chunkedPubkey[1][i] <== pubKey.out[1][i];
    // }

    // component pubKeyToAddress = PubkeyToAddress();

    // component pubToAddr = PubkeyToAddress();
    // for (var i = 0; i < 512; i++) {
    //     pubToAddr.pubkeyBits[i] <== flattenPub.pubkeyBits[i];
    // }

    // The address should not be revelaed in real-world applications 
    // and should be used, for example, as a leaf of a merkle proof.
    // This circuit outputs the address for demonstration purposes.
    // addr <== pubToAddr.address;
}

component main { public [modInvRMultPubKey2] } = PubKeyFromSecretMessage(64, 4);