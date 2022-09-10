pragma circom 2.0.2;

include "./circom-ecdsa-circuits/ecdsa.circom";

template Secp256k1ScalarMultWithPreCompute(n, k) {
    // TODO: Implement this
}

// n: bits per register
// k: number of registers
template ECDSAVerify(n, k) {
    signal input msg2[k]; // message 2 (256bits)
    signal input r[k]; // r (256bits?)
    signal input pubKey[2][k]; // Pubkey
    signal input pubKeyPreComputes[2][256]; // PubKey pre computations

    signal output mG[2][k]; // m * G
    signal output rP[2][k]; // r * PubKey

    component msg2ToPubKey = ECDSAPrivToPub(n, k);
    for (var i = 0; i < k; i++) {
        msg2ToPubKey.privkey[i] <== msg2[i];
    }

    component rToPubKey = ECDSAPrivToPub(n, k);
    for (var i = 0; i < k; i++) {
        rToPubKey.privkey[i] <== r[i];
    }

    // m * G + r * PubKey
    component pubKey2 = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        pubKey2.a[0][i] <== msg2ToPubKey.pubkey[0][i];
        pubKey2.a[1][i] <== msg2ToPubKey.pubkey[1][i];
        pubKey2.b[0][i] <== rToPubKey.pubkey[0][i];
        pubKey2.b[1][i] <== rToPubKey.pubkey[1][i];
    }

    // Check if pub key equals or not.
    for (var i = 0; i < k; i++) {
        pubKey[0][i] === pubKey2.out[0][i];
        pubKey[1][i] === pubKey2.out[1][i];
    }
}

component main = ECDSAVerify(64, 4);