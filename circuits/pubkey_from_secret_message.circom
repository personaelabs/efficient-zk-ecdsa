pragma circom 2.0.6;
include "./circom-ecdsa-circuits/bigint_func.circom";
include "./circom-ecdsa-circuits/ecdsa.circom";
include "./circom-ecdsa-circuits/zk-identity/eth.circom";
include "./secp256k1_scalar_mult_cached_windowed.circom";

template PubKeyFromSecretMessage(n, k) {
    signal input msg[k]; // secret message 
    signal input modInvRMultPubKey2[2][k]; // r^-1 * pubKey2
    signal input modInvRMultGPreComputes[32][256][2][4];  // Pre computes for r^-1 * G

    // The address should be hidden in real-world applications.
    // This circuit outputs the address only for demonstration purposes.
    signal output addr;

    // msg * r^-1 * G
    component msgMultCachedPoint = Secp256K1ScalarMultCachedWindowed(n, k);

    var stride = 8;
    var num_strides = div_ceil(n * k, stride);

    for (var i = 0; i < num_strides; i++) {
        for (var j = 0; j < 2 ** stride; j++) {
            for (var l = 0; l < k; l++) {
                msgMultCachedPoint.pointPreComputes[i][j][0][l] <== modInvRMultGPreComputes[i][j][0][l];
                msgMultCachedPoint.pointPreComputes[i][j][1][l] <== modInvRMultGPreComputes[i][j][1][l];
            }
        }
    }

    for (var i = 0; i < k; i++) {
        msgMultCachedPoint.privkey[i] <== msg[i];
    }


    // pubLe
    component pubKey = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        pubKey.a[0][i] <== msgMultCachedPoint.pubkey[0][i];
        pubKey.a[1][i] <== msgMultCachedPoint.pubkey[1][i];
        pubKey.b[0][i] <== modInvRMultPubKey2[0][i];
        pubKey.b[1][i] <== modInvRMultPubKey2[1][i];
    }

    component flattenPub = FlattenPubkey(n, k);
    for (var i = 0; i < k; i++) {
        flattenPub.chunkedPubkey[0][i] <== pubKey.out[0][i];
        flattenPub.chunkedPubkey[1][i] <== pubKey.out[1][i];
    }

    component pubKeyToAddress = PubkeyToAddress();

    component pubToAddr = PubkeyToAddress();
    for (var i = 0; i < 512; i++) {
        pubToAddr.pubkeyBits[i] <== flattenPub.pubkeyBits[i];
    }

    // The address should not be revelaed in real-world applications 
    // and should be used, for example, as a leaf of a merkle proof.
    // This circuit outputs the address for demonstration purposes.
    addr <== pubToAddr.address;
}

component main { public [modInvRMultPubKey2] } = PubKeyFromSecretMessage(64, 4);