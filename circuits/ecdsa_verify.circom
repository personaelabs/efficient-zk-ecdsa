pragma circom 2.0.6;
include "./ecdsa.circom";
component main { public [TPreComputes, U] } = ECDSA(64, 4);