pragma circom 2.0.6;
include "../../circuits/ecdsa_verify_no_precompute.circom";
component main { public [T, U] } = ECDSAVerifyNoPrecompute(64, 4);