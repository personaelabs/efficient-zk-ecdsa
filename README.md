# efficient-zk-sig

Please refer to [this Ethereum Research post](https://ethresear.ch/t/efficient-ecdsa-signature-verification-using-circom/13629) for details. The circuits in this repo uses circuits from [circom-ecdsa](https://github.com/0xPARC/circom-ecdsa).

## Install dependencies

```
yarn
```

## Compile the circuit and generate the zkey

```
yarn run build:ecdsaverify
```

## Run proof generation

```
yarn run run:ecdsaverify
```

## Benchmarks

### Circuit info

| Circuit                     | Constraints | zKey size |
| --------------------------- | ----------- | --------- |
| ecdsa_verify                | 163,239     | 119MB     |
| ecdsa_verify_pubkey_to_addr | 466,599     | 291MB     |

### Browser proving

_The setup_:

- M1 Pro Macbook Pro
- Internet speed: 40Mbps
- Browser: Brave browser

| Circuit                     | Proving time |
| --------------------------- | ------------ |
| ecdsa_verify                | 51s          |
| ecdsa_verify_pubkey_to_addr | 107s         |

### Command line proving

_The setup:_

- M1 Pro Macbook Pro

| Circuit                     | Proving time |
| --------------------------- | ------------ |
| ecdsa_verify                | 18s          |
| ecdsa_verify_pubkey_to_addr | 32s          |
