# efficient-zk-ecdsa

_The code in this repo is unaudited and not recommended for production use._

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

## Run benchmarks

```
cd ./bench
```

```
open ./index.html
```

_The full proof and the proving time will be displayed in the browser console._

## Benchmarks

_Disclaimer: the following benchmarks are to give an intuition about the proving time of this method. We hope to run a more comprehensive benchmark across many devices soon._

### Circuit info

| Circuit                     | Constraints | zKey size |
| --------------------------- | ----------- | --------- |
| ecdsa_verify                | 163,239     | 119MB     |
| ecdsa_verify_pubkey_to_addr | 315,175     | 197MB     |

### Browser proving

_The setup_:

- M1 Pro Macbook Pro
- Internet speed: 170Mbps
- Browser: Brave browser

| Circuit                     | Proving time |
| --------------------------- | ------------ |
| ecdsa_verify                | 40s          |
| ecdsa_verify_pubkey_to_addr | 45s          |

### Command line proving

_The setup:_

- M1 Pro Macbook Pro

| Circuit                     | Proving time |
| --------------------------- | ------------ |
| ecdsa_verify                | 18s          |
| ecdsa_verify_pubkey_to_addr | 30s          |
