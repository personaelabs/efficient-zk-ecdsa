# efficient-zk-ecdsa
### ⚠️ This repo is no longer maintained⚠️
### We recommend [spartan-ecdsa](https://github.com/personaelabs/spartan-ecdsa) as a replacement




_The code in this repo is unaudited and not recommended for production use._

Please refer to [this blog post](https://personaelabs.org/posts/efficient-ecdsa-1/) for details. The circuits in this repo uses circuits from [circom-ecdsa](https://github.com/0xPARC/circom-ecdsa).

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

We include details on the circuit implementing the rearranged formula without precomputed multiples for comparison. The more precomputed multiples one uses, the larger the input size but the fewer the # of constraints. This tradeoff is relevant for any on-chain applications of this work:

| Circuit                     | Constraints | zKey size |
| --------------------------- | ----------- | --------- |
| ecdsa_verify                | 163,239     | 119MB     |
| ecdsa_verify_pubkey_to_addr | 315,175     | 197MB     |
| ecdsa_verify_no_precompute  | 1,401,956   | 874MB     |

### Browser proving

_The setup_:

- M1 Pro Macbook Pro
- Internet speed: 40Mbps
- Browser: Chrome browser

| Circuit                     | Proving time |
| --------------------------- | ------------ |
| ecdsa_verify                | 39.4s        |
| ecdsa_verify_pubkey_to_addr | 58.2s        |

### Command line proving

_The setup:_

- M1 Pro Macbook Pro

| Circuit                     | Proving time |
| --------------------------- | ------------ |
| ecdsa_verify                | 18s          |
| ecdsa_verify_pubkey_to_addr | 30s          |
