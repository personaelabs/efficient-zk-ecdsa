# zk-ecdsa

Please refer to [this Ethereum Research post](https://ethresear.ch/t/efficient-ecdsa-signature-verification-using-circom/13629) for details. The circuits in this repo uses circuits from [circom-ecdsa](https://github.com/0xPARC/circom-ecdsa).

## Install dependencies

```
yarn
```

## Run proof generation

```
yarn run prove
```

## Benchmarks

On a MacBook Pro

| Full proving time | 23s    |
| ----------------- | ------ |
| Proving key size  | 221MB  |
| Constraints       | 401319 |

_When the proving is done in a browser, it might take some time to download the proving key, which is 256MB in size._
