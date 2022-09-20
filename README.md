# zk-ecdsa-verify

Please refer to [this Ethresearch post](https://ethresear.ch/t/efficient-ecdsa-signature-verification-using-circom/13629) for details. (Plese read [the reply](https://ethresear.ch/t/efficient-ecdsa-signature-verification-using-circom/13629/2?u=0danieltehrani) to the post as well.)
This repo uses circuits from [circom-ecdsa](https://github.com/0xPARC/circom-ecdsa). 

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

| Full proving time | 25s    |
| ----------------- | ------ |
| Proving key size  | 256MB  |
| Constraints       | 466599 |

_When the proving is done in a browser, it might take some time to download the proving key, which is 256MB in size._
