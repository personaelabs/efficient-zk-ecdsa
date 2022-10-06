# zk-ecdsa

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

| Circuit     | Constraints | Full proving time <br /> (M1 Pro MacBook Pro) | zKey size |
| ----------- | ----------- | --------------------------------------------- | --------- |
| ecdsaverify | 163,239     | 24s                                           | 119MB     |
