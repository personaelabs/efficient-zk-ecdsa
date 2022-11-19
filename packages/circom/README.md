# efficient-zk-ecdsa in circom

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
