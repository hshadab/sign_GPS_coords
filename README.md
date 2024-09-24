# Example of timestamping and signing GPS coordinates

This example shows a rust code that takes gps coordinates in input together with a private key, adds a timestamp to the coordinates, and then signs the object using the private key.

This code can be compiled to a wasm target, so that the correct execution can be proved - for example using NovaNet's zkEngine.

## Prerequisites

`wasmtime` is needed.

You will also need to have installed the wasm32-wasi target for rust

```bash
rustup target add wasm32-wasi
```

## How to use

Also make sure to export environnment variables from `.env` file.

```bash
source .env
```

This will add a PRIVATE_KEY_HEX variable, used to sign the timestamped GPS coordinates.

You can then compile the main file to wasm32-wasi target

```bash
cargo build --target wasm32-wasi
```

Finally you can run the wasm executable

```bash
wasmtime ./target/wasm32-wasi/debug/signDataRust.wasm <latitude> <longitude> $PRIVATE_KEY_HEX
```

Example use:

```bash
wasmtime ./target/wasm32-wasi/debug/signDataRust.wasm 48.84735470017182 2.328560495690661 $PRIVATE_KEY_HEX
```
