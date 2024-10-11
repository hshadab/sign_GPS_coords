# Example of timestamping and signing GPS coordinates

This example shows a rust code that takes gps coordinates in input together with a private key, adds a timestamp to the coordinates, and then signs the object using the private key.

A zero-knowledge proof of the signing is also generated, that can be verified as well.

## Get started

```
cargo +nightly run
```
