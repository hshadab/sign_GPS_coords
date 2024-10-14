# Example of timestamping and signing GPS coordinates

This example shows a rust code that takes gps coordinates in input together with a private key, adds a timestamp to the coordinates, and then signs the object using the private key.

A zero-knowledge proof of the signing is also generated, that can be verified as well.

## Get started

### Device register

Copy `core` directory from `device_register/ioConnect` to `device_register/src`.

in `device_register/src/core/src/include/config`, remove `autoconfig.h` and rename `autoconfig_linux.h` to `autoconfig.h`

```
cd device_register/ioConnect/src
```

```
mkdir build && cd build
```

```
cmake .. && make && ./DIDComme_server
```

### Signing data

from root:

```
cargo +nightly run
```
