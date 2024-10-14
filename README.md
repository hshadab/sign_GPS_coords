# Example of timestamping and signing GPS coordinates

This example shows a rust code that takes gps coordinates in input together with a private key, adds a timestamp to the coordinates, and then signs the object using the private key.

A zero-knowledge proof of the signing is also generated, that can be verified as well.

# Get started

## Setting up client

First get to `/client` directory:

```
cd client
```

### Device register

in `/client`, create a `.env` file and set the `SECRET_KEY_HEX` variable, as a 64-characters hexadecimal string, corresponding to a 32-bytes secret key.

Copy `core` directory from `device_register/ioConnect` to `device_register/src`.

in `device_register/src/core/src/include/config`, remove `autoconfig.h` and rename `autoconfig_linux.h` to `autoconfig.h`

```
cd device_register/ioConnect/src
```

```
mkdir build && cd build
```

```
cmake .. && make && ./DIDComm_server
```

Running `./DIDComm_Server` creates a DIDDoc using our secret key and stores it in a file for later use.

## Setting up server

From project root:

```
cd server/add_client
```

Create a `libraries` directory, and in there also copy `core` directory from `ioConnect`, and change the `autoconfig.h` following same logic as in `Setting up client`.

then:

```
mkdir build && cd build
```

```
cmake .. && make
```

This will create a `./add_client` executable in `build`, which will be used later by `/server/src/main.rs`.

## Starting demo

From `server` directory:

```
cargo run
```

This will start a server listening for requests from client

Now from `client` directory:

```
cargo +nighlty run
```

This will prove signing the object, and then send (for now) just the DIDDoc generated in `Setting up client` to the server
