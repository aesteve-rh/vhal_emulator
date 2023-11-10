# Vhal Emulator

This library provides a Vhal class which sends and receives messages to the
vehicle HAL module on an Android Auto device.
It uses port forwarding via ADB to communicate with the Android device.

## Usage

### Open a socket connection

First we need to connect to an Android Auto device running a Vehicle HAL with simulator.
To do that, this library uses adb por forwarding to a hardcoded remote port.
Currently, no device can be specified, so it connects as default device.

We can use the local port returned to open a socket connection:

```rust
use vhal_emulator as ve;

let local_port: u16 = ve::adb_port_forwarding().expect("Could not run adb for port forwarding");
let v = ve::Vhal::new(local_port).unwrap();
```

### Send and receive a message

A message can be sent using the various helper function that the library provides.
Direct message manipulation is not allowed.

Receiving can be achieved through `recv_cmd`, which return an `EmulatorMessage`
with an status field set, which allows to check for errors.

```rust
use vhal_emulator::vhal_consts_2_0 as c;
use vhal_emulator::VehicleHalProto::Status;

// Get the property config
v.get_config(c::VehicleProperty::HVAC_TEMPERATURE_SET).unwrap();

// Get the response message to get_config
let reply = v.recv_cmd().unwrap();
println!(reply);

// Set left temperature to 70 degrees
v.set_property(
    c::VehicleProperty::HVAC_TEMPERATURE_SET,
    ve::VehiclePropertyValue::Int32(70),
    c::VEHICLEAREASEAT_ROW_1_LEFT,
    None,
).unwrap();

// Get the response message to set_property
let reply = v.recv_cmd().unwrap();
println!(reply);

// Set the car gear to reverse
vhal.set_gear_selection(c::VehicleGear::GEAR_REVERSE).unwrap()

// Get the response message to set_gear_selection
let reply = v.recv_cmd().unwrap();
println!(reply);
assert!(reply.status() == Status::RESULT_OK);
```

### Protocol Buffer
This module relies on VehicleHalProto.rs being in sync with the protobuf in
the VHAL. If the VehicleHalProto.proto file has changes, update the file
from the repository to generate an updated version. The update happens
automatically at build time.

## Testing

Test assumes there is a running AAOS VM. Make sure you have `adb` binary
accessible in your path, or excplicitely set `ADP_PATH` env var.

```shell
$ ADB_PATH=/path/to/adb/bin cargo test
```

## Contributing

Please make sure your patches have all commits signed-up, and that you
have passed `fmt` and `clippy`.

```shell
$ cargo +nightly fmt
$ cargo clippy --all-features --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks
```