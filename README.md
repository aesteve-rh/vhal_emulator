<!--
SPDX-FileCopyrightText: 2023 Albert Esteve <aesteve@redhat.com>
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# VHAL Emulator

Based on Google's [VHAL Host Emulator](https://android.googlesource.com/platform/packages/services/Car/+/refs/heads/main/tools/emulator/).

`vhal_emulator` is a Rust library designed to simulate CAN bus communication
with an Android Automotive system. The emulator leverages sockets and port
forwarding through ADB (Android Debug Bridge) to facilitate communication
between the emulator and the Android Automotive system.

## Features

- CAN Bus Simulation: Emulate CAN bus messages for testing Android Automotive
  Vehicle Hardware Abstraction Layer (VHAL) implementations.

- Socket Communication: Utilize sockets for communication between the emulator
  and the Android Automotive system.

- ADB Port Forwarding: Enable seamless communication by leveraging ADB port
  forwarding to establish a connection between the emulator and the Android device.

## Usage

### ADB Port Forwarding

First we need to connect to an Android Auto device running a Vehicle HAL with simulator.
To do that, this library uses ADB port forwarding to a hardcoded remote port.
Ensure that ADB is installed on your machine, or give the path to the directory
containing the binary through the `ADB_PATH` environment variable.

You can let the library do the binding for you, using a random unused port on
the host (note: currently, no device can be specified, so it binds as default device):

```rust
use vhal_emulator as ve;

let local_port: u16 = ve::adb_port_forwarding().expect("Could not run adb for port forwarding");
let v = ve::Vhal::new(local_port).unwrap();
```

Otherwise, you can manually forward the required port to establish a connection
with the Android device, and then use it in the `Vhal` instantiation call.

```shell
    adb forward port tcp:0 tcp:33452      # random free port returned
    adb forward port tcp:12345 tcp:33452  # explicitely select the port to be used
```

### Send and receive messages

Use the emulator to simulate CAN bus messages and test the VHAL implementation
on the Android Automotive system.

Messages can be sent using the various helper functions that the library provides.
Direct message manipulation is not allowed. For most general interaction, you
can use `set_property`.

Receiving a message is done through `recv_cmd`, which returns an `EmulatorMessage`
with an status field set, which allows to check for communication errors.

---
**NOTE**

`recv_msg` is a blocking call, so it may be desirable to set up a
separate RX thread to handle any async messages coming from the device.

---

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
    c::VehicleArea::SEAT | c:VehicleAreaSeat::ROW_1_LEFT,
    None,
).unwrap();

// Get the response message to set_property
let reply = v.recv_cmd().unwrap();
println!(reply);

// Set the car gear to reverse
v.set_gear_selection(c::VehicleGear::GEAR_REVERSE).unwrap()

// Get the response message to set_gear_selection
let reply = v.recv_cmd().unwrap();
println!(reply);
assert!(reply.status() == Status::RESULT_OK);
```

### Protocol Buffer

This module relies on `VehicleHalProto.rs` being in sync with the protobuf in
the Vehicle HAL. If the `VehicleHalProto.proto` file has changed, update the file
in the repository to generate an updated version. The update happens
automatically at build time.

## Testing

Test assumes there is a running AAOS VM. Again, make sure you also have ADB installed.
Also, tests may interfere when run in parallel. To avoid false negatives, make
sure you force a single thread.

```shell
$ ADB_PATH=/path/to/adb/bin cargo test --lib -- --test-threads=1
```

## Regenerating vhal constants

File at `src/vhal_consts_2_0.rs` is autogenerated by the Python script at
`src/codegen/gen_vhal_const.py`, and contains definitions for property ID,
zone, and others, from the `types.hal` file. If the source file `types.hal`
has changed, you can update the repository copy and use the script to
regenerate the definitions.

To do so, you can use these commands:
```shell
$ make venv
$ source $HOME/.venv/vhal_emulator/bin/activate
$ make render
$ deactivate
```

## Contributing

Contributions are welcome! Feel free to open issues or pull requests.

Please make sure your patches have all commits signed-up, and that you
have passed `fmt` and `clippy`.

```shell
$ cargo +nightly fmt
$ cargo clippy --all-features --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks
```

## License

This project is licensed under the LGPL-3.0-or-later License.

Files coming from the Android Open Source Project, are
licensed under the Apache-2.0 license.

For more details, see the [LICENSES](LICENSES) folder.
