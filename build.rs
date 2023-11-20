// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: LGPL-3.0-or-later

fn main() {
    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .include("src/protos")
        .input("src/protos/VehicleHalProto.proto")
        .cargo_out_dir("protos")
        .run_from_script();
}
