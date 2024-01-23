// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: LGPL-3.0-or-later

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

#[rustfmt::skip]
pub mod vhal_consts_2_0;

use log::{debug, warn};
use protobuf::Message;
use socket2::{Domain, Socket, Type};
use std::{
    collections::HashMap, env, mem::MaybeUninit, net::SocketAddr, path::PathBuf, process::Command,
};
use thiserror::Error as ThisError;
use vhal_consts_2_0::{self as c, VehicleProperty, VehiclePropertyType};
use VehicleHalProto::{EmulatorMessage, VehiclePropGet};

#[macro_use]
extern crate structure;

const REMOTE_PORT: u16 = 33452;

pub type Result<T> = std::result::Result<T, VhalError>;

pub trait GetPropertyValue {
    fn get_value(&self) -> Result<VehiclePropertyValue>;
}

pub trait CheckResponse {
    fn is_valid(&self, exp_type: VehicleHalProto::MsgType) -> Result<()>;
}

pub trait ExpectType {
    fn expect_i32(&self) -> Result<i32>;
    fn expect_f32(&self) -> Result<f32>;
}

#[derive(Debug, ThisError)]
pub enum VhalError {
    #[error("adb command failed: {0}")]
    AdbCommandError(std::io::Error),
    #[error("Could not pack message length into byte array")]
    PackMessageError,
    #[error("Could not unpack byte array into message length")]
    UnPackMessageError,
    #[error("Failed to create socket: {0}")]
    CreateSocketError(std::io::Error),
    #[error("Message could not be sent: {0}")]
    SendMessageError(std::io::Error),
    #[error("Message could not be received: {0}")]
    ReceiveMessageError(std::io::Error),
    #[error("Unexpected message length, expected {0}, found {1}")]
    ReceiveMessageLengthError(usize, usize),
    #[error("Unexpected message status: {0}")]
    ReceiveMessageStatusError(usize),
    #[error("Unexpected message type: {0}")]
    ReceiveMessageTypeError(usize),
    #[error("Unexpected message value type")]
    ReceiveMessageValueTypeError,
    #[error("Received message invalid value")]
    ReceiveMessageValueError,
    #[error("Received too many message values, expected 1, found {0}")]
    ReceiveMessageTooManyValuesError(usize),
    #[error("Invalid property ID: {0}")]
    PropertyError(i32),
    #[error("Mismatched property type received")]
    PropertyTypeError,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VehiclePropertyValue {
    String(String),
    Bytes(Vec<u8>),
    Int32(i32),
    Int64(i64),
    Float(f32),
}

impl VehiclePropertyValue {
    fn set_prop_value(&self, prop_value: &mut VehicleHalProto::VehiclePropValue) {
        match self {
            Self::String(v) => prop_value.set_string_value(v.to_owned()),
            Self::Int32(v) => prop_value.int32_values.push(*v),
            Self::Int64(v) => prop_value.int64_values.push(*v),
            Self::Float(v) => prop_value.float_values.push(*v),
            Self::Bytes(v) => prop_value.set_bytes_value(v.clone()),
        }
    }

    fn from_prop(
        prop_type: &VehiclePropertyType,
        prop_value: &VehicleHalProto::VehiclePropValue,
    ) -> Result<Self> {
        Ok(match *prop_type {
            VehiclePropertyType::STRING => Self::String(
                prop_value
                    .string_value
                    .as_ref()
                    .ok_or(VhalError::PropertyTypeError)?
                    .to_owned(),
            ),
            VehiclePropertyType::BYTES => Self::Bytes(
                prop_value
                    .bytes_value
                    .as_ref()
                    .ok_or(VhalError::PropertyTypeError)?
                    .to_vec(),
            ),
            VehiclePropertyType::BOOLEAN => Self::Int32(
                *prop_value
                    .int32_values
                    .first()
                    .ok_or(VhalError::PropertyTypeError)?,
            ),
            VehiclePropertyType::INT32 => Self::Int32(
                *prop_value
                    .int32_values
                    .first()
                    .ok_or(VhalError::PropertyTypeError)?,
            ),
            VehiclePropertyType::INT64 => Self::Int64(
                *prop_value
                    .int64_values
                    .first()
                    .ok_or(VhalError::PropertyTypeError)?,
            ),
            VehiclePropertyType::FLOAT => Self::Float(
                *prop_value
                    .float_values
                    .first()
                    .ok_or(VhalError::PropertyTypeError)?,
            ),
            _ => return Err(VhalError::ReceiveMessageValueTypeError),
        })
    }

    fn check_valid_type(&self, prop_type: &VehiclePropertyType) -> bool {
        match self {
            Self::String(_) => prop_type.is_string(),
            Self::Int32(_) => prop_type.is_int32(),
            Self::Int64(_) => prop_type.is_int64(),
            Self::Float(_) => prop_type.is_float(),
            Self::Bytes(_) => prop_type.is_bytes(),
        }
    }
}

impl GetPropertyValue for EmulatorMessage {
    fn get_value(&self) -> Result<VehiclePropertyValue> {
        if self.value.len() != 1 {
            return Err(VhalError::ReceiveMessageTooManyValuesError(
                self.value.len(),
            ));
        }

        let value = self.value.first().unwrap();
        let val_type = VehiclePropertyType::try_from(match value.value_type {
            Some(val) => val,
            None => return Err(VhalError::ReceiveMessageValueError),
        })
        .map_err(|_| VhalError::ReceiveMessageValueTypeError)?;

        VehiclePropertyValue::from_prop(&val_type, value)
    }
}

impl CheckResponse for EmulatorMessage {
    fn is_valid(&self, exp_type: VehicleHalProto::MsgType) -> Result<()> {
        if self.status() != VehicleHalProto::Status::RESULT_OK {
            return Err(VhalError::ReceiveMessageStatusError(self.status() as usize));
        }
        if self.msg_type() != exp_type {
            return Err(VhalError::ReceiveMessageTypeError(self.msg_type() as usize));
        }

        Ok(())
    }
}

impl ExpectType for EmulatorMessage {
    fn expect_i32(&self) -> Result<i32> {
        Ok(match self.get_value()? {
            VehiclePropertyValue::Int32(value) => value,
            _ => return Err(VhalError::ReceiveMessageValueTypeError),
        })
    }

    fn expect_f32(&self) -> Result<f32> {
        Ok(match self.get_value()? {
            VehiclePropertyValue::Float(value) => value,
            _ => return Err(VhalError::ReceiveMessageValueTypeError),
        })
    }
}

pub fn adb_port_forwarding() -> Result<u16> {
    use std::str;
    let adb_path = match env::var("ADB_PATH") {
        Ok(v) => [&v, "adb"].iter().collect(),
        Err(_) => PathBuf::from("adb"),
    };
    let mut remote_port = "tcp:".to_owned();
    remote_port.push_str(REMOTE_PORT.to_string().as_str());
    Ok(
        match Command::new(adb_path)
            .args(["forward", "tcp:0", remote_port.as_str()])
            .output()
        {
            Err(e) => return Err(VhalError::AdbCommandError(e)),
            Ok(output) => {
                String::from(str::from_utf8(&output.stdout).expect("Output is not UTF-8 format"))
                    .trim()
                    .parse::<u16>()
                    .expect("Expected a number")
            }
        },
    )
}

#[derive(Debug)]
#[non_exhaustive]
pub struct Vhal {
    socket: Socket,
    prop_to_type: HashMap<VehicleProperty, VehiclePropertyType>,
}

impl Vhal {
    const RESP_HEADER_SIZE: usize = 4;
    const MAX_RESP_SIZE: usize = 10000;

    pub fn new(local_port: u16) -> Result<Self> {
        let addr = SocketAddr::from(([127, 0, 0, 1], local_port));
        Socket::new(Domain::IPV4, Type::STREAM, None)
            .and_then(|socket| {
                socket.connect(&addr.into())?;
                Ok(Self {
                    socket,
                    prop_to_type: HashMap::new(),
                })
            })
            .map_err(VhalError::CreateSocketError)?
            .init_config_dict()
    }

    fn init_config_dict(mut self) -> Result<Self> {
        self.get_config_all()?;
        let msg = self.recv_cmd()?;
        for cfg in msg.config {
            let key = match VehicleProperty::try_from(cfg.prop()) {
                Err(_) => continue,
                Ok(value) => value,
            };
            self.prop_to_type.insert(
                key,
                VehiclePropertyType::try_from(cfg.value_type()).expect("Unexpected value type"),
            );
        }
        Ok(self)
    }

    pub fn get_config(&self, prop: VehicleProperty) -> Result<()> {
        let mut cmd = EmulatorMessage::new();
        let mut prop_get = VehiclePropGet::new();
        cmd.set_msg_type(VehicleHalProto::MsgType::GET_CONFIG_CMD);
        prop_get.set_prop(prop as i32);
        cmd.prop.push(prop_get);
        self.send_cmd(cmd)?;

        Ok(())
    }

    pub fn get_config_all(&self) -> Result<()> {
        let mut cmd = EmulatorMessage::new();
        cmd.set_msg_type(VehicleHalProto::MsgType::GET_CONFIG_ALL_CMD);
        self.send_cmd(cmd)?;

        Ok(())
    }

    pub fn set_property(
        &self,
        prop: VehicleProperty,
        value: VehiclePropertyValue,
        area_id: i32,
        status: Option<VehicleHalProto::VehiclePropStatus>,
    ) -> Result<()> {
        let mut cmd = EmulatorMessage::new();
        let mut vhal_prop_value = VehicleHalProto::VehiclePropValue::new();
        cmd.set_msg_type(VehicleHalProto::MsgType::SET_PROPERTY_CMD);
        vhal_prop_value.set_prop(prop as i32);
        vhal_prop_value.set_area_id(area_id);
        vhal_prop_value.set_status(match status {
            None => VehicleHalProto::VehiclePropStatus::AVAILABLE,
            Some(value) => value,
        });
        let val_type = match self.prop_to_type.get(&prop) {
            Some(val_type) => val_type,
            None => return Err(VhalError::PropertyError(prop as i32)),
        };
        vhal_prop_value.set_value_type(*val_type as i32);
        if !value.check_valid_type(val_type) {
            return Err(VhalError::PropertyTypeError);
        }
        value.set_prop_value(&mut vhal_prop_value);
        cmd.value.push(vhal_prop_value);
        self.send_cmd(cmd)?;

        Ok(())
    }

    pub fn get_property(&self, prop: VehicleProperty, area_id: i32) -> Result<()> {
        let mut cmd = EmulatorMessage::new();
        let mut vhal_prop_get = VehicleHalProto::VehiclePropGet::new();
        cmd.set_msg_type(VehicleHalProto::MsgType::GET_PROPERTY_CMD);
        vhal_prop_get.set_prop(prop as i32);
        vhal_prop_get.set_area_id(area_id);
        cmd.prop.push(vhal_prop_get);
        self.send_cmd(cmd)?;

        Ok(())
    }

    pub fn set_gear_selection(&self, gear: c::VehicleGear) -> Result<()> {
        let value = VehiclePropertyValue::Int32(gear as i32);
        self.set_property(VehicleProperty::GEAR_SELECTION, value, 0, None)
    }

    pub fn get_gear_selection(&self) -> Result<c::VehicleGear> {
        self.get_property(VehicleProperty::GEAR_SELECTION, 0)?;
        let resp = self.recv_retry()?;

        Ok(c::VehicleGear::try_from(resp.expect_i32()?)
            .map_err(|_| VhalError::ReceiveMessageValueError)?)
    }

    pub fn set_vehicle_speed(&self, speed: f32) -> Result<()> {
        let value = VehiclePropertyValue::Float(speed);
        self.set_property(VehicleProperty::PERF_VEHICLE_SPEED, value, 0, None)
    }

    pub fn get_vehicle_speed(&self) -> Result<f32> {
        self.get_property(VehicleProperty::PERF_VEHICLE_SPEED, 0)?;
        let resp = self.recv_retry()?;

        resp.expect_f32()
    }

    pub fn set_vehicle_display_speed(&self, speed: f32) -> Result<()> {
        let value = VehiclePropertyValue::Float(speed);
        self.set_property(VehicleProperty::PERF_VEHICLE_SPEED_DISPLAY, value, 0, None)
    }

    pub fn get_vehicle_display_speed(&self) -> Result<f32> {
        self.get_property(VehicleProperty::PERF_VEHICLE_SPEED_DISPLAY, 0)?;
        let resp = self.recv_retry()?;

        resp.expect_f32()
    }

    fn send_cmd(&self, cmd: EmulatorMessage) -> Result<()> {
        debug!("Sending command: {:?}", cmd);
        let msg_bytes = cmd.write_to_bytes().expect("msg");
        // Convert the message lenght into int32 byte array
        let msg_hdr = match structure!("!I").pack(msg_bytes.len() as u32) {
            Err(e) => {
                warn!("Error: {}", e);
                return Err(VhalError::PackMessageError);
            }
            Ok(value) => value,
        };
        self.socket
            .send(msg_hdr.as_slice())
            .map_err(VhalError::SendMessageError)?;
        self.socket
            .send(&msg_bytes)
            .map_err(VhalError::SendMessageError)?;

        Ok(())
    }

    pub fn recv_cmd(&self) -> Result<EmulatorMessage> {
        let mut buf: [MaybeUninit<u8>; Self::RESP_HEADER_SIZE] =
            // SAFETY: Data is initialised right after or we return early
            unsafe { MaybeUninit::uninit().assume_init() };
        let bytes = match self.socket.recv(&mut buf) {
            Err(e) => return Err(VhalError::ReceiveMessageError(e)),
            Ok(bytes) => bytes,
        };
        if bytes != Self::RESP_HEADER_SIZE {
            return Err(VhalError::ReceiveMessageLengthError(
                Self::RESP_HEADER_SIZE,
                bytes,
            ));
        }
        let buf: Vec<_> = buf
            .iter()
            // SAFETY: At this point the buffer is already initialised
            .map(|byte| unsafe { byte.assume_init() })
            .collect();
        let msg_len = match structure!("!I").unpack(buf) {
            Err(e) => {
                warn!("Error: {}", e);
                return Err(VhalError::UnPackMessageError);
            }
            Ok(value) => value.0 as usize,
        };
        let mut msg_raw = [MaybeUninit::new(0); Self::MAX_RESP_SIZE];
        let bytes = match self.socket.recv(&mut msg_raw) {
            Err(e) => return Err(VhalError::ReceiveMessageError(e)),
            Ok(bytes) => bytes,
        };
        if bytes != msg_len {
            return Err(VhalError::ReceiveMessageLengthError(msg_len, bytes));
        }
        let mut msg = EmulatorMessage::new();
        let msg_raw = msg_raw[0..msg_len]
            .iter()
            // SAFETY: At this point the buffer is already initialised
            .map(|byte| unsafe { byte.assume_init() })
            .collect::<Vec<u8>>();
        msg.merge_from_bytes(&msg_raw)
            .map_err(|e| VhalError::ReceiveMessageError(e.into()))?;
        debug!("Message received: {}", msg);

        Ok(msg)
    }

    fn recv_retry(&self) -> Result<EmulatorMessage> {
        let mut resp = self.recv_cmd()?;
        if resp.is_valid(VehicleHalProto::MsgType::GET_PROPERTY_RESP).is_err() {
            // Allow a single retry.
            resp = self.recv_cmd()?;
            resp.is_valid(VehicleHalProto::MsgType::GET_PROPERTY_RESP)?;
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;
    use VehicleHalProto::Status;

    use super::*;

    /// Creates a new port forward through adb
    #[fixture]
    pub fn local_port() -> u16 {
        adb_port_forwarding().expect("Could not run adb for port forwarding")
    }

    #[rstest]
    #[case::neutral(c::VehicleGear::GEAR_NEUTRAL)]
    #[case::park(c::VehicleGear::GEAR_PARK)]
    #[case::drive(c::VehicleGear::GEAR_DRIVE)]
    #[case::reverse(c::VehicleGear::GEAR_REVERSE)]
    fn gear_selection_test(local_port: u16, #[case] gear: c::VehicleGear) {
        let vhal = Vhal::new(local_port).unwrap();
        vhal.set_gear_selection(gear).unwrap();
        assert!(vhal
            .recv_cmd()
            .is_ok_and(|cmd| cmd.has_status() && cmd.status() == Status::RESULT_OK));
        assert!(vhal
            .get_gear_selection()
            .is_ok_and(|rcv_gear| rcv_gear == gear));
    }

    #[rstest]
    #[case::stopped(0.0)]
    #[case::slow(30.0)]
    #[case::city(50.0)]
    #[case::road(80.0)]
    #[case::highway(120.0)]
    #[case::reverse(-10.0)]
    fn speed_test(local_port: u16, #[case] speed: f32) {
        let vhal = Vhal::new(local_port).unwrap();
        vhal.set_vehicle_speed(speed).unwrap();
        assert!(vhal
            .recv_cmd()
            .is_ok_and(|cmd| cmd.has_status() && cmd.status() == Status::RESULT_OK));
        assert!(vhal
            .get_vehicle_speed()
            .is_ok_and(|rcv_speed| rcv_speed == speed));
        vhal.set_vehicle_display_speed(speed).unwrap();
        assert!(vhal
            .recv_cmd()
            .is_ok_and(|cmd| cmd.has_status() && cmd.status() == Status::RESULT_OK));
        assert!(vhal
            .get_vehicle_display_speed()
            .is_ok_and(|rcv_speed| rcv_speed == speed));
    }
}
