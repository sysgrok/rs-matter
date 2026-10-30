/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! PASE (Passcode-Authenticated Session Establishment) protocol implementation.
//!
//! This module provides both the initiator (commissioner) and responder (device) sides
//! of the PASE protocol for establishing secure sessions using a shared passcode.

use crate::tlv::{FromTLV, OctetStr, ToTLV};
use crate::SessionParameters;

pub use initiator::PaseInitiator;
pub use responder::PaseResponder;
pub use rs_matter_transport::sc::pase::*;

mod initiator;
mod responder;
pub mod spake2p;

/// The info string for SPAKE2 session key derivation
pub(crate) const SPAKE2_SESSION_KEYS_INFO: &[u8] = b"SessionKeys";

/// The PBKDFParamRequest structure
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct PBKDFParamReq<'a> {
    /// The initiator random bytes
    pub initiator_random: OctetStr<'a>,
    /// The initiator session identifier
    pub initiator_ssid: u16,
    /// The passcode identifier
    pub passcode_id: u16,
    /// Whether parameters are included
    pub has_params: bool,
    /// The session parameters, if any
    pub session_parameters: Option<SessionParameters>,
}

/// The PBKDFParamResponse structure
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct PBKDFParamResp<'a> {
    /// The initiator random bytes (echoed back)
    pub initiator_random: OctetStr<'a>,
    /// The responder random bytes
    pub responder_random: OctetStr<'a>,
    /// The responder session identifier
    pub responder_ssid: u16,
    /// The PBKDF2 parameters, if any
    pub params: Option<PBKDFParamRespParams<'a>>,
    /// The responder session parameters, if any
    pub session_parameters: Option<SessionParameters>,
}

/// The PBKDFParamResponse parameters structure
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct PBKDFParamRespParams<'a> {
    /// The iteration count
    pub iterations: u32,
    /// The salt bytes
    pub salt: OctetStr<'a>,
}

/// TLV structure for Pake1 (sent by initiator)
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct Pake1<'a> {
    /// The pA point (65 bytes, uncompressed P-256)
    pub pa: OctetStr<'a>,
}

/// The Pake1Resp structure (Pake2 message from responder)
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct Pake2<'a> {
    /// The pB bytes
    pub pb: OctetStr<'a>,
    /// The cB bytes
    pub cb: OctetStr<'a>,
}

/// TLV structure for Pake3 (sent by initiator)
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub(crate) struct Pake3<'a> {
    /// The cA confirmation (32 bytes HMAC)
    pub ca: OctetStr<'a>,
}
