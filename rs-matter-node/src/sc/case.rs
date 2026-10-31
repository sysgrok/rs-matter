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

//! The state of CASE (Certificate Authenticated Session Establishment) that is a
//! part of `MatterState`: the session resumption cache. The protocol itself is in
//! `rs-matter-sc`.

use crate::crypto::canon;

#[cfg(feature = "case-resumption")]
pub use resumption::{ResumableSession, ResumableSessions, MAX_RESUMPTION_RECORDS};

#[cfg(feature = "case-resumption")]
pub mod resumption;

/// The length of a CASE resumption ID
pub const CASE_RESUMPTION_ID_LEN: usize = 16;

canon!(
    CASE_RESUMPTION_ID_LEN,
    CASE_RESUMPTION_ID_ZEROED,
    CaseResumptionId,
    CaseResumptionIdRef
);
