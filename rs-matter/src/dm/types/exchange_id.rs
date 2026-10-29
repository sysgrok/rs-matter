/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

use core::fmt::{self, Display};

/// An exchange identifier, uniquely identifying a session and an exchange within that session for a given Matter stack.
///
/// The operation contexts give it to the handlers, so that they can find the
/// session an operation arrived on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExchangeId(u32);

impl ExchangeId {
    /// Create an identifier from the ID of a session and the index of an
    /// exchange within it.
    ///
    /// Panics if the session ID does not fit in 28 bits, or if the exchange
    /// index is not below 16.
    pub fn new(session_id: u32, exchange_index: usize) -> Self {
        if session_id > 0x0fff_ffff {
            panic!("Session ID out of range");
        }

        if exchange_index >= 16 {
            panic!("Exchange index out of range");
        }

        Self(((exchange_index as u32) << 28) | session_id)
    }

    /// The ID of the session of the exchange.
    pub fn session_id(&self) -> u32 {
        self.0 & 0x0fff_ffff
    }

    /// The index of the exchange within its session.
    pub fn exchange_index(&self) -> usize {
        (self.0 >> 28) as _
    }
}

impl Display for ExchangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.session_id(), self.exchange_index())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ExchangeId {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{}::{}", self.session_id(), self.exchange_index())
    }
}
