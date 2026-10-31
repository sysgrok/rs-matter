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

//! The SPAKE2+ verifier data of a commissioning window: the passcode or the
//! verifier, the salt and the iteration count. SPAKE2+ itself is in `rs-matter-sc`.

use crate::crypto::{canon, EC_CANON_POINT_LEN, EC_CANON_SCALAR_LEN};
pub use crate::pairing::{
    Spake2pVerifierPassword, Spake2pVerifierPasswordRef, SPAKE2P_VERIFIER_PASSWORD_LEN,
    SPAKE2P_VERIFIER_PASSWORD_ZEROED,
};
use crate::utils::init::{init, Init};

pub const SPAKE2P_ITERATION_COUNT: u32 = 2000;

pub const SPAKE2P_VERIFIER_STR_LEN: usize = EC_CANON_SCALAR_LEN + EC_CANON_POINT_LEN;

/// Maximum size of the PASE salt buffer, in bytes.
///
/// The Matter Core spec (Cryptographic Building Blocks) defines the
/// PASE salt as a variable-length octet string in **the range 16..=32**.
pub const SPAKE2P_VERIFIER_SALT_LEN: usize = 32;

/// Minimum PASE salt length per Matter Core spec.
pub const SPAKE2P_VERIFIER_SALT_MIN_LEN: usize = 16;

canon!(
    SPAKE2P_VERIFIER_STR_LEN,
    SPAKE2P_VERIFIER_STR_ZEROED,
    Spake2pVerifierStr,
    Spake2pVerifierStrRef
);
canon!(
    SPAKE2P_VERIFIER_SALT_LEN,
    SPAKE2P_VERIFIER_SALT_ZEROED,
    Spake2pVerifierSalt,
    Spake2pVerifierSaltRef
);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Spake2pVerifierData {
    /// When `password` is `None`, `verifier` is expected to be set
    pub password: Option<Spake2pVerifierPassword>,
    pub verifier: Spake2pVerifierStr,
    // For the VerifierOption::Verifier, the following fields only serve
    // information purposes
    pub salt: Spake2pVerifierSalt,
    /// Number of valid bytes in the salt.
    pub salt_len: u8,
    pub count: u32,
}

impl Spake2pVerifierData {
    pub fn init_with_pw<'a>(
        password: Spake2pVerifierPasswordRef<'a>,
        salt: &'a [u8],
    ) -> impl Init<Self> + 'a {
        Self::init_empty().chain(move |this| {
            this.configure_pw(password, salt);
            Ok(())
        })
    }

    pub fn init<'a>(
        verifier: Spake2pVerifierStrRef<'a>,
        salt: &'a [u8],
        count: u32,
    ) -> impl Init<Self> + 'a {
        Self::init_empty().chain(move |this| {
            this.configure_verifier(verifier, salt, count);

            Ok(())
        })
    }

    fn init_empty() -> impl Init<Self> {
        init!(Self {
            password: None,
            verifier <- Spake2pVerifierStr::init(),
            salt <- Spake2pVerifierSalt::init(),
            salt_len: SPAKE2P_VERIFIER_SALT_LEN as u8,
            count: SPAKE2P_ITERATION_COUNT,
        })
    }

    fn configure_pw(&mut self, password: Spake2pVerifierPasswordRef<'_>, salt: &[u8]) {
        self.password = Some(password.into());
        self.set_salt(salt);
        self.verifier.zeroize();
        self.count = SPAKE2P_ITERATION_COUNT;
    }

    fn configure_verifier(&mut self, verifier: Spake2pVerifierStrRef<'_>, salt: &[u8], count: u32) {
        self.password = None;
        self.set_salt(salt);
        self.verifier.load(verifier);
        self.count = count;
    }

    /// Stamp the variable-length PASE salt into the fixed-size storage.
    /// Truncates anything past [`SPAKE2P_VERIFIER_SALT_LEN`] (32 B) so a
    /// caller bug can't out-of-bounds the buffer.
    fn set_salt(&mut self, salt: &[u8]) {
        debug_assert!(
            (SPAKE2P_VERIFIER_SALT_MIN_LEN..=SPAKE2P_VERIFIER_SALT_LEN).contains(&salt.len()),
            "PASE salt out of range: {} not in {}..={}",
            salt.len(),
            SPAKE2P_VERIFIER_SALT_MIN_LEN,
            SPAKE2P_VERIFIER_SALT_LEN
        );

        let n = salt.len().min(SPAKE2P_VERIFIER_SALT_LEN);

        let storage = self.salt.access_mut();
        storage.fill(0);
        storage[..n].copy_from_slice(&salt[..n]);

        self.salt_len = n as u8;
    }

    /// Return the in-use slice of the PASE salt (`salt_len` bytes).
    pub fn salt_bytes(&self) -> &[u8] {
        &self.salt.access()[..self.salt_len as usize]
    }
}
