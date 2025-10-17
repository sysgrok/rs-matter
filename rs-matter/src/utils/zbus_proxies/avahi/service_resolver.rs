/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

//! # D-Bus interface proxy for: `org.freedesktop.Avahi.ServiceResolver`

use alloc::vec;

use zbus::proxy;

extern crate alloc;
extern crate std;

#[proxy(
    interface = "org.freedesktop.Avahi.ServiceResolver",
    default_service = "org.freedesktop.Avahi"
)]
pub trait ServiceResolver {
    /// Free method
    fn free(&self) -> zbus::Result<()>;

    /// Start method
    fn start(&self) -> zbus::Result<()>;

    /// Failure signal
    #[zbus(signal)]
    fn failure(&self, error: &str) -> zbus::Result<()>;

    /// Found signal
    #[zbus(signal)]
    fn found(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        type_: &str,
        domain: &str,
        host: &str,
        aprotocol: i32,
        address: &str,
        port: u16,
        txt: Vec<Vec<u8>>,
        flags: u32,
    ) -> zbus::Result<()>;
}
