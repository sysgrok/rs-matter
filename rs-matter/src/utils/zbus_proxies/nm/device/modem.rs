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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.Modem`

use alloc::vec;

use zbus::proxy;

extern crate alloc;
extern crate std;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Modem",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Modem {
    /// ModemCapabilities property
    #[zbus(property)]
    fn modem_capabilities(&self) -> zbus::Result<u32>;

    /// CurrentCapabilities property
    #[zbus(property)]
    fn current_capabilities(&self) -> zbus::Result<u32>;

    /// DeviceId property
    #[zbus(property)]
    fn device_id(&self) -> zbus::Result<String>;

    /// OperatorCode property
    #[zbus(property)]
    fn operator_code(&self) -> zbus::Result<String>;

    /// Apn property
    #[zbus(property)]
    fn apn(&self) -> zbus::Result<String>;
}
