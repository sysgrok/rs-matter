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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.OlpcMesh`

use alloc::vec;

use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

extern crate alloc;
extern crate std;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.OlpcMesh",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait OlpcMesh {
    /// HwAddress property
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;

    /// Companion property
    #[zbus(property)]
    fn companion(&self) -> zbus::Result<OwnedObjectPath>;

    /// ActiveChannel property
    #[zbus(property)]
    fn active_channel(&self) -> zbus::Result<u32>;
}
