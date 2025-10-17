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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.IP4Config`

use alloc::vec;

use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::OwnedValue;

extern crate alloc;
extern crate std;

#[proxy(
    interface = "org.freedesktop.NetworkManager.IP4Config",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait IP4Config {
    /// AddressData property
    #[zbus(property)]
    fn address_data(&self) -> zbus::Result<Vec<HashMap<String, OwnedValue>>>;

    /// Addresses property
    #[zbus(property)]
    fn addresses(&self) -> zbus::Result<Vec<Vec<u32>>>;

    /// DnsOptions property
    #[zbus(property)]
    fn dns_options(&self) -> zbus::Result<Vec<String>>;

    /// DnsPriority property
    #[zbus(property)]
    fn dns_priority(&self) -> zbus::Result<i32>;

    /// Domains property
    #[zbus(property)]
    fn domains(&self) -> zbus::Result<Vec<String>>;

    /// Gateway property
    #[zbus(property)]
    fn gateway(&self) -> zbus::Result<String>;

    /// NameserverData property
    #[zbus(property)]
    fn nameserver_data(&self) -> zbus::Result<Vec<HashMap<String, OwnedValue>>>;

    /// Nameservers property
    #[zbus(property)]
    fn nameservers(&self) -> zbus::Result<Vec<u32>>;

    /// RouteData property
    #[zbus(property)]
    fn route_data(&self) -> zbus::Result<Vec<HashMap<String, OwnedValue>>>;

    /// Routes property
    #[zbus(property)]
    fn routes(&self) -> zbus::Result<Vec<Vec<u32>>>;

    /// Searches property
    #[zbus(property)]
    fn searches(&self) -> zbus::Result<Vec<String>>;

    /// WinsServerData property
    #[zbus(property)]
    fn wins_server_data(&self) -> zbus::Result<Vec<String>>;

    /// WinsServers property
    #[zbus(property)]
    fn wins_servers(&self) -> zbus::Result<Vec<u32>>;
}
