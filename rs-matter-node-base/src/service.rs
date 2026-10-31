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

/// A Matter service that **this** node advertises (publishes) over a discovery
/// transport such as mDNS.
///
/// This is the *publish-side* identity; the *query-side* analog is
/// `MatterRemoteService`. The discovery-transport encoding (e.g. the mDNS
/// `MdnsLocalService` record) lives in the `mdns` module of `rs-matter-node`
/// (`MatterLocalService::service`).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MatterLocalService {
    /// A commissioned Matter service for a particular fabric
    ///
    /// The published name is in the form `<compressed-fabric-id-hex>-<node-id-hex>`.
    Commissioned {
        compressed_fabric_id: u64,
        node_id: u64,
    },
    /// A non-commissioned Matter service
    ///
    /// The published name is in the form `<id-hex>`. The discriminator should be used as an mDNS TXT entry
    Commissionable {
        id: u64,
        /// The discriminator to be communicated over mDNS
        discriminator: u16,
        /// Whether this is an enhanced (ECM) commissioning window (`CM=2`) vs basic (`CM=1`)
        enhanced: bool,
    },
}
