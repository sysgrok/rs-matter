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

#![cfg(all(feature = "std", feature = "async-io"))]

//! UDP transport implementation for async-io

use crate::error::*;

use std::net::UdpSocket;

use async_io::Async;

use crate::transport::network::Address;

use super::{NetworkReceive, NetworkSend};

extern crate std;

impl NetworkSend for &Async<UdpSocket> {
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        Async::<UdpSocket>::send_to(self, data, addr.udp().ok_or(ErrorCode::NoNetworkInterface)?)
            .await?;

        Ok(())
    }
}

impl NetworkReceive for &Async<UdpSocket> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        Async::<UdpSocket>::readable(self).await?;

        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let (len, addr) = Async::<UdpSocket>::recv_from(self, buffer).await?;

        Ok((len, Address::Udp(addr)))
    }
}
