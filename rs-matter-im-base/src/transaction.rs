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

//! The client side of a single Interaction Model transaction.
//!
//! The generated cluster clients (`<Cluster>Client`) are written against the
//! traits in this module rather than against a concrete exchange type, so that
//! they do not depend on the transport.

use core::future::Future;

use crate::error::Error;
use crate::tlv::TLVBuilderParent;
use crate::utils::sync::MaybeSend;

use super::{
    InvReqBuilder, InvokeResp, ReadReqBuilder, ReportDataResp, WriteReqBuilder, WriteResp,
};

/// A single Interaction Model transaction with a peer: one Read, Write or
/// Invoke request, and the response to it.
///
/// Each method consumes the transaction.
///
/// The `build` closure passed to each method writes the request. It may be
/// called more than once, when the request has to be sent again, and must
/// write the same request every time.
pub trait ImTransaction: Sized {
    /// The parent of the builder of a Read request.
    type ReadSender: TLVBuilderParent;
    /// The parent of the builder of a Write request.
    type WriteSender: TLVBuilderParent;
    /// The parent of the builder of an Invoke request.
    type InvokeSender: TLVBuilderParent;
    /// A chunk of the response to a Read request.
    type ReadChunk: ImReadChunk;
    /// The response to a Write request.
    type WriteHandle: ImWriteHandle;
    /// A chunk of the response to an Invoke request.
    type InvokeChunk: ImInvokeChunk;

    /// Send a Read request and return the first chunk of the response.
    fn read_with<B>(
        self,
        build: B,
    ) -> impl Future<Output = Result<Self::ReadChunk, Error>> + MaybeSend
    where
        B: FnMut(ReadReqBuilder<Self::ReadSender>) -> Result<Self::ReadSender, Error> + MaybeSend;

    /// Send a Write request and return the response.
    ///
    /// If `timed_timeout_ms` is `Some`, the request is preceded by a Timed
    /// Request with that timeout.
    fn write_with<B>(
        self,
        timed_timeout_ms: Option<u16>,
        build: B,
    ) -> impl Future<Output = Result<Self::WriteHandle, Error>> + MaybeSend
    where
        B: FnMut(WriteReqBuilder<Self::WriteSender>) -> Result<Self::WriteSender, Error>
            + MaybeSend;

    /// Send an Invoke request and return the first chunk of the response.
    ///
    /// If `timed_timeout_ms` is `Some`, the request is preceded by a Timed
    /// Request with that timeout.
    fn invoke_with<B>(
        self,
        timed_timeout_ms: Option<u16>,
        build: B,
    ) -> impl Future<Output = Result<Self::InvokeChunk, Error>> + MaybeSend
    where
        B: FnMut(InvReqBuilder<Self::InvokeSender>) -> Result<Self::InvokeSender, Error>
            + MaybeSend;
}

/// A chunk of the response to a Read request.
pub trait ImReadChunk: Sized {
    /// The response carried by this chunk.
    fn response(&self) -> Result<ReportDataResp<'_>, Error>;

    /// Acknowledge this chunk and return the next one, or `None` if this was
    /// the last one.
    fn complete(self) -> impl Future<Output = Result<Option<Self>, Error>> + MaybeSend;
}

/// A chunk of the response to an Invoke request.
pub trait ImInvokeChunk: Sized {
    /// The response carried by this chunk, or `None` if the peer replied with
    /// a status only.
    fn response(&self) -> Result<Option<InvokeResp<'_>>, Error>;

    /// Acknowledge this chunk and return the next one, or `None` if this was
    /// the last one.
    fn complete(self) -> impl Future<Output = Result<Option<Self>, Error>> + MaybeSend;
}

/// The response to a Write request.
pub trait ImWriteHandle {
    /// The response.
    fn response(&self) -> Result<WriteResp<'_>, Error>;
}
