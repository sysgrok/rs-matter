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

use core::fmt::{self, Display};
use core::pin::pin;

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_time::{Duration, Instant, Timer};

use crate::acl::Accessor;
use crate::dm::clusters::basic_info::BasicInfoSettings;
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricMgr;
use crate::failsafe::FailSafe;
use crate::im::{self, PROTO_ID_INTERACTION_MODEL};
use crate::sc::pake::PaseMgr;
use crate::sc::{self, PROTO_ID_SECURE_CHANNEL};
use crate::utils::epoch::Epoch;
use crate::utils::storage::WriteBuf;
use crate::Matter;

use super::mrp::{ReliableMessage, RetransEntry};
use super::network;
use super::packet::PacketHdr;
use super::plain_hdr::PlainHdr;
use super::proto_hdr::ProtoHdr;
use super::session::Session;
use super::{Packet, PacketAccess, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};

/// Minimum buffer which should be allocated by user code that wants to pull RX messages via `Exchange::recv_into`
// TODO: Revisit with large packets
pub const MAX_EXCHANGE_RX_BUF_SIZE: usize = network::MAX_RX_PACKET_SIZE;

/// Maximum buffer which should be allocated and used by user code that wants to send messages via `Exchange::send`
// TODO: Revisit with large packets
pub const MAX_EXCHANGE_TX_BUF_SIZE: usize =
    network::MAX_TX_PACKET_SIZE - PacketHdr::HDR_RESERVE - PacketHdr::TAIL_RESERVE;

/// An exchange identifier, uniquely identifying a session and an exchange within that session for a given Matter stack.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExchangeId(u32);

impl ExchangeId {
    pub(crate) fn new(session_id: u32, exchange_index: usize) -> Self {
        if session_id > 0x0fff_ffff {
            panic!("Session ID out of range");
        }

        if exchange_index >= 16 {
            panic!("Exchange index out of range");
        }

        Self(((exchange_index as u32) << 28) | session_id)
    }

    pub(crate) fn session_id(&self) -> u32 {
        self.0 & 0x0fff_ffff
    }

    pub(crate) fn exchange_index(&self) -> usize {
        (self.0 >> 28) as _
    }

    pub(crate) fn display<'a>(&'a self, session: &'a Session) -> ExchangeIdDisplay<'a> {
        ExchangeIdDisplay { id: self, session }
    }

    async fn recv<'a, M: Matter>(&self, matter: &'a M) -> Result<RxMessage<'a>, Error> {
        self.check_no_pending_retrans(matter)?;

        let transport = &matter.transport();

        loop {
            let mut recv = pin!(transport.get_if(&transport.rx, |packet| {
                if packet.buf.is_empty() {
                    false
                } else {
                    let for_us = self.with_ctx(matter, |sess, exch_index| {
                        if sess.is_for_rx(&packet.peer, &packet.header.plain) {
                            let exchange = unwrap!(sess.exchanges[exch_index].as_ref());

                            return Ok(exchange.is_for_rx(&packet.header.proto));
                        }

                        Ok(false)
                    });

                    for_us.unwrap_or(true)
                }
            }));

            let mut session_removed = pin!(transport.session_removed.wait());

            let mut timeout = pin!(Timer::after(Duration::from_millis(
                RetransEntry::new(matter.dev_det().sai, 0).max_delay_ms() * 3 / 2
            )));

            match select3(&mut recv, &mut session_removed, &mut timeout).await {
                Either3::First(mut packet) => {
                    packet.clear_on_drop(true);

                    self.check_no_pending_retrans(matter)?;

                    break Ok(RxMessage(packet));
                }
                Either3::Second(_) => {
                    // Session removed

                    // Bail out if it was ours
                    self.with_session(matter, |_| Ok(()))?;

                    // If not, go back waiting for a packet
                    continue;
                }
                Either3::Third(_) => {
                    // Timeout waiting for an answer from the other peer
                    Err(ErrorCode::RxTimeout)?;
                }
            };
        }
    }

    /// Gets access to the TX buffer of the Matter stack for constructing a new TX message.
    /// If the TX buffer is not available, the method will wait indefinitely until it becomes available.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn init_send<'a, M: Matter>(&self, matter: &'a M) -> Result<TxMessage<'a, M>, Error> {
        self.with_ctx(matter, |_, _| Ok(()))?;

        let transport = matter.transport();

        let mut packet = transport
            .get_if(&transport.tx, |packet| {
                packet.buf.is_empty() || self.with_ctx(matter, |_, _| Ok(())).is_err()
            })
            .await;

        // TODO: Resizing might be a bit expensive with large buffers
        unwrap!(packet.buf.resize_default(MAX_TX_BUF_SIZE));

        packet.clear_on_drop(true);

        let tx = TxMessage {
            exchange_id: *self,
            matter,
            packet,
        };

        self.with_ctx(matter, |_, _| Ok(()))?;

        Ok(tx)
    }

    /// Waits until the other side acknowledges the last message sent on this exchange,
    /// or until time for a re-transmission had come.
    ///
    /// If the last sent message was not using the MRP protocol, the method will return immediately with `TxOutcome::Done`.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn wait_tx(&self, matter: impl Matter) -> Result<TxOutcome, Error> {
        if let Some(delay) = self.retrans_delay_ms(&matter)? {
            let expired = unwrap!(Instant::now().checked_add(Duration::from_millis(delay)));

            loop {
                let mut notification = pin!(self.internal_wait_ack(&matter));
                let mut session_removed = pin!(matter.transport().session_removed.wait());
                let mut timer = pin!(Timer::at(expired));

                if !matches!(
                    select3(&mut notification, &mut session_removed, &mut timer).await,
                    Either3::Second(_)
                ) {
                    break;
                }

                // Bail out if the removed session was ours
                self.with_session(&matter, |_| Ok(()))?;
            }

            if self.retrans_delay_ms(&matter)?.is_some() {
                Ok(TxOutcome::Retransmit)
            } else {
                Ok(TxOutcome::Done)
            }
        } else {
            Ok(TxOutcome::Done)
        }
    }

    fn accessor(&self, matter: impl Matter) -> Result<Accessor, Error> {
        self.with_session(matter, |sess| {
            Ok(Accessor::for_session(sess))
        })
    }

    fn state<F, T>(&self, matter: impl Matter, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut ExchangeState0) -> Result<T, Error>,
    {
        matter.state(|state| {
            if let Some(session) = state.sessions.get(self.session_id()) {
                f(&mut ExchangeState0 {
                    fabrics: &mut state.fabrics,
                    pase: &mut state.pase,
                    failsafe: &mut state.failsafe,
                    basic_info_settings: &mut state.basic_info_settings,
                    session, 
                    exch_idx: self.exchange_index(),
                })
            } else {
                warn!("Exchange {}: No session", self);
                Err(ErrorCode::NoSession.into())
            }
        })
    }

    async fn internal_wait_ack(&self, matter: impl Matter) -> Result<(), Error> {
        let transport = matter.transport();

        transport
            .get_if(&transport.rx, |_| {
                self.retrans_delay_ms(&matter)
                    .map(|retrans| retrans.is_none())
                    .unwrap_or(true)
            })
            .await;

        self.with_ctx(matter, |_, _| Ok(()))
    }

    fn retrans_delay_ms(&self, matter: impl Matter) -> Result<Option<u64>, Error> {
        self.with_ctx(&matter, |sess, exch_index| {
            let exchange = unwrap!(sess.exchanges[exch_index].as_mut());

            let mut jitter_rand = [0; 1];
            matter.rand()(&mut jitter_rand);

            Ok(exchange.retrans_delay_ms(jitter_rand[0]))
        })
    }

    fn check_no_pending_retrans(&self, matter: impl Matter) -> Result<(), Error> {
        self.with_ctx(matter, |sess, exch_index| {
            let exchange = unwrap!(sess.exchanges[exch_index].as_mut());

            if exchange.mrp.is_retrans_pending() {
                error!("Exchange {}: Retransmission pending", self.display(sess));
                Err(ErrorCode::InvalidState)?;
            }

            Ok(())
        })
    }

    fn pending_retrans(&self, matter: impl Matter) -> Result<bool, Error> {
        Ok(self.retrans_delay_ms(matter)?.is_some())
    }

    fn pending_ack(&self, matter: impl Matter) -> Result<bool, Error> {
        self.with_ctx(matter, |sess, exch_index| {
            let exchange = unwrap!(sess.exchanges[exch_index].as_ref());

            Ok(exchange.mrp.is_ack_pending())
        })
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

/// A display wrapper for `ExchangeId` which also displays
/// the packet session ID, packet peer session ID and packet exchange ID.
pub struct ExchangeIdDisplay<'a> {
    id: &'a ExchangeId,
    session: &'a Session,
}

impl Display for ExchangeIdDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.session.exchanges[self.id.exchange_index()].as_ref();

        if let Some(state) = state {
            write!(
                f,
                "{} [SID:{:x},RSID:{:x},EID:{:x}]",
                self.id,
                self.session.get_local_sess_id(),
                self.session.get_peer_sess_id(),
                state.exch_id
            )
        } else {
            // This should never happen, as that would mean we have invalid exchange index
            // but let's not crash when displaying that
            write!(f, "{}???", self.id)
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ExchangeIdDisplay<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        let state = self.session.exchanges[self.id.exchange_index()].as_ref();

        if let Some(state) = state {
            defmt::write!(
                f,
                "{} [SID:{:x},RSID:{:x},EID:{:x}]",
                self.id,
                self.session.get_local_sess_id(),
                self.session.get_peer_sess_id(),
                state.exch_id
            )
        } else {
            // This should never happen, as that would mean we have invalid exchange index
            // but let's not crash when displaying that
            defmt::write!(f, "{}???", self.id)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum InitiatorState {
    #[default]
    Owned,
    Dropped,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum ResponderState {
    #[default]
    AcceptPending,
    Owned,
    Dropped,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Role {
    Initiator(InitiatorState),
    Responder(ResponderState),
}

impl Role {
    pub fn is_dropped_state(&self) -> bool {
        match self {
            Self::Initiator(state) => *state == InitiatorState::Dropped,
            Self::Responder(state) => *state == ResponderState::Dropped,
        }
    }

    pub fn set_dropped_state(&mut self) {
        match self {
            Self::Initiator(state) => *state = InitiatorState::Dropped,
            Self::Responder(state) => *state = ResponderState::Dropped,
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct ExchangeState {
    pub(crate) exch_id: u16,
    pub(crate) role: Role,
    pub(crate) mrp: ReliableMessage,
}

impl ExchangeState {
    pub fn is_for_rx(&self, rx_proto: &ProtoHdr) -> bool {
        self.exch_id == rx_proto.exch_id
            && rx_proto.is_initiator() == matches!(self.role, Role::Responder(_))
    }

    pub fn post_recv(
        &mut self,
        rx_plain: &PlainHdr,
        rx_proto: &ProtoHdr,
        epoch: Epoch,
    ) -> Result<(), Error> {
        self.mrp.post_recv(rx_plain, rx_proto, epoch)?;

        Ok(())
    }

    pub fn pre_send(
        &mut self,
        tx_plain: &PlainHdr,
        tx_proto: &mut ProtoHdr,
        session_active_interval_ms: Option<u16>,
        session_idle_interval_ms: Option<u16>,
    ) -> Result<(), Error> {
        if matches!(self.role, Role::Initiator(_)) {
            tx_proto.set_initiator();
        } else {
            tx_proto.unset_initiator();
        }

        tx_proto.exch_id = self.exch_id;

        self.mrp.pre_send(
            tx_plain,
            tx_proto,
            session_active_interval_ms,
            session_idle_interval_ms,
        )
    }

    pub fn retrans_delay_ms(&mut self, jitter_rand: u8) -> Option<u64> {
        self.mrp
            .retrans
            .as_ref()
            .map(|retrans| retrans.delay_ms(jitter_rand))
    }
}

/// Meta-data when sending/receving messages via an Exchange.
/// Basically, the protocol ID, the protocol opcode and whether the message should be set in a reliable manner.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct MessageMeta {
    pub proto_id: u16,
    pub proto_opcode: u8,
    pub reliable: bool,
}

impl MessageMeta {
    // Create a new message meta-data instance
    pub const fn new(proto_id: u16, proto_opcode: u8, reliable: bool) -> Self {
        Self {
            proto_id,
            proto_opcode,
            reliable,
        }
    }

    /// Try to cast the protocol opcode to a specific type
    pub fn opcode<T: num::FromPrimitive>(&self) -> Result<T, Error> {
        num::FromPrimitive::from_u8(self.proto_opcode).ok_or(ErrorCode::InvalidOpcode.into())
    }

    /// Check if the protocol opcode is equal to a specific value
    pub fn check_opcode<T: num::FromPrimitive + PartialEq>(&self, opcode: T) -> Result<(), Error> {
        if self.opcode::<T>()? == opcode {
            Ok(())
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    /// Create an instance from a ProtoHdr instance
    pub fn from(proto: &ProtoHdr) -> Self {
        Self {
            proto_id: proto.proto_id,
            proto_opcode: proto.proto_opcode,
            reliable: proto.is_reliable(),
        }
    }

    /// Set the protocol ID and opcode into a ProtoHdr instance
    pub fn set_into(&self, proto: &mut ProtoHdr) {
        proto.proto_id = self.proto_id;
        proto.proto_opcode = self.proto_opcode;
        proto.set_vendor(None);

        if self.reliable {
            proto.set_reliable();
        } else {
            proto.unset_reliable();
        }
    }

    pub fn reliable(self, reliable: bool) -> Self {
        Self { reliable, ..self }
    }

    /// Utility method to check if the specific proto opcode in the instance is expecting a TLV payload.
    pub(crate) fn is_tlv(&self) -> bool {
        match self.proto_id {
            PROTO_ID_SECURE_CHANNEL => self
                .opcode::<sc::OpCode>()
                .ok()
                .map(|op| op.is_tlv())
                .unwrap_or(false),
            PROTO_ID_INTERACTION_MODEL => self
                .opcode::<im::OpCode>()
                .ok()
                .map(|op| op.is_tlv())
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Utility method to check if the protocol is Secure Channel, and the opcode is a standalone ACK (`MrpStandaloneAck`).
    pub(crate) fn is_standalone_ack(&self) -> bool {
        self.proto_id == PROTO_ID_SECURE_CHANNEL
            && self.proto_opcode == sc::OpCode::MRPStandAloneAck as u8
    }

    /// Utility method to check if the protocol is Secure Channel, and the opcode is Status.
    pub(crate) fn is_sc_status(&self) -> bool {
        self.proto_id == PROTO_ID_SECURE_CHANNEL
            && self.proto_opcode == sc::OpCode::StatusReport as u8
    }

    /// Utility method to check if the protocol is Secure Channel, and the opcode is a new session request.
    pub(crate) fn is_new_session(&self) -> bool {
        self.proto_id == PROTO_ID_SECURE_CHANNEL
            && (self.proto_opcode == sc::OpCode::PBKDFParamRequest as u8
                || self.proto_opcode == sc::OpCode::CASESigma1 as u8)
    }

    /// Utility method to check if the meta-data indicates a new exchange
    pub(crate) fn is_new_exchange(&self) -> bool {
        // Don't create new exchanges for standalone ACKs and for SC status codes
        !self.is_standalone_ack() && !self.is_sc_status()
    }
}

impl Display for MessageMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.proto_id {
            PROTO_ID_SECURE_CHANNEL => {
                if let Ok(opcode) = self.opcode::<sc::OpCode>() {
                    write!(f, "SC::{:?}", opcode)
                } else {
                    write!(f, "SC::{:02x}", self.proto_opcode)
                }
            }
            PROTO_ID_INTERACTION_MODEL => {
                if let Ok(opcode) = self.opcode::<im::OpCode>() {
                    write!(f, "IM::{:?}", opcode)
                } else {
                    write!(f, "IM::{:02x}", self.proto_opcode)
                }
            }
            _ => write!(f, "{:02x}::{:02x}", self.proto_id, self.proto_opcode),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for MessageMeta {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self.proto_id {
            PROTO_ID_SECURE_CHANNEL => {
                if let Ok(opcode) = self.opcode::<sc::OpCode>() {
                    defmt::write!(f, "SC::{:?}", opcode)
                } else {
                    defmt::write!(f, "SC::{:02x}", self.proto_opcode)
                }
            }
            PROTO_ID_INTERACTION_MODEL => {
                if let Ok(opcode) = self.opcode::<im::OpCode>() {
                    defmt::write!(f, "IM::{:?}", opcode)
                } else {
                    defmt::write!(f, "IM::{:02x}", self.proto_opcode)
                }
            }
            _ => defmt::write!(f, "{:02x}::{:02x}", self.proto_id, self.proto_opcode),
        }
    }
}

/// An RX message pending on an `Exchange` instance.
pub struct RxMessage<'a>(PacketAccess<'a, MAX_RX_BUF_SIZE>);

impl RxMessage<'_> {
    /// Get the meta-data of the pending message
    pub fn meta(&self) -> MessageMeta {
        MessageMeta::from(&self.0.header.proto)
    }

    /// Get the payload of the pending message
    pub fn payload(&self) -> &[u8] {
        &self.0.buf[self.0.payload_start..]
    }
}

/// Accessor to the TX message buffer of the underlying Matter transport stack.
///
/// This is used to construct a new TX message to be sent on an `Exchange` instance.
///
/// NOTE: It is strongly advised to use the `TxMessage` accessor in combination with the `Sender` utility,
/// which takes care of all message retransmission logic. Alternatively, one can use the
/// `Exchange::send` or `Exchange::send_with` which also take care of re-transmissions.
pub struct TxMessage<'a, T> {
    exchange_id: ExchangeId,
    matter: &'a T,
    packet: PacketAccess<'a, MAX_TX_BUF_SIZE>,
}

impl<T> TxMessage<'_, T> 
where 
    T: Matter,
{
    /// Get a reference to the payload buffer of the TX message being built
    pub fn payload(&mut self) -> &mut [u8] {
        &mut self.packet.buf[PacketHdr::HDR_RESERVE..MAX_TX_BUF_SIZE - PacketHdr::TAIL_RESERVE]
    }

    /// Complete and send a TX message by providing:
    /// - The payload size that was filled-in by user code in the payload buffer returned by `TxMessage::payload`
    /// - The TX message meta-data
    pub fn complete<M>(
        mut self,
        payload_start: usize,
        payload_end: usize,
        meta: M,
    ) -> Result<(), Error>
    where
        M: Into<MessageMeta>,
    {
        if payload_start > payload_end
            || payload_end > MAX_TX_BUF_SIZE - PacketHdr::HDR_RESERVE - PacketHdr::TAIL_RESERVE
        {
            Err(ErrorCode::Invalid)?;
        }

        let meta: MessageMeta = meta.into();

        self.packet.header.reset();

        meta.set_into(&mut self.packet.header.proto);

        let mut session_mgr = self.matter.transport_mgr.session_mgr.borrow_mut();

        let session = session_mgr
            .get(self.exchange_id.session_id())
            .ok_or(ErrorCode::NoSession)?;

        let (peer, retransmission) = session.pre_send(
            Some(self.exchange_id.exchange_index()),
            &mut self.packet.header,
            // NOTE: It is not entirely correct to use our own SAI/SII when sending to a peer,
            // as the peer might be slower than us
            //
            // However, given that for now `rs-matter` would be in the role of the device rather
            // than a controller, that's a good-enough approximation (i.e. if we are running on Thread,
            // the controller would either be running on Thread as well, or on a network faster than ours)
            self.matter.dev_det().sai,
            self.matter.dev_det().sii,
        )?;

        self.packet.peer = peer;

        debug!(
            "\n<<SND {}\n      => {}",
            Packet::<0>::display(&self.packet.peer, &self.packet.header),
            if retransmission {
                "Re-sending"
            } else {
                "Sending"
            },
        );

        trace!(
            "{}",
            Packet::<0>::display_payload(
                &self.packet.header.proto,
                &self.packet.buf
                    [PacketHdr::HDR_RESERVE + payload_start..PacketHdr::HDR_RESERVE + payload_end]
            )
        );

        let packet = &mut *self.packet;

        let mut writebuf = WriteBuf::new_with(
            &mut packet.buf,
            PacketHdr::HDR_RESERVE + payload_start,
            PacketHdr::HDR_RESERVE + payload_end,
        );
        session.encode(&packet.header, &mut writebuf)?;

        let encoded_payload_start = writebuf.get_start();
        let encoded_payload_end = writebuf.get_tail();

        self.packet.payload_start = encoded_payload_start;
        self.packet.buf.truncate(encoded_payload_end);
        self.packet.clear_on_drop(false);

        Ok(())
    }
}

/// Outcome from calling `Exchange::wait_tx`
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TxOutcome {
    /// The other side has acknowledged the last message or the last message was not using the MRP protocol
    /// Stop re-sending.
    Done,
    /// Need to re-send the last message.
    Retransmit,
}

impl TxOutcome {
    /// Check if the outcome is `Done`
    pub const fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }
}

pub struct SenderTx<'a, 'b, E, M> {
    sender: &'b mut Sender<E>,
    message: TxMessage<'a, M>,
}

impl<'a, 'b, E, M> SenderTx<'a, 'b, E, M> 
where 
    E: Exchange,
    M: Matter,
{
    pub fn split(&mut self) -> (&mut E, &mut [u8]) {
        (&mut self.sender.exchange, self.message.payload())
    }

    pub fn payload(&mut self) -> &mut [u8] {
        self.message.payload()
    }

    pub fn complete(
        self,
        payload_start: usize,
        payload_end: usize,
        meta: MessageMeta,
    ) -> Result<(), Error> {
        self.message.complete(payload_start, payload_end, meta)?;

        self.sender.initial = false;

        Ok(())
    }
}

/// Utility struct for sending a message with potential retransmissions.
pub struct Sender<T> {
    exchange: T,
    initial: bool,
    complete: bool,
}

impl<T> Sender<T> 
where 
    T: Exchange,
{
    fn new(exchange: T) -> Result<Self, Error> {
        exchange.id().check_no_pending_retrans(exchange.matter())?;

        Ok(Self {
            exchange,
            initial: true,
            complete: false,
        })
    }

    /// Get the TX buffer of the underlying Matter stack for (re)constructing a new TX message,
    /// waiting for the TX buffer to become available, if it is not.
    ///
    /// If the method returns `None`, it means that the message was already acknowledged by the other side,
    /// or that the message does not need acknowledgement and re-transmissions.
    ///
    /// When called for the first time, the method will always return a `Some` value, as the message has not been sent even once yet.
    /// Once the method returns `None`, it will always return `None` on subsequent calls, as the message has been acknowledged by the other side.
    ///
    /// Example:
    /// ```ignore
    /// let exchange = ...;
    ///
    /// let sender = exchange.sender()?;
    ///
    /// while let Some(mut tx) = sender.tx().await? {
    ///     let (exchange, payload) = tx.split()?;
    ///
    ///     // Write the message payload in the `payload` `&mut [u8]` slice
    ///     // On every iteration of the loop, write the _same_ payload (as message re-transmission is idempotent w.r.t. the message)
    ///     ...
    ///
    ///     // Complete the payload by providing `MessageMeta`, payload start and payload end
    ///     // On every iteration of the loop, proide the _same_ meta-data (as message re-transmission is idempotent w.r.t. the message)
    ///     let meta = ...;
    ///     let payload_start = ...;
    ///     let payload_end = ...;
    ///
    ///     tx.complete(payload_start, payload_end, meta)?;
    /// }
    /// ```
    pub async fn tx(&mut self) -> Result<Option<SenderTx<'a, '_, T, impl Matter + 'a>>, Error> {
        if self.complete {
            return Ok(None);
        }

        if !self.initial
            && self
                .exchange
                .id()
                .wait_tx(self.exchange.matter())
                .await?
                .is_done()
        {
            // No need to re-transmit
            self.complete = true;
            return Ok(None);
        }

        let id = self.exchange.id();
        let matter1 = self.exchange.matter();
        let matter2 = self.exchange.matter();

        let tx = id.init_send(matter1).await?;

        if self.initial || id.pending_retrans(matter2)? {
            Ok(Some(SenderTx {
                sender: self,
                message: tx,
            }))
        } else {
            self.complete = true;
            Ok(None)
        }
    }
}

pub trait ExchangeInitiate {
    /// Create a new initiator exchange on the provided Matter stack for the provided peer Node ID.
    ///
    /// For now, this method will fail if there is no existing session in the provided Matter stack
    /// for the provided peer Node ID.
    ///
    /// In future, this method will do an mDNS lookup and create a new session on its own.
    async fn initiate(
        matter: impl Matter,
        fabric_idx: u8,
        peer_node_id: u64,
        secure: bool,
    ) -> Result<Self, Error>
    where 
        Self: Sized;

    /// Create a new initiator exchange on the provided Matter stack for the provided session ID.
    fn initiate_for_session(matter: impl Matter, session_id: u32) -> Result<Self, Error>
    where 
        Self: Sized;

    /// Accepts a new responder exchange pending on the provided Matter stack.
    ///
    /// If there is no new pending responder exchange, the method will wait indefinitely until one appears.
    async fn accept(matter: impl Matter) -> Result<Self, Error>
    where 
        Self: Sized;

    /// Accepts a new responder exchange pending on the provided Matter stack, but only if the
    /// pending exchange was pending for longer than `received_timeout_ms`.
    ///
    /// If there is no new pending responder exchange, the method will wait indefinitely until one appears.
    async fn accept_after(
        matter: impl Matter,
        received_timeout_ms: u32,
    ) -> Result<Self, Error>
    where 
        Self: Sized;
}

pub struct ExchangeState0<'a> {
    pub fabrics: &'a mut FabricMgr,
    pub pase: &'a mut PaseMgr,
    pub failsafe: &'a mut FailSafe,
    pub basic_info_settings: &'a mut BasicInfoSettings,
    pub session: &'a mut Session,
    pub exch_idx: usize,
}

pub trait Exchange {
    /// Get the Id of the exchange
    fn id(&self) -> ExchangeId;

    /// Get the Matter stack instance associated with this exchange
    fn matter(&self) -> impl Matter + '_;

    fn split(&mut self) -> (impl Exchange + '_, impl Matter + '_);

    /// Get access to the pending RX message on this exchange, and consume it when the returned `RxMessage` instance is dropped.
    ///
    /// If there is no pending RX message, the method will wait indefinitely until one appears.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn recv(&mut self) -> Result<RxMessage<'_>, Error>;

    /// Get access to the pending RX message on this exchange, and consume it
    /// by copying the payload into the provided `WriteBuf` instance.
    ///
    /// A syntax sugar for calling ```self.recv().await?``` and then copying the payload.
    ///
    /// Returns the exchange message meta-data.
    ///
    /// If there is no pending RX message, the method will wait indefinitely until one appears.
    ///
    /// If there is already a pending RX message, which was already fetched using `Exchange::recv_fetch` and that
    /// message is not cleared yet using `Exchange::rx_done` or via some of the `Exchange::send*` methods,
    /// the method will return that message.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn recv_into(&mut self, wb: &mut WriteBuf<'_>) -> Result<MessageMeta, Error> {
        let rx = self.recv().await?;

        wb.reset();
        wb.append(rx.payload())?;

        Ok(rx.meta())
    }

    /// Return a _reference_ to the pending RX message on this exchange.
    ///
    /// If there is no pending RX message, the method will wait indefinitely until one appears.
    ///
    /// Unlike `recv` which returns the actual message object which - when dropped - allows the transport to
    /// fetch the _next_ RX message for this or other exchanges, `recv_fetch` keeps the received message around,
    /// which is convenient when the message needs to be examined / processed by multiple layers of application code.
    ///
    /// Note however that this does not come for free - keeping the RX message around means that the transport cannot receive
    /// _other_ RX messages which blocks the whole transport layer, as the transport layer uses a single RX message buffer.
    ///
    /// Therefore, calling `recv_fetch` should be done with care and the message should be marked as processed (and thus dropped) -
    /// via `rx_done` as soon as possible, ideally without `await`-ing between `recv_fetch` and `rx_done`
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn recv_fetch(&mut self) -> Result<&RxMessage<'_>, Error>;

    /// Returns the RX message which was already fetched using a previous call to `recv_fetch`.
    /// If there is no fetched RX message, the method will fail with `ErrorCode::InvalidState`.
    ///
    /// This method only exists as a slight optimization for the cases where the user is sure, that there is
    /// an RX message already fetched with `recv_fetch`, as - unlike `recv_fetch` - this method does not `await` and hence
    /// variables used after calling `rx` do not have to be stored in the generated future.
    ///
    /// But in general and putting optimizations aside, it is always safe to replace calls to `rx` with calls to `recv_fetch`.
    fn rx(&self) -> Result<&RxMessage<'_>, Error>;

    /// Clears the RX message which was already fetched using a previous call to `recv_fetch`.
    /// If there is no fetched RX message, the method will do nothing.
    fn rx_done(&mut self) -> Result<(), Error>;

    /// Gets access to the TX buffer of the Matter stack for constructing a new TX message.
    /// If the TX buffer is not available, the method will wait indefinitely until it becomes available.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn init_send(&mut self) -> Result<TxMessage<'_, impl Matter + '_>, Error>;

    /// Waits until the other side acknowledges the last message sent on this exchange,
    /// or until time for a re-transmission had come.
    ///
    /// If the last sent message was not using the MRP protocol, the method will return immediately with `TxOutcome::Done`.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn wait_tx(&mut self) -> Result<TxOutcome, Error>;

    /// Returns `true` if there is a pending message re-transmission.
    /// A re-transmission will be pending if the last sent message was using the MRP protocol, and
    /// an acknowledgement for the other side is still pending.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    fn pending_retrans(&self) -> Result<bool, Error>;

    /// Returns `true` if there is a pending message acknowledgement.
    /// An acknowledgement be pending if the last received message was using the MRP protocol, and we have to acknowledge it.
    ///
    /// NOTE:
    /// This is a low-level method that leaves the re-transmission logic on the shoulders of the user.
    /// Therefore, prefer using `Exchange::sender`, `Exchange::send` or `Exchange::send_with` instead.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    fn pending_ack(&self) -> Result<bool, Error>;

    /// Acknowledge the last message received on this exchange (by sending a `MrpStandaloneAck`).
    ///
    /// If the last message was already acknowledged
    /// (either by a previous call to this method, by piggy-backing on a reliable message, or by the Matter stack itself),
    /// this method does nothing.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn acknowledge(&mut self) -> Result<(), Error>;

    /// Utility for sending a message on this exchange that automatically handles all re-transmission logic
    /// in case the constructed message needs to be send reliably.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    fn sender(&mut self) -> Result<Sender<impl Exchange + '_>, Error>;

    /// Utility for sending a message on this exchange that automatically handles all re-transmission logic
    /// in case the constructed message needs to be send reliably.
    ///
    /// The message is constructed by the provided closure, which is given a `WriteBuf` instance to write the message payload into.
    ///
    /// Note that the closure is expected to construct the exact same message when called multiple times.
    ///
    /// Note also that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn send_with<F>(&mut self, f: F) -> Result<(), Error>
    where
        F: FnMut(&dyn Exchange, &mut WriteBuf) -> Result<Option<MessageMeta>, Error>;

    /// Send the provided exchange meta-data and payload as part of this exchange.
    ///
    /// If the provided exchange meta-data indicates a reliable message, the message will be automatically re-transmitted until
    /// the other side acknowledges it.
    ///
    /// Note that if the uderlying session or exchange tracked by the Matter stack is dropped
    /// (say, because of lack of resources or a hard networking error), the method will return an error.
    async fn send<M>(&mut self, meta: M, payload: &[u8]) -> Result<(), Error>
    where
        M: Into<MessageMeta>;

    /*pub(crate)*/ fn accessor(&self) -> Result<Accessor, Error>;

    /*pub(crate)*/ fn with_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>;

    /*pub(crate)*/ fn with_ctx<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session, usize) -> Result<T, Error>;
}

impl<T> Exchange for &mut T 
where 
    T: Exchange,
{
    fn id(&self) -> ExchangeId {
        (**self).id()
    }

    fn matter(&self) -> impl Matter + '_ {
        (**self).matter()
    }

    fn split(&mut self) -> (impl Exchange + '_, impl Matter + '_) {
        (**self).split()
    }

    async fn recv(&mut self) -> Result<RxMessage<'_>, Error> {
        (**self).recv().await
    }

    async fn recv_into(&mut self, wb: &mut WriteBuf<'_>) -> Result<MessageMeta, Error> {
        (**self).recv_into(wb).await
    }

    async fn recv_fetch(&mut self) -> Result<&RxMessage<'_>, Error> {
        (**self).recv_fetch().await
    }

    fn rx(&self) -> Result<&RxMessage<'_>, Error> {
        (**self).rx()
    }

    fn rx_done(&mut self) -> Result<(), Error> {
        (**self).rx_done()
    }

    async fn init_send(&mut self) -> Result<TxMessage<'_, impl Matter + '_>, Error> {
        (**self).init_send().await
    }

    async fn wait_tx(&mut self) -> Result<TxOutcome, Error> {
        (**self).wait_tx().await
    }

    fn pending_retrans(&self) -> Result<bool, Error> {
        (**self).pending_retrans()
    }

    fn pending_ack(&self) -> Result<bool, Error> {
        (**self).pending_ack()
    }

    async fn acknowledge(&mut self) -> Result<(), Error> {
        (**self).acknowledge().await
    }

    fn sender(&mut self) -> Result<Sender<impl Exchange + '_>, Error> {
        (**self).sender()
    }

    async fn send_with<F>(&mut self, f: F) -> Result<(), Error>
    where
        F: FnMut(&dyn Exchange, &mut WriteBuf) -> Result<Option<MessageMeta>, Error>,
    {
        (**self).send_with(f).await
    }

    async fn send<M>(&mut self, meta: M, payload: &[u8]) -> Result<(), Error>
    where
        M: Into<MessageMeta>,
    {
        (**self).send(meta, payload).await
    }

    fn accessor(&self) -> Result<Accessor, Error> {
        (**self).accessor()
    }

    fn with_session<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(&mut Session) -> Result<R, Error>,
    {
        (**self).with_session(f)
    }

    fn with_ctx<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(&mut Session, usize) -> Result<R, Error>,
    {
        (**self).with_ctx(f)
    }
}

/// An exchange within a Matter stack, representing a session and an exchange within that session.
///
/// This is the main API for sending and receiving messages within the Matter stack.
/// Used by upper-level layers like the Secure Channel and Interaction Model.
pub struct ExchangeInstance<'a, M> 
where 
    M: Matter,
{
    id: ExchangeId,
    matter: &'a M,
    rx: Option<RxMessage<'a>>,
}

impl<'a, M> ExchangeInstance<'a, M> 
where 
    M: Matter,
{
    pub(crate) const fn new(id: ExchangeId, matter: &'a M) -> Self {
        Self {
            id,
            matter,
            rx: None,
        }
    }

    /// Create a new initiator exchange on the provided Matter stack for the provided peer Node ID.
    ///
    /// For now, this method will fail if there is no existing session in the provided Matter stack
    /// for the provided peer Node ID.
    ///
    /// In future, this method will do an mDNS lookup and create a new session on its own.
    #[inline(always)]
    pub async fn initiate(
        matter: &'a M,
        fabric_idx: u8,
        peer_node_id: u64,
        secure: bool,
    ) -> Result<Self, Error> {
        matter
            .transport()
            .initiate(matter, fabric_idx, peer_node_id, secure)
            .await
    }

    /// Create a new initiator exchange on the provided Matter stack for the provided session ID.
    #[inline(always)]
    pub fn initiate_for_session(matter: &'a M, session_id: u32) -> Result<Self, Error> {
        matter
            .transport()
            .initiate_for_session(matter, session_id)
    }

    /// Accepts a new responder exchange pending on the provided Matter stack.
    ///
    /// If there is no new pending responder exchange, the method will wait indefinitely until one appears.
    #[inline(always)]
    pub async fn accept(matter: &'a M) -> Result<Self, Error> {
        Self::accept_after(matter, 0).await
    }

    /// Accepts a new responder exchange pending on the provided Matter stack, but only if the
    /// pending exchange was pending for longer than `received_timeout_ms`.
    ///
    /// If there is no new pending responder exchange, the method will wait indefinitely until one appears.
    pub async fn accept_after(
        matter: &'a M,
        received_timeout_ms: u32,
    ) -> Result<Self, Error> {
        if received_timeout_ms > 0 {
            let epoch = matter.epoch();

            loop {
                let mut accept = pin!(matter.transport().accept_if(matter, |_, exch, _| {
                    exch.mrp.has_rx_timed_out(received_timeout_ms as _, epoch)
                }));

                let mut timer = pin!(Timer::after(embassy_time::Duration::from_millis(
                    received_timeout_ms as u64
                )));

                if let Either::First(exchange) = select(&mut accept, &mut timer).await {
                    break exchange;
                }
            }
        } else {
            matter.transport().accept_if(matter, |_, _, _| true).await
        }
    }
}

impl<M> Exchange for ExchangeInstance<'_, M> 
where  
    M: Matter,
{
    fn id(&self) -> ExchangeId {
        self.id
    }

    fn matter(&self) -> impl Matter + '_ {
        self.matter
    }

    fn split(&mut self) -> (impl Exchange + '_, impl Matter + '_) {
        let matter = self.matter;

        (self, matter)
    }

    #[inline(always)]
    async fn recv(&mut self) -> Result<RxMessage<'_>, Error> {
        self.recv_fetch().await?;

        self.rx.take().ok_or(ErrorCode::InvalidState.into())
    }

    #[inline(always)]
    async fn recv_fetch(&mut self) -> Result<&RxMessage<'_>, Error> {
        if self.rx.is_none() {
            let rx = self.id.recv(self.matter).await?;

            self.rx = Some(rx);
        }

        self.rx.as_ref().ok_or(ErrorCode::InvalidState.into())
    }

    #[inline(always)]
    fn rx(&self) -> Result<&RxMessage<'_>, Error> {
        self.rx.as_ref().ok_or(ErrorCode::InvalidState.into())
    }

    #[inline(always)]
    fn rx_done(&mut self) -> Result<(), Error> {
        self.rx = None;

        Ok(())
    }

    #[inline(always)]
    async fn init_send(&mut self) -> Result<TxMessage<'_, impl Matter + '_>, Error> {
        self.rx = None;

        self.id.init_send(self.matter).await
    }

    #[inline(always)]
    async fn wait_tx(&mut self) -> Result<TxOutcome, Error> {
        self.rx = None;

        self.id.wait_tx(self.matter).await
    }

    fn pending_retrans(&self) -> Result<bool, Error> {
        self.id.pending_retrans(self.matter)
    }

    fn pending_ack(&self) -> Result<bool, Error> {
        self.id.pending_ack(self.matter)
    }

    #[inline(always)]
    async fn acknowledge(&mut self) -> Result<(), Error> {
        if self.pending_ack()? {
            let tx = self.id.init_send(self.matter).await?;

            if self.pending_ack()? {
                // Check whether we still need to send an ACK.
                // Necessary because we `.await` above, and while we are awaiting, the transport
                // might automatically send an ACK for us.
                // (That is, if the global RX transport buffer happens to be already empty and if the other peer re-sends the message.)
                tx.complete::<MessageMeta>(0, 0, sc::OpCode::MRPStandAloneAck.into())?;
            }
        }

        Ok(())
    }

    fn sender(&mut self) -> Result<Sender<impl Exchange + '_>, Error> {
        self.rx = None;

        Sender::new(self)
    }

    async fn send_with<F>(&mut self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&dyn Exchange, &mut WriteBuf) -> Result<Option<MessageMeta>, Error>,
    {
        let mut sender = self.sender()?;

        while let Some(mut tx) = sender.tx().await? {
            let (exchange, payload) = tx.split();

            let mut wb = WriteBuf::new(payload);

            if let Some(meta) = f(exchange, &mut wb)? {
                let payload_start = wb.get_start();
                let payload_end = wb.get_tail();
                tx.complete(payload_start, payload_end, meta)?;
            } else {
                // Closure aborted sending
                break;
            }
        }

        Ok(())
    }

    async fn send<T>(&mut self, meta: T, payload: &[u8]) -> Result<(), Error>
    where
        T: Into<MessageMeta>,
    {
        let meta = meta.into();

        self.send_with(|_, wb| {
            wb.append(payload)?;

            Ok(Some(meta))
        })
        .await
    }

    /*pub(crate)*/ fn accessor(&self) -> Result<Accessor, Error> {
        self.id.accessor(self.matter)
    }

    /*pub(crate)*/ fn with_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>,
    {
        self.id.with_session(self.matter, f)
    }

    /*pub(crate)*/ fn with_ctx<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session, usize) -> Result<T, Error>,
    {
        self.id.with_ctx(self.matter, f)
    }
}

impl<M> Drop for ExchangeInstance<'_, M> 
where 
    M: Matter,
{
    fn drop(&mut self) {
        let closed = self.with_ctx(|sess, exch_index| Ok(sess.remove_exch(exch_index)));

        if !matches!(closed, Ok(true)) {
            self.matter.transport().dropped.notify();
        }
    }
}

impl<M> Display for ExchangeInstance<'_, M> 
where 
    M: Matter,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}
