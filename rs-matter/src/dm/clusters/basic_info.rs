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

//! This module contains the implementation of the Basic Information cluster and its handler.

use core::str::FromStr;

use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext, WriteContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, Nullable, TLVBuilderParent, TLVElement, TLVTag, ToTLV, Utf8StrBuilder};
use crate::transport::exchange::Exchange;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::WriteBuf;
use crate::with;

pub use crate::dm::clusters::decl::basic_information::*;

const SUPPORTED_MATTER_SPEC_VERSION: u32 = 0x01000000;

/// Basic information which is immutable
/// (i.e. valid for the lifetime of the device firmware)
///
/// All optional fields will not be reported if they are `None`
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct BasicInfoConfig<'a> {
    /// Vendor name (up to 32 characters)
    pub vendor_name: &'a str,
    /// Vendor ID
    pub vid: u16,
    /// Product name (up to 32 characters)
    pub product_name: &'a str,
    /// Product ID
    pub pid: u16,
    /// Hardware version
    pub hw_ver: u16,
    /// Hardware version string (up to 64 characters)
    pub hw_ver_str: &'a str,
    /// Software version
    pub sw_ver: u32,
    /// Software version string (up to 64 characters)
    pub sw_ver_str: &'a str,
    /// Manufacturing date (up to 16 characters)
    pub manufacturing_date: Option<&'a str>,
    /// Part number (up to 32 characters)
    pub part_number: Option<&'a str>,
    /// Product URL (up to 256 characters)
    pub product_url: Option<&'a str>,
    /// Product label (up to 64 characters)
    pub product_label: Option<&'a str>,
    /// Serial number (up to 32 characters)
    pub serial_no: Option<&'a str>,
    /// Local Config Disabled
    pub local_config_disabled: Option<bool>,
    /// Unique ID (up to 64 characters)
    pub unique_id: Option<&'a str>,
    /// Capability Minima
    pub capability_minima: CapabilityMinima,
    /// Product Appearance
    pub product_appearance: Option<ProductAppearance>,
    /// Device Name
    ///
    /// Not a real attribute; used in the mDNS commissioning advertisement
    pub device_name: &'a str,
    /// Session Active Interval in ms
    /// If not specified, defaults to 300
    ///
    /// Not a real attribute, just used to configure the session timeouts
    pub sai: Option<u16>,
    /// Session Idle Interval in ms
    /// If not specified, defaults to 5000
    ///
    /// Not a real attribute, just used to configure the session timeouts
    pub sii: Option<u16>,
}

impl BasicInfoConfig<'_> {
    pub const fn new() -> Self {
        Self {
            vid: 0,
            pid: 0,
            hw_ver: 0,
            hw_ver_str: "",
            sw_ver: 0,
            sw_ver_str: "",
            serial_no: None,
            product_name: "",
            vendor_name: "",
            device_name: "Matter Device",
            sai: None,
            sii: None,
            manufacturing_date: None,
            part_number: None,
            product_url: None,
            product_label: None,
            local_config_disabled: None,
            unique_id: None,
            capability_minima: CapabilityMinima::new(),
            product_appearance: None,
        }
    }

    pub const fn extra_attributes(&self) -> u32 {
        let mut bitset = 0;

        if self.manufacturing_date.is_some() {
            bitset |= AttributeId::ManufacturingDate as u32;
        }

        if self.part_number.is_some() {
            bitset |= AttributeId::PartNumber as u32;
        }

        if self.product_url.is_some() {
            bitset |= AttributeId::ProductURL as u32;
        }

        if self.product_label.is_some() {
            bitset |= AttributeId::ProductLabel as u32;
        }

        if self.serial_no.is_some() {
            bitset |= AttributeId::SerialNumber as u32;
        }

        if self.local_config_disabled.is_some() {
            bitset |= AttributeId::LocalConfigDisabled as u32;
        }

        if self.unique_id.is_some() {
            bitset |= AttributeId::UniqueID as u32;
        }

        if self.product_appearance.is_some() {
            bitset |= AttributeId::ProductAppearance as u32;
        }

        bitset
    }
}

impl Default for BasicInfoConfig<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CapabilityMinima {
    pub case_sessions_per_fabric: u16,
    pub subscriptions_per_fabric: u16,
}

impl CapabilityMinima {
    pub const fn new() -> Self {
        Self {
            case_sessions_per_fabric: 3,
            subscriptions_per_fabric: 3,
        }
    }
}

impl Default for CapabilityMinima {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct ProductAppearance {
    pub finish: ProductFinishEnum,
    pub color: Option<ColorEnum>,
}

/// Mutable basic information
#[derive(Debug, Clone, Eq, PartialEq, Hash, ToTLV, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicInfoSettings {
    pub node_label: heapless::String<32>, // Max node-label as per the spec
    pub location: Option<heapless::String<2>>, // Max location as per the spec
    pub changed: bool,
}

impl BasicInfoSettings {
    /// Create a new instance of `BasicInfoSettings`
    pub const fn new() -> Self {
        Self {
            node_label: heapless::String::new(),
            location: None,
            changed: false,
        }
    }

    /// Return an in-place initializer for `BasicInfoSettings`
    pub fn init() -> impl Init<Self> {
        init!(Self {
            node_label: heapless::String::new(),
            location: None,
            changed: false,
        })
    }

    /// Resets the basic info to initial values
    pub fn reset(&mut self) {
        self.node_label.clear();
        self.location = None;
        self.changed = false;
    }

    /// Load the basic info settings from the provided TLV data
    pub fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        *self = FromTLV::from_tlv(&TLVElement::new(data))?;

        self.changed = false;

        Ok(())
    }

    /// Store the basic info settings into the provided buffer as TLV data
    ///
    /// If the basic info has not changed since the last store operation, the
    /// function returns `None` and does not store the basic info.
    pub fn store<'a>(&mut self, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        if !self.changed {
            return Ok(None);
        }

        let mut wb = WriteBuf::new(buf);

        self.to_tlv(&TLVTag::Anonymous, &mut wb)
            .map_err(|_| ErrorCode::NoSpace)?;

        self.changed = false;

        let len = wb.get_tail();

        Ok(Some(&buf[..len]))
    }
}

impl Default for BasicInfoSettings {
    fn default() -> Self {
        Self::new()
    }
}

/// The system implementation of a handler for the Basic Information Matter cluster.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BasicInfoHandler(Dataver);

impl BasicInfoHandler {
    /// Create a new instance of `BasicInfoHandler` with the given `Dataver`
    pub fn new(dataver: Dataver) -> Self {
        Self(dataver)
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    fn config<'a>(exchange: &'a Exchange) -> &'a BasicInfoConfig<'a> {
        exchange.matter().dev_det()
    }

    fn settings<'a>(exchange: &'a Exchange) -> &'a RefCell<BasicInfoSettings> {
        &exchange.matter().basic_info_settings
    }

    fn checked_unwrap<T>(id: AttributeId, name: &str, opt: Option<T>) -> T {
        if let Some(value) = opt {
            value
        } else {
            panic!(
                "Attribute {:?} is enabled; provide value for field {}",
                id, name
            );
        }
    }
}

impl ClusterHandler for BasicInfoHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required; AttributeId::SerialNumber))
        .with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.0.get()
    }

    fn dataver_changed(&self) {
        self.0.changed();
    }

    fn data_model_revision(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(0) // TODO
    }

    fn vendor_id(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).vid)
    }

    fn vendor_name<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).vendor_name)
    }

    fn product_id(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).pid)
    }

    fn product_name<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).product_name)
    }

    fn hardware_version(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(Self::config(ctx.exchange()).hw_ver)
    }

    fn hardware_version_string<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).hw_ver_str)
    }

    fn software_version(&self, ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(Self::config(ctx.exchange()).sw_ver)
    }

    fn software_version_string<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::config(ctx.exchange()).sw_ver_str)
    }

    fn node_label<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        out.set(Self::settings(ctx.exchange()).borrow().node_label.as_str())
    }

    fn set_node_label(&self, ctx: impl WriteContext, label: &str) -> Result<(), Error> {
        if label.len() > 32 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut settings = Self::settings(ctx.exchange()).borrow_mut();
        settings.node_label.clear();
        settings
            .node_label
            .push_str(label)
            .map_err(|_| ErrorCode::NoSpace)?;
        settings.changed = true;

        settings.changed = true;
        ctx.exchange().matter().notify_persist();

        Ok(())
    }

    fn location<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        out: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        let settings = Self::settings(ctx.exchange()).borrow();
        out.set(settings.location.as_ref().map_or("XX", |loc| loc.as_str()))
    }

    fn set_location(&self, ctx: impl WriteContext, location: &str) -> Result<(), Error> {
        if location.len() != 2 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut settings = Self::settings(ctx.exchange()).borrow_mut();
        if location == "XX" {
            settings.location = None;
        } else {
            settings.location = Some(unwrap!(heapless::String::<2>::from_str(location)));
            settings.changed = true;
        }

        settings.changed = true;
        ctx.exchange().matter().notify_persist();

        Ok(())
    }

    fn capability_minima<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: CapabilityMinimaStructBuilder<P>,
    ) -> Result<P, Error> {
        let cm = Self::config(_ctx.exchange()).capability_minima;

        builder
            .case_sessions_per_fabric(cm.case_sessions_per_fabric)?
            .subscriptions_per_fabric(cm.subscriptions_per_fabric)?
            .end()
    }

    fn specification_version(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(SUPPORTED_MATTER_SPEC_VERSION)
    }

    fn max_paths_per_invoke(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(1) // TODO: Report real value
    }

    fn handle_mfg_specific_ping(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn manufacturing_date<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::checked_unwrap(
            AttributeId::ManufacturingDate,
            "manufacturing_date",
            Self::config(ctx.exchange()).manufacturing_date,
        ))
    }

    fn part_number<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::checked_unwrap(
            AttributeId::PartNumber,
            "part_number",
            Self::config(ctx.exchange()).part_number,
        ))
    }

    fn product_url<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::checked_unwrap(
            AttributeId::ProductURL,
            "product_url",
            Self::config(ctx.exchange()).product_url,
        ))
    }

    fn product_label<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::checked_unwrap(
            AttributeId::ProductLabel,
            "product_label",
            Self::config(ctx.exchange()).product_label,
        ))
    }

    fn serial_number<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::checked_unwrap(
            AttributeId::SerialNumber,
            "serial_number",
            Self::config(ctx.exchange()).serial_no,
        ))
    }

    fn local_config_disabled(&self, ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(Self::checked_unwrap(
            AttributeId::LocalConfigDisabled,
            "local_config_disabled",
            Self::config(ctx.exchange()).local_config_disabled,
        ))
    }

    fn unique_id<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Self::checked_unwrap(
            AttributeId::UniqueID,
            "unique_id",
            Self::config(ctx.exchange()).unique_id,
        ))
    }

    fn product_appearance<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ProductAppearanceStructBuilder<P>,
    ) -> Result<P, Error> {
        let appearance = Self::checked_unwrap(
            AttributeId::ProductAppearance,
            "product_appearance",
            Self::config(ctx.exchange()).product_appearance,
        );

        builder
            .finish(appearance.finish)?
            .primary_color(Nullable::new(appearance.color))?
            .end()
    }
}
