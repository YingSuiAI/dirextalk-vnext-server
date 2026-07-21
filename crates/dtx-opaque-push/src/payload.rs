use crate::PushError;
use serde::Serialize;
use std::{fmt, str::FromStr};
use uuid::{Uuid, Variant, Version};

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct WakeDeliveryId(Uuid);
impl WakeDeliveryId {
    pub fn parse(value: &str) -> Result<Self, PushError> {
        let uuid = Uuid::parse_str(value).map_err(|_| PushError::InvalidWakeDeliveryId)?;
        if uuid.hyphenated().to_string() != value
            || uuid.get_variant() != Variant::RFC4122
            || uuid.get_version() != Some(Version::SortRand)
        {
            return Err(PushError::InvalidWakeDeliveryId);
        }
        Ok(Self(uuid))
    }
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}
impl fmt::Display for WakeDeliveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl fmt::Debug for WakeDeliveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WakeDeliveryId")
            .field(&self.to_string())
            .finish()
    }
}
impl FromStr for WakeDeliveryId {
    type Err = PushError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakePayload {
    pub wake_delivery_id: WakeDeliveryId,
}

impl WakePayload {
    pub const VERSION: u8 = 1;
    pub fn new(id: WakeDeliveryId) -> Self {
        Self {
            wake_delivery_id: id,
        }
    }
    pub fn canonical_json(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Wire<'a> {
            version: u8,
            wake_delivery_id: &'a str,
        }
        let id = self.wake_delivery_id.to_string();
        serde_json::to_vec(&Wire {
            version: 1,
            wake_delivery_id: &id,
        })
        .expect("payload serializable")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportPolicy {
    pub ttl_seconds: u16,
    pub android_priority: AndroidPriority,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidPriority {
    High,
}
impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            ttl_seconds: 60,
            android_priority: AndroidPriority::High,
        }
    }
}
