// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Passive firmware inventory observations shared by component backends.
//! Reported versions do not establish whether an image is active or staged.

use mac_address::MacAddress;

/// `FirmwareInventorySource` identifies a backend with passive inventory reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareInventorySource {
    /// Inventory obtained directly from the BMC through Redfish.
    Redfish,
    /// Inventory obtained through Rack Management Service.
    Rms,
}

/// `FirmwareReadError` describes unavailable evidence without backend error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareReadError {
    /// Client creation, collection metadata, or one member read failed.
    ReadFailed,
    /// The shared request deadline expired before this read completed.
    DeadlineExceeded,
    /// The inventory or its text exceeds the reader's documented bound.
    LimitExceeded,
}

/// `ComponentFirmwareInventoryResult` keeps an observation with its requested endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentFirmwareInventoryResult {
    /// Requested BMC MAC for compute/switches, or PMC MAC for a power shelf.
    pub mac_address: MacAddress,
    /// Collection failure or every listed member, in backend order, including repeats.
    /// An empty success means the backend returned an empty collection. Each member
    /// must also be checked: a successful list can contain failed member reads.
    pub inventory: Result<Vec<FirmwareInventoryEntry>, FirmwareReadError>,
}

/// `FirmwareInventoryEntry` preserves a listed member even when its read fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareInventoryEntry {
    /// Identifier returned by the inventory listing and used to read this member.
    pub inventory_id: String,
    /// Reported component metadata or the reason this member could not be read.
    pub firmware: Result<FirmwareComponent, FirmwareReadError>,
}

/// `FirmwareComponent` contains backend metadata, including vendor normalization.
/// Missing versions stay absent; none of these fields proves active-image selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareComponent {
    /// Component identifier from the member response, without rewriting it to its lookup ID.
    pub id: String,
    /// Resource URI supplied by the backend, such as Redfish `@odata.id`.
    pub resource_uri: String,
    /// Backend description, if supplied.
    pub description: Option<String>,
    /// Backend-provided version, which may be vendor-normalized. An explicitly
    /// supplied empty string remains distinct from an absent version.
    pub version: Option<String>,
    /// Backend release date, retained as supplied rather than inferred or parsed.
    pub release_date: Option<String>,
}
