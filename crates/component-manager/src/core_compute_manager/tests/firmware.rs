// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Firmware proofs reuse the compute reader's credential checks and owned gates.

use super::*;
use crate::nv_switch_manager::NvSwitchManager;
use crate::power_shelf_manager::PowerShelfManager;

/// Existing managers inherit an unavailable capability and reject passive reads;
/// an existing firmware updater is not evidence of passive inventory support.
#[tokio::test]
async fn firmware_inventory_defaults_are_unsupported() {
    let compute = crate::mock::MockComputeTrayManager;
    let switch = crate::mock::MockNvSwitchManager::default();
    let shelf = crate::mock::MockPowerShelfManager;

    let results = [
        (
            compute.firmware_inventory_source(),
            compute.get_firmware_inventory(&[]).await,
        ),
        (
            switch.firmware_inventory_source(),
            switch.get_firmware_inventory(&[]).await,
        ),
        (
            shelf.firmware_inventory_source(),
            shelf.get_firmware_inventory(&[]).await,
        ),
    ];

    for (source, result) in results {
        assert_eq!(source, None);
        assert!(matches!(result, Err(ComponentManagerError::Unsupported(_))));
    }
}

/// Seeds the simulator's raw collection so the reader must validate collection
/// metadata before it can request members. Repeated IDs remain repeated links.
fn set_firmware_test_inventory(pool: &ComputeReadTestPool, ids: &[String]) {
    let members: Vec<_> = ids
        .iter()
        .map(|id| serde_json::json!({ "@odata.id": format!("{FIRMWARE_INVENTORY_URI}/{id}") }))
        .collect();
    pool.sim.set_resource(
        FIRMWARE_INVENTORY_URI,
        serde_json::json!({ "Members": members, "Members@odata.count": ids.len() }),
    );
}

/// Reversed endpoint/member completion must preserve the caller's identities,
/// repeated slots, exact backend versions, and the difference between absent and empty.
#[tokio::test]
async fn firmware_inventory_preserves_members_metadata_and_endpoint_order() {
    let endpoints = [
        test_compute_tray_endpoint(1),
        test_compute_tray_endpoint(2),
        test_compute_tray_endpoint(2),
    ];
    let pool = compute_read_test_pool(&endpoints);
    set_firmware_test_inventory(
        &pool,
        &["BMC_Firmware".into(), "other".into(), "BMC_Firmware".into()],
    );
    for (index, endpoint) in endpoints[..2].iter().enumerate() {
        let host = endpoint.bmc_ip.to_string();
        for id in ["BMC_Firmware", "other"] {
            let version = if id == "BMC_Firmware" {
                Some(format!("v{index}.2.3"))
            } else if index == 0 {
                None
            } else {
                Some(String::new())
            };
            pool.firmware.members.lock().unwrap().insert(
                (host.clone(), id.into()),
                Ok(SoftwareInventory {
                    odata: libredfish::model::ODataLinks {
                        // The response URI deliberately does not identify the lookup path.
                        odata_id: format!("/reported/{index}/image-{id}"),
                        ..Default::default()
                    },
                    id: format!("image-{index}-{id}"),
                    description: Some(format!("Image on host {index}")),
                    version,
                    release_date: Some("2026-11-03".into()),
                }),
            );
        }
    }
    let manager = CoreComputeTrayManager::new(pool.clone());
    let before = pool.sim.timepoint();

    assert!(
        manager
            .get_firmware_inventory(&[])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(pool.sim.create_client_calls().is_empty());
    let delayed_setup = pool.setup_gates.block(&endpoints[0]);
    let delayed_member = pool
        .firmware
        .member_gates
        .block_key(format!("{}/BMC_Firmware", endpoints[0].bmc_ip));
    let mut request = Box::pin(manager.get_firmware_inventory(&endpoints));

    // Both later endpoint slots finish while the first waits for its client.
    assert!(futures_util::poll!(request.as_mut()).is_pending());
    assert_eq!(pool.firmware.member_calls.lock().unwrap().len(), 6);
    delayed_setup.send(()).unwrap();
    // The first member then waits while that endpoint's later members finish.
    assert!(futures_util::poll!(request.as_mut()).is_pending());
    assert_eq!(pool.firmware.member_calls.lock().unwrap().len(), 9);
    delayed_member.send(()).unwrap();
    let results = request.await.unwrap();

    assert_eq!(
        manager.firmware_inventory_source(),
        Some(FirmwareInventorySource::Redfish)
    );
    assert_eq!(results.len(), 3);
    for (slot, result) in results.iter().enumerate() {
        let host_index = if slot == 0 { 0 } else { 1 };
        assert_eq!(result.mac_address, endpoints[slot].bmc_mac);
        let expected: Vec<_> = ["BMC_Firmware", "other", "BMC_Firmware"]
            .into_iter()
            .map(|id| FirmwareInventoryEntry {
                inventory_id: id.into(),
                firmware: Ok(FirmwareComponent {
                    id: format!("image-{host_index}-{id}"),
                    resource_uri: format!("/reported/{host_index}/image-{id}"),
                    description: Some(format!("Image on host {host_index}")),
                    version: match (id, host_index) {
                        ("BMC_Firmware", 0) => Some("v0.2.3".into()),
                        ("BMC_Firmware", _) => Some("v1.2.3".into()),
                        (_, 0) => None,
                        _ => Some(String::new()),
                    },
                    release_date: Some("2026-11-03".into()),
                }),
            })
            .collect();
        assert_eq!(result.inventory, Ok(expected));
    }
    assert_eq!(
        pool.sim
            .create_client_calls()
            .iter()
            .map(|call| call.host.as_str())
            .collect::<Vec<_>>(),
        ["192.0.2.2", "192.0.2.2", "192.0.2.1"]
    );
    assert_eq!(
        pool.sim.resource_requests(),
        vec![FIRMWARE_INVENTORY_URI; 3]
    );
    assert!(pool.sim.actions_since(&before).all_hosts().is_empty());
}

/// A collection must prove completeness before any member GET: otherwise an
/// incomplete page or malformed identity can masquerade as a complete inventory.
#[tokio::test]
async fn firmware_inventory_rejects_incomplete_or_malformed_raw_collections() {
    let cases = [
        // Matching count is insufficient when the BMC supplies another page.
        (
            "continuation",
            serde_json::json!({"Members": [{"@odata.id": "member"}], "Members@odata.count": 1, "Members@odata.nextLink": "next-page"}),
        ),
        // A count larger than the supplied list exposes missing evidence without a link.
        (
            "count mismatch",
            serde_json::json!({"Members": [], "Members@odata.count": 1}),
        ),
        // A nonnumeric count cannot establish collection completeness.
        (
            "malformed count",
            serde_json::json!({"Members": [], "Members@odata.count": "0"}),
        ),
        // An object in place of the list is not an empty collection.
        ("malformed Members", serde_json::json!({"Members": {}})),
        // Malformed members must not be silently filtered from a successful list.
        (
            "malformed member",
            serde_json::json!({"Members": [{"@odata.id": 7}]}),
        ),
        // An empty lookup would read the collection itself as if it were a member.
        (
            "empty ID",
            serde_json::json!({"Members": [{"@odata.id": ""}]}),
        ),
        // The dependency extracts the last segment, so a trailing slash is also empty.
        (
            "trailing slash",
            serde_json::json!({"Members": [{"@odata.id": "/inventory/member/"}]}),
        ),
    ];
    for (name, collection) in cases {
        let endpoints = [test_compute_tray_endpoint(1)];
        let pool = compute_read_test_pool(&endpoints);
        pool.sim.set_resource(FIRMWARE_INVENTORY_URI, collection);
        let manager = CoreComputeTrayManager::new(pool.clone());
        let before = pool.sim.timepoint();

        let results = manager.get_firmware_inventory(&endpoints).await.unwrap();

        assert_eq!(
            results,
            vec![ComponentFirmwareInventoryResult {
                mac_address: endpoints[0].bmc_mac,
                inventory: Err(FirmwareReadError::ReadFailed),
            }],
            "{name}"
        );
        assert_eq!(
            pool.sim.resource_requests(),
            vec![FIRMWARE_INVENTORY_URI],
            "{name}"
        );
        assert!(
            pool.firmware.member_calls.lock().unwrap().is_empty(),
            "{name}"
        );
        assert!(
            pool.sim.actions_since(&before).all_hosts().is_empty(),
            "{name}"
        );
    }
}

/// Setup/list failures make the collection unavailable. A failed or oversized
/// member keeps its slot while its healthy peer remains available, without raw errors.
#[tokio::test]
async fn firmware_inventory_reports_failures_without_losing_healthy_members() {
    /// Each case injects one failure at the collection or member boundary.
    struct Case {
        name: &'static str,
        configure: fn(&ComputeReadTestPool),
        whole_inventory: bool,
        error: FirmwareReadError,
    }
    let cases = [
        // Client creation fails before the collection can be observed.
        Case {
            name: "client",
            configure: |pool| pool.sim.set_create_client_error("secret-client-detail"),
            whole_inventory: true,
            error: FirmwareReadError::ReadFailed,
        },
        // A failed list cannot be presented as an empty successful inventory.
        Case {
            name: "list",
            configure: |pool| pool.sim.fail_resource(FIRMWARE_INVENTORY_URI),
            whole_inventory: true,
            error: FirmwareReadError::ReadFailed,
        },
        // Cardinality is checked before issuing any follow-up member requests.
        Case {
            name: "member count",
            configure: |pool| set_firmware_test_inventory(pool, &vec!["member".into(); 257]),
            whole_inventory: true,
            error: FirmwareReadError::LimitExceeded,
        },
        // An overlong lookup ID cannot be clipped or echoed in an error slot.
        Case {
            name: "lookup text",
            configure: |pool| set_firmware_test_inventory(pool, &["x".repeat(1025)]),
            whole_inventory: true,
            error: FirmwareReadError::LimitExceeded,
        },
        // Individually valid IDs can still exceed the retained collection budget.
        Case {
            name: "total lookup text",
            configure: |pool| set_firmware_test_inventory(pool, &vec!["x".repeat(1024); 65]),
            whole_inventory: true,
            error: FirmwareReadError::LimitExceeded,
        },
        // One unreadable member must not make the other component disappear.
        Case {
            name: "member",
            configure: |pool| {
                pool.firmware.members.lock().unwrap().insert(
                    ("192.0.2.1".into(), "broken".into()),
                    Err("secret-member-detail".into()),
                );
            },
            whole_inventory: false,
            error: FirmwareReadError::ReadFailed,
        },
        // Truncating a version would fabricate a different firmware version.
        Case {
            name: "member text",
            configure: |pool| {
                pool.firmware.members.lock().unwrap().insert(
                    ("192.0.2.1".into(), "broken".into()),
                    Ok(SoftwareInventory {
                        odata: Default::default(),
                        id: "broken".into(),
                        description: None,
                        version: Some("x".repeat(1025)),
                        release_date: None,
                    }),
                );
            },
            whole_inventory: false,
            error: FirmwareReadError::LimitExceeded,
        },
    ];
    for case in cases {
        let endpoints = [test_compute_tray_endpoint(1), test_compute_tray_endpoint(2)];
        let pool = compute_read_test_pool(&endpoints);
        set_firmware_test_inventory(&pool, &["BMC_Firmware".into(), "broken".into()]);
        let before = pool.sim.timepoint();
        let manager = CoreComputeTrayManager::new(pool.clone());
        let delayed_first = pool.setup_gates.block(&endpoints[0]);
        let mut request = Box::pin(manager.get_firmware_inventory(&endpoints));

        // Finish the healthy endpoint before injecting a client, collection, or
        // member failure. Global simulator changes then affect only the first.
        assert!(futures_util::poll!(request.as_mut()).is_pending());
        assert_eq!(pool.firmware.member_calls.lock().unwrap().len(), 2);
        (case.configure)(&pool);
        delayed_first.send(()).unwrap();
        let results = request.await.unwrap();

        assert_eq!(results.len(), endpoints.len(), "{}", case.name);
        assert_eq!(results[0].mac_address, endpoints[0].bmc_mac);
        if case.whole_inventory {
            assert_eq!(results[0].inventory, Err(case.error), "{}", case.name);
            assert_eq!(
                *pool.firmware.member_calls.lock().unwrap(),
                vec![
                    ("192.0.2.2".into(), "BMC_Firmware".into()),
                    ("192.0.2.2".into(), "broken".into())
                ],
                "{}",
                case.name
            );
        } else {
            let entries = results[0].inventory.as_ref().unwrap();
            assert_eq!(entries.len(), 2, "{}", case.name);
            assert_eq!(entries[0].inventory_id, "BMC_Firmware");
            assert!(entries[0].firmware.is_ok());
            assert_eq!(entries[1].inventory_id, "broken");
            assert_eq!(entries[1].firmware, Err(case.error), "{}", case.name);
        }
        assert_eq!(results[1].mac_address, endpoints[1].bmc_mac);
        let healthy = results[1].inventory.as_ref().unwrap();
        assert_eq!(
            healthy
                .iter()
                .map(|entry| entry.inventory_id.as_str())
                .collect::<Vec<_>>(),
            ["BMC_Firmware", "broken"]
        );
        assert!(
            healthy.iter().all(|entry| entry.firmware.is_ok()),
            "{}",
            case.name
        );
        assert!(
            pool.sim.actions_since(&before).all_hosts().is_empty(),
            "{}",
            case.name
        );
    }
}

/// Every retained metadata field and lookup ID consumes the shared byte budget.
/// Listing order decides which records fit, even when an early repeated read is slow.
#[tokio::test]
async fn firmware_inventory_bounds_total_metadata_and_endpoint_count() {
    let endpoints = [test_compute_tray_endpoint(1)];
    let pool = compute_read_test_pool(&endpoints);
    let id = "i".repeat(1024);
    set_firmware_test_inventory(&pool, &vec![id.clone(); 16]);
    pool.firmware.members.lock().unwrap().insert(
        (endpoints[0].bmc_ip.to_string(), id.clone()),
        Ok(SoftwareInventory {
            odata: libredfish::model::ODataLinks {
                odata_id: "u".repeat(1024),
                ..Default::default()
            },
            id: "r".repeat(1024),
            description: Some("d".repeat(1024)),
            version: Some("v".repeat(1024)),
            release_date: Some("t".repeat(1024)),
        }),
    );
    let delayed_first = pool
        .firmware
        .member_gates
        .block_key(format!("{}/{id}", endpoints[0].bmc_ip));
    let manager = CoreComputeTrayManager::new(pool.clone());
    let before = pool.sim.timepoint();
    let mut request = Box::pin(manager.get_firmware_inventory(&endpoints));

    // The first occurrence waits while the other fifteen finish. Completion-order
    // accounting would give its allowance to a later occurrence instead.
    assert!(futures_util::poll!(request.as_mut()).is_pending());
    assert_eq!(pool.firmware.member_calls.lock().unwrap().len(), 16);
    delayed_first.send(()).unwrap();
    let results = request.await.unwrap();

    let entries = results[0].inventory.as_ref().unwrap();
    assert_eq!(entries.len(), 16);
    assert!(entries.iter().all(|entry| entry.inventory_id == id));
    // Sixteen 1 KiB lookup IDs plus nine 5 KiB records fit; the tenth cannot.
    // Omitting lookup bytes or any metadata field changes this cutoff.
    assert!(entries[..9].iter().all(|entry| entry.firmware.is_ok()));
    assert!(
        entries[9..]
            .iter()
            .all(|entry| entry.firmware == Err(FirmwareReadError::LimitExceeded))
    );

    // Empty collections make the accepted endpoint boundary cheap to exercise.
    set_firmware_test_inventory(&pool, &[]);
    let accepted = manager
        .get_firmware_inventory(&vec![endpoints[0].clone(); 64])
        .await
        .unwrap();
    let rejected = manager
        .get_firmware_inventory(&vec![endpoints[0].clone(); 65])
        .await;

    assert_eq!(accepted.len(), 64);
    assert!(
        accepted
            .iter()
            .all(|result| result.mac_address == endpoints[0].bmc_mac
                && result.inventory == Ok(vec![]))
    );
    assert!(matches!(
        rejected,
        Err(ComponentManagerError::InvalidArgument(_))
    ));
    assert_eq!(pool.sim.create_client_calls().len(), 65);
    assert_eq!(pool.sim.resource_requests().len(), 65);
    assert_eq!(pool.firmware.member_calls.lock().unwrap().len(), 16);
    assert!(pool.sim.actions_since(&before).all_hosts().is_empty());
}

/// Endpoint admission lasts through member reads: at most four BMCs with four
/// members each run. Cancellation drops active waits and leaves queued work unstarted.
#[tokio::test(start_paused = true)]
async fn firmware_inventory_cancellation_bounds_setup_listing_and_member_work() {
    /// Selects which owned future must be dropped with the caller.
    #[derive(Clone, Copy, Debug)]
    enum Phase {
        Setup,
        Listing,
        Members,
    }

    for phase in [Phase::Setup, Phase::Listing, Phase::Members] {
        let endpoints: Vec<_> = (1..=5).map(test_compute_tray_endpoint).collect();
        let pool = compute_read_test_pool(&endpoints);
        let members: Vec<_> = (0..5).map(|i| format!("member-{i}")).collect();
        set_firmware_test_inventory(&pool, &members);
        let (gates, keys) = match phase {
            Phase::Setup => (
                &pool.setup_gates,
                endpoints
                    .iter()
                    .map(|endpoint| endpoint.bmc_ip.to_string())
                    .collect::<Vec<_>>(),
            ),
            Phase::Listing => (
                &pool.firmware.list_gates,
                endpoints
                    .iter()
                    .map(|endpoint| endpoint.bmc_ip.to_string())
                    .collect(),
            ),
            Phase::Members => (
                &pool.firmware.member_gates,
                endpoints
                    .iter()
                    .flat_map(|endpoint| {
                        members
                            .iter()
                            .map(move |id| format!("{}/{id}", endpoint.bmc_ip))
                    })
                    .collect(),
            ),
        };
        let senders: Vec<_> = keys.into_iter().map(|key| gates.block_key(key)).collect();
        let manager = CoreComputeTrayManager::new(pool.clone());
        let before = pool.sim.timepoint();
        let mut request = Box::pin(manager.get_firmware_inventory(&endpoints));
        let active = if matches!(phase, Phase::Members) {
            16
        } else {
            4
        };

        // Nested buffers can yield cooperatively before admitting every member.
        // Wait for the intended gates, rather than assuming one poll fills them.
        tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(request.as_mut(), cx).is_pending());
                if gates.started.load(Ordering::Relaxed) >= active {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            }),
        )
        .await
        .expect("expected read gates must be admitted before cancellation");
        assert_eq!(gates.started.load(Ordering::Relaxed), active, "{phase:?}");
        if matches!(phase, Phase::Members) {
            assert_eq!(
                pool.sim
                    .create_client_calls()
                    .iter()
                    .map(|call| call.host.as_str())
                    .collect::<Vec<_>>(),
                ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]
            );
            assert_eq!(pool.firmware.member_calls.lock().unwrap().len(), 16);
        }
        drop(request);
        tokio::task::yield_now().await;

        if matches!(phase, Phase::Members) {
            // Gates are in host/member order. The fifth member on each active
            // BMC and every member on the fifth BMC were never admitted.
            for (index, sender) in senders.iter().enumerate() {
                assert_eq!(
                    sender.is_closed(),
                    index / 5 < 4 && index % 5 < 4,
                    "member gate {index}"
                );
            }
        } else {
            assert!(
                senders[..4].iter().all(oneshot::Sender::is_closed),
                "{phase:?}"
            );
            assert!(!senders[4].is_closed(), "{phase:?}: queued work started");
        }
        assert_eq!(gates.started.load(Ordering::Relaxed), active, "{phase:?}");
        assert!(
            pool.sim.actions_since(&before).all_hosts().is_empty(),
            "{phase:?}"
        );
    }
}

/// Setup and queueing consume the original budget; it cannot restart at listing
/// or member reads. Completed evidence survives while late success/error is rejected.
#[tokio::test(start_paused = true)]
async fn firmware_inventory_deadline_preserves_peers_and_rejects_late_results() {
    // Both ready outcomes must lose to expiry, rather than replace it with a
    // successful member or an ordinary read error.
    for late_failure in [false, true] {
        let endpoints: Vec<_> = (1..=5).map(test_compute_tray_endpoint).collect();
        let pool = compute_read_test_pool(&endpoints);
        let ids: Vec<_> = [
            "BMC_Firmware",
            "late",
            "blocked-1",
            "blocked-2",
            "blocked-3",
            "queued",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        set_firmware_test_inventory(&pool, &ids);
        if late_failure {
            pool.firmware.members.lock().unwrap().insert(
                (endpoints[0].bmc_ip.to_string(), "late".into()),
                Err("secret-late-error".into()),
            );
        }
        let mut setup_senders: Vec<_> = endpoints
            .iter()
            .map(|endpoint| Some(pool.setup_gates.block(endpoint)))
            .collect();
        let delayed_listing = pool.firmware.list_gates.block(&endpoints[1]);
        let mut member_senders: Vec<_> = ids[1..]
            .iter()
            .map(|id| {
                pool.firmware
                    .member_gates
                    .block_key(format!("{}/{id}", endpoints[0].bmc_ip))
            })
            .collect();
        let manager = CoreComputeTrayManager::new(pool.clone());
        let before = pool.sim.timepoint();
        let started = Instant::now();
        let mut request = Box::pin(manager.get_firmware_inventory(&endpoints));

        assert!(futures_util::poll!(request.as_mut()).is_pending());
        assert_eq!(pool.setup_gates.started.load(Ordering::Relaxed), 4);
        assert!(pool.sim.create_client_calls().is_empty());
        // Five seconds spent setting up clients must count against later reads.
        tokio::time::advance(Duration::from_secs(5)).await;
        setup_senders[0].take().unwrap().send(()).unwrap();
        setup_senders[1].take().unwrap().send(()).unwrap();
        assert!(futures_util::poll!(request.as_mut()).is_pending());
        assert_eq!(
            pool.firmware.member_gates.started.load(Ordering::Relaxed),
            4
        );
        assert_eq!(pool.firmware.list_calls.load(Ordering::Relaxed), 2);
        assert_eq!(pool.sim.create_client_calls().len(), 2);

        // The original deadline is neither shortened nor reset after setup.
        tokio::time::advance(Duration::from_millis(24_999)).await;
        assert!(futures_util::poll!(request.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(1)).await;
        member_senders.remove(0).send(()).unwrap();
        delayed_listing.send(()).unwrap();
        setup_senders[2].take().unwrap().send(()).unwrap();
        let results = request.await.unwrap();

        assert_eq!(Instant::now() - started, Duration::from_secs(30));
        assert_eq!(results.len(), 5);
        assert_eq!(
            results
                .iter()
                .map(|result| result.mac_address)
                .collect::<Vec<_>>(),
            endpoints
                .iter()
                .map(|endpoint| endpoint.bmc_mac)
                .collect::<Vec<_>>()
        );
        let entries = results[0].inventory.as_ref().unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| &entry.inventory_id)
                .collect::<Vec<_>>(),
            ids.iter().collect::<Vec<_>>()
        );
        assert!(entries[0].firmware.is_ok());
        assert!(
            entries[1..]
                .iter()
                .all(|entry| entry.firmware == Err(FirmwareReadError::DeadlineExceeded))
        );
        assert!(
            results[1..]
                .iter()
                .all(|result| result.inventory == Err(FirmwareReadError::DeadlineExceeded))
        );
        assert!(member_senders[..3].iter().all(oneshot::Sender::is_closed));
        assert!(
            !member_senders[3].is_closed(),
            "queued member started after expiry"
        );
        assert!(setup_senders[3].as_ref().unwrap().is_closed());
        assert!(
            !setup_senders[4].as_ref().unwrap().is_closed(),
            "queued endpoint started after expiry"
        );
        assert_eq!(pool.setup_gates.started.load(Ordering::Relaxed), 4);
        assert_eq!(pool.sim.create_client_calls().len(), 3);
        assert_eq!(
            pool.firmware.list_calls.load(Ordering::Relaxed),
            2,
            "late setup admitted a collection read"
        );
        let calls = pool.firmware.member_calls.lock().unwrap();
        assert_eq!(calls.len(), 5);
        assert!(
            calls
                .iter()
                .all(|(host, id)| host == "192.0.2.1" && id != "queued")
        );
        assert!(pool.sim.actions_since(&before).all_hosts().is_empty());
    }
}
