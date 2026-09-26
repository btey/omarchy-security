// SPDX-License-Identifier: GPL-3.0-or-later

//! USBGuard module (task 2.3, plan §2.5).
//!
//! Talks to `usbguard-dbus` on the system bus. The plan names
//! `org.isis.USBGuard`, but current USBGuard releases publish
//! `org.usbguard1` with the `org.usbguard.Devices1` interface at
//! `/org/usbguard1/Devices`. `usbguard-dbus` checks polkit on each call, so
//! this module needs no privileges of its own.
//!
//! The module keeps a cache of devices, fills it with `listDevices`, and
//! keeps it current from the `DevicePresenceChanged` and
//! `DevicePolicyChanged` signals. It goes `unavailable` while
//! `org.usbguard1` has no owner, and resyncs when the service comes back.
//! `usbguard-dbus` takes its bus name before it has reached
//! `usbguard-daemon` (the two units start together), so a `listDevices`
//! that fails while the name has an owner is retried with backoff.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use omarchy_security_proto::events::{UsbDeviceRef, UsbPolicyChanged};
use omarchy_security_proto::methods::{UsbDeviceList, UsbSetPolicyParams};
use omarchy_security_proto::types::{Module, ModuleState, UsbDevice, UsbTarget};
use omarchy_security_proto::{ErrorCode, Event, RpcError};
use serde_json::json;

use crate::hub::Hub;

#[zbus::proxy(
    interface = "org.usbguard.Devices1",
    default_service = "org.usbguard1",
    default_path = "/org/usbguard1/Devices",
    gen_blocking = false
)]
pub trait Devices {
    #[zbus(name = "listDevices")]
    fn list_devices(&self, query: &str) -> zbus::Result<Vec<(u32, String)>>;

    #[zbus(name = "applyDevicePolicy", allow_interactive_auth)]
    fn apply_device_policy(&self, id: u32, target: u32, permanent: bool) -> zbus::Result<u32>;

    #[zbus(signal)]
    fn device_presence_changed(
        &self,
        id: u32,
        event: u32,
        target: u32,
        device_rule: String,
        attributes: HashMap<String, String>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    fn device_policy_changed(
        &self,
        id: u32,
        target_old: u32,
        target_new: u32,
        device_rule: String,
        rule_id: u32,
        attributes: HashMap<String, String>,
    ) -> zbus::Result<()>;
}

/// Backoff for a resync that failed while usbguard-dbus was on the bus.
const RESYNC_RETRY_FIRST: Duration = Duration::from_millis(500);
const RESYNC_RETRY_MAX: Duration = Duration::from_secs(30);

/// USBGuard's numeric targets.
fn target_from_wire(target: u32) -> Option<UsbTarget> {
    match target {
        0 => Some(UsbTarget::Allow),
        1 => Some(UsbTarget::Block),
        2 => Some(UsbTarget::Reject),
        _ => None,
    }
}

fn target_to_wire(target: UsbTarget) -> u32 {
    match target {
        UsbTarget::Allow => 0,
        UsbTarget::Block => 1,
        UsbTarget::Reject => 2,
    }
}

/// `DevicePresenceChanged` event codes.
mod presence {
    pub const PRESENT: u32 = 0;
    pub const INSERT: u32 = 1;
    pub const UPDATE: u32 = 2;
    pub const REMOVE: u32 = 3;
}

// ----------------------------------------------------------- rule parsing

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Quoted(String),
    Open,
    Close,
}

fn tokenize(rule: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = rule.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '{' => {
                chars.next();
                tokens.push(Token::Open);
            }
            '}' => {
                chars.next();
                tokens.push(Token::Close);
            }
            '"' => {
                chars.next();
                let mut value = String::new();
                loop {
                    match chars.next() {
                        None => return Err("unterminated string".into()),
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some('x') => {
                                let hex: String = chars.by_ref().take(2).collect();
                                let byte = u8::from_str_radix(&hex, 16)
                                    .map_err(|_| format!("bad escape \\x{hex}"))?;
                                value.push(char::from(byte));
                            }
                            Some(other) => value.push(other),
                            None => return Err("unterminated escape".into()),
                        },
                        Some(other) => value.push(other),
                    }
                }
                tokens.push(Token::Quoted(value));
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == '{' || c == '}' || c == '"' {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                tokens.push(Token::Word(word));
            }
        }
    }
    Ok(tokens)
}

/// The fields of a USBGuard device rule this module reports, e.g. from
/// `allow id 0951:1666 serial "X" name "Y" with-interface { 08:06:50 }`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRule {
    pub target: Option<UsbTarget>,
    pub vendor_id: String,
    pub product_id: String,
    pub serial: String,
    pub name: String,
    /// Full `class:subclass:protocol` triplets, one per interface.
    pub interfaces: Vec<String>,
}

const SET_OPERATORS: [&str; 6] = [
    "all-of",
    "one-of",
    "none-of",
    "equals",
    "equals-ordered",
    "match-all",
];

pub fn parse_device_rule(rule: &str) -> Result<DeviceRule, String> {
    let mut tokens = tokenize(rule)?.into_iter().peekable();
    let mut parsed = DeviceRule::default();
    if let Some(Token::Word(target)) = tokens.peek() {
        parsed.target = match target.as_str() {
            "allow" => Some(UsbTarget::Allow),
            "block" => Some(UsbTarget::Block),
            "reject" => Some(UsbTarget::Reject),
            _ => None,
        };
        if parsed.target.is_some() {
            tokens.next();
        }
    }
    while let Some(token) = tokens.next() {
        let Token::Word(key) = token else {
            return Err(format!("expected an attribute name, got {token:?}"));
        };
        if matches!(tokens.peek(), Some(Token::Word(w)) if SET_OPERATORS.contains(&w.as_str())) {
            tokens.next();
        }
        let values: Vec<String> = match tokens.next() {
            Some(Token::Open) => {
                let mut values = Vec::new();
                loop {
                    match tokens.next() {
                        Some(Token::Close) => break,
                        Some(Token::Word(v) | Token::Quoted(v)) => values.push(v),
                        _ => return Err(format!("unterminated {{ }} after {key}")),
                    }
                }
                values
            }
            Some(Token::Word(v) | Token::Quoted(v)) => vec![v],
            other => return Err(format!("missing value for {key}: {other:?}")),
        };
        let first = values.first().cloned().unwrap_or_default();
        match key.as_str() {
            "id" => {
                let (vendor, product) = first
                    .split_once(':')
                    .ok_or_else(|| format!("bad id '{first}'"))?;
                parsed.vendor_id = vendor.to_ascii_lowercase();
                parsed.product_id = product.to_ascii_lowercase();
            }
            "serial" => parsed.serial = first,
            "name" => parsed.name = first,
            "with-interface" => {
                parsed.interfaces = values.into_iter().map(|v| v.to_ascii_lowercase()).collect()
            }
            _ => {}
        }
    }
    Ok(parsed)
}

/// Builds the protocol's view of a device from its USBGuard rule. `target`
/// overrides the rule's own target when the signal carries one.
pub fn device_from_rule(
    id: u32,
    rule: &str,
    target: Option<UsbTarget>,
) -> Result<UsbDevice, String> {
    let parsed = parse_device_rule(rule)?;
    let classes: Vec<String> = parsed
        .interfaces
        .iter()
        .map(|i| i.split(':').next().unwrap_or_default().to_owned())
        .collect();
    let name = if parsed.name.is_empty() {
        format!("USB device {}:{}", parsed.vendor_id, parsed.product_id)
    } else {
        parsed.name
    };
    Ok(UsbDevice {
        device_id: id,
        name,
        vendor_id: parsed.vendor_id,
        product_id: parsed.product_id,
        serial: parsed.serial,
        rule: target.or(parsed.target).unwrap_or(UsbTarget::Block),
        interface_class: classes.first().cloned().unwrap_or_default(),
        interfaces: if classes.len() > 1 { classes } else { vec![] },
    })
}

// ----------------------------------------------------------------- module

pub struct Usbguard {
    hub: Arc<Hub>,
    proxy: Mutex<Option<DevicesProxy<'static>>>,
    devices: Mutex<BTreeMap<u32, UsbDevice>>,
    /// `permanent` of our own pending `applyDevicePolicy` calls, reported
    /// in the `USB_DEVICE_POLICY_CHANGED` the signal produces.
    pending_permanent: Mutex<HashMap<u32, bool>>,
}

fn map_dbus_error(err: zbus::Error) -> RpcError {
    let text = err.to_string();
    let code = match &err {
        zbus::Error::MethodError(name, _, _)
            if name.contains("AccessDenied") || name.contains("NotAuthorized") =>
        {
            ErrorCode::PermissionDenied
        }
        zbus::Error::MethodError(name, _, _)
            if name.contains("ServiceUnknown") || name.contains("NameHasNoOwner") =>
        {
            ErrorCode::ModuleUnavailable
        }
        _ => ErrorCode::BackendError,
    };
    RpcError::new(code, format!("usbguard: {text}")).with_data(json!({ "detail": text }))
}

impl Usbguard {
    /// Starts the module on `bus`, normally the system bus. With no bus the
    /// module stays unavailable.
    pub fn start(hub: Arc<Hub>, bus: zbus::Result<zbus::Connection>) -> Arc<Self> {
        let module = Arc::new(Self {
            hub,
            proxy: Mutex::new(None),
            devices: Mutex::new(BTreeMap::new()),
            pending_permanent: Mutex::new(HashMap::new()),
        });
        match bus {
            Ok(conn) => {
                module.unavailable("connecting to usbguard-dbus");
                let task = module.clone();
                tokio::spawn(async move {
                    if let Err(err) = task.clone().run(conn).await {
                        task.unavailable(&format!("D-Bus error: {err}"));
                    }
                });
            }
            Err(err) => module.unavailable(&format!("system bus unavailable: {err}")),
        }
        module
    }

    fn unavailable(&self, detail: &str) {
        self.hub.set_status(
            Module::Usbguard,
            ModuleState::Unavailable,
            Some(detail.into()),
        );
    }

    fn proxy(&self) -> Result<DevicesProxy<'static>, RpcError> {
        self.proxy
            .lock()
            .expect("usbguard lock")
            .clone()
            .ok_or_else(|| {
                RpcError::new(
                    ErrorCode::ModuleUnavailable,
                    "usbguard-dbus is not connected",
                )
            })
    }

    async fn run(self: Arc<Self>, conn: zbus::Connection) -> zbus::Result<()> {
        let proxy = DevicesProxy::new(&conn).await?;
        let mut owner = proxy.inner().receive_owner_changed().await?;
        let mut presence = proxy.receive_device_presence_changed().await?;
        let mut policy = proxy.receive_device_policy_changed().await?;
        *self.proxy.lock().expect("usbguard lock") = Some(proxy.clone());
        // The delay before the next resync attempt, and when it is due.
        let mut retry: Option<(Duration, tokio::time::Instant)> = None;
        let schedule = |delay: Duration| (delay, tokio::time::Instant::now() + delay);
        if self.resync(&proxy).await {
            retry = Some(schedule(RESYNC_RETRY_FIRST));
        }
        loop {
            let due = retry.map(|(_, at)| at);
            tokio::select! {
                change = owner.next() => match change {
                    Some(Some(_)) => {
                        retry = self.resync(&proxy).await.then(|| schedule(RESYNC_RETRY_FIRST));
                    }
                    Some(None) => {
                        retry = None;
                        self.devices.lock().expect("usbguard lock").clear();
                        self.unavailable("usbguard-dbus stopped");
                    }
                    None => return Ok(()),
                },
                () = tokio::time::sleep_until(due.unwrap_or_else(tokio::time::Instant::now)), if due.is_some() => {
                    let delay = retry.map_or(RESYNC_RETRY_FIRST, |(d, _)| (d * 2).min(RESYNC_RETRY_MAX));
                    retry = self.resync(&proxy).await.then(|| schedule(delay));
                }
                signal = presence.next() => {
                    let Some(signal) = signal else { return Ok(()) };
                    match signal.args() {
                        Ok(a) => self.on_presence(a.id, a.event, a.target, &a.device_rule),
                        Err(err) => tracing::warn!("bad DevicePresenceChanged: {err}"),
                    }
                }
                signal = policy.next() => {
                    let Some(signal) = signal else { return Ok(()) };
                    match signal.args() {
                        Ok(a) => self.on_policy(a.id, a.target_new, &a.device_rule),
                        Err(err) => tracing::warn!("bad DevicePolicyChanged: {err}"),
                    }
                }
            }
        }
    }

    /// Reloads the device cache. Returns whether to try again later: true
    /// when the call failed although `org.usbguard1` has an owner.
    async fn resync(&self, proxy: &DevicesProxy<'static>) -> bool {
        match proxy.list_devices("match").await {
            Ok(list) => {
                let devices = list
                    .into_iter()
                    .filter_map(|(id, rule)| match device_from_rule(id, &rule, None) {
                        Ok(device) => Some((id, device)),
                        Err(err) => {
                            tracing::warn!(id, "unparsable usbguard rule '{rule}': {err}");
                            None
                        }
                    })
                    .collect();
                *self.devices.lock().expect("usbguard lock") = devices;
                self.hub
                    .set_status(Module::Usbguard, ModuleState::Active, None);
                false
            }
            Err(err) => {
                let rpc = map_dbus_error(err);
                if rpc.kind() == Some(ErrorCode::ModuleUnavailable) {
                    self.unavailable(
                        "usbguard-dbus is not running (org.usbguard1 is not on the system bus)",
                    );
                    return false;
                }
                tracing::debug!("listing usbguard devices: {}", rpc.message);
                self.unavailable(&format!("{}; retrying", rpc.message));
                true
            }
        }
    }

    fn on_presence(&self, id: u32, event: u32, target: u32, rule: &str) {
        match event {
            presence::PRESENT | presence::INSERT | presence::UPDATE => {
                let device = match device_from_rule(id, rule, target_from_wire(target)) {
                    Ok(device) => device,
                    Err(err) => {
                        tracing::warn!(id, "unparsable usbguard rule '{rule}': {err}");
                        return;
                    }
                };
                let known = self
                    .devices
                    .lock()
                    .expect("usbguard lock")
                    .insert(id, device.clone())
                    .is_some();
                if event != presence::UPDATE && !known {
                    tracing::info!(id, name = %device.name, rule = ?device.rule, "usb device presented");
                    self.hub.emit(Event::UsbDevicePresented(device));
                }
            }
            presence::REMOVE => {
                self.devices.lock().expect("usbguard lock").remove(&id);
                self.pending_permanent
                    .lock()
                    .expect("usbguard lock")
                    .remove(&id);
                self.hub
                    .emit(Event::UsbDeviceRemoved(UsbDeviceRef { device_id: id }));
            }
            other => tracing::debug!(id, event = other, "unknown presence event"),
        }
    }

    fn on_policy(&self, id: u32, target: u32, rule: &str) {
        let Some(target) = target_from_wire(target) else {
            return;
        };
        {
            let mut devices = self.devices.lock().expect("usbguard lock");
            match devices.get_mut(&id) {
                Some(device) => device.rule = target,
                None => {
                    if let Ok(device) = device_from_rule(id, rule, Some(target)) {
                        devices.insert(id, device);
                    }
                }
            }
        }
        let permanent = self
            .pending_permanent
            .lock()
            .expect("usbguard lock")
            .remove(&id)
            .unwrap_or(false);
        self.hub
            .emit(Event::UsbDevicePolicyChanged(UsbPolicyChanged {
                device_id: id,
                target,
                permanent,
            }));
    }

    pub fn list(&self) -> UsbDeviceList {
        UsbDeviceList {
            devices: self
                .devices
                .lock()
                .expect("usbguard lock")
                .values()
                .cloned()
                .collect(),
        }
    }

    pub async fn set_policy(&self, params: UsbSetPolicyParams) -> Result<UsbDevice, RpcError> {
        let proxy = self.proxy()?;
        let known = self
            .devices
            .lock()
            .expect("usbguard lock")
            .get(&params.device_id)
            .cloned();
        let Some(mut device) = known else {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                format!("no USB device with id {}", params.device_id),
            ));
        };
        self.pending_permanent
            .lock()
            .expect("usbguard lock")
            .insert(params.device_id, params.permanent);
        let applied = proxy
            .apply_device_policy(
                params.device_id,
                target_to_wire(params.target),
                params.permanent,
            )
            .await;
        if let Err(err) = applied {
            self.pending_permanent
                .lock()
                .expect("usbguard lock")
                .remove(&params.device_id);
            return Err(map_dbus_error(err));
        }
        tracing::info!(id = params.device_id, target = ?params.target, permanent = params.permanent, "usb policy applied");
        // The DevicePolicyChanged signal confirms this; a rejected device
        // is dropped from the cache by the removal that follows.
        device.rule = params.target;
        self.devices
            .lock()
            .expect("usbguard lock")
            .insert(params.device_id, device.clone());
        Ok(device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Bus;

    const RULE: &str = r#"block id 0951:1666 serial "00187D0F2E3B" name "Mass Storage Device" hash "abc=" parent-hash "def=" via-port "1-2" with-interface 08:06:50 with-connect-type "hotplug""#;

    #[test]
    fn parses_the_spec_example() {
        let device = device_from_rule(14, RULE, None).unwrap();
        assert_eq!(
            device,
            UsbDevice {
                device_id: 14,
                name: "Mass Storage Device".into(),
                vendor_id: "0951".into(),
                product_id: "1666".into(),
                serial: "00187D0F2E3B".into(),
                rule: UsbTarget::Block,
                interface_class: "08".into(),
                interfaces: vec![],
            }
        );
    }

    #[test]
    fn parses_interface_sets_escapes_and_empty_names() {
        let rule = r#"allow id 1050:0407 serial "" name "YubiKey \"OTP\"\x2bFIDO" with-interface { 03:01:01 03:00:00 0B:00:00 } with-connect-type """#;
        let device = device_from_rule(3, rule, None).unwrap();
        assert_eq!(device.name, r#"YubiKey "OTP"+FIDO"#);
        assert_eq!(device.rule, UsbTarget::Allow);
        assert_eq!(device.interface_class, "03");
        assert_eq!(device.interfaces, ["03", "03", "0b"]);

        let device = device_from_rule(
            4,
            "allow id 1D6B:0002 with-interface one-of { 09:00:00 }",
            Some(UsbTarget::Reject),
        )
        .unwrap();
        assert_eq!(device.name, "USB device 1d6b:0002");
        assert_eq!(device.rule, UsbTarget::Reject);
        assert!(device.interfaces.is_empty());
    }

    #[test]
    fn rejects_malformed_rules() {
        assert!(parse_device_rule(r#"allow name "unterminated"#).is_err());
        assert!(parse_device_rule("allow with-interface { 08:06:50").is_err());
        assert!(parse_device_rule("allow id nocolon").is_err());
    }

    /// A stand-in for usbguard-dbus served on a private bus.
    struct FakeUsbguard {
        devices: Arc<Mutex<Vec<(u32, String)>>>,
        /// How many more `listDevices` calls fail the way usbguard-dbus
        /// does before it has reached usbguard-daemon.
        not_connected: Arc<std::sync::atomic::AtomicU32>,
    }

    #[zbus::interface(name = "org.usbguard.Devices1")]
    impl FakeUsbguard {
        #[zbus(name = "listDevices")]
        fn list_devices(&self, _query: &str) -> zbus::fdo::Result<Vec<(u32, String)>> {
            use std::sync::atomic::Ordering;
            let left = self.not_connected.load(Ordering::SeqCst);
            if left > 0 {
                self.not_connected.store(left - 1, Ordering::SeqCst);
                return Err(zbus::fdo::Error::NoServer(
                    "USBGuard DBus service is not connected to the daemon.".into(),
                ));
            }
            Ok(self.devices.lock().unwrap().clone())
        }

        #[zbus(name = "applyDevicePolicy")]
        async fn apply_device_policy(
            &self,
            id: u32,
            target: u32,
            _permanent: bool,
            #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
        ) -> zbus::fdo::Result<u32> {
            if id == 666 {
                return Err(zbus::fdo::Error::AccessDenied("not authorized".into()));
            }
            Self::device_policy_changed(&emitter, id, 1, target, RULE.into(), 0, HashMap::new())
                .await
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            Ok(0)
        }

        #[zbus(signal, name = "DevicePolicyChanged")]
        async fn device_policy_changed(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            id: u32,
            target_old: u32,
            target_new: u32,
            device_rule: String,
            rule_id: u32,
            attributes: HashMap<String, String>,
        ) -> zbus::Result<()>;

        #[zbus(signal, name = "DevicePresenceChanged")]
        async fn device_presence_changed(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            id: u32,
            event: u32,
            target: u32,
            device_rule: String,
            attributes: HashMap<String, String>,
        ) -> zbus::Result<()>;
    }

    async fn wait_for(hub: &Hub, state: ModuleState) {
        for _ in 0..200 {
            if hub.status(Module::Usbguard).state == state {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!(
            "usbguard never became {state:?}: {:?}",
            hub.status(Module::Usbguard)
        );
    }

    async fn next_event(rx: &mut tokio::sync::broadcast::Receiver<Event>) -> Event {
        loop {
            let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("event within 5 s")
                .unwrap();
            if !matches!(event, Event::ModuleStateChanged(_)) {
                return event;
            }
        }
    }

    #[tokio::test]
    async fn follows_a_usbguard_service() {
        let Some(bus) = Bus::start() else {
            eprintln!("dbus-daemon not available; skipping");
            return;
        };
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let module = Usbguard::start(hub.clone(), Ok(bus.connect().await));
        wait_for(&hub, ModuleState::Unavailable).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            hub.status(Module::Usbguard)
                .detail
                .unwrap()
                .contains("not running")
        );

        // The service appears: the module lists its devices.
        let devices = Arc::new(Mutex::new(vec![(14, RULE.to_owned())]));
        let service = zbus::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name("org.usbguard1")
            .unwrap()
            .serve_at(
                "/org/usbguard1/Devices",
                FakeUsbguard {
                    devices: devices.clone(),
                    not_connected: Default::default(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        wait_for(&hub, ModuleState::Active).await;
        assert_eq!(module.list().devices.len(), 1);

        // Hotplug.
        let emitter = service
            .object_server()
            .interface::<_, FakeUsbguard>("/org/usbguard1/Devices")
            .await
            .unwrap();
        let rule2 = r#"block id 1050:0407 name "YubiKey" with-interface 03:00:00"#;
        FakeUsbguard::device_presence_changed(
            emitter.signal_emitter(),
            20,
            presence::INSERT,
            1,
            rule2.into(),
            HashMap::new(),
        )
        .await
        .unwrap();
        match next_event(&mut events).await {
            Event::UsbDevicePresented(d) => {
                assert_eq!((d.device_id, d.name.as_str()), (20, "YubiKey"))
            }
            other => panic!("unexpected {other:?}"),
        }

        // Policy change round trip.
        let device = module
            .set_policy(UsbSetPolicyParams {
                device_id: 14,
                target: UsbTarget::Allow,
                permanent: true,
            })
            .await
            .unwrap();
        assert_eq!(device.rule, UsbTarget::Allow);
        match next_event(&mut events).await {
            Event::UsbDevicePolicyChanged(c) => assert_eq!(
                c,
                UsbPolicyChanged {
                    device_id: 14,
                    target: UsbTarget::Allow,
                    permanent: true
                }
            ),
            other => panic!("unexpected {other:?}"),
        }

        let err = module
            .set_policy(UsbSetPolicyParams {
                device_id: 99,
                target: UsbTarget::Allow,
                permanent: false,
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::NotFound));
        devices.lock().unwrap().push((666, RULE.into()));
        FakeUsbguard::device_presence_changed(
            emitter.signal_emitter(),
            666,
            presence::INSERT,
            1,
            RULE.into(),
            HashMap::new(),
        )
        .await
        .unwrap();
        next_event(&mut events).await;
        let err = module
            .set_policy(UsbSetPolicyParams {
                device_id: 666,
                target: UsbTarget::Allow,
                permanent: false,
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::PermissionDenied));

        // Removal, then the service goes away.
        FakeUsbguard::device_presence_changed(
            emitter.signal_emitter(),
            20,
            presence::REMOVE,
            1,
            rule2.into(),
            HashMap::new(),
        )
        .await
        .unwrap();
        assert!(matches!(
            next_event(&mut events).await,
            Event::UsbDeviceRemoved(UsbDeviceRef { device_id: 20 })
        ));
        drop(emitter);
        drop(service);
        wait_for(&hub, ModuleState::Unavailable).await;
        assert!(module.list().devices.is_empty());
    }

    #[tokio::test]
    async fn retries_until_usbguard_dbus_reaches_the_daemon() {
        let Some(bus) = Bus::start() else {
            eprintln!("dbus-daemon not available; skipping");
            return;
        };
        let hub = Arc::new(Hub::new());
        let module = Usbguard::start(hub.clone(), Ok(bus.connect().await));
        wait_for(&hub, ModuleState::Unavailable).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // The name appears, but the first two listDevices fail (NoServer).
        let not_connected = Arc::new(std::sync::atomic::AtomicU32::new(2));
        let _service = zbus::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name("org.usbguard1")
            .unwrap()
            .serve_at(
                "/org/usbguard1/Devices",
                FakeUsbguard {
                    devices: Arc::new(Mutex::new(vec![(14, RULE.to_owned())])),
                    not_connected: not_connected.clone(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        for _ in 0..200 {
            if hub
                .status(Module::Usbguard)
                .detail
                .is_some_and(|d| d.contains("retrying"))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            hub.status(Module::Usbguard)
                .detail
                .unwrap()
                .contains("retrying")
        );

        // Retried after 0.5 s and 1 s: active by about 1.5 s.
        for _ in 0..300 {
            if hub.status(Module::Usbguard).state == ModuleState::Active {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(hub.status(Module::Usbguard).state, ModuleState::Active);
        assert_eq!(not_connected.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(module.list().devices.len(), 1);
    }
}
