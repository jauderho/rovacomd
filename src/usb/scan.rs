//! USB device discovery, platform independent: C `usbid_list`
//! (`host/device_list.c`), `novacom_usb_find_endpoints`,
//! `novacom_usb_open` and `novacom_usb_findandattach_thread`
//! (`host/usb-linux.c`). The OS side is a [`Backend`]
//! ([`super::backend::Nusb`] in the daemon).
//!
//! Once a second (as C): list the devices; take the first one whose
//! vendor/product is in [`USBID_LIST`] and that is not attached yet; open
//! it; find the novacom interface (class 0xff, subclass 0x47, protocol
//! 0x11, `endpoint[0]` IN, `endpoint[1]` OUT); claim it; start its rx and
//! tx threads. Then sleep 1 s and count the recovery records down by 1.
//!
//! Intentional changes:
//! - C tells attached devices apart by the failing claim (`EBUSY`) on the
//!   next scan; here attached devices are tracked and not opened again
//!   until both of their threads have ended.
//! - C (Linux) exits at start when not root; here a device that cannot be
//!   opened or claimed is reported with one line, once, until it is
//!   unplugged or attached (C ignores these failures silently).
//! - D18: C bounds the alternate settings of every interface by the count
//!   of interface 0 and reads `endpoint[1]` without checking
//!   `bNumEndpoints`; here interface `i` uses its first
//!   `min(count(0), count(i))` settings, and a missing endpoint counts as
//!   0 (`failed to find acceptable endpoints`).

use std::collections::HashSet;
use std::io;
use std::sync::PoisonError;
use std::thread::JoinHandle;
use std::time::Duration;

use super::UsbLink;
use crate::log::{LOG_ERROR, LOG_TRACE};
use crate::usbll::Host;

/// C `usbid_list`: vendor, product, device type name.
pub const USBID_LIST: [(u16, u16, &[u8]); 95] = [
    (0x0830, 0x1000, b"unknown-bootie"),
    (0x0830, 0x0101, b"castle-linux"),
    (0x0830, 0x8001, b"castle-bootie"),
    (0x0830, 0x8002, b"castle-linux"),
    (0x05AC, 0x0101, b"castle-linux"),
    (0x05AC, 0x1209, b"castle-linux"),
    (0x05AC, 0x8002, b"castle-linux"),
    (0x05AC, 0x8003, b"castle-linux"),
    (0x05AC, 0x8004, b"castle-linux"),
    (0x05AC, 0x8012, b"castle-linux"),
    (0x0830, 0x8003, b"castle-linux"),
    (0x0830, 0x8004, b"castle-linux"),
    (0x0830, 0x8006, b"castle-linux"),
    (0x0830, 0x8007, b"castle-linux"),
    (0x0830, 0x8011, b"pixie-bootie"),
    (0x0830, 0x8012, b"pixie-linux"),
    (0x0830, 0x8016, b"pixie-linux"),
    (0x0830, 0x8017, b"pixie-linux"),
    (0x0830, 0x0103, b"pixie-linux"),
    (0x0830, 0xc001, b"zepfloyd-bootie"),
    (0x0830, 0xc002, b"zepfloyd-linux"),
    (0x0830, 0x8021, b""),
    (0x0830, 0x8022, b""),
    (0x0830, 0x8026, b""),
    (0x0830, 0x8027, b""),
    (0x0830, 0x0105, b""),
    (0x0830, 0x8031, b""),
    (0x0830, 0x8032, b""),
    (0x0830, 0x8036, b""),
    (0x0830, 0x8037, b""),
    (0x0830, 0x0107, b""),
    (0x0830, 0x8041, b""),
    (0x0830, 0x8042, b""),
    (0x0830, 0x8046, b""),
    (0x0830, 0x8047, b""),
    (0x0830, 0x8051, b""),
    (0x0830, 0x8052, b""),
    (0x0830, 0x8056, b""),
    (0x0830, 0x8057, b""),
    (0x0830, 0x8061, b""),
    (0x0830, 0x8062, b""),
    (0x0830, 0x8066, b""),
    (0x0830, 0x8067, b""),
    (0x0830, 0x8071, b""),
    (0x0830, 0x8072, b""),
    (0x0830, 0x8076, b""),
    (0x0830, 0x8077, b""),
    (0x0830, 0x8081, b""),
    (0x0830, 0x8082, b""),
    (0x0830, 0x8086, b""),
    (0x0830, 0x8087, b""),
    (0x0830, 0x8091, b""),
    (0x0830, 0x8092, b""),
    (0x0830, 0x8096, b""),
    (0x0830, 0x8097, b""),
    (0x03F0, 0x1128, b""),
    (0x03F0, 0x1228, b""),
    (0x03F0, 0x1628, b""),
    (0x03F0, 0x1728, b""),
    (0x03F0, 0x1928, b""),
    (0x03F0, 0x1a28, b""),
    (0x03F0, 0x1e28, b""),
    (0x03F0, 0x1f28, b""),
    (0x03F0, 0x2128, b""),
    (0x03F0, 0x2228, b""),
    (0x03F0, 0x2628, b""),
    (0x03F0, 0x2728, b""),
    (0x03F0, 0x2928, b""),
    (0x03F0, 0x2a28, b""),
    (0x03F0, 0x2e28, b""),
    (0x03F0, 0x2f28, b""),
    (0x03F0, 0x3128, b""),
    (0x03F0, 0x3228, b""),
    (0x03F0, 0x3628, b""),
    (0x03F0, 0x3728, b""),
    (0x03F0, 0x3928, b""),
    (0x03F0, 0x3a28, b""),
    (0x03F0, 0x3e28, b""),
    (0x03F0, 0x3f28, b""),
    (0x03F0, 0x4128, b""),
    (0x03F0, 0x4228, b""),
    (0x03F0, 0x4628, b""),
    (0x03F0, 0x4728, b""),
    (0x03F0, 0x4928, b""),
    (0x03F0, 0x4a28, b""),
    (0x03F0, 0x4e28, b""),
    (0x03F0, 0x4f28, b""),
    (0x03F0, 0x5128, b""),
    (0x03F0, 0x5228, b""),
    (0x03F0, 0x5628, b""),
    (0x03F0, 0x5728, b""),
    (0x03F0, 0x5928, b""),
    (0x03F0, 0x5a28, b""),
    (0x03F0, 0x5e28, b""),
    (0x03F0, 0x5f28, b""),
];

/// C `USB_CLASS_VENDOR_SPEC`.
pub const CLASS_VENDOR_SPEC: u8 = 0xff;
/// Interface subclass of novacom.
pub const NOVACOM_SUBCLASS: u8 = 0x47;
/// Interface protocol of novacom.
pub const NOVACOM_PROTOCOL: u8 = 0x11;
/// C `sleep(1)` between scans.
pub const RESCAN: Duration = Duration::from_secs(1);
/// Seconds subtracted from the recovery records per scan (C
/// `usbrecords_update(1)`).
const RESCAN_SECS: i32 = 1;

/// The `usbid_list` name of a vendor/product (first match, as C).
pub fn devtype(vendor: u16, product: u16) -> Option<&'static [u8]> {
    USBID_LIST
        .iter()
        .find(|(v, p, _)| *v == vendor && *p == product)
        .map(|(_, _, name)| *name)
}

/// One alternate setting of an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltSetting {
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// `bEndpointAddress` of each endpoint, in descriptor order.
    pub endpoints: Vec<u8>,
}

/// One interface of a configuration with its alternate settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceDesc {
    /// `bInterfaceNumber`.
    pub number: u8,
    pub alt_settings: Vec<AltSetting>,
}

/// The novacom interface of a device and its bulk endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoints {
    /// `bInterfaceNumber` (C claims index `i`; interface numbers are the
    /// indexes in a conforming configuration).
    pub interface: u8,
    /// IN endpoint address (C `eps[0]`, `rxep`).
    pub rx: u8,
    /// OUT endpoint address (C `eps[1]`, `txep`).
    pub tx: u8,
}

/// C `novacom_usb_find_endpoints` up to the claim: the first alternate
/// setting with the novacom class triple whose first endpoint is IN and
/// second is OUT. A triple match with other endpoints logs `failed to
/// find acceptable endpoints` and the search goes on.
pub fn find_endpoints(config: &[InterfaceDesc], host: &impl Host) -> Option<Endpoints> {
    let alts0 = config.first().map_or(0, |i| i.alt_settings.len());
    for intf in config {
        for alt in intf.alt_settings.iter().take(alts0) {
            if alt.class != CLASS_VENDOR_SPEC
                || alt.subclass != NOVACOM_SUBCLASS
                || alt.protocol != NOVACOM_PROTOCOL
            {
                continue;
            }
            let rx = alt.endpoints.first().copied().filter(|a| a & 0x80 != 0);
            let tx = alt.endpoints.get(1).copied().filter(|a| a & 0x80 == 0);
            match (rx, tx) {
                (Some(rx), Some(tx)) if rx != 0 && tx != 0 => {
                    return Some(Endpoints {
                        interface: intf.number,
                        rx,
                        tx,
                    });
                }
                _ => host.log(LOG_ERROR, b"failed to find acceptable endpoints\n"),
            }
        }
    }
    None
}

/// A listed device, before it is opened.
#[derive(Clone, Debug)]
pub struct Found<I> {
    /// Identity while the device stays plugged in.
    pub key: u64,
    pub vendor: u16,
    pub product: u16,
    /// C `busnum` (`atoi(bus->dirname)`).
    pub busnum: i32,
    /// C `devnum`.
    pub devnum: i32,
    /// What the backend needs to open it.
    pub info: I,
}

/// The OS side of discovery.
pub trait Backend {
    type Info;
    type Device;
    type Link: UsbLink + 'static;
    /// All USB devices (C `usb_find_busses`, `usb_find_devices`).
    fn list(&self) -> io::Result<Vec<Found<Self::Info>>>;
    /// C `usb_open`.
    fn open(&self, info: &Self::Info) -> io::Result<Self::Device>;
    /// The first configuration (C `dev->config`); `None` if there is none.
    fn config(&self, dev: &Self::Device) -> Option<Vec<InterfaceDesc>>;
    /// C `usb_claim_interface`, then the two bulk endpoints.
    fn claim(&self, dev: Self::Device, eps: Endpoints) -> io::Result<Self::Link>;
}

/// A claimed device, ready for its rx and tx threads.
pub struct Opened<L> {
    pub link: L,
    pub devtype: &'static [u8],
    pub busnum: i32,
    pub devnum: i32,
    pub key: u64,
}

/// The state of the find-and-attach thread.
pub struct Scanner<B: Backend> {
    backend: B,
    /// Attached devices and their rx/tx threads.
    attached: Vec<(u64, Vec<JoinHandle<()>>)>,
    /// Devices whose open or claim failure was logged.
    reported: HashSet<u64>,
}

impl<B: Backend> Scanner<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            attached: Vec::new(),
            reported: HashSet::new(),
        }
    }

    /// Whether the device `key` counts as attached.
    pub fn is_attached(&self, key: u64) -> bool {
        self.attached.iter().any(|(k, _)| *k == key)
    }

    /// C `novacom_usb_open`: the first listed `usbid_list` device that is
    /// not attached and can be opened, matched and claimed.
    pub fn open_next(&mut self, host: &impl Host) -> Option<Opened<B::Link>> {
        self.attached
            .retain(|(_, threads)| !threads.iter().all(JoinHandle::is_finished));
        // C: a failed listing ends the scan silently.
        let list = self.backend.list().ok()?;
        self.reported.retain(|k| list.iter().any(|f| f.key == *k));
        for f in &list {
            let Some(devtype) = devtype(f.vendor, f.product) else {
                continue;
            };
            if self.is_attached(f.key) {
                continue;
            }
            let dev = match self.backend.open(&f.info) {
                Ok(dev) => dev,
                Err(e) => {
                    self.report(host, f, "open", &e);
                    continue;
                }
            };
            let Some(eps) = self
                .backend
                .config(&dev)
                .and_then(|c| find_endpoints(&c, host))
            else {
                continue;
            };
            match self.backend.claim(dev, eps) {
                Ok(link) => {
                    self.reported.remove(&f.key);
                    return Some(Opened {
                        link,
                        devtype,
                        busnum: f.busnum,
                        devnum: f.devnum,
                        key: f.key,
                    });
                }
                Err(e) => self.report(host, f, "claim", &e),
            }
        }
        None
    }

    /// Logs a failed open or claim once per plugged-in device.
    fn report(&mut self, host: &impl Host, f: &Found<B::Info>, what: &str, e: &io::Error) {
        if !self.reported.insert(f.key) {
            return;
        }
        let hint = if e.kind() == io::ErrorKind::PermissionDenied {
            " (check the device permissions, see contrib/udev/60-rovacomd.rules)"
        } else {
            ""
        };
        host.log(
            LOG_ERROR,
            format!(
                "unable to {what} usb device {:04x}:{:04x} bus={:03} dev={:03}: {e}{hint}\n",
                f.vendor, f.product, f.busnum, f.devnum
            )
            .as_bytes(),
        );
    }

    /// One pass of C `novacom_usb_findandattach_thread`: attach the next
    /// device with `attach` (which starts its threads), sleep 1 s, count
    /// the recovery records down.
    pub fn pass<H: Host>(
        &mut self,
        host: &H,
        attach: impl FnOnce(Opened<B::Link>) -> Vec<JoinHandle<()>>,
    ) {
        if let Some(o) = self.open_next(host) {
            // C prints the still unset usbll handle (NULL).
            host.log(
                LOG_TRACE,
                format!(
                    "novacom_usb_findandattach_thread:583: usb_handle 0x00000000, bus={:03} dev={:03}\n",
                    o.busnum, o.devnum
                )
                .as_bytes(),
            );
            let key = o.key;
            let threads = attach(o);
            self.attached.push((key, threads));
        }
        host.sleep(RESCAN);
        host.records()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .update(RESCAN_SECS, host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usbll::tests::TestHost;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    const PALM: u16 = 0x0830;

    fn alt(class: u8, subclass: u8, protocol: u8, endpoints: &[u8]) -> AltSetting {
        AltSetting {
            class,
            subclass,
            protocol,
            endpoints: endpoints.to_vec(),
        }
    }

    fn novacom(endpoints: &[u8]) -> AltSetting {
        alt(0xff, 0x47, 0x11, endpoints)
    }

    fn intf(number: u8, alt_settings: Vec<AltSetting>) -> InterfaceDesc {
        InterfaceDesc {
            number,
            alt_settings,
        }
    }

    fn errors(host: &TestHost) -> Vec<String> {
        host.logs()
            .into_iter()
            .filter(|(m, _)| *m == LOG_ERROR)
            .map(|(_, t)| t)
            .collect()
    }

    #[test]
    fn usbid_table_matches_c() {
        assert_eq!(USBID_LIST.len(), 95);
        assert_eq!(devtype(PALM, 0x1000), Some(&b"unknown-bootie"[..]));
        assert_eq!(devtype(0x05AC, 0x1209), Some(&b"castle-linux"[..]));
        assert_eq!(devtype(PALM, 0xc002), Some(&b"zepfloyd-linux"[..]));
        assert_eq!(devtype(PALM, 0x8062), Some(&b""[..]));
        assert_eq!(devtype(0x03F0, 0x5f28), Some(&b""[..]));
        assert_eq!(devtype(PALM, 0x8063), None);
        assert_eq!(devtype(0x046d, 0x8062), None);
        // No duplicates, so the first match is the only one.
        let mut ids: Vec<(u16, u16)> = USBID_LIST.iter().map(|(v, p, _)| (*v, *p)).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 95);
        // Only the vendors the test guard knows.
        assert!(
            USBID_LIST
                .iter()
                .all(|(v, _, _)| [0x0830, 0x03F0, 0x05AC].contains(v))
        );
    }

    #[test]
    fn finds_novacom_interface_after_others() {
        let host = TestHost::new();
        let config = [
            intf(0, vec![alt(8, 6, 0x50, &[0x81, 0x02])]),
            intf(1, vec![novacom(&[0x83, 0x04])]),
        ];
        assert_eq!(
            find_endpoints(&config, &host),
            Some(Endpoints {
                interface: 1,
                rx: 0x83,
                tx: 0x04
            })
        );
        assert!(host.logs().is_empty());
    }

    #[test]
    fn class_triple_must_match_exactly() {
        let host = TestHost::new();
        for a in [
            alt(0xfe, 0x47, 0x11, &[0x81, 0x02]),
            alt(0xff, 0x46, 0x11, &[0x81, 0x02]),
            alt(0xff, 0x47, 0x10, &[0x81, 0x02]),
        ] {
            assert_eq!(find_endpoints(&[intf(0, vec![a])], &host), None);
        }
        assert!(host.logs().is_empty());
        assert_eq!(find_endpoints(&[], &host), None);
    }

    #[test]
    fn bad_endpoints_are_logged_and_skipped() {
        let host = TestHost::new();
        // OUT first, IN second; then only one endpoint; then none; then a
        // good second alternate setting.
        let config = [intf(
            0,
            vec![
                novacom(&[0x02, 0x81]),
                novacom(&[0x81]),
                novacom(&[]),
                novacom(&[0x81, 0x80]),
                novacom(&[0x82, 0x01, 0x83]),
            ],
        )];
        assert_eq!(
            find_endpoints(&config, &host),
            Some(Endpoints {
                interface: 0,
                rx: 0x82,
                tx: 0x01
            })
        );
        assert_eq!(
            errors(&host),
            vec!["failed to find acceptable endpoints\n"; 4]
        );
    }

    #[test]
    fn alt_settings_bounded_by_interface_zero() {
        let host = TestHost::new();
        // Interface 0 has one setting: only the first setting of
        // interface 1 is looked at, as in C.
        let config = [
            intf(0, vec![alt(8, 6, 0x50, &[])]),
            intf(1, vec![alt(2, 2, 0, &[]), novacom(&[0x81, 0x02])]),
        ];
        assert_eq!(find_endpoints(&config, &host), None);
        // Interface 0 has more settings than interface 1: no overrun.
        let config = [
            intf(0, vec![alt(8, 6, 0x50, &[]); 3]),
            intf(1, vec![novacom(&[0x81, 0x02])]),
        ];
        assert_eq!(find_endpoints(&config, &host).map(|e| e.interface), Some(1));
    }

    /// A fake link; its threads hold it while they run.
    struct NoLink;

    impl UsbLink for NoLink {
        fn read(&self, _: &mut [u8], _: i32) -> io::Result<usize> {
            Ok(0)
        }

        fn write(&self, buf: &[u8], _: i32) -> io::Result<usize> {
            Ok(buf.len())
        }
    }

    /// A fake device: its key and configuration.
    type FakeInfo = (u64, Vec<InterfaceDesc>);

    /// Fake devices: `fail_open` / `fail_claim` hold the error kinds per
    /// key; every open is recorded.
    #[derive(Default)]
    struct FakeBackend {
        devices: Mutex<Vec<Found<FakeInfo>>>,
        fail_open: Mutex<Vec<(u64, io::ErrorKind)>>,
        fail_claim: Mutex<Vec<u64>>,
        list_fails: AtomicBool,
        opens: Mutex<Vec<u64>>,
    }

    impl FakeBackend {
        fn plug(&self, key: u64, vendor: u16, product: u16, config: Vec<InterfaceDesc>) {
            self.devices.lock().unwrap().push(Found {
                key,
                vendor,
                product,
                busnum: 1,
                devnum: key as i32,
                info: (key, config),
            });
        }

        fn unplug(&self, key: u64) {
            self.devices.lock().unwrap().retain(|f| f.key != key);
        }

        fn opens(&self) -> Vec<u64> {
            std::mem::take(&mut *self.opens.lock().unwrap())
        }
    }

    impl Backend for &FakeBackend {
        type Info = FakeInfo;
        type Device = (u64, Vec<InterfaceDesc>);
        type Link = NoLink;

        fn list(&self) -> io::Result<Vec<Found<Self::Info>>> {
            if self.list_fails.load(Ordering::Relaxed) {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Ok(self.devices.lock().unwrap().clone())
        }

        fn open(&self, info: &Self::Info) -> io::Result<Self::Device> {
            let key = info.0;
            self.opens.lock().unwrap().push(key);
            match self
                .fail_open
                .lock()
                .unwrap()
                .iter()
                .find(|(k, _)| *k == key)
            {
                Some((_, kind)) => Err(io::Error::from(*kind)),
                None => Ok(info.clone()),
            }
        }

        fn config(&self, dev: &Self::Device) -> Option<Vec<InterfaceDesc>> {
            (!dev.1.is_empty()).then(|| dev.1.clone())
        }

        fn claim(&self, dev: Self::Device, _: Endpoints) -> io::Result<NoLink> {
            if self.fail_claim.lock().unwrap().contains(&dev.0) {
                Err(io::Error::from(io::ErrorKind::ResourceBusy))
            } else {
                Ok(NoLink)
            }
        }
    }

    fn good(n: u8) -> Vec<InterfaceDesc> {
        vec![intf(0, vec![novacom(&[0x81, n])])]
    }

    /// Device threads that run until `stop` is set.
    fn threads(stop: &Arc<AtomicBool>) -> Vec<JoinHandle<()>> {
        (0..2)
            .map(|_| {
                let stop = Arc::clone(stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                })
            })
            .collect()
    }

    fn wait_finished(scanner: &Scanner<&FakeBackend>, key: u64) {
        // The threads are polled by the next scan; wait until they ended.
        for (k, ths) in &scanner.attached {
            if *k == key {
                while !ths.iter().all(JoinHandle::is_finished) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    #[test]
    fn attaches_one_device_per_pass_and_skips_attached_ones() {
        let host = TestHost::new();
        let be = FakeBackend::default();
        be.plug(1, 0x046d, 0xc52b, good(2)); // not in the list
        be.plug(2, PALM, 0x8062, good(2));
        be.plug(3, 0x03F0, 0x1228, good(3));
        let mut scanner = Scanner::new(&be);
        let stop = Arc::new(AtomicBool::new(false));
        let mut attached = Vec::new();
        for _ in 0..3 {
            scanner.pass(&host, |o| {
                attached.push((o.key, o.devtype, o.busnum, o.devnum));
                threads(&stop)
            });
        }
        assert_eq!(attached, [(2, &b""[..], 1, 2), (3, &b""[..], 1, 3)]);
        // Only listed devices are opened; attached ones not again.
        assert_eq!(be.opens(), [2, 3]);
        assert!(scanner.is_attached(2) && scanner.is_attached(3));
        // 1 s per pass on the injected clock.
        assert_eq!(host.ms(), 3000);
        assert_eq!(
            host.log_texts(),
            [
                "novacom_usb_findandattach_thread:583: usb_handle 0x00000000, bus=001 dev=002\n",
                "novacom_usb_findandattach_thread:583: usb_handle 0x00000000, bus=001 dev=003\n",
            ]
        );
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn ended_device_is_attached_again() {
        let host = TestHost::new();
        let be = FakeBackend::default();
        be.plug(7, PALM, 0x8002, good(2));
        let mut scanner = Scanner::new(&be);
        let stop = Arc::new(AtomicBool::new(false));
        let mut n = 0;
        scanner.pass(&host, |o| {
            n += 1;
            assert_eq!(o.devtype, b"castle-linux");
            threads(&stop)
        });
        scanner.pass(&host, |_| unreachable!("still attached"));
        assert_eq!(be.opens(), [7]);
        // The link gave up (threads ended): the device is opened again,
        // as C re-claims it.
        stop.store(true, Ordering::Relaxed);
        wait_finished(&scanner, 7);
        let stop2 = Arc::new(AtomicBool::new(false));
        scanner.pass(&host, |_| {
            n += 1;
            threads(&stop2)
        });
        assert_eq!((n, be.opens()), (2, vec![7]));
        // Unplugged: the threads end on I/O errors and the entry goes.
        be.unplug(7);
        stop2.store(true, Ordering::Relaxed);
        wait_finished(&scanner, 7);
        scanner.pass(&host, |_| unreachable!("gone"));
        assert!(!scanner.is_attached(7));
        assert!(be.opens().is_empty());
    }

    #[test]
    fn open_failure_logged_once_per_plug() {
        let host = TestHost::new();
        let be = FakeBackend::default();
        be.plug(4, PALM, 0x8062, good(2));
        be.fail_open
            .lock()
            .unwrap()
            .push((4, io::ErrorKind::PermissionDenied));
        let mut scanner = Scanner::new(&be);
        for _ in 0..3 {
            scanner.pass(&host, |_| unreachable!());
        }
        // Tried every pass, reported once.
        assert_eq!(be.opens(), [4, 4, 4]);
        let want = format!(
            "unable to open usb device 0830:8062 bus=001 dev=004: {} (check the device permissions, see contrib/udev/60-rovacomd.rules)\n",
            io::Error::from(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(errors(&host), std::slice::from_ref(&want));
        // Unplugged and plugged again: reported again.
        be.unplug(4);
        scanner.pass(&host, |_| unreachable!());
        be.plug(4, PALM, 0x8062, good(2));
        scanner.pass(&host, |_| unreachable!());
        assert_eq!(errors(&host), [want.clone(), want]);
    }

    #[test]
    fn claim_failure_logged_once_and_cleared_by_attach() {
        let host = TestHost::new();
        let be = FakeBackend::default();
        be.plug(5, PALM, 0x8012, good(2));
        be.fail_claim.lock().unwrap().push(5);
        let mut scanner = Scanner::new(&be);
        scanner.pass(&host, |_| unreachable!());
        scanner.pass(&host, |_| unreachable!());
        let want = format!(
            "unable to claim usb device 0830:8012 bus=001 dev=005: {}\n",
            io::Error::from(io::ErrorKind::ResourceBusy)
        );
        assert_eq!(errors(&host), [want]);
        be.fail_claim.lock().unwrap().clear();
        scanner.pass(&host, |_| Vec::new());
        // Attached (its threads ended at once), so the next failure is
        // reported again.
        be.fail_claim.lock().unwrap().push(5);
        scanner.pass(&host, |_| unreachable!());
        assert_eq!(errors(&host).len(), 2);
    }

    #[test]
    fn bad_endpoints_logged_every_pass_and_no_config_is_silent() {
        let host = TestHost::new();
        let be = FakeBackend::default();
        be.plug(6, PALM, 0x8022, vec![intf(0, vec![novacom(&[0x01, 0x82])])]);
        be.plug(8, PALM, 0x8032, Vec::new());
        let mut scanner = Scanner::new(&be);
        scanner.pass(&host, |_| unreachable!());
        scanner.pass(&host, |_| unreachable!());
        assert_eq!(
            errors(&host),
            vec!["failed to find acceptable endpoints\n"; 2]
        );
        assert_eq!(be.opens(), [6, 8, 6, 8]);
    }

    #[test]
    fn failed_listing_is_quiet_and_records_count_down() {
        use crate::usbll::{Link, RecoveryToken};
        let host = TestHost::new();
        let be = FakeBackend::default();
        be.list_fails.store(true, Ordering::Relaxed);
        let link = Arc::new(Mutex::new(Link::new(b"", 16384, 0, 2000, &host)));
        host.records()
            .lock()
            .unwrap()
            .add(RecoveryToken { txid: 1, rxid: 2 }, b"x", link, 1);
        let mut scanner = Scanner::new(&be);
        scanner.pass(&host, |_| unreachable!());
        assert_eq!(host.records_len(), 1);
        scanner.pass(&host, |_| unreachable!());
        // 1 - 1 - 1 < 0: destroyed, as C usbrecords_update(1).
        assert_eq!(host.records_len(), 0);
        assert_eq!(host.ms(), 2000);
        assert!(errors(&host).is_empty());
    }
}
