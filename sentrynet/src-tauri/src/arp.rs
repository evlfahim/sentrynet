//! SentryNet ARP discovery module.
//!
//! Discovers active hosts on the local IPv4 subnet together with their MAC
//! addresses and hardware vendors, without raw sockets or admin rights:
//!
//! 1. Resolve the target subnet (explicit CIDR, or the local address as /24).
//! 2. Send one tiny UDP datagram to every host in the subnet. The OS must
//!    ARP-resolve each address before it can send, which fills its ARP cache.
//! 3. Read the OS ARP cache (`/proc/net/arp`, `ip neigh` or `arp -a`).
//! 4. Keep valid unicast entries inside the subnet and attach vendor names
//!    from an embedded OUI table (optionally extended with IEEE `oui.txt`).

use crate::database::Device;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::process::Command;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

/// Prefix length used when the subnet is auto-detected.
pub const DEFAULT_PREFIX: u8 = 24;

/// Smallest prefix allowed (largest subnet: /16 = 65 534 hosts).
pub const MIN_PREFIX: u8 = 16;

/// Default time to wait for ARP replies after probing.
pub const DEFAULT_SETTLE_MS: u64 = 1500;

/// UDP "discard" port; the payload is irrelevant, only the ARP lookup matters.
const PROBE_PORT: u16 = 9;

/// Probes are sent in batches with a short pause to avoid flooding the LAN.
const PROBE_BATCH: usize = 64;
const PROBE_BATCH_PAUSE_MS: u64 = 5;

/// Vendor label for locally administered (usually randomized) MACs.
pub const RANDOMIZED_MAC_VENDOR: &str = "Randomized MAC (private address)";

// ──────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────

/// A host found in the ARP cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: String,
    /// Uppercase, colon separated (`AA:BB:CC:DD:EE:FF`).
    pub mac: String,
    pub vendor: Option<String>,
    /// Interface name (`eth0`, `en0`) or, on Windows, the local interface IP.
    pub interface: Option<String>,
}

impl ArpEntry {
    /// Convert into a database `Device` seen at `now`.
    pub fn to_device(&self, now: DateTime<Utc>) -> Device {
        Device {
            ip: self.ip.clone(),
            mac: self.mac.clone(),
            name: None,
            vendor: self.vendor.clone(),
            last_seen: now,
            first_seen: now,
        }
    }
}

/// Options for [`arp_scan`].
#[derive(Debug, Clone)]
pub struct ArpScanOptions {
    /// Subnet in CIDR notation (`192.168.1.0/24`). `None` = auto-detect.
    pub cidr: Option<String>,
    /// Send UDP probes to fill the ARP cache before reading it.
    pub probe: bool,
    /// How long to wait for ARP replies after probing.
    pub settle: Duration,
}

impl Default for ArpScanOptions {
    fn default() -> Self {
        Self {
            cidr: None,
            probe: true,
            settle: Duration::from_millis(DEFAULT_SETTLE_MS),
        }
    }
}

/// Errors raised by ARP discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpError {
    InvalidCidr(String),
    SubnetTooLarge(u8),
    NoLocalAddress(String),
    Probe(String),
    TableUnavailable(String),
}

impl fmt::Display for ArpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpError::InvalidCidr(s) => write!(f, "invalid CIDR subnet: {s}"),
            ArpError::SubnetTooLarge(p) => write!(
                f,
                "subnet /{p} is too large to scan (minimum prefix is /{MIN_PREFIX})"
            ),
            ArpError::NoLocalAddress(e) => {
                write!(f, "could not detect a local IPv4 address: {e}")
            }
            ArpError::Probe(e) => write!(f, "failed to send probes: {e}"),
            ArpError::TableUnavailable(e) => write!(f, "could not read the ARP table: {e}"),
        }
    }
}

impl std::error::Error for ArpError {}

// ──────────────────────────────────────────────
// Subnet handling
// ──────────────────────────────────────────────

/// An IPv4 subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    network: u32,
    prefix: u8,
}

impl Subnet {
    /// Build the subnet containing `addr` with the given prefix length.
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, ArpError> {
        if prefix > 32 {
            return Err(ArpError::InvalidCidr(format!("{addr}/{prefix}")));
        }
        if prefix < MIN_PREFIX {
            return Err(ArpError::SubnetTooLarge(prefix));
        }
        Ok(Self {
            network: u32::from(addr) & Self::mask_for(prefix),
            prefix,
        })
    }

    /// Parse `a.b.c.d/nn`. A bare address is treated as a single host (/32).
    pub fn parse(s: &str) -> Result<Self, ArpError> {
        let s = s.trim();
        let invalid = || ArpError::InvalidCidr(s.to_string());
        let (ip_part, prefix_part) = match s.split_once('/') {
            Some((ip, prefix)) => (ip.trim(), Some(prefix.trim())),
            None => (s, None),
        };
        let addr: Ipv4Addr = ip_part.parse().map_err(|_| invalid())?;
        let prefix = match prefix_part {
            Some(p) => p.parse::<u8>().map_err(|_| invalid())?,
            None => 32,
        };
        Self::new(addr, prefix)
    }

    fn mask_for(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        }
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn mask(&self) -> u32 {
        Self::mask_for(self.prefix)
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network | !self.mask())
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == self.network
    }

    /// Usable host addresses (network and broadcast excluded for /30 and larger).
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        let last = self.network | !self.mask();
        if self.prefix >= 31 {
            (self.network..=last).map(Ipv4Addr::from).collect()
        } else {
            (self.network + 1..last).map(Ipv4Addr::from).collect()
        }
    }

    /// True if `ip` is the network or broadcast address of a /30-or-larger subnet.
    fn is_reserved(&self, ip: Ipv4Addr) -> bool {
        self.prefix <= 30 && (ip == self.network() || ip == self.broadcast())
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

/// Detect the primary local IPv4 address.
///
/// "Connecting" a UDP socket only performs a route lookup (no packets are
/// sent); the socket's local address is then the outbound interface address.
pub fn detect_local_ipv4() -> Result<Ipv4Addr, ArpError> {
    const ROUTE_TARGETS: [&str; 4] = ["8.8.8.8:80", "1.1.1.1:80", "192.168.0.1:80", "10.0.0.1:80"];
    let mut last_err = String::from("no IPv4 route found");
    for target in ROUTE_TARGETS {
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };
        if let Err(e) = socket.connect(target) {
            last_err = e.to_string();
            continue;
        }
        match socket.local_addr() {
            Ok(SocketAddr::V4(addr)) if !addr.ip().is_loopback() && !addr.ip().is_unspecified() => {
                return Ok(*addr.ip());
            }
            Ok(_) => continue,
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(ArpError::NoLocalAddress(last_err))
}

/// Resolve the subnet to scan: explicit CIDR, or the local address as /24.
pub fn resolve_subnet(cidr: Option<&str>) -> Result<Subnet, ArpError> {
    match cidr.map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => Subnet::parse(c),
        None => Subnet::new(detect_local_ipv4()?, DEFAULT_PREFIX),
    }
}

// ──────────────────────────────────────────────
// MAC helpers
// ──────────────────────────────────────────────

/// Parse a MAC in any common notation:
/// `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`, `0:1a:2b:3c:4d:5e` (macOS drops
/// leading zeros), `aabb.ccdd.eeff` (Cisco) or `aabbccddeeff`.
pub fn normalize_mac(raw: &str) -> Option<[u8; 6]> {
    let s = raw.trim();
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.')) {
        return None;
    }
    let groups: Vec<&str> = s.split(|c: char| matches!(c, ':' | '-' | '.')).collect();
    let mut bytes = [0u8; 6];
    match groups.len() {
        6 => {
            for (i, g) in groups.iter().enumerate() {
                if g.is_empty() || g.len() > 2 {
                    return None;
                }
                bytes[i] = u8::from_str_radix(g, 16).ok()?;
            }
        }
        3 => {
            for (i, g) in groups.iter().enumerate() {
                if g.len() != 4 {
                    return None;
                }
                bytes[i * 2] = u8::from_str_radix(&g[0..2], 16).ok()?;
                bytes[i * 2 + 1] = u8::from_str_radix(&g[2..4], 16).ok()?;
            }
        }
        1 => {
            let g = groups[0];
            if g.len() != 12 {
                return None;
            }
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&g[i * 2..i * 2 + 2], 16).ok()?;
            }
        }
        _ => return None,
    }
    Some(bytes)
}

/// Format as uppercase colon-separated (`AA:BB:CC:DD:EE:FF`).
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// False for incomplete (all-zero), broadcast and multicast MACs.
pub fn is_usable_mac(mac: &[u8; 6]) -> bool {
    mac != &[0u8; 6] && mac != &[0xFFu8; 6] && mac[0] & 0x01 == 0
}

/// True for locally administered MACs (phones/laptops with private addresses).
pub fn is_locally_administered(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

fn is_usable_ip(ip: Ipv4Addr) -> bool {
    !ip.is_multicast() && !ip.is_broadcast() && !ip.is_unspecified() && !ip.is_loopback()
}

// ──────────────────────────────────────────────
// Vendor (OUI) lookup
// ──────────────────────────────────────────────

/// Maps the first three MAC bytes (OUI) to a vendor name.
#[derive(Debug, Clone, Default)]
pub struct VendorDb {
    map: HashMap<[u8; 3], String>,
}

impl VendorDb {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Database populated with the embedded table of common home-LAN vendors.
    pub fn builtin() -> Self {
        let mut db = Self::empty();
        for (vendor, prefixes) in BUILTIN_OUIS {
            for prefix in *prefixes {
                if let Some(oui) = parse_oui_prefix(prefix) {
                    db.insert(oui, vendor);
                }
            }
        }
        db
    }

    pub fn insert(&mut self, oui: [u8; 3], vendor: &str) {
        self.map.insert(oui, vendor.to_string());
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Merge entries from the IEEE registry file (`oui.txt`), whose lines look
    /// like `00-1A-11   (hex)\t\tGoogle, Inc.`. Returns the number merged.
    pub fn merge_ieee_oui(&mut self, text: &str) -> usize {
        let mut merged = 0;
        for line in text.lines() {
            let Some((prefix, vendor)) = line.split_once("(hex)") else {
                continue;
            };
            let vendor = vendor.trim();
            if vendor.is_empty() {
                continue;
            }
            if let Some(oui) = parse_oui_prefix(prefix.trim()) {
                self.insert(oui, vendor);
                merged += 1;
            }
        }
        merged
    }

    /// Vendor registered for this MAC's OUI.
    pub fn lookup(&self, mac: &[u8; 6]) -> Option<&str> {
        self.map.get(&[mac[0], mac[1], mac[2]]).map(String::as_str)
    }

    /// Vendor name, or a "randomized MAC" label for unknown private addresses.
    pub fn describe(&self, mac: &[u8; 6]) -> Option<String> {
        match self.lookup(mac) {
            Some(v) => Some(v.to_string()),
            None if is_locally_administered(mac) => Some(RANDOMIZED_MAC_VENDOR.to_string()),
            None => None,
        }
    }
}

/// Parse an OUI prefix: `00:1A:11`, `00-1A-11` or `001A11`.
fn parse_oui_prefix(s: &str) -> Option<[u8; 3]> {
    let hex: String = s.chars().filter(|c| !matches!(*c, ':' | '-' | '.')).collect();
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 3];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn builtin_vendors() -> &'static VendorDb {
    static DB: OnceLock<VendorDb> = OnceLock::new();
    DB.get_or_init(VendorDb::builtin)
}

/// Look up the vendor for a MAC string using the embedded table.
pub fn lookup_vendor(mac: &str) -> Option<String> {
    normalize_mac(mac).and_then(|m| builtin_vendors().describe(&m))
}

/// Common vendors seen on home networks.
const BUILTIN_OUIS: &[(&str, &[&str])] = &[
    ("Apple", &[
        "00:03:93", "00:0A:27", "00:0A:95", "00:0D:93", "00:16:CB", "00:17:F2", "00:1B:63",
        "00:1E:C2", "00:1F:F3", "00:23:12", "00:25:00", "00:26:BB", "28:CF:E9", "3C:07:54",
        "40:6C:8F", "68:A8:6D", "70:56:81", "7C:6D:62", "88:66:A5", "98:01:A7", "A4:5E:60",
        "AC:BC:32", "D8:30:62", "F0:18:98",
    ]),
    ("Samsung", &[
        "00:00:F0", "00:12:FB", "00:15:99", "00:16:32", "00:1D:25", "00:21:19", "00:26:37",
        "5C:0A:5B", "8C:77:12",
    ]),
    ("Google", &["00:1A:11", "3C:5A:B4", "54:60:09", "A4:77:33", "F4:F5:D8", "F4:F5:E8"]),
    ("Google Nest", &["18:B4:30", "64:16:66"]),
    ("Amazon", &[
        "0C:47:C9", "40:B4:CD", "44:65:0D", "50:F5:DA", "68:54:FD", "74:C2:46", "84:D6:D0",
        "F0:27:2D", "FC:65:DE",
    ]),
    ("Microsoft", &["00:0D:3A", "00:50:F2", "28:18:78", "7C:1E:52"]),
    ("Microsoft Hyper-V", &["00:15:5D"]),
    ("Intel", &["00:02:B3", "00:13:E8", "00:1B:21", "00:1E:67", "00:21:6A", "3C:A9:F4", "A4:4E:31"]),
    ("Dell", &["00:14:22", "00:1E:4F", "00:21:9B", "00:24:E8", "18:03:73", "B8:AC:6F", "D4:BE:D9", "F8:B1:56"]),
    ("HP", &["00:0B:CD", "00:17:A4", "00:1A:4B", "00:21:5A", "3C:D9:2B"]),
    ("ASUS", &[
        "00:1A:92", "00:1D:60", "00:22:15", "00:24:8C", "08:60:6E", "10:BF:48", "2C:56:DC",
        "50:46:5D", "AC:22:0B", "BC:EE:7B", "F4:6D:04",
    ]),
    ("Realtek", &["00:E0:4C"]),
    ("Raspberry Pi", &["B8:27:EB", "DC:A6:32", "E4:5F:01", "D8:3A:DD", "28:CD:C1"]),
    ("Espressif", &[
        "18:FE:34", "24:0A:C4", "24:6F:28", "30:AE:A4", "3C:71:BF", "5C:CF:7F", "60:01:94",
        "84:F3:EB", "A4:CF:12", "BC:DD:C2", "EC:FA:BC",
    ]),
    ("TP-Link", &[
        "00:1D:0F", "14:CC:20", "30:B5:C2", "50:C7:BF", "60:E3:27", "98:DA:C4", "A0:F3:C1",
        "B0:4E:26", "C0:4A:00", "EC:08:6B", "F4:F2:6D",
    ]),
    ("Netgear", &[
        "00:09:5B", "00:14:6C", "00:1B:2F", "00:1E:2A", "00:22:3F", "00:24:B2", "20:4E:7F",
        "28:C6:8E", "A0:21:B7", "C0:3F:0E", "E0:91:F5",
    ]),
    ("Cisco", &["00:00:0C", "00:01:42", "00:1B:54"]),
    ("Cisco-Linksys", &[
        "00:06:25", "00:0C:41", "00:12:17", "00:14:BF", "00:18:39", "00:1A:70", "00:1C:10",
        "00:1E:E5", "00:21:29", "00:22:6B", "00:23:69", "00:25:9C",
    ]),
    ("Belkin", &["00:11:50", "00:17:3F", "08:86:3B", "94:10:3E", "EC:1A:59"]),
    ("D-Link", &[
        "00:05:5D", "00:0D:88", "00:11:95", "00:13:46", "00:15:E9", "00:17:9A", "00:19:5B",
        "00:1B:11", "00:1C:F0", "00:1E:58", "00:21:91", "00:22:B0", "00:24:01", "1C:7E:E5",
        "28:10:7B", "84:C9:B2", "C8:BE:19",
    ]),
    ("Ubiquiti", &[
        "00:15:6D", "00:27:22", "04:18:D6", "24:A4:3C", "44:D9:E7", "68:72:51", "74:83:C2",
        "78:8A:20", "80:2A:A8", "B4:FB:E4", "DC:9F:DB", "E0:63:DA", "F0:9F:C2", "FC:EC:DA",
    ]),
    ("MikroTik", &[
        "00:0C:42", "2C:C8:1B", "48:8F:5A", "4C:5E:0C", "64:D1:54", "6C:3B:6B", "B8:69:F4",
        "CC:2D:E0", "D4:CA:6D", "E4:8D:8C",
    ]),
    ("AVM (FRITZ!Box)", &["00:04:0E", "24:65:11", "38:10:D5", "3C:A6:2F", "7C:FF:4D", "C8:0E:14"]),
    ("Huawei", &["00:18:82", "00:25:9E", "00:E0:FC", "28:6E:D4", "48:46:FB", "70:72:3C"]),
    ("Xiaomi", &["28:6C:07", "34:CE:00", "64:09:80", "78:11:DC", "F8:A4:5F"]),
    ("Sonos", &["00:0E:58", "48:A6:B8", "5C:AA:FD", "78:28:CA", "94:9F:3E", "B8:E9:37"]),
    ("Roku", &["08:05:81", "AC:3A:7A", "B0:A7:37", "CC:6D:A0", "DC:3A:5E"]),
    ("LG Electronics", &["00:1C:62", "00:1E:75", "A8:23:FE"]),
    ("Sony", &["00:04:1F", "00:13:15", "00:15:C1", "00:19:C5", "00:1D:0D", "28:0D:FC"]),
    ("Nintendo", &["00:09:BF", "00:17:AB", "00:1F:32", "00:22:4C", "98:B6:E9"]),
    ("Philips Hue (Signify)", &["00:17:88", "EC:B5:FA"]),
    ("Synology", &["00:11:32"]),
    ("QNAP", &["00:08:9B", "24:5E:BE"]),
    ("VMware", &["00:05:69", "00:0C:29", "00:1C:14", "00:50:56"]),
    ("VirtualBox", &["08:00:27"]),
    ("QEMU/KVM", &["52:54:00"]),
    ("Parallels", &["00:1C:42"]),
    ("Xen", &["00:16:3E"]),
];

// ──────────────────────────────────────────────
// ARP table parsing
// ──────────────────────────────────────────────

/// One parsed ARP cache line before filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawEntry {
    ip: Ipv4Addr,
    mac: [u8; 6],
    interface: Option<String>,
}

/// Parse Linux `/proc/net/arp`:
/// `IP address  HW type  Flags  HW address  Mask  Device`
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_arp(text: &str) -> Vec<RawEntry> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let Ok(ip) = cols[0].parse::<Ipv4Addr>() else {
            continue;
        };
        // ATF_COM (0x2) marks a completed entry.
        let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).unwrap_or(0);
        if flags & 0x2 == 0 {
            continue;
        }
        let Some(mac) = normalize_mac(cols[3]) else {
            continue;
        };
        out.push(RawEntry {
            ip,
            mac,
            interface: cols.get(5).map(|s| s.to_string()),
        });
    }
    out
}

/// Parse the output of `arp -a` (Windows, macOS/BSD, Linux net-tools) or
/// `ip neigh` (Linux iproute2). Works line by line on tokens, so localized
/// Windows headers do not matter.
fn parse_arp_table(text: &str) -> Vec<RawEntry> {
    let mut out = Vec::new();
    let mut section_iface: Option<String> = None;
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        // Windows section header: "Interface: 192.168.1.10 --- 0xb"
        if tokens.contains(&"---") {
            section_iface = tokens
                .iter()
                .find_map(|t| t.parse::<Ipv4Addr>().ok())
                .map(|ip| ip.to_string());
            continue;
        }
        let ip = tokens
            .iter()
            .find_map(|t| t.trim_matches(|c: char| c == '(' || c == ')').parse::<Ipv4Addr>().ok());
        // Prefer the token after "at" (BSD/net-tools) or "lladdr" (iproute2) so
        // hostnames are never mistaken for MACs; "at (incomplete)" yields None.
        let mac = tokens
            .windows(2)
            .find(|w| w[0] == "at" || w[0] == "lladdr")
            .map(|w| normalize_mac(w[1]))
            .unwrap_or_else(|| tokens.iter().find_map(|t| normalize_mac(t)));
        let (Some(ip), Some(mac)) = (ip, mac) else {
            continue;
        };
        let named_iface = tokens
            .windows(2)
            .find(|w| w[0] == "on" || w[0] == "dev")
            .map(|w| w[1].to_string());
        out.push(RawEntry {
            ip,
            mac,
            interface: named_iface.or_else(|| section_iface.clone()),
        });
    }
    out
}

fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Don't flash a console window from the GUI app.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let output = cmd
        .output()
        .map_err(|e| format!("failed to run `{program}`: {e}"))?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err(format!("`{program}` exited with {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Read the OS ARP cache.
fn read_arp_table() -> Result<Vec<RawEntry>, ArpError> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
            return Ok(parse_proc_net_arp(&text));
        }
        if let Ok(text) = run_command("ip", &["-4", "neigh", "show"]) {
            return Ok(parse_arp_table(&text));
        }
    }
    // `-n` skips reverse DNS on Unix; on Windows `-a` alone is numeric.
    let args: &[&str] = if cfg!(windows) { &["-a"] } else { &["-an"] };
    run_command("arp", args)
        .map(|text| parse_arp_table(&text))
        .map_err(ArpError::TableUnavailable)
}

// ──────────────────────────────────────────────
// Scanning
// ──────────────────────────────────────────────

/// Send one UDP datagram per host so the OS ARP-resolves every address.
fn probe_hosts(hosts: &[Ipv4Addr]) -> Result<(), ArpError> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| ArpError::Probe(e.to_string()))?;
    let _ = socket.set_nonblocking(true);
    for chunk in hosts.chunks(PROBE_BATCH) {
        for ip in chunk {
            // Errors (unreachable host, ICMP resets) are expected and ignored.
            let _ = socket.send_to(&[0u8], SocketAddrV4::new(*ip, PROBE_PORT));
        }
        thread::sleep(Duration::from_millis(PROBE_BATCH_PAUSE_MS));
    }
    Ok(())
}

/// Filter raw entries to valid hosts in `subnet`, dedupe by IP, attach vendors,
/// and sort by address.
fn collect_entries(raw: Vec<RawEntry>, subnet: &Subnet, vendors: &VendorDb) -> Vec<ArpEntry> {
    let mut by_ip: BTreeMap<u32, ArpEntry> = BTreeMap::new();
    for entry in raw {
        if !subnet.contains(entry.ip)
            || subnet.is_reserved(entry.ip)
            || !is_usable_ip(entry.ip)
            || !is_usable_mac(&entry.mac)
        {
            continue;
        }
        by_ip.entry(u32::from(entry.ip)).or_insert_with(|| ArpEntry {
            ip: entry.ip.to_string(),
            mac: format_mac(&entry.mac),
            vendor: vendors.describe(&entry.mac),
            interface: entry.interface,
        });
    }
    by_ip.into_values().collect()
}

/// Discover active hosts on the subnet: probe, wait, then read the ARP cache.
pub fn arp_scan(options: &ArpScanOptions) -> Result<Vec<ArpEntry>, ArpError> {
    let subnet = resolve_subnet(options.cidr.as_deref())?;
    if options.probe {
        probe_hosts(&subnet.hosts())?;
        if !options.settle.is_zero() {
            thread::sleep(options.settle);
        }
    }
    let raw = read_arp_table()?;
    Ok(collect_entries(raw, &subnet, builtin_vendors()))
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> [u8; 6] {
        normalize_mac(s).expect("valid MAC")
    }

    // ── MAC parsing ──

    #[test]
    fn normalize_mac_accepts_common_formats() {
        let expected = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        assert_eq!(normalize_mac("00:1a:2b:3c:4d:5e"), Some(expected));
        assert_eq!(normalize_mac("00-1A-2B-3C-4D-5E"), Some(expected));
        assert_eq!(normalize_mac("0:1a:2b:3c:4d:5e"), Some(expected));
        assert_eq!(normalize_mac("001a.2b3c.4d5e"), Some(expected));
        assert_eq!(normalize_mac("001A2B3C4D5E"), Some(expected));
        assert_eq!(normalize_mac("  00:1a:2b:3c:4d:5e  "), Some(expected));
    }

    #[test]
    fn normalize_mac_rejects_invalid() {
        assert_eq!(normalize_mac(""), None);
        assert_eq!(normalize_mac("00:1a:2b:3c:4d"), None);
        assert_eq!(normalize_mac("00:1a:2b:3c:4d:5e:6f"), None);
        assert_eq!(normalize_mac("gg:hh:ii:jj:kk:ll"), None);
        assert_eq!(normalize_mac("192.168.1.1"), None);
        assert_eq!(normalize_mac("(incomplete)"), None);
        assert_eq!(normalize_mac("dynamic"), None);
        assert_eq!(normalize_mac("001:1a:2b:3c:4d:5e"), None);
    }

    #[test]
    fn format_mac_is_uppercase_colon_separated() {
        assert_eq!(format_mac(&mac("0:a:b:c:d:e")), "00:0A:0B:0C:0D:0E");
    }

    #[test]
    fn usable_mac_filters_special_addresses() {
        assert!(is_usable_mac(&mac("b8:27:eb:12:34:56")));
        assert!(!is_usable_mac(&mac("00:00:00:00:00:00")));
        assert!(!is_usable_mac(&mac("ff:ff:ff:ff:ff:ff")));
        assert!(!is_usable_mac(&mac("01:00:5e:00:00:16")));
        assert!(!is_usable_mac(&mac("33:33:00:00:00:01")));
    }

    #[test]
    fn locally_administered_detection() {
        assert!(is_locally_administered(&mac("da:a1:19:00:00:01")));
        assert!(!is_locally_administered(&mac("b8:27:eb:12:34:56")));
    }

    // ── Subnets ──

    #[test]
    fn subnet_parse_and_hosts() {
        let s = Subnet::parse("192.168.1.77/24").unwrap();
        assert_eq!(s.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(s.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(s.prefix(), 24);
        assert_eq!(s.to_string(), "192.168.1.0/24");
        let hosts = s.hosts();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn subnet_small_prefixes() {
        assert_eq!(Subnet::parse("10.0.0.5/30").unwrap().hosts().len(), 2);
        assert_eq!(Subnet::parse("10.0.0.5/31").unwrap().hosts().len(), 2);
        let single = Subnet::parse("10.0.0.5").unwrap();
        assert_eq!(single.prefix(), 32);
        assert_eq!(single.hosts(), vec![Ipv4Addr::new(10, 0, 0, 5)]);
    }

    #[test]
    fn subnet_contains() {
        let s = Subnet::parse("10.1.0.0/16").unwrap();
        assert!(s.contains(Ipv4Addr::new(10, 1, 200, 3)));
        assert!(!s.contains(Ipv4Addr::new(10, 2, 0, 1)));
    }

    #[test]
    fn subnet_rejects_invalid_and_oversized() {
        assert!(matches!(Subnet::parse("not-an-ip/24"), Err(ArpError::InvalidCidr(_))));
        assert!(matches!(Subnet::parse("192.168.1.0/33"), Err(ArpError::InvalidCidr(_))));
        assert!(matches!(Subnet::parse("192.168.1.0/x"), Err(ArpError::InvalidCidr(_))));
        assert_eq!(Subnet::parse("10.0.0.0/8"), Err(ArpError::SubnetTooLarge(8)));
        assert_eq!(Subnet::parse("10.0.0.0/16").unwrap().hosts().len(), 65534);
    }

    #[test]
    fn resolve_subnet_uses_explicit_cidr() {
        let s = resolve_subnet(Some(" 172.16.5.9/24 ")).unwrap();
        assert_eq!(s.to_string(), "172.16.5.0/24");
    }

    // ── Vendor lookup ──

    #[test]
    fn builtin_vendor_lookup() {
        assert_eq!(lookup_vendor("b8:27:eb:12:34:56").as_deref(), Some("Raspberry Pi"));
        assert_eq!(lookup_vendor("00-50-56-AA-BB-CC").as_deref(), Some("VMware"));
        assert_eq!(lookup_vendor("3c:07:54:00:00:01").as_deref(), Some("Apple"));
        assert_eq!(lookup_vendor("02:00:00:00:00:01").as_deref(), Some(RANDOMIZED_MAC_VENDOR));
        assert_eq!(lookup_vendor("fc:00:00:00:00:01"), None);
        assert_eq!(lookup_vendor("garbage"), None);
    }

    #[test]
    fn builtin_table_entries_all_parse() {
        let expected: usize = BUILTIN_OUIS.iter().map(|(_, p)| p.len()).sum();
        for (_, prefixes) in BUILTIN_OUIS {
            for p in *prefixes {
                assert!(parse_oui_prefix(p).is_some(), "bad builtin OUI {p}");
            }
        }
        assert_eq!(VendorDb::builtin().len(), expected, "duplicate builtin OUI");
    }

    #[test]
    fn merge_ieee_oui_file() {
        let text = "\
OUI/MA-L                                                    Organization
company_id                                                  Organization
                                                            Address

FC-00-00   (hex)\t\tExample Widgets Ltd
FC0000     (base 16)\t\tExample Widgets Ltd
\t\t\t\tSomewhere 1

FC-00-01   (hex)\t\tSecond Corp.
";
        let mut db = VendorDb::empty();
        assert!(db.is_empty());
        assert_eq!(db.merge_ieee_oui(text), 2);
        assert_eq!(db.lookup(&mac("fc:00:00:11:22:33")), Some("Example Widgets Ltd"));
        assert_eq!(db.lookup(&mac("fc:00:01:11:22:33")), Some("Second Corp."));
        assert_eq!(db.lookup(&mac("fc:00:02:11:22:33")), None);
    }

    // ── ARP table parsers ──

    #[test]
    fn parses_linux_proc_net_arp() {
        let text = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         b8:27:eb:12:34:56     *        eth0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.20     0x1         0x6         3c:07:54:aa:bb:cc     *        wlan0
";
        let entries = parse_proc_net_arp(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].mac, mac("b8:27:eb:12:34:56"));
        assert_eq!(entries[0].interface.as_deref(), Some("eth0"));
        assert_eq!(entries[1].interface.as_deref(), Some("wlan0"));
    }

    #[test]
    fn parses_windows_arp_a() {
        let text = "\r
Interface: 192.168.1.10 --- 0xb\r
  Internet Address      Physical Address      Type\r
  192.168.1.1           b8-27-eb-12-34-56     dynamic\r
  192.168.1.20          3c-07-54-aa-bb-cc     dynamic\r
  192.168.1.255         ff-ff-ff-ff-ff-ff     static\r
  224.0.0.22            01-00-5e-00-00-16     static\r
\r
Interface: 10.0.0.5 --- 0x12\r
  Internet Address      Physical Address      Type\r
  10.0.0.1              00-50-56-c0-00-08     dynamic\r
";
        let entries = parse_arp_table(text);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].interface.as_deref(), Some("192.168.1.10"));
        assert_eq!(entries[4].ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(entries[4].interface.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_macos_arp_an() {
        let text = "\
? (192.168.1.1) at b8:27:eb:12:34:56 on en0 ifscope [ethernet]
router.lan (192.168.1.2) at 0:50:56:a:b:c on en0 ifscope [ethernet]
? (192.168.1.3) at (incomplete) on en0 ifscope [ethernet]
";
        let entries = parse_arp_table(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].ip, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(entries[1].mac, mac("00:50:56:0a:0b:0c"));
        assert_eq!(entries[1].interface.as_deref(), Some("en0"));
    }

    #[test]
    fn parses_linux_arp_and_ip_neigh() {
        let net_tools = "? (192.168.1.1) at b8:27:eb:12:34:56 [ether] on eth0\n";
        let e = parse_arp_table(net_tools);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].interface.as_deref(), Some("eth0"));

        let iproute = "\
192.168.1.1 dev eth0 lladdr b8:27:eb:12:34:56 REACHABLE
192.168.1.9 dev eth0 FAILED
192.168.1.20 dev wlan0 lladdr 3c:07:54:aa:bb:cc STALE
";
        let e = parse_arp_table(iproute);
        assert_eq!(e.len(), 2);
        assert_eq!(e[1].ip, Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(e[1].interface.as_deref(), Some("wlan0"));
    }

    // ── Filtering / aggregation ──

    #[test]
    fn collect_entries_filters_dedupes_and_sorts() {
        let raw = vec![
            RawEntry { ip: Ipv4Addr::new(192, 168, 1, 20), mac: mac("3c:07:54:aa:bb:cc"), interface: Some("eth0".into()) },
            RawEntry { ip: Ipv4Addr::new(192, 168, 1, 1), mac: mac("b8:27:eb:12:34:56"), interface: None },
            RawEntry { ip: Ipv4Addr::new(192, 168, 1, 1), mac: mac("00:50:56:00:00:01"), interface: None },
            RawEntry { ip: Ipv4Addr::new(192, 168, 1, 255), mac: mac("ff:ff:ff:ff:ff:ff"), interface: None },
            RawEntry { ip: Ipv4Addr::new(192, 168, 1, 0), mac: mac("b8:27:eb:00:00:00"), interface: None },
            RawEntry { ip: Ipv4Addr::new(224, 0, 0, 22), mac: mac("01:00:5e:00:00:16"), interface: None },
            RawEntry { ip: Ipv4Addr::new(10, 0, 0, 1), mac: mac("00:50:56:c0:00:08"), interface: None },
            RawEntry { ip: Ipv4Addr::new(192, 168, 1, 30), mac: mac("00:00:00:00:00:00"), interface: None },
            RawEntry { ip: Ipv4Addr::new(192, 168, 1, 40), mac: mac("da:a1:19:00:00:01"), interface: None },
        ];
        let subnet = Subnet::parse("192.168.1.0/24").unwrap();
        let entries = collect_entries(raw, &subnet, &VendorDb::builtin());
        let ips: Vec<&str> = entries.iter().map(|e| e.ip.as_str()).collect();
        assert_eq!(ips, vec!["192.168.1.1", "192.168.1.20", "192.168.1.40"]);
        assert_eq!(entries[0].mac, "B8:27:EB:12:34:56");
        assert_eq!(entries[0].vendor.as_deref(), Some("Raspberry Pi"));
        assert_eq!(entries[1].vendor.as_deref(), Some("Apple"));
        assert_eq!(entries[1].interface.as_deref(), Some("eth0"));
        assert_eq!(entries[2].vendor.as_deref(), Some(RANDOMIZED_MAC_VENDOR));
    }

    #[test]
    fn arp_entry_to_device() {
        let now = Utc::now();
        let entry = ArpEntry {
            ip: "192.168.1.1".into(),
            mac: "B8:27:EB:12:34:56".into(),
            vendor: Some("Raspberry Pi".into()),
            interface: Some("eth0".into()),
        };
        let device = entry.to_device(now);
        assert_eq!(device.ip, "192.168.1.1");
        assert_eq!(device.mac, "B8:27:EB:12:34:56");
        assert_eq!(device.vendor.as_deref(), Some("Raspberry Pi"));
        assert_eq!(device.name, None);
        assert_eq!(device.first_seen, now);
        assert_eq!(device.last_seen, now);
    }

    #[test]
    fn arp_entry_serializes_to_json() {
        let entry = ArpEntry {
            ip: "192.168.1.1".into(),
            mac: "B8:27:EB:12:34:56".into(),
            vendor: None,
            interface: None,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["ip"], "192.168.1.1");
        assert_eq!(json["mac"], "B8:27:EB:12:34:56");
        assert!(json["vendor"].is_null());
    }

    #[test]
    fn scan_without_probe_reads_table_for_single_host() {
        // Reads the real ARP cache without sending traffic; result may be empty
        // but must not error on a normal machine.
        let opts = ArpScanOptions {
            cidr: Some("127.0.0.1/32".into()),
            probe: false,
            settle: Duration::ZERO,
        };
        let result = arp_scan(&opts);
        assert!(result.is_ok(), "{result:?}");
        assert!(result.unwrap().is_empty(), "loopback never appears in ARP");
    }

    // ── detect_local_ipv4 ──

    #[test]
    fn detect_local_ipv4_returns_a_valid_address() {
        let result = detect_local_ipv4();
        assert!(result.is_ok(), "detect_local_ipv4 should succeed on a machine with a route");
        let ip = result.unwrap();
        assert!(!ip.is_loopback());
        assert!(!ip.is_unspecified());
    }

    // ── resolve_subnet with None ──

    #[test]
    fn resolve_subnet_with_none_uses_local_address() {
        let result = resolve_subnet(None);
        assert!(result.is_ok(), "resolve_subnet(None) should succeed on a machine with a route");
        let subnet = result.unwrap();
        assert_eq!(subnet.prefix(), DEFAULT_PREFIX);
    }

    // ── ArpEntry serialization ──

    #[test]
    fn arp_entry_serializes_with_interface() {
        let entry = ArpEntry {
            ip: "192.168.1.1".into(),
            mac: "B8:27:EB:12:34:56".into(),
            vendor: Some("Raspberry Pi".into()),
            interface: Some("eth0".into()),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["interface"], "eth0");
    }

    // ── Subnet /30 and /31 edge cases ──

    #[test]
    fn subnet_30_excludes_network_and_broadcast() {
        let s = Subnet::parse("10.0.0.0/30").unwrap();
        assert_eq!(s.hosts().len(), 2); // .1 and .2 (network .0 and broadcast .3 excluded)
        assert_eq!(s.hosts()[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(s.hosts()[1], Ipv4Addr::new(10, 0, 0, 2));
        // hosts() excludes network and broadcast for /30+
        assert!(!s.hosts().contains(&Ipv4Addr::new(10, 0, 0, 0)));
        assert!(!s.hosts().contains(&Ipv4Addr::new(10, 0, 0, 3)));
    }

    // ── VendorDb empty ──

    #[test]
    fn vendor_db_empty_returns_none() {
        let db = VendorDb::empty();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert_eq!(db.lookup(&mac("00:00:00:00:00:01")), None);
        assert_eq!(db.describe(&mac("00:00:00:00:00:01")), None);
    }

    // ── VendorDb insert and lookup ──

    #[test]
    fn vendor_db_insert_and_lookup() {
        let mut db = VendorDb::empty();
        db.insert([0xAA, 0xBB, 0xCC], "TestVendor");
        assert_eq!(db.len(), 1);
        assert!(!db.is_empty());
        assert_eq!(db.lookup(&[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]), Some("TestVendor"));
        assert_eq!(db.lookup(&[0xAA, 0xBB, 0xDD, 0x00, 0x00, 0x01]), None);
    }

    // ── is_locally_administered ──

    #[test]
    fn locally_administered_various_macs() {
        // Locally administered (second bit of first byte set)
        assert!(is_locally_administered(&mac("02:00:00:00:00:01")));
        assert!(is_locally_administered(&mac("da:a1:19:00:00:01")));
        assert!(is_locally_administered(&mac("5a:bb:cc:dd:ee:ff")));
        assert!(is_locally_administered(&mac("02:00:00:00:00:00"))); // 0x02 has bit 1 set
        // Globally administered (second bit of first byte clear)
        assert!(!is_locally_administered(&mac("00:00:00:00:00:01")));
        assert!(!is_locally_administered(&mac("b8:27:eb:12:34:56")));
    }

    // ── is_usable_ip ──

    #[test]
    fn is_usable_ip_filters_special_addresses() {
        assert!(is_usable_ip(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_usable_ip(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_usable_ip(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_usable_ip(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!is_usable_ip(Ipv4Addr::new(255, 255, 255, 255)));
    }

    // ── Subnet Display ──

    #[test]
    fn subnet_display_format() {
        let s = Subnet::parse("192.168.1.0/24").unwrap();
        assert_eq!(s.to_string(), "192.168.1.0/24");
    }

    // ── Subnet mask ──

    #[test]
    fn subnet_mask_for_prefix() {
        let s = Subnet::parse("192.168.1.0/24").unwrap();
        assert_eq!(s.mask(), 0xFFFFFF00);
        let s = Subnet::parse("10.0.0.0/16").unwrap();
        assert_eq!(s.mask(), 0xFFFF0000);
    }
}
