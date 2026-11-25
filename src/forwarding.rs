//! TCP forwarding grammar, negotiation and operator policy (protocol §18).
use crate::{
    cbor::Value,
    hello::Capabilities,
    wire::{self, Failure, Message},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

pub mod native;
pub mod runtime;
#[cfg(test)]
mod tests;
pub const CAP: u64 = 4;
pub const RULE: u64 = 4;
pub const FLOW: u64 = 5;
pub const READY: u64 = 0x4020;
pub const CONNECTED: u64 = 0x4021;
pub const DATA: u64 = 0x4022;
pub const OPEN: std::time::Duration = std::time::Duration::from_secs(10);
pub const PROGRESS: std::time::Duration = std::time::Duration::from_secs(60);
pub const CHUNK: usize = 16384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub rules: usize,
    pub flows: usize,
    pub modes: Vec<u64>,
}
impl Selection {
    pub fn offer() -> Self {
        Self {
            rules: 8,
            flows: 64,
            modes: vec![1, 2, 3],
        }
    }
    pub fn value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(0), Value::Uint(1)),
            (Value::Uint(1), Value::Uint(self.rules as u64)),
            (Value::Uint(2), Value::Uint(self.flows as u64)),
            (
                Value::Uint(3),
                Value::Array(self.modes.iter().copied().map(Value::Uint).collect()),
            ),
        ])
    }
    pub fn parse(v: &Value) -> Option<Self> {
        let m = v.as_map()?;
        if !m.iter().all(|(k, _)| k.is_int()) {
            return None;
        }
        let f = |n| m.iter().find(|(k, _)| *k == Value::Uint(n)).map(|(_, v)| v);
        if f(0)?.as_uint()? != 1 {
            return None;
        }
        let rules = usize::try_from(f(1)?.as_uint()?).ok()?;
        let flows = usize::try_from(f(2)?.as_uint()?).ok()?;
        if !(1..=64).contains(&rules) || !(1..=1024).contains(&flows) {
            return None;
        }
        let modes: Vec<_> = f(3)?
            .as_array()?
            .iter()
            .map(Value::as_uint)
            .collect::<Option<_>>()?;
        if modes.is_empty()
            || modes.iter().any(|n| !(1..=3).contains(n))
            || (1..=3).any(|n| modes.iter().filter(|x| **x == n).count() > 1)
        {
            return None;
        }
        Some(Self {
            rules,
            flows,
            modes,
        })
    }
}
pub fn selected(c: &Capabilities) -> Option<Selection> {
    c.iter()
        .find(|(n, _)| *n == CAP)
        .and_then(|(_, v)| Selection::parse(v))
}
pub fn check(c: &Capabilities, o: &Capabilities) -> Result<(), Failure> {
    if c.iter().any(|(n, _)| *n == CAP) {
        let (Some(c), Some(o)) = (selected(c), selected(o)) else {
            return Err(bad("invalid forwarding selection"));
        };
        if c.rules > o.rules || c.flows > o.flows || c.modes.iter().any(|m| !o.modes.contains(m)) {
            return Err(bad("enlarged forwarding selection"));
        }
    }
    Ok(())
}
pub fn bad(s: &str) -> Failure {
    Failure::violation(s)
}
pub fn uint(m: &Message, n: u64) -> Result<u64, Failure> {
    m.field(n)
        .and_then(Value::as_uint)
        .ok_or_else(|| bad("missing forwarding integer"))
}
pub fn normal(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
pub fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip,IpAddr::V6(v) if v.is_unicast_link_local())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}
pub fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.parse::<IpAddr>().is_err()
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && l.as_bytes()[0] != b'-'
                && l.as_bytes()[l.len() - 1] != b'-'
        })
}
impl FromStr for Target {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if let Ok(a) = s.parse::<SocketAddr>() {
            if a.port() == 0 || a.scope_id() != 0 {
                return Err("invalid target".into());
            }
            return Ok(Self {
                host: Host::Ip(normal(a.ip())),
                port: a.port(),
            });
        }
        let (h, p) = s
            .rsplit_once(':')
            .ok_or("expected HOST:PORT (bracket IPv6)")?;
        let port = p.parse::<u16>().map_err(|_| "invalid port")?;
        let h = h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase();
        if port == 0 || !name(&h) {
            return Err("invalid ASCII DNS target".into());
        }
        Ok(Self {
            host: Host::Name(h),
            port,
        })
    }
}
trait Scope {
    fn scope_id(&self) -> u32;
}
impl Scope for SocketAddr {
    fn scope_id(&self) -> u32 {
        match self {
            Self::V4(_) => 0,
            Self::V6(a) => a.scope_id(),
        }
    }
}
impl Target {
    pub fn value(&self) -> Value {
        let (k, v) = match &self.host {
            Host::Ip(IpAddr::V4(a)) => (1, Value::Bytes(a.octets().to_vec())),
            Host::Ip(IpAddr::V6(a)) => (2, Value::Bytes(a.octets().to_vec())),
            Host::Name(n) => (3, Value::Text(n.clone())),
        };
        Value::Array(vec![Value::Uint(k), v, Value::Uint(self.port as u64)])
    }
    pub fn parse(v: &Value, bind: bool) -> Result<Self, Failure> {
        let a = v
            .as_array()
            .filter(|a| a.len() == 3)
            .ok_or_else(|| bad("invalid forwarding address"))?;
        let host = match (&a[0], &a[1]) {
            (Value::Uint(1), Value::Bytes(b)) if b.len() == 4 => {
                Host::Ip(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            }
            (Value::Uint(2), Value::Bytes(b)) if b.len() == 16 => Host::Ip(IpAddr::V6(
                Ipv6Addr::from(<[u8; 16]>::try_from(b.as_slice()).unwrap()),
            )),
            (Value::Uint(3), Value::Text(n)) if !bind && name(n) => Host::Name(n.clone()),
            _ => return Err(bad("invalid forwarding host")),
        };
        let port = a[2]
            .as_uint()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| bind || *p != 0)
            .ok_or_else(|| bad("invalid forwarding port"))?;
        Ok(Self { host, port })
    }
    pub fn socket(&self) -> Option<SocketAddr> {
        match self.host {
            Host::Ip(ip) => Some(SocketAddr::new(ip, self.port)),
            _ => None,
        }
    }
    pub fn supported(&self) -> bool {
        match self.host {
            Host::Ip(ip) => normal(ip) == ip && usable(ip),
            Host::Name(_) => true,
        }
    }
}
pub fn socket_value(a: SocketAddr) -> Value {
    Target {
        host: Host::Ip(normal(a.ip())),
        port: a.port(),
    }
    .value()
}
pub fn socket_of(v: &Value) -> Result<SocketAddr, Failure> {
    Target::parse(v, true)?
        .socket()
        .ok_or_else(|| bad("non-numeric socket"))
}
#[derive(Clone, Debug)]
pub struct Rule {
    pub mode: u64,
    pub target: Option<Target>,
    pub bind: Option<SocketAddr>,
}
impl Rule {
    pub fn parse(m: &Message) -> Result<Self, Failure> {
        let mode = uint(m, 1)?;
        if !(1..=3).contains(&mode)
            || (mode != 1 && m.field(2).is_some())
            || (mode != 2 && m.field(3).is_some())
        {
            return Err(bad("invalid rule fields"));
        }
        let target = if mode == 1 {
            Some(Target::parse(
                m.field(2).ok_or_else(|| bad("missing target"))?,
                false,
            )?)
        } else {
            None
        };
        let bind = if mode == 2 {
            Some(socket_of(m.field(3).ok_or_else(|| bad("missing bind"))?)?)
        } else {
            None
        };
        Ok(Self { mode, target, bind })
    }
    pub fn message(&self) -> Message {
        let mut f = vec![(0, Value::Uint(RULE)), (1, Value::Uint(self.mode))];
        if let Some(t) = &self.target {
            f.push((2, t.value()))
        }
        if let Some(a) = self.bind {
            f.push((3, socket_value(a)))
        }
        Message::new(wire::CHANNEL_OPEN, f)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    Denied = 1,
    Unsupported = 2,
    InUse = 3,
    Name = 4,
    Network = 5,
    Host = 6,
    Refused = 7,
    Limit = 8,
    Failed = 9,
}
impl Status {
    pub fn io(e: &std::io::Error) -> Self {
        use std::io::ErrorKind::*;
        match e.kind() {
            PermissionDenied => Self::Denied,
            AddrInUse => Self::InUse,
            NetworkUnreachable => Self::Network,
            HostUnreachable => Self::Host,
            ConnectionRefused => Self::Refused,
            _ => Self::Failed,
        }
    }
    pub fn value(n: u64) -> Self {
        match n {
            0 => Self::Ok,
            1 => Self::Denied,
            2 => Self::Unsupported,
            3 => Self::InUse,
            4 => Self::Name,
            5 => Self::Network,
            6 => Self::Host,
            7 => Self::Refused,
            8 => Self::Limit,
            _ => Self::Failed,
        }
    }
    pub fn reply(self, kind: u64, a: Option<SocketAddr>) -> Message {
        let mut f = vec![(0, Value::Uint(self as u64))];
        if let Some(a) = a {
            f.push((1, socket_value(a)))
        }
        Message::new(kind, f)
    }
}
pub fn outcome(
    m: &Message,
    kind: u64,
    socket: bool,
) -> Result<(Status, Option<SocketAddr>), Failure> {
    if m.kind != kind {
        return Err(bad("unexpected forwarding reply"));
    }
    let status = Status::value(uint(m, 0)?);
    let a = m.field(1).map(socket_of).transpose()?;
    if a.is_some_and(|a| {
        a.port() == 0 || normal(a.ip()) != a.ip() || (kind == CONNECTED && !usable(a.ip()))
    }) {
        return Err(bad("invalid connected/bound socket"));
    }
    if (status == Status::Ok && socket) != a.is_some() {
        return Err(bad("invalid forwarding reply fields"));
    }
    Ok((status, a))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Net {
    ip: IpAddr,
    bits: u8,
}
impl FromStr for Net {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (ip, n) = s.split_once('/').ok_or("expected IP/prefix")?;
        let ip = ip.parse::<IpAddr>().map_err(|_| "invalid network")?;
        let bits = n.parse::<u8>().map_err(|_| "invalid prefix")?;
        if bits > if ip.is_ipv4() { 32 } else { 128 } || normal(ip) != ip {
            return Err("invalid network prefix or mapped IP".into());
        }
        Ok(Self { ip, bits })
    }
}
impl<'de> Deserialize<'de> for Net {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
impl Net {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, normal(ip)) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                self.bits == 0
                    || (u32::from(a) >> (32 - self.bits)) == (u32::from(b) >> (32 - self.bits))
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                self.bits == 0
                    || (u128::from(a) >> (128 - self.bits)) == (u128::from(b) >> (128 - self.bits))
            }
            _ => false,
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    pub network: Net,
    pub ports: Option<Vec<u16>>,
}
impl Permit {
    pub fn allows(&self, a: SocketAddr) -> bool {
        self.network.contains(a.ip()) && self.ports.as_ref().is_none_or(|p| p.contains(&a.port()))
    }
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub local: bool,
    pub remote: bool,
    pub dynamic: bool,
    pub targets: Vec<Permit>,
    pub binds: Vec<Permit>,
    pub names: Option<Vec<String>>,
    pub ingress: Vec<Net>,
}
impl Policy {
    pub fn modes(&self) -> Vec<u64> {
        [(1, self.local), (2, self.remote), (3, self.dynamic)]
            .into_iter()
            .filter_map(|(n, yes)| yes.then_some(n))
            .collect()
    }
    pub fn target(&self, t: &Target) -> bool {
        match &t.host {
            Host::Name(n) => {
                self.names.as_ref().is_none_or(|v| v.contains(n))
                    && self
                        .targets
                        .iter()
                        .any(|p| p.ports.as_ref().is_none_or(|v| v.contains(&t.port)))
            }
            Host::Ip(ip) => self
                .targets
                .iter()
                .any(|p| p.allows(SocketAddr::new(*ip, t.port))),
        }
    }
    pub fn ingress(&self, ip: IpAddr) -> bool {
        self.ingress.is_empty() || self.ingress.iter().any(|n| n.contains(ip))
    }
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub accounts: BTreeMap<String, Policy>,
}
