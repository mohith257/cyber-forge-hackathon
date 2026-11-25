// Where the agent may connect. Mirrors internal/egress (Go) for public docs:
// https on 443 only, no credentials in the URL, public unicast IPs only,
// checked on the addresses actually dialled (the resolver filters them, so
// DNS rebinding cannot swap in an internal IP), no proxy, same-host redirects.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::{Host, Url};

const MAX_URL: usize = 2000;
const MAX_REDIRECTS: usize = 3;

#[derive(Clone, Copy)]
pub struct Policy {
    // Tests only: loopback http servers. Never set by main().
    loopback: bool,
}

impl Policy {
    pub fn production() -> Self {
        Policy { loopback: false }
    }
    #[cfg(test)]
    pub fn loopback_for_tests() -> Self {
        Policy { loopback: true }
    }
}

fn v4_in(ip: Ipv4Addr, net: [u8; 4], bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn v6_in(ip: Ipv6Addr, net: &str, bits: u32) -> bool {
    let net: Ipv6Addr = net.parse().expect("static prefix");
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    u128::from(ip) & mask == u128::from(net) & mask
}

// Ranges that look public but must never be reached (same list as Go).
const BLOCKED_V4: &[([u8; 4], u32)] = &[
    ([0, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([240, 0, 0, 0], 4),
];
const BLOCKED_V6: &[(&str, u32)] = &[
    ("64:ff9b::", 96),
    ("64:ff9b:1::", 48),
    ("100::", 64),
    ("2001::", 32),
    ("2001:db8::", 32),
    ("2002::", 16),
];

pub fn check_ip(ip: IpAddr) -> Result<(), String> {
    let ip = match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    let bad = match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || BLOCKED_V4.iter().any(|(n, b)| v4_in(v4, *n, *b))
        }
        // Stricter than Go: only allocated global unicast (2000::/3) is public.
        IpAddr::V6(v6) => {
            !v6_in(v6, "2000::", 3) || BLOCKED_V6.iter().any(|(n, b)| v6_in(v6, n, *b))
        }
    };
    if bad {
        Err(format!("address {ip} is not public"))
    } else {
        Ok(())
    }
}

// Query keys that look like they carry a credential (same as Go safeQuery).
const CREDENTIAL_KEYS: &[&str] = &[
    "key",
    "token",
    "secret",
    "sig",
    "signature",
    "password",
    "passwd",
    "auth",
    "session",
    "credential",
];

/// Shape checks before any request is built (Go: publicDocURL + CheckURL).
pub fn check_url(raw: &str, policy: Policy) -> Result<Url, String> {
    if raw.len() > MAX_URL || !raw.is_ascii() {
        return Err("URL too long or non-ASCII (use the punycode form)".into());
    }
    let u = Url::parse(raw).map_err(|_| "not a valid URL".to_string())?;
    let local = policy.loopback && u.scheme() == "http";
    if u.scheme() != "https" && !local {
        return Err("only https URLs are allowed".into());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("credentials inside the URL are not allowed".into());
    }
    if !local && u.port().is_some_and(|p| p != 443) {
        return Err("nonstandard ports are not allowed".into());
    }
    match u.host() {
        None => return Err("URL has no host".into()),
        // The url crate turns legacy spellings (127.1, 0x7f000001) into IPs.
        Some(Host::Ipv4(ip)) if !(local && ip.is_loopback()) => check_ip(IpAddr::V4(ip))?,
        Some(Host::Ipv6(ip)) => check_ip(IpAddr::V6(ip))?,
        Some(Host::Domain(d)) if d.contains("your-") => return Err("placeholder host".into()),
        _ => {}
    }
    for (k, _) in u.query_pairs() {
        let k = k.to_ascii_lowercase();
        if CREDENTIAL_KEYS.iter().any(|c| k.contains(c)) {
            return Err("query parameters that look like credentials are not allowed".into());
        }
    }
    Ok(u)
}

/// Resolves names and keeps only public addresses; reqwest dials exactly
/// these, so the check covers the real connection.
struct PublicResolver {
    policy: Policy,
}

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy;
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let ok: Vec<SocketAddr> = found
                .filter(|a| check_ip(a.ip()).is_ok() || (policy.loopback && a.ip().is_loopback()))
                .collect();
            if ok.is_empty() {
                return Err("blocked: host has no public address".into());
            }
            Ok(Box::new(ok.into_iter()) as Addrs)
        })
    }
}

fn builder(policy: Policy, timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .dns_resolver(Arc::new(PublicResolver { policy }))
        .https_only(!policy.loopback)
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .user_agent("ConfigBridge-DocsAgent/1")
}

/// The only HTTP client the agent uses for the open web: same-host redirects
/// (docs sites add ?view=...), each hop re-checked.
pub fn client(policy: Policy, timeout: Duration) -> reqwest::Client {
    let redirect = reqwest::redirect::Policy::custom(move |attempt| {
        let first_host = attempt
            .previous()
            .first()
            .and_then(|u| u.host_str().map(str::to_owned));
        if attempt.previous().len() > MAX_REDIRECTS
            || attempt.url().host_str().map(str::to_owned) != first_host
            || check_url(attempt.url().as_str(), policy).is_err()
        {
            return attempt.error("redirect not followed");
        }
        attempt.follow()
    });
    builder(policy, timeout)
        .redirect(redirect)
        .build()
        .expect("http client")
}

/// Never follows a redirect: reads a grounding redirect's Location header
/// without visiting the target.
pub fn client_no_redirects(policy: Policy, timeout: Duration) -> reqwest::Client {
    builder(policy, timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_internal_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.1.1",
            "198.18.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::",
            "2001:db8::1",
            "::",
        ] {
            assert!(
                check_ip(ip.parse().unwrap()).is_err(),
                "{ip} must be blocked"
            );
        }
        for ip in ["8.8.8.8", "140.82.112.3", "2606:4700::1111"] {
            assert!(
                check_ip(ip.parse().unwrap()).is_ok(),
                "{ip} must be allowed"
            );
        }
    }

    #[test]
    fn url_shape() {
        let p = Policy::production();
        for bad in [
            "http://docs.example.com/",
            "https://user:pw@docs.example.com/",
            "https://docs.example.com:8443/",
            "https://127.1/",
            "https://0x7f000001/",
            "https://[::1]/",
            "https://169.254.169.254/latest/meta-data",
            "https://docs.example.com/?api_key=x",
            "https://your-tenant.example.com/",
            "https://dоcs.example.com/", // Cyrillic o
            "file:///etc/passwd",
        ] {
            assert!(check_url(bad, p).is_err(), "{bad} must be refused");
        }
        assert!(
            check_url(
                "https://learn.microsoft.com/graph/api/user-list?view=graph-rest-1.0",
                p
            )
            .is_ok()
        );
    }
}
