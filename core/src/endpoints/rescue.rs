//! Tiers 2 and 3: what to do when every address we know about has stopped answering.
//!
//! Nothing in here runs on a healthy machine. It is reached from the stub only after the upstream
//! has failed repeatedly, and it is rate-limited by a stamp that survives a reboot — because the
//! machine this exists for is one that boots into a configuration pointing at a node that is gone,
//! and a retry loop on that machine is a retry loop at every boot.
//!
//! **The name resolution problem is the whole difficulty.** At the moment this code runs, the
//! machine's own DNS is this program, and this program is what is broken; asking Windows to
//! resolve `raw.githubusercontent.com` would come straight back to us. So nothing here uses the
//! system resolver. The public resolvers are addressed **by IP** — no name to look up — and the
//! one name that does have to be resolved, the manifest's host, is resolved by asking them. This
//! is the client's statement of invariant I7, which the egress node has for the same reason: a
//! component that resolves names through itself is a component that deadlocks the moment it is the
//! thing that is broken.
//!
//! Their certificates are checked normally. `8.8.8.8` and friends carry the address in the
//! certificate's SAN list, which is what makes DoH-by-IP a real transport rather than a trick, and
//! rustls is compiled with its own root bundle — so this path does not depend on the Windows root
//! store being current, which on a Windows 7 that has been offline for years it will not be.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;

use super::{Endpoints, DOH_PORT, FORMAT, MAX_ADDRS};
use crate::config::RESOLVER_HOST;
use crate::dnsmsg::{self, TYPE_A, TYPE_AAAA};

const DNS_MESSAGE: &str = "application/dns-message";

/// Where to ask when our own resolver cannot be reached.
///
/// Ordered for the network this program ships to: Google's is the one that answers most reliably
/// from RU, Quad9 second, Cloudflare last — `1.1.1.1` is the most frequently interfered with of
/// the three, and being last costs nothing when the first two work.
///
/// Three, not one, and none of them ever sees a user's actual queries: the only name asked here is
/// our own, and only on a machine whose DNS is already down.
const PUBLIC_RESOLVERS: [&str; 3] = [
    "https://8.8.8.8/dns-query",
    "https://9.9.9.9/dns-query",
    "https://1.1.1.1/dns-query",
];

/// The published list, and its mirror. GitHub first because it is the copy that survives losing
/// the site; the mirror exists because `raw.githubusercontent.com` is not reliably reachable from
/// every Russian ISP, which is the one network this program is for.
const MANIFESTS: [(&str, &str); 2] = [
    (
        "raw.githubusercontent.com",
        "https://raw.githubusercontent.com/confeden/DNS-AI/main/endpoints.json",
    ),
    ("dns-ai.ru", "https://dns-ai.ru/endpoints.json"),
];

/// A manifest is a few hundred bytes. Anything willing to send more is not one.
const MAX_BODY: usize = 64 * 1024;

/// Short on purpose: this runs while the machine has no DNS, and every second here is a second of
/// a user watching nothing work.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Ask the outside world where the resolver went. Returns true when the answer changed something.
///
/// Never fails loudly: every path here is best-effort, and the caller's fallback — the addresses
/// compiled into this binary — is the same one it had before calling.
pub async fn rescue() -> bool {
    if !super::claim_rescue() {
        log::debug!("rescue skipped: asked too recently");
        return false;
    }
    log::info!("the resolver is unreachable at every known address; asking the outside world");
    search(false).await
}

/// The same search with the cooldown skipped and every channel tried, for `dns-ai test-update`.
///
/// A diagnostic has to answer "would this work?" on demand. A check that silently does nothing
/// because it ran half an hour ago is worse than no check — it looks like a pass — and one that
/// stops at the first tier that answers never exercises the published file at all, which is the
/// tier nobody would otherwise notice was broken.
pub async fn rescue_forced() -> bool {
    search(true).await
}

async fn search(probe_all: bool) -> bool {
    // Whether anything out there answered at all, which is a different question from whether the
    // answer was useful — see `relax_cooldown`.
    let mut reached = false;
    let mut changed = false;

    // Tier 2. One query to a public resolver for our own name — no new trust, no third-party file,
    // and the answer is the record the operator already edits when a node changes.
    let v4 = public_lookup(RESOLVER_HOST, TYPE_A, &mut reached).await;
    let v6 = public_lookup(RESOLVER_HOST, TYPE_AAAA, &mut reached).await;
    if !v4.is_empty() {
        let v4: Vec<_> = v4.into_iter().filter_map(only_v4).collect();
        let v6: Vec<_> = v6.into_iter().filter_map(only_v6).collect();
        if super::adopt_addresses(&v4, &v6, "public-dns") {
            log::info!("a public resolver knows a newer address for {RESOLVER_HOST}");
            if !probe_all {
                return true;
            }
            changed = true;
        } else {
            log::info!("a public resolver returns the addresses we already have");
        }
    }

    // Tier 3. Either the name did not resolve at all, or it resolves to what is already failing —
    // both mean the answer is not in DNS, so go and read the published file.
    for (host, url) in MANIFESTS {
        match fetch_manifest(host, url, &mut reached).await {
            Ok(manifest) => {
                if super::adopt_manifest(manifest) {
                    log::info!("{url} carried a newer endpoint list");
                    changed = true;
                } else {
                    log::info!("{url} carries nothing newer than what is cached");
                }
                return changed;
            }
            Err(e) => log::warn!("{url}: {e:#}"),
        }
    }

    if !reached {
        log::info!("nothing on the network answered; this machine is offline rather than lost");
        super::relax_cooldown();
    }
    changed
}

fn only_v4(ip: IpAddr) -> Option<std::net::Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

fn only_v6(ip: IpAddr) -> Option<std::net::Ipv6Addr> {
    match ip {
        IpAddr::V6(v6) => Some(v6),
        IpAddr::V4(_) => None,
    }
}

/// A client for hosts that need no name resolution, because their host *is* an address.
fn client_for_literals() -> Result<Client> {
    Client::builder()
        .use_rustls_tls()
        .https_only(true)
        // The same reasoning as the stub's own client: a proxy variable in the environment turns
        // every request here into a CONNECT that the proxy refuses, on exactly the machine that
        // has no other way to recover.
        .no_proxy()
        .timeout(TIMEOUT)
        .user_agent(concat!("dns-ai-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("could not build the HTTPS client")
}

/// One DoH query to each public resolver in turn, first usable answer wins.
async fn public_lookup(host: &str, qtype: u16, reached: &mut bool) -> Vec<IpAddr> {
    let Ok(query) = dnsmsg::build_query(host, qtype, 0) else {
        return Vec::new();
    };
    let Ok(client) = client_for_literals() else {
        return Vec::new();
    };

    for url in PUBLIC_RESOLVERS {
        match post_dns(&client, url, &query).await {
            Ok(answer) => {
                *reached = true;
                let addrs = dnsmsg::addresses(&answer);
                if !addrs.is_empty() {
                    log::info!("{url} answered for {host}: {addrs:?}");
                    return addrs;
                }
                log::debug!("{url} answered for {host} with no usable records");
            }
            Err(e) => log::debug!("{url} did not answer: {e:#}"),
        }
    }
    Vec::new()
}

async fn post_dns(client: &Client, url: &str, query: &[u8]) -> Result<Vec<u8>> {
    let resp = client
        .post(url)
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .header(ACCEPT, DNS_MESSAGE)
        .body(query.to_vec())
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    let body = resp.bytes().await?;
    if body.len() < 12 {
        bail!("{} bytes, too short for DNS", body.len());
    }
    Ok(body.to_vec())
}

/// Fetch and parse one published list. The host is resolved through [`public_lookup`], never
/// through the machine.
async fn fetch_manifest(host: &str, url: &str, reached: &mut bool) -> Result<Endpoints> {
    let addrs = public_lookup(host, TYPE_A, reached).await;
    if addrs.is_empty() {
        bail!("{host} did not resolve through any public resolver");
    }
    let addrs: Vec<SocketAddr> = addrs
        .into_iter()
        .take(MAX_ADDRS)
        .map(|ip| SocketAddr::new(ip, DOH_PORT))
        .collect();

    let client = Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .timeout(TIMEOUT)
        .user_agent(concat!("dns-ai-client/", env!("CARGO_PKG_VERSION")))
        .resolve_to_addrs(host, &addrs)
        .build()
        .context("could not build the HTTPS client")?;

    let mut resp = client.get(url).send().await?;
    *reached = true;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }

    // Read in chunks against a cap rather than calling `bytes()`: a hostile or merely broken
    // server on the other end should not be able to spend this machine's memory, and there is no
    // legitimate manifest anywhere near this size.
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_BODY {
            bail!("the file is larger than {MAX_BODY} bytes");
        }
        body.extend_from_slice(&chunk);
    }

    let text = std::str::from_utf8(&body).context("the file is not UTF-8")?;
    let manifest: Endpoints = serde_json::from_str(super::strip_bom(text))
        .context("the file is not a readable endpoint list")?;
    if manifest.v > FORMAT {
        bail!(
            "the file is format v{}, which this build does not read",
            manifest.v
        );
    }
    Ok(manifest)
}
