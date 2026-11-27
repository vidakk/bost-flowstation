//! WAP web proxy: fetches http(s) pages for WAP browsers and serves them as small WML pages.
//!
//! A WSP GET for a host other than the gateway is checked against `[cell_info.wap_proxy]` and
//! queued on a fetch thread; the radio gets a WTP hold-on Ack at once and the WTP Result once the
//! page is fetched and converted. A page that needs several WML decks is kept for paging under
//! `http://<gateway>/p/<doc>/<n>`, which is served from memory without a new fetch.
//!
//! The proxy runs inside the home network, so it never connects to private, loopback or
//! link-local addresses unless the host is allowlisted. The check happens in the DNS resolver,
//! so it covers every redirect and the address actually connected to.

use super::{wap_html, wap_ip};
use crossbeam_channel::{Receiver, Sender};
use reqwest::Url;
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tetra_config::bluestation::{CfgWapProxy, WapProxyMode};

const MAX_REDIRECTS: usize = 3;
const USER_AGENT: &str = "Mozilla/5.0 (Linux; FlowStation WAP proxy)";
/// Fetched documents kept for paging, across all radios.
const MAX_DOCS: usize = 64;
/// How long a sent Result is kept to answer a retransmitted Invoke.
const ANSWERED_KEEP: Duration = Duration::from_secs(120);
/// Extra time past the fetch timeout before a pending request is answered with a timeout page.
const PENDING_GRACE: Duration = Duration::from_secs(10);
pub const WEB_PAGE_PATH: &str = "/web";
const SEARCH_URL: &str = "https://lite.duckduckgo.com/lite/";

/// Why a URL is not fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Scheme(String),
    NoHost,
    Port(u16),
    NotAllowlisted(String),
    PrivateAddress(String),
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::Scheme(s) => format!("{s}: links are not supported, only http and https."),
            Refusal::NoHost => "The address has no host name.".into(),
            Refusal::Port(p) => format!("Port {p} is not allowed."),
            Refusal::NotAllowlisted(h) => format!("{h} is not on the allowlist."),
            Refusal::PrivateAddress(h) => format!("{h} is a local network address."),
        }
    }
}

/// True for addresses on the public internet; false for private, loopback, link-local,
/// carrier-grade NAT, documentation, multicast and reserved ranges.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
                let [a, b] = s[6].to_be_bytes();
                let [c, d] = s[7].to_be_bytes();
                return is_public_ip(IpAddr::from([a, b, c, d]));
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || s[..6] == [0; 6])
        }
    }
}

fn host_of(url: &Url) -> Option<String> {
    url.host_str().map(|h| h.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase())
}

/// Check a URL against the proxy policy before it is fetched or a redirect to it is followed.
/// Host names are checked again at resolve time by [`GuardedResolver`].
pub fn check_url(url: &Url, cfg: &CfgWapProxy) -> Result<(), Refusal> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Refusal::Scheme(url.scheme().to_string()));
    }
    let host = host_of(url).filter(|h| !h.is_empty()).ok_or(Refusal::NoHost)?;
    let allowlisted = cfg.host_allowlisted(&host);
    if cfg.mode == WapProxyMode::Allowlist && !allowlisted {
        return Err(Refusal::NotAllowlisted(host));
    }
    if let Some(port) = url.port()
        && !allowlisted
    {
        return Err(Refusal::Port(port));
    }
    if let Ok(ip) = host.parse::<IpAddr>()
        && !allowlisted
        && !is_public_ip(ip)
    {
        return Err(Refusal::PrivateAddress(host));
    }
    Ok(())
}

/// A fetched upstream response.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// Final URL after redirects; links on the page are resolved against it.
    pub url: Url,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    /// The body was longer than `max_fetch_bytes` and was cut.
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub enum FetchError {
    Timeout,
    Failed(String),
}

/// Fetches one URL. Runs on the proxy's own thread, so it may block.
pub trait Fetcher: Send {
    fn fetch(&self, url: &Url) -> Result<Fetched, FetchError>;
}

/// Resolves host names with the system resolver and drops non-public addresses unless the host
/// is allowlisted.
struct GuardedResolver {
    cfg: CfgWapProxy,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let allow_private = self.cfg.host_allowlisted(&host);
        Box::pin(async move {
            let addrs: Vec<SocketAddr> =
                (host.as_str(), 0).to_socket_addrs()?.filter(|a| allow_private || is_public_ip(a.ip())).collect();
            if addrs.is_empty() {
                return Err(format!("{host} resolves only to local network addresses").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The production fetcher: blocking reqwest with the guarded resolver and a redirect policy that
/// re-checks every hop.
pub struct HttpFetcher {
    client: reqwest::blocking::Client,
    max_bytes: usize,
}

impl HttpFetcher {
    pub fn new(cfg: &CfgWapProxy) -> Result<Self, String> {
        let redirect_cfg = cfg.clone();
        let policy = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error("too many redirects");
            }
            match check_url(attempt.url(), &redirect_cfg) {
                Ok(()) => attempt.follow(),
                Err(r) => {
                    let msg = format!("redirect refused: {}", r.message());
                    attempt.error(msg)
                }
            }
        });
        let client = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .connect_timeout(Duration::from_secs(cfg.timeout_secs.min(5)))
            .redirect(policy)
            .dns_resolver(Arc::new(GuardedResolver { cfg: cfg.clone() }))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client, max_bytes: cfg.max_fetch_bytes })
    }
}

/// The innermost message of an error chain, which names the actual cause.
fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur = e;
    while let Some(next) = cur.source() {
        cur = next;
    }
    cur.to_string()
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, url: &Url) -> Result<Fetched, FetchError> {
        let map_err = |e: reqwest::Error| if e.is_timeout() { FetchError::Timeout } else { FetchError::Failed(root_cause(&e)) };
        let resp = self
            .client
            .get(url.clone())
            .header("Accept", "text/html,application/xhtml+xml,text/vnd.wap.wml;q=0.9,text/plain;q=0.8")
            .send()
            .map_err(map_err)?;
        let final_url = resp.url().clone();
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let mut body = Vec::new();
        resp.take(self.max_bytes as u64 + 1).read_to_end(&mut body).map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut { FetchError::Timeout } else { FetchError::Failed(e.to_string()) }
        })?;
        let truncated = body.len() > self.max_bytes;
        body.truncate(self.max_bytes);
        Ok(Fetched { url: final_url, status, content_type, body, truncated })
    }
}

type Key = (u32, u16);

struct Job {
    key: Key,
    url: Url,
}

struct Done {
    key: Key,
    url: Url,
    result: Result<Fetched, FetchError>,
}

struct Worker {
    jobs: Sender<Job>,
    done: Receiver<Done>,
}

fn spawn_worker(fetcher: Box<dyn Fetcher>) -> std::io::Result<Worker> {
    let (jobs, jobs_rx) = crossbeam_channel::unbounded::<Job>();
    let (done_tx, done) = crossbeam_channel::unbounded::<Done>();
    std::thread::Builder::new().name("wap-proxy".into()).spawn(move || {
        for job in jobs_rx {
            tracing::info!("WAP proxy: fetching {}", job.url);
            let result = fetcher.fetch(&job.url);
            if done_tx.send(Done { key: job.key, url: job.url, result }).is_err() {
                break;
            }
        }
    })?;
    Ok(Worker { jobs, done })
}

struct Pending<C> {
    ctx: C,
    since: Instant,
}

struct Doc {
    issi: u32,
    pages: Vec<String>,
    at: Instant,
}

/// What to do with a WSP GET.
#[derive(Debug, PartialEq, Eq)]
pub enum GetAction {
    /// Not for the proxy: serve the station's own pages.
    Local,
    /// Send this WTP PDU now (a Result, or a hold-on Ack while the fetch runs).
    Reply(Vec<u8>),
}

/// Proxy state for one SNDCP entity. `C` is the context needed to address a deferred reply.
pub struct WapProxy<C> {
    fetcher: Option<Box<dyn Fetcher>>,
    worker: Option<Worker>,
    pending: HashMap<Key, Pending<C>>,
    answered: HashMap<Key, (Instant, Vec<u8>)>,
    docs: HashMap<u32, Doc>,
    next_doc: u32,
    fetches: HashMap<u32, VecDeque<Instant>>,
}

impl<C> Default for WapProxy<C> {
    fn default() -> Self {
        Self {
            fetcher: None,
            worker: None,
            pending: HashMap::new(),
            answered: HashMap::new(),
            docs: HashMap::new(),
            next_doc: 1,
            fetches: HashMap::new(),
        }
    }
}

fn dotted(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn page_url(gateway: [u8; 4], doc: u32, n: usize) -> String {
    format!("http://{}/p/{doc}/{n}", dotted(gateway))
}

/// `/p/<doc>/<n>` -> (doc, n).
fn parse_page_path(path: &str) -> Option<(u32, usize)> {
    let mut parts = path.strip_prefix("/p/")?.split('/');
    let doc = parts.next()?.parse().ok()?;
    let n = parts.next()?.split(['?', '#']).next()?.parse().ok()?;
    Some((doc, n))
}

fn is_text_content(ct: &str) -> bool {
    ct.is_empty() || ct.starts_with("text/") || ct.contains("xhtml") || ct.contains("xml") || ct.contains("vnd.wap.wml")
}

fn wml_result(tid: u16, page: &str) -> Vec<u8> {
    wap_ip::wtp_result(tid, &wap_ip::wsp_reply(wap_ip::WSP_CT_WML, page.as_bytes()))
}

/// The local start page: a search box and a field to open any address.
fn web_page() -> String {
    format!(
        "<wml><card title=\"Web\"><p>Search:<input name=\"q\"/><anchor>Search<go href=\"{SEARCH_URL}\" method=\"get\">\
         <postfield name=\"q\" value=\"$(q)\"/></go></anchor><br/>Address:<input name=\"u\" value=\"http://\"/>\
         <anchor>Open<go href=\"$(u)\"/></anchor></p></card></wml>"
    )
}

impl<C> WapProxy<C> {
    /// A proxy that fetches with `fetcher` instead of building an [`HttpFetcher`].
    pub fn with_fetcher(fetcher: Box<dyn Fetcher>) -> Self {
        Self { fetcher: Some(fetcher), ..Self::default() }
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    fn ensure_worker(&mut self, cfg: &CfgWapProxy) -> Result<&Worker, String> {
        if self.worker.is_none() {
            let fetcher = match self.fetcher.take() {
                Some(f) => f,
                None => Box::new(HttpFetcher::new(cfg)?),
            };
            self.worker = Some(spawn_worker(fetcher).map_err(|e| e.to_string())?);
        }
        Ok(self.worker.as_ref().expect("worker just started"))
    }

    fn message(cfg: &CfgWapProxy, tid: u16, title: &str, lines: &[&str]) -> GetAction {
        GetAction::Reply(wml_result(tid, &wap_html::message_page(title, lines, cfg.page_bytes)))
    }

    /// Handle a WSP GET of `uri` from radio `issi`. `cfg` is `[cell_info.wap_proxy]`; without it
    /// every request stays local, as before the proxy existed.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_get(
        &mut self,
        cfg: Option<&CfgWapProxy>,
        gateway: [u8; 4],
        issi: u32,
        tid: u16,
        retransmission: bool,
        uri: &str,
        ctx: C,
        now: Instant,
    ) -> GetAction {
        let Some(cfg) = cfg else { return GetAction::Local };
        let key = (issi, tid);

        let url = match Url::parse(uri) {
            Ok(u) if host_of(&u).as_deref() != Some(dotted(gateway).as_str()) => u,
            parsed => {
                let path = match &parsed {
                    Ok(u) => u.path().to_string(),
                    Err(_) => uri.split(['?', '#']).next().unwrap_or("").to_string(),
                };
                if let Some((doc, n)) = parse_page_path(&path) {
                    let page = self.docs.get(&doc).filter(|d| d.issi == issi).and_then(|d| d.pages.get(n)).cloned();
                    return match page {
                        Some(p) => GetAction::Reply(wml_result(tid, &p)),
                        None => Self::message(cfg, tid, "Expired", &["This page has expired.", "Go back and open it again."]),
                    };
                }
                if path == WEB_PAGE_PATH && cfg.enabled {
                    return GetAction::Reply(wml_result(tid, &web_page()));
                }
                return GetAction::Local;
            }
        };

        if !cfg.enabled {
            return Self::message(cfg, tid, "Web off", &["Web access is turned off on this station."]);
        }
        if self.pending.contains_key(&key) {
            return GetAction::Reply(wap_ip::wtp_ack(tid));
        }
        if retransmission && let Some((_, payload)) = self.answered.get(&key) {
            return GetAction::Reply(payload.clone());
        }
        if !cfg.radio_allowed(issi) {
            let line = format!("Web access is not enabled for radio {issi}.");
            return Self::message(cfg, tid, "Not available", &[&line]);
        }
        if let Err(r) = check_url(&url, cfg) {
            tracing::info!("WAP proxy: refused {url} for {issi}: {}", r.message());
            return Self::message(cfg, tid, "Not allowed", &[&r.message()]);
        }
        let log = self.fetches.entry(issi).or_default();
        while log.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
            log.pop_front();
        }
        if log.len() >= cfg.fetches_per_minute as usize {
            return Self::message(cfg, tid, "Slow down", &["Too many pages this minute.", "Try again shortly."]);
        }
        log.push_back(now);

        let sent = match self.ensure_worker(cfg) {
            Ok(w) => w.jobs.send(Job { key, url: url.clone() }).map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        if let Err(e) = sent {
            tracing::warn!("WAP proxy: cannot start a fetch: {e}");
            self.worker = None;
            return Self::message(cfg, tid, "Proxy error", &["The proxy could not start the fetch."]);
        }
        tracing::info!("WAP proxy: {issi} tid {tid} -> {url} (hold-on sent)");
        self.pending.insert(key, Pending { ctx, since: now });
        GetAction::Reply(wap_ip::wtp_ack(tid))
    }

    /// Collect finished fetches and stale requests. Returns the WTP Result to send for each, with
    /// the context its GET came with.
    pub fn poll(&mut self, cfg: Option<&CfgWapProxy>, gateway: [u8; 4], now: Instant) -> Vec<(C, Vec<u8>)> {
        let Some(cfg) = cfg else {
            self.pending.clear();
            return Vec::new();
        };
        let done: Vec<Done> = self.worker.as_ref().map(|w| w.done.try_iter().collect()).unwrap_or_default();
        let mut out = Vec::new();
        for d in done {
            let Some(p) = self.pending.remove(&d.key) else { continue };
            let page = self.render(cfg, gateway, d.key.0, &d.url, d.result, now);
            let payload = wml_result(d.key.1, &page);
            self.answered.insert(d.key, (now, payload.clone()));
            out.push((p.ctx, payload));
        }

        let limit = Duration::from_secs(cfg.timeout_secs) + PENDING_GRACE;
        let stale: Vec<Key> = self.pending.iter().filter(|(_, p)| now.duration_since(p.since) > limit).map(|(k, _)| *k).collect();
        for key in stale {
            if let Some(p) = self.pending.remove(&key) {
                let page = wap_html::message_page("Timed out", &["The site did not answer in time."], cfg.page_bytes);
                out.push((p.ctx, wml_result(key.1, &page)));
            }
        }

        self.answered.retain(|_, (t, _)| now.duration_since(*t) < ANSWERED_KEEP);
        let keep = Duration::from_secs(cfg.cache_secs);
        self.docs.retain(|_, d| now.duration_since(d.at) < keep);
        self.fetches.retain(|_, log| log.back().is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60)));
        out
    }

    fn render(&mut self, cfg: &CfgWapProxy, gateway: [u8; 4], issi: u32, url: &Url, result: Result<Fetched, FetchError>, now: Instant) -> String {
        let host = host_of(url).unwrap_or_default();
        let budget = cfg.page_bytes;
        let f = match result {
            Ok(f) => f,
            Err(FetchError::Timeout) => {
                tracing::info!("WAP proxy: {url} timed out");
                return wap_html::message_page("Timed out", &[&host, "The site did not answer in time."], budget);
            }
            Err(FetchError::Failed(e)) => {
                tracing::info!("WAP proxy: {url} failed: {e}");
                return wap_html::message_page("Fetch failed", &[&host, &e], budget);
            }
        };
        tracing::info!("WAP proxy: {} -> HTTP {} {} ({} bytes{})", f.url, f.status, f.content_type, f.body.len(), if f.truncated { ", cut" } else { "" });
        if !is_text_content(&f.content_type) {
            let line = format!("This is {}, which a radio cannot show.", f.content_type);
            return wap_html::message_page("Can't show", &[&line], budget);
        }
        let html = String::from_utf8_lossy(&f.body);
        let mut doc = wap_html::parse_html(&html, &f.url);
        if !(200..300).contains(&f.status) {
            doc.items.insert(0, wap_html::Item::Break);
            doc.items.insert(0, wap_html::Item::Text(format!("HTTP {}", f.status)));
        }
        if f.truncated {
            doc.items.push(wap_html::Item::Break);
            doc.items.push(wap_html::Item::Text("(page cut at the size limit)".into()));
        }

        let id = self.next_doc;
        self.next_doc = self.next_doc.checked_add(1).unwrap_or(1);
        let pages = wap_html::paginate(&doc, budget, &|n| page_url(gateway, id, n));
        let first = pages[0].clone();
        if pages.len() > 1 {
            if self.docs.len() >= MAX_DOCS
                && let Some(oldest) = self.docs.iter().min_by_key(|(_, d)| d.at).map(|(k, _)| *k)
            {
                self.docs.remove(&oldest);
            }
            self.docs.insert(id, Doc { issi, pages, at: now });
        }
        first
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    fn cfg(mode: WapProxyMode) -> CfgWapProxy {
        CfgWapProxy {
            enabled: true,
            mode,
            allowlist: vec!["lite.duckduckgo.com".into(), "ha.home".into()],
            issis: vec![2200279],
            timeout_secs: 8,
            max_fetch_bytes: 200_000,
            fetches_per_minute: 3,
            cache_secs: 300,
            page_bytes: 480,
        }
    }

    const GW: [u8; 4] = [10, 0, 0, 1];
    const MS: u32 = 2200279;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn private_and_reserved_addresses_are_not_public() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255"] {
            assert!(!is_public_ip(ip.parse::<Ipv4Addr>().unwrap().into()), "{ip}");
        }
        for ip in ["::1", "fd00::1", "fe80::1", "::ffff:192.168.1.1", "64:ff9b::a00:1"] {
            assert!(!is_public_ip(ip.parse::<Ipv6Addr>().unwrap().into()), "{ip}");
        }
        assert!(is_public_ip("1.1.1.1".parse::<Ipv4Addr>().unwrap().into()));
        assert!(is_public_ip("2606:4700::1111".parse::<Ipv6Addr>().unwrap().into()));
    }

    #[test]
    fn open_mode_refuses_lan_ports_and_other_schemes() {
        let c = cfg(WapProxyMode::Open);
        assert_eq!(check_url(&url("https://en.wikipedia.org/wiki/TETRA"), &c), Ok(()));
        assert_eq!(check_url(&url("http://192.168.1.1/"), &c), Err(Refusal::PrivateAddress("192.168.1.1".into())));
        assert_eq!(check_url(&url("http://[::1]/"), &c), Err(Refusal::PrivateAddress("::1".into())));
        assert_eq!(check_url(&url("http://example.com:8080/"), &c), Err(Refusal::Port(8080)));
        assert_eq!(check_url(&url("http://example.com:80/"), &c), Ok(()), "default port is fine");
        assert_eq!(check_url(&url("ftp://example.com/"), &c), Err(Refusal::Scheme("ftp".into())));
        assert_eq!(check_url(&url("http://ha.home:8123/"), &c), Ok(()), "allowlisted hosts may use other ports");
    }

    #[test]
    fn allowlist_mode_only_reaches_listed_hosts() {
        let c = cfg(WapProxyMode::Allowlist);
        assert_eq!(check_url(&url("https://lite.duckduckgo.com/lite/?q=x"), &c), Ok(()));
        assert_eq!(check_url(&url("https://en.wikipedia.org/"), &c), Err(Refusal::NotAllowlisted("en.wikipedia.org".into())));
    }

    #[test]
    fn page_paths_parse() {
        assert_eq!(parse_page_path("/p/12/3"), Some((12, 3)));
        assert_eq!(parse_page_path("/p/12"), None);
        assert_eq!(parse_page_path("/status.wml"), None);
    }

    /// Answers every URL with a long page and records what was fetched.
    struct FakeFetcher {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl Fetcher for FakeFetcher {
        fn fetch(&self, url: &Url) -> Result<Fetched, FetchError> {
            self.seen.lock().unwrap().push(url.to_string());
            let body = (0..40).map(|n| format!("<p><a href=\"/r{n}\">Result {n}</a> some snippet text here</p>")).collect::<String>();
            Ok(Fetched { url: url.clone(), status: 200, content_type: "text/html; charset=utf-8".into(), body: body.into_bytes(), truncated: false })
        }
    }

    fn proxy() -> (WapProxy<u32>, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        (WapProxy::with_fetcher(Box::new(FakeFetcher { seen: seen.clone() })), seen)
    }

    fn wait_poll(p: &mut WapProxy<u32>, c: &CfgWapProxy) -> Vec<(u32, Vec<u8>)> {
        for _ in 0..200 {
            let out = p.poll(Some(c), GW, Instant::now());
            if !out.is_empty() {
                return out;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no fetch result");
    }

    fn body_of(wtp: &[u8]) -> String {
        assert_eq!(&wtp[3..7], &[0x04, 0x20, 0x01, wap_ip::WSP_CT_WML]);
        String::from_utf8(wtp[7..].to_vec()).unwrap()
    }

    #[test]
    fn remote_get_is_held_then_answered_and_paged_from_memory() {
        let c = cfg(WapProxyMode::Open);
        let (mut p, seen) = proxy();
        let now = Instant::now();
        let a = p.handle_get(Some(&c), GW, MS, 0x10, false, "http://example.com/", 7, now);
        assert_eq!(a, GetAction::Reply(wap_ip::wtp_ack(0x10)), "hold-on Ack first");

        // A retransmitted Invoke while the fetch runs gets the Ack again, not a second fetch.
        let again = p.handle_get(Some(&c), GW, MS, 0x10, true, "http://example.com/", 7, now);
        assert_eq!(again, GetAction::Reply(wap_ip::wtp_ack(0x10)));

        let out = wait_poll(&mut p, &c);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 7, "reply goes to the GET's context");
        let first = body_of(&out[0].1);
        assert!(first.len() <= 480 && first.contains("Result 0") && first.contains("http://10.0.0.1/p/1/1"));
        assert_eq!(seen.lock().unwrap().len(), 1);

        let GetAction::Reply(page2) = p.handle_get(Some(&c), GW, MS, 0x11, false, "http://10.0.0.1/p/1/1", 7, now) else {
            panic!("page 2 served locally")
        };
        assert!(body_of(&page2).contains("http://10.0.0.1/p/1/0"), "page 2 links back");
        assert_eq!(seen.lock().unwrap().len(), 1, "paging does not fetch again");

        // Another radio cannot read this radio's pages.
        let GetAction::Reply(other) = p.handle_get(Some(&c), GW, 1234, 0x12, false, "http://10.0.0.1/p/1/1", 7, now) else { panic!() };
        assert!(body_of(&other).contains("expired"));
    }

    #[test]
    fn refused_requests_answer_at_once_without_fetching() {
        let c = cfg(WapProxyMode::Open);
        let (mut p, seen) = proxy();
        let now = Instant::now();
        let GetAction::Reply(r) = p.handle_get(Some(&c), GW, 1234, 1, false, "http://example.com/", 0, now) else { panic!() };
        assert!(body_of(&r).contains("not enabled for radio 1234"));
        let GetAction::Reply(r) = p.handle_get(Some(&c), GW, MS, 2, false, "http://192.168.1.1/", 0, now) else { panic!() };
        assert!(body_of(&r).contains("local network address"));
        assert!(seen.lock().unwrap().is_empty());
        assert!(!p.has_pending());
    }

    #[test]
    fn fetches_are_rate_limited_per_radio() {
        let c = cfg(WapProxyMode::Open);
        let (mut p, _) = proxy();
        let now = Instant::now();
        for tid in 0..3 {
            assert_eq!(p.handle_get(Some(&c), GW, MS, tid, false, "http://example.com/", 0, now), GetAction::Reply(wap_ip::wtp_ack(tid)));
        }
        let GetAction::Reply(r) = p.handle_get(Some(&c), GW, MS, 9, false, "http://example.com/", 0, now) else { panic!() };
        assert!(body_of(&r).contains("Too many pages"));
    }

    #[test]
    fn gateway_pages_stay_local_and_web_page_is_served() {
        let c = cfg(WapProxyMode::Open);
        let (mut p, _) = proxy();
        let now = Instant::now();
        assert_eq!(p.handle_get(Some(&c), GW, MS, 1, false, "http://10.0.0.1:9200/", 0, now), GetAction::Local);
        assert_eq!(p.handle_get(Some(&c), GW, MS, 1, false, "/status.wml?s=1", 0, now), GetAction::Local);
        assert_eq!(p.handle_get(None, GW, MS, 1, false, "http://example.com/", 0, now), GetAction::Local, "no proxy section = old behaviour");
        let GetAction::Reply(r) = p.handle_get(Some(&c), GW, MS, 1, false, "http://10.0.0.1:9200/web", 0, now) else { panic!() };
        assert!(body_of(&r).contains("<go href=\"https://lite.duckduckgo.com/lite/\" method=\"get\">"));
    }

    #[test]
    #[ignore = "needs internet access"]
    fn live_search_converts_and_local_names_are_refused() {
        let f = HttpFetcher::new(&cfg(WapProxyMode::Open)).unwrap();
        let got = f.fetch(&url("https://lite.duckduckgo.com/lite/?q=tetra+radio")).expect("search fetched");
        let doc = wap_html::parse_html(&String::from_utf8_lossy(&got.body), &got.url);
        let pages = wap_html::paginate(&doc, 480, &|n| page_url(GW, 1, n));
        println!("HTTP {} {} bytes -> {} pages\n{}\n{}", got.status, got.body.len(), pages.len(), pages[0], pages.get(1).cloned().unwrap_or_default());
        assert!(pages.len() > 1 && pages.iter().all(|p| p.len() <= 480));

        match f.fetch(&url("http://localhost/")) {
            Err(FetchError::Failed(e)) => assert!(e.contains("local network"), "{e}"),
            other => panic!("localhost must be refused, got {other:?}"),
        }
    }

    #[test]
    fn retransmitted_invoke_after_the_result_gets_the_same_result() {
        let c = cfg(WapProxyMode::Open);
        let (mut p, seen) = proxy();
        p.handle_get(Some(&c), GW, MS, 5, false, "http://example.com/", 0, Instant::now());
        let out = wait_poll(&mut p, &c);
        let again = p.handle_get(Some(&c), GW, MS, 5, true, "http://example.com/", 0, Instant::now());
        assert_eq!(again, GetAction::Reply(out[0].1.clone()));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
