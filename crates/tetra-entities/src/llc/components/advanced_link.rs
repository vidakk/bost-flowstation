//! Receiving side of the original acknowledged advanced link (ETSI EN 300 392-2 clauses 21.2.3
//! and 22.3.3). Radios that send SN-DATA (acknowledged packet data) set up an advanced link first
//! and send their TL-SDUs segmented over it; the station accepts the set-up, re-assembles and
//! FCS-checks the TL-SDUs, delivers them in N(S) order and acknowledges on request.
//!
//! Everything here works on PDU bit-strings (after the 4-bit LLC PDU type has been read) so it can
//! be tested without the rest of the stack. The LLC entity owns the per-link state and does the I/O.

use std::collections::{BTreeMap, HashMap, VecDeque};

use tetra_core::{BitBuffer, LinkId};

use crate::llc::components::fcs;

/// LLC PDU type values (table 21.1) for the PDUs built here.
const LLC_AL_SETUP: u64 = 0b1000;
const LLC_AL_ACK: u64 = 0b1011;
const LLC_AL_RECONNECT: u64 = 0b1100;
const LLC_AL_DISC: u64 = 0b1111;

/// TL-SDU numbers on the original advanced link are 3 bits (clause 22.3.3.2.0).
const NS_MODULO: u8 = 8;
/// Largest window the original advanced link may negotiate (clause 22.2.2.5).
const MAX_WINDOW: u8 = 3;
/// Largest "number of acknowledged segments" an acknowledgement block can carry (table 21.13).
const MAX_ACK_LENGTH: u8 = 62;
/// Acknowledgement length value asking for the whole TL-SDU again (FCS failure, table 21.13).
const ACK_LENGTH_REPEAT_SDU: u64 = 0b111111;
/// LLC PDU type of AL-DATA / AL-FINAL (and their -AR forms).
const LLC_AL_DATA: u64 = 0b1001;

/// Link identifier on TL-SDUs delivered from advanced link n (0..=3) is this plus n, so a service
/// user answering with the same link identifier is answered over that advanced link. Basic link
/// TL-SDUs carry the receiving timeslot (1..=4) instead.
pub const ADVANCED_LINK_ID_BASE: LinkId = 0x100;

pub fn is_advanced_link_id(link_id: LinkId) -> bool {
    (ADVANCED_LINK_ID_BASE..ADVANCED_LINK_ID_BASE + 4).contains(&link_id)
}

/// Payload bits per downlink segment: with the 17-bit AL-DATA header, a MAC-RESOURCE addressed by
/// SSI and room for a slot grant, one segment fits a single SCH/F slot.
const DL_SEGMENT_BITS: usize = 192;
/// Time to wait for the AL-ACK of a TL-SDU before sending it again, in timeslots (~2 s).
const DL_ACK_WAIT_TIMESLOTS: u32 = 4 * 18 * 2;
/// Transmissions of one TL-SDU before it is dropped.
const DL_MAX_ATTEMPTS: u8 = 4;

/// Set-up report (table 21.23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupReport {
    Success,
    ServiceDefinition,
    ServiceChange,
    Reset,
    SuccessQosIncomplete,
    Reserved(u8),
}

impl SetupReport {
    fn from_bits(v: u64) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::ServiceDefinition,
            2 => Self::ServiceChange,
            3 => Self::Reset,
            4 => Self::SuccessQosIncomplete,
            v => Self::Reserved(v as u8),
        }
    }
}

/// An AL-SETUP PDU (table 21.23). Only the fields the station negotiates are kept as values; the
/// radio-resource fields are echoed back unchanged in the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlSetup {
    pub acknowledged: bool,
    /// Advanced link number N.261, 0..=3 for links 1..=4.
    pub link: u8,
    /// N.271 code (0 = 32 octets .. 7 = 4096 octets).
    pub max_sdu_len_code: u8,
    connection_width: u8,
    symmetry: u8,
    timeslots_ul: Option<u8>,
    timeslots_dl: Option<u8>,
    throughput: u8,
    /// Negotiated N.272 for the original advanced link, 1..=3 (an augmented set-up is folded in).
    pub window: u8,
    /// N.273.
    pub max_sdu_retx: u8,
    /// N.274.
    pub max_seg_retx: u8,
    pub report: SetupReport,
    /// True when the radio proposed an extended advanced link in an augmented set-up.
    pub proposed_extended: bool,
}

impl AlSetup {
    /// Parse the PDU body that follows the 4-bit LLC PDU type.
    pub fn parse(body: &str) -> Option<Self> {
        let mut r = BitReader::new(body);
        let acknowledged = r.take(1)? == 1;
        let link = r.take(2)? as u8;
        let max_sdu_len_code = r.take(3)? as u8;
        let connection_width = r.take(1)? as u8;
        let symmetry = r.take(1)? as u8;
        let timeslots_ul = if connection_width == 1 { Some(r.take(2)? as u8) } else { None };
        let timeslots_dl = if connection_width == 1 && symmetry == 1 { Some(r.take(2)? as u8) } else { None };
        let throughput = r.take(3)? as u8;
        let window_code = r.take(2)? as u8;
        let max_sdu_retx = r.take(3)? as u8;
        let max_seg_retx = r.take(4)? as u8;
        let report = SetupReport::from_bits(r.take(3)?);
        if !acknowledged {
            r.take(8)?; // N(S), unacknowledged service only
        }
        let (window, proposed_extended) = if window_code == 0 {
            // Augmented set-up: advanced link type, then the window for that type, then 3 reserved bits.
            let extended = r.take(1)? == 1;
            let w = if extended { r.take(4)? as u8 } else { r.take(2)? as u8 };
            r.take(3)?;
            (w.clamp(1, MAX_WINDOW), extended)
        } else {
            (window_code, false)
        };
        Some(Self {
            acknowledged,
            link,
            max_sdu_len_code,
            connection_width,
            symmetry,
            timeslots_ul,
            timeslots_dl,
            throughput,
            window,
            max_sdu_retx,
            max_seg_retx,
            report,
            proposed_extended,
        })
    }

    /// The accepting response: the same parameters with report "success", as a non-augmented
    /// AL-SETUP for the original advanced link (clause 22.3.3.1.2 a; an extended proposal may be
    /// answered with the original advanced link, clause 22.2.2.1 NOTE 2).
    pub fn accept_pdu(&self) -> BitBuffer {
        self.to_pdu(0b000)
    }

    /// True when the radio asks for a specified multislot connection (more than one π/4-DQPSK
    /// timeslot per frame, table 21.23), which a single-slot packet data channel cannot give.
    pub fn asks_for_multislot(&self) -> bool {
        self.connection_width == 1 && self.throughput != 0b110 && self.timeslots_ul.is_some_and(|n| n > 0)
    }

    /// The counter-offer for a multislot request: the same link as a single-slot connection, with
    /// report "service change" (clause 22.3.3.1.2 b). The radio confirms with report "success".
    pub fn single_slot_offer_pdu(&self) -> BitBuffer {
        Self { connection_width: 0, symmetry: 0, timeslots_ul: None, timeslots_dl: None, ..self.clone() }.to_pdu(0b010)
    }

    fn to_pdu(&self, report: u64) -> BitBuffer {
        let mut b = BitBuffer::new_autoexpand(32);
        b.write_bits(LLC_AL_SETUP, 4);
        b.write_bits(self.acknowledged as u64, 1);
        b.write_bits(self.link as u64, 2);
        b.write_bits(self.max_sdu_len_code as u64, 3);
        b.write_bits(self.connection_width as u64, 1);
        b.write_bits(self.symmetry as u64, 1);
        if let Some(ul) = self.timeslots_ul {
            b.write_bits(ul as u64, 2);
        }
        if let Some(dl) = self.timeslots_dl {
            b.write_bits(dl as u64, 2);
        }
        b.write_bits(self.throughput as u64, 3);
        b.write_bits(self.window as u64, 2);
        b.write_bits(self.max_sdu_retx as u64, 3);
        b.write_bits(self.max_seg_retx as u64, 4);
        b.write_bits(report, 3);
        b.seek(0);
        b
    }
}

/// A segment PDU: AL-DATA, AL-DATA-AR, AL-FINAL or AL-FINAL-AR (tables 21.17 and 21.19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlSegment {
    pub last: bool,
    pub ack_request: bool,
    pub ns: u8,
    pub ss: u8,
    /// Segment payload as a bit-string; the last segment carries the FCS (or its tail).
    pub payload: String,
}

impl AlSegment {
    pub fn parse(body: &str) -> Option<Self> {
        let mut r = BitReader::new(body);
        let last = r.take(1)? == 1;
        let ack_request = r.take(1)? == 1;
        let ns = r.take(3)? as u8;
        let ss = r.take(8)? as u8;
        Some(Self { last, ack_request, ns, ss, payload: r.rest().to_string() })
    }
}

/// AL-DISC report (table 21.21).
pub const DISC_SUCCESS: u8 = 0b000;
pub const DISC_CLOSE: u8 = 0b001;

/// An AL-DISC PDU (table 21.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlDisc {
    pub acknowledged: bool,
    pub link: u8,
    pub report: u8,
}

impl AlDisc {
    pub fn parse(body: &str) -> Option<Self> {
        let mut r = BitReader::new(body);
        Some(Self { acknowledged: r.take(1)? == 1, link: r.take(2)? as u8, report: r.take(3)? as u8 })
    }

    pub fn to_pdu(self) -> BitBuffer {
        let mut b = BitBuffer::new_autoexpand(10);
        b.write_bits(LLC_AL_DISC, 4);
        b.write_bits(self.acknowledged as u64, 1);
        b.write_bits(self.link as u64, 2);
        b.write_bits(self.report as u64, 3);
        b.seek(0);
        b
    }
}

/// AL-RECONNECT reconnect report (table 21.22).
pub const RECONNECT_PROPOSE: u8 = 0b00;
pub const RECONNECT_REJECT: u8 = 0b01;
pub const RECONNECT_ACCEPT: u8 = 0b10;

/// An AL-RECONNECT PDU (table 21.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlReconnect {
    pub acknowledged: bool,
    pub link: u8,
    pub report: u8,
}

impl AlReconnect {
    pub fn parse(body: &str) -> Option<Self> {
        let mut r = BitReader::new(body);
        Some(Self { acknowledged: r.take(1)? == 1, link: r.take(2)? as u8, report: r.take(2)? as u8 })
    }

    pub fn to_pdu(self) -> BitBuffer {
        let mut b = BitBuffer::new_autoexpand(9);
        b.write_bits(LLC_AL_RECONNECT, 4);
        b.write_bits(self.acknowledged as u64, 1);
        b.write_bits(self.link as u64, 2);
        b.write_bits(self.report as u64, 2);
        b.seek(0);
        b
    }
}

/// Re-assembly state of one TL-SDU in the receive window.
#[derive(Debug, Default)]
enum RxSdu {
    #[default]
    Empty,
    Partial {
        segments: BTreeMap<u8, String>,
        last: Option<u8>,
    },
    /// Received and FCS-checked, waiting for an older TL-SDU before it can be delivered.
    Complete(String),
    /// All segments arrived but the FCS failed; the radio is asked to send it again.
    FcsFailed,
}

/// What the LLC should do after a segment was taken in.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RxOutcome {
    /// TL-SDUs (FCS removed) ready for the service user, in N(S) order.
    pub delivered: Vec<String>,
    /// An AL-ACK to send, when the segment asked for one.
    pub ack: Option<String>,
    /// True when a TL-SDU was fully received but failed its FCS.
    pub fcs_failed: bool,
}

/// Receive side of one original acknowledged advanced link.
#[derive(Debug)]
pub struct AlReceiver {
    pub setup: AlSetup,
    /// Lowest TL-SDU number not yet delivered (lower window edge).
    v_r: u8,
    window: u8,
    sdus: HashMap<u8, RxSdu>,
}

impl AlReceiver {
    pub fn new(setup: AlSetup) -> Self {
        let window = setup.window.clamp(1, MAX_WINDOW);
        Self { setup, v_r: 0, window, sdus: HashMap::new() }
    }

    fn offset(&self, ns: u8) -> u8 {
        (ns + NS_MODULO - self.v_r) % NS_MODULO
    }

    fn in_window(&self, ns: u8) -> bool {
        self.offset(ns) < self.window
    }

    /// TL-SDUs below the window were already delivered; a repeat means our AL-ACK was lost
    /// (clause 22.3.3.2.7 NOTE 6).
    fn below_window(&self, ns: u8) -> bool {
        self.offset(ns) >= NS_MODULO - self.window
    }

    /// Take in one AL-DATA(-AR) / AL-FINAL(-AR) segment (clause 22.3.3.2.7 b and c).
    pub fn receive(&mut self, seg: AlSegment) -> RxOutcome {
        let mut out = RxOutcome::default();
        let ns = seg.ns % NS_MODULO;

        if self.in_window(ns) {
            let entry = self.sdus.entry(ns).or_default();
            if matches!(entry, RxSdu::Empty | RxSdu::FcsFailed) {
                *entry = RxSdu::Partial { segments: BTreeMap::new(), last: None };
            }
            if let RxSdu::Partial { segments, last } = entry {
                segments.entry(seg.ss).or_insert(seg.payload);
                if seg.last {
                    *last = Some(seg.ss);
                }
                if let Some(l) = *last
                    && (0..=l).all(|s| segments.contains_key(&s))
                {
                    let bits: String = segments.range(0..=l).map(|(_, p)| p.as_str()).collect();
                    *entry = match strip_fcs(&bits) {
                        Some(sdu) => RxSdu::Complete(sdu),
                        None => {
                            out.fcs_failed = true;
                            RxSdu::FcsFailed
                        }
                    };
                }
            }
            while let Some(RxSdu::Complete(_)) = self.sdus.get(&self.v_r) {
                if let Some(RxSdu::Complete(sdu)) = self.sdus.remove(&self.v_r) {
                    out.delivered.push(sdu);
                }
                self.v_r = (self.v_r + 1) % NS_MODULO;
            }
        } else if !self.below_window(ns) {
            tracing::debug!("advanced link: TL-SDU N(S)={} outside window (V(R)={}, size {}), discarding", ns, self.v_r, self.window);
        }

        if seg.ack_request {
            out.ack = Some(self.build_ack(ns));
        }
        out
    }

    /// AL-ACK (table 21.12) for an acknowledgement request on TL-SDU `ns`: one block for every
    /// TL-SDU from the lower window edge up to and including `ns` (clause 22.3.3.2.3).
    fn build_ack(&mut self, ns: u8) -> String {
        let mut bits = String::new();
        push_bits(&mut bits, LLC_AL_ACK, 4);
        push_bits(&mut bits, 1, 1); // flow control: receiver ready
        if !self.in_window(ns) {
            push_ack_block(&mut bits, ns, &RxSdu::Complete(String::new()));
            return bits;
        }
        for off in 0..=self.offset(ns) {
            let n = (self.v_r + off) % NS_MODULO;
            let state = self.sdus.get(&n).unwrap_or(&RxSdu::Empty);
            push_ack_block(&mut bits, n, state);
        }
        bits
    }
}

/// One TL-SDU being sent, cut into complete AL-DATA / AL-FINAL-AR PDUs.
#[derive(Debug)]
struct TxSdu {
    sdu: String,
    ns: u8,
    segments: Vec<String>,
    attempts: u8,
    wait: u32,
}

/// Sending side of one original acknowledged advanced link (clause 22.3.3.2), one TL-SDU at a
/// time: the TL-SDU goes out with its FCS as AL-DATA segments closed by an AL-FINAL-AR, and stays
/// until the peer's AL-ACK covers it. Missing segments are sent again; with no AL-ACK the whole
/// TL-SDU is sent again until [`DL_MAX_ATTEMPTS`].
#[derive(Debug, Default)]
pub struct AlSender {
    v_s: u8,
    queue: VecDeque<String>,
    in_flight: Option<TxSdu>,
}

impl AlSender {
    /// Queue a TL-SDU (bit-string, without FCS). Returns the PDUs to send now.
    pub fn push(&mut self, sdu: String) -> Vec<String> {
        self.queue.push_back(sdu);
        self.start_next()
    }

    pub fn is_idle(&self) -> bool {
        self.in_flight.is_none() && self.queue.is_empty()
    }

    /// The link was set up again: numbering restarts at 0 and an unacknowledged TL-SDU is sent
    /// again from the start (clause 22.3.3.1.3). Returns the PDUs to send now.
    pub fn reset(&mut self) -> Vec<String> {
        if let Some(tx) = self.in_flight.take() {
            self.queue.push_front(tx.sdu);
        }
        self.v_s = 0;
        self.start_next()
    }

    /// The link was reconnected: the peer may have missed the last transmission. Returns the PDUs
    /// to send now.
    pub fn resend(&mut self) -> Vec<String> {
        match self.in_flight.as_mut() {
            Some(tx) => {
                tx.wait = DL_ACK_WAIT_TIMESLOTS;
                tx.segments.clone()
            }
            None => self.start_next(),
        }
    }

    /// One timeslot passed. Returns the PDUs to send again when the AL-ACK wait ran out.
    pub fn tick(&mut self) -> Vec<String> {
        let Some(tx) = self.in_flight.as_mut() else {
            return Vec::new();
        };
        tx.wait = tx.wait.saturating_sub(1);
        if tx.wait > 0 {
            return Vec::new();
        }
        if tx.attempts >= DL_MAX_ATTEMPTS {
            tracing::info!("advanced link: TL-SDU N(S)={} not acknowledged after {} attempts, dropped", tx.ns, tx.attempts);
            self.in_flight = None;
            self.v_s = (self.v_s + 1) % NS_MODULO;
            return self.start_next();
        }
        tx.attempts += 1;
        tx.wait = DL_ACK_WAIT_TIMESLOTS;
        tx.segments.clone()
    }

    /// Take in an AL-ACK body (after the LLC PDU type). Returns the PDUs to send now: missing
    /// segments, or the next TL-SDU once the current one is acknowledged.
    pub fn on_ack(&mut self, body: &str) -> Vec<String> {
        let Some(tx) = self.in_flight.as_mut() else {
            return Vec::new();
        };
        let mut r = BitReader::new(body);
        if r.take(1).is_none() {
            return Vec::new(); // flow control
        }
        while let (Some(nr), Some(len)) = (r.take(3), r.take(6)) {
            let (nr, len) = (nr as u8, len as u8);
            let mut received = vec![false; tx.segments.len()];
            match len {
                0 => received.iter_mut().for_each(|s| *s = true),
                l if l as u64 == ACK_LENGTH_REPEAT_SDU => {}
                l => {
                    let Some(sr) = r.take(8) else { break };
                    let sr = sr as usize;
                    received.iter_mut().take(sr).for_each(|s| *s = true);
                    for s in sr + 1..sr + l as usize {
                        let Some(bit) = r.take(1) else { break };
                        if bit == 1 && s < received.len() {
                            received[s] = true;
                        }
                    }
                }
            }
            if nr != tx.ns {
                continue;
            }
            if received.iter().all(|&s| s) {
                self.in_flight = None;
                self.v_s = (self.v_s + 1) % NS_MODULO;
                return self.start_next();
            }
            tx.wait = DL_ACK_WAIT_TIMESLOTS;
            let mut missing: Vec<String> =
                tx.segments.iter().zip(&received).filter(|(_, got)| !**got).map(|(seg, _)| seg.clone()).collect();
            // The last segment carries the acknowledgement request, so the peer reports again.
            if received[tx.segments.len() - 1] {
                missing.push(tx.segments[tx.segments.len() - 1].clone());
            }
            return missing;
        }
        Vec::new()
    }

    fn start_next(&mut self) -> Vec<String> {
        if self.in_flight.is_some() {
            return Vec::new();
        }
        let Some(sdu) = self.queue.pop_front() else {
            return Vec::new();
        };
        let segments = segment(self.v_s, &sdu);
        let out = segments.clone();
        self.in_flight = Some(TxSdu { sdu, ns: self.v_s, segments, attempts: 1, wait: DL_ACK_WAIT_TIMESLOTS });
        out
    }
}

/// Cut a TL-SDU plus its FCS into AL-DATA PDUs, the last one an AL-FINAL-AR (table 21.19).
fn segment(ns: u8, sdu: &str) -> Vec<String> {
    let mut b = BitBuffer::from_bitstr(&format!("{sdu}{}", "0".repeat(32)));
    let crc = fcs::compute_fcs(&b, 0, sdu.len());
    b.seek(sdu.len());
    b.write_bits(crc as u64, 32);
    b.seek(0);
    let bits = b.dump_bin_unformatted();
    let chunks: Vec<&str> = bits.as_bytes().chunks(DL_SEGMENT_BITS).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    chunks
        .iter()
        .enumerate()
        .map(|(ss, payload)| {
            let last = ss + 1 == chunks.len();
            let mut pdu = String::new();
            push_bits(&mut pdu, LLC_AL_DATA, 4);
            push_bits(&mut pdu, last as u64, 1);
            push_bits(&mut pdu, last as u64, 1); // acknowledgement request on the final segment
            push_bits(&mut pdu, ns as u64, 3);
            push_bits(&mut pdu, ss as u64, 8);
            pdu.push_str(payload);
            pdu
        })
        .collect()
}

/// One acknowledgement block (table 21.13).
fn push_ack_block(bits: &mut String, n: u8, state: &RxSdu) {
    push_bits(bits, n as u64, 3);
    match state {
        RxSdu::Complete(_) => push_bits(bits, 0, 6),
        RxSdu::FcsFailed => push_bits(bits, ACK_LENGTH_REPEAT_SDU, 6),
        RxSdu::Empty => {
            push_bits(bits, 1, 6);
            push_bits(bits, 0, 8);
        }
        RxSdu::Partial { segments, .. } => {
            let sr = (0..=u8::MAX).find(|s| !segments.contains_key(s)).unwrap_or(u8::MAX);
            let highest = segments.keys().next_back().copied().unwrap_or(0);
            // Segments S(R)..=highest are covered: S(R) itself is implicitly missing and the bitmap
            // reports the rest. With nothing received past S(R), only S(R) is sent.
            let covered = if highest > sr { (highest - sr + 1).min(MAX_ACK_LENGTH) } else { 1 };
            push_bits(bits, covered as u64, 6);
            push_bits(bits, sr as u64, 8);
            for s in (sr as u16 + 1)..(sr as u16 + covered as u16) {
                bits.push(if segments.contains_key(&(s as u8)) { '1' } else { '0' });
            }
        }
    }
}

/// Check the 32-bit FCS at the end of a re-assembled TL-SDU and return the TL-SDU without it.
fn strip_fcs(bits: &str) -> Option<String> {
    if bits.len() < 32 {
        return None;
    }
    let buf = BitBuffer::from_bitstr(bits);
    fcs::check_fcs(&buf).then(|| bits[..bits.len() - 32].to_string())
}

fn push_bits(s: &mut String, value: u64, n: usize) {
    for i in (0..n).rev() {
        s.push(if (value >> i) & 1 == 1 { '1' } else { '0' });
    }
}

struct BitReader<'a> {
    bits: &'a str,
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(bits: &'a str) -> Self {
        Self { bits, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<u64> {
        let s = self.bits.get(self.pos..self.pos + n)?;
        self.pos += n;
        u64::from_str_radix(s, 2).ok()
    }

    fn rest(&self) -> &'a str {
        self.bits.get(self.pos..).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AL-SETUP from an MXP600 (after the LLC PDU type 1000), field by field: acknowledged, link 1,
    /// 2048 octets, multislot, symmetric, 4 timeslots, maximum throughput, window 3, N.273 = 0,
    /// N.274 = 3, report "service definition".
    const MXP600_SETUP: &str = "1001101011111110000011001";

    fn with_fcs(sdu: &str) -> String {
        let mut b = BitBuffer::from_bitstr(&format!("{sdu}{}", "0".repeat(32)));
        let fcs = fcs::compute_fcs(&b, 0, sdu.len());
        b.seek(sdu.len());
        b.write_bits(fcs as u64, 32);
        b.seek(0);
        b.dump_bin_unformatted()
    }

    fn seg(last: bool, ar: bool, ns: u8, ss: u8, payload: &str) -> AlSegment {
        AlSegment { last, ack_request: ar, ns, ss, payload: payload.to_string() }
    }

    #[test]
    fn parses_captured_mxp600_setup() {
        let s = AlSetup::parse(MXP600_SETUP).unwrap();
        assert!(s.acknowledged);
        assert_eq!(s.link, 0);
        assert_eq!(s.max_sdu_len_code, 0b110);
        assert_eq!(s.timeslots_ul, Some(0b11));
        assert_eq!(s.timeslots_dl, None);
        assert_eq!(s.window, 3);
        assert_eq!((s.max_sdu_retx, s.max_seg_retx), (0, 3));
        assert_eq!(s.report, SetupReport::ServiceDefinition);
        assert!(!s.proposed_extended);
    }

    #[test]
    fn accept_echoes_the_setup_with_report_success() {
        let s = AlSetup::parse(MXP600_SETUP).unwrap();
        let expected = format!("1000{}000", &MXP600_SETUP[..MXP600_SETUP.len() - 3]);
        assert_eq!(s.accept_pdu().dump_bin_unformatted(), expected);
    }

    fn deliver(rx: &mut AlReceiver, pdus: &[String]) -> RxOutcome {
        let mut all = RxOutcome::default();
        for pdu in pdus {
            assert_eq!(&pdu[..4], "1001");
            let out = rx.receive(AlSegment::parse(&pdu[4..]).unwrap());
            all.delivered.extend(out.delivered);
            all.ack = out.ack.or(all.ack);
        }
        all
    }

    #[test]
    fn sent_sdu_is_reassembled_by_the_peer_and_its_ack_frees_the_sender() {
        let sdu: String = (0..363).map(|i| if i % 3 == 0 { '1' } else { '0' }).collect();
        let mut tx = AlSender::default();
        let pdus = tx.push(sdu.clone());
        assert_eq!(pdus.len(), 3, "363 bits + FCS in 192-bit segments");
        assert!(pdus[..2].iter().all(|p| &p[4..6] == "00"));
        assert_eq!(&pdus[2][4..6], "11", "AL-FINAL-AR");

        let mut rx = AlReceiver::new(AlSetup::parse(MXP600_SETUP).unwrap());
        let out = deliver(&mut rx, &pdus);
        assert_eq!(out.delivered, vec![sdu]);
        let ack = out.ack.expect("AL-ACK");
        assert!(tx.on_ack(&ack[4..]).is_empty());
        assert!(tx.is_idle());

        let next = tx.push("1010".into());
        assert_eq!(&next[0][6..9], "001", "the next TL-SDU is N(S) 1");
    }

    #[test]
    fn missing_segment_is_sent_again_with_the_final_one() {
        let sdu = "1".repeat(500);
        let mut tx = AlSender::default();
        let pdus = tx.push(sdu.clone());
        assert_eq!(pdus.len(), 3);

        let mut rx = AlReceiver::new(AlSetup::parse(MXP600_SETUP).unwrap());
        let out = deliver(&mut rx, &[pdus[0].clone(), pdus[2].clone()]);
        let again = tx.on_ack(&out.ack.unwrap()[4..]);
        assert_eq!(again, vec![pdus[1].clone(), pdus[2].clone()]);

        let out = deliver(&mut rx, &again);
        assert_eq!(out.delivered, vec![sdu]);
        tx.on_ack(&out.ack.unwrap()[4..]);
        assert!(tx.is_idle());
    }

    #[test]
    fn unacknowledged_sdu_is_repeated_then_dropped() {
        let mut tx = AlSender::default();
        let first = tx.push("1100".into());
        let mut repeats = 0;
        for _ in 0..DL_ACK_WAIT_TIMESLOTS * DL_MAX_ATTEMPTS as u32 {
            let out = tx.tick();
            if !out.is_empty() {
                assert_eq!(out, first);
                repeats += 1;
            }
        }
        assert_eq!(repeats, DL_MAX_ATTEMPTS - 1);
        assert!(tx.is_idle());
    }

    #[test]
    fn multislot_request_is_offered_a_single_slot_connection() {
        let s = AlSetup::parse(MXP600_SETUP).unwrap();
        assert!(s.asks_for_multislot());
        // Width 0, symmetry 0, no timeslot counts, everything else kept, report "service change".
        let expected = format!("1000{}0{}{}010", &MXP600_SETUP[..6], "0", &MXP600_SETUP[10..MXP600_SETUP.len() - 3]);
        assert_eq!(s.single_slot_offer_pdu().dump_bin_unformatted(), expected);

        let offer = s.single_slot_offer_pdu().dump_bin_unformatted();
        let reply = format!("{}000", &offer[4..offer.len() - 3]);
        let confirmed = AlSetup::parse(&reply).unwrap();
        assert_eq!(confirmed.report, SetupReport::Success);
        assert!(!confirmed.asks_for_multislot());
    }

    #[test]
    fn extended_proposal_is_answered_as_original_link() {
        // Single-slot, no radio info, augmented (window 00), extended type, window 15.
        let body = "1 00 110 0 0 110 00 000 0011 001 1 1111 000".replace(' ', "");
        let s = AlSetup::parse(&body).unwrap();
        assert!(s.proposed_extended);
        assert_eq!(s.window, 3);
        let resp = s.accept_pdu().dump_bin_unformatted();
        assert_eq!(resp, "1000 1 00 110 0 0 110 11 000 0011 000".replace(' ', ""));
    }

    #[test]
    fn single_segment_sdu_is_delivered_and_acknowledged() {
        let sdu = "1000101000010001";
        let mut rx = AlReceiver::new(AlSetup::parse(MXP600_SETUP).unwrap());
        let out = rx.receive(seg(true, true, 0, 0, &with_fcs(sdu)));
        assert_eq!(out.delivered, vec![sdu.to_string()]);
        // AL-ACK, receiver ready, block for N(S)=0 now below the window: SDU correctly received.
        assert_eq!(out.ack.as_deref(), Some("1011 1 000 000000".replace(' ', "").as_str()));
    }

    #[test]
    fn segments_reassemble_in_any_order() {
        let sdu = "110011001010101011110000";
        let full = with_fcs(sdu);
        let (a, b, c) = (&full[..20], &full[20..40], &full[40..]);
        let mut rx = AlReceiver::new(AlSetup::parse(MXP600_SETUP).unwrap());
        assert!(rx.receive(seg(false, false, 0, 1, b)).delivered.is_empty());
        assert!(rx.receive(seg(true, false, 0, 2, c)).delivered.is_empty());
        assert_eq!(rx.receive(seg(false, false, 0, 0, a)).delivered, vec![sdu.to_string()]);
    }

    #[test]
    fn missing_segment_is_reported_with_a_bitmap() {
        let full = with_fcs("1".repeat(40).as_str());
        let mut rx = AlReceiver::new(AlSetup::parse(MXP600_SETUP).unwrap());
        rx.receive(seg(false, false, 0, 0, &full[..18]));
        rx.receive(seg(false, false, 0, 2, &full[36..54]));
        let out = rx.receive(seg(true, true, 0, 3, &full[54..]));
        assert!(out.delivered.is_empty());
        // N(R)=0, 3 segments covered from S(R)=1: 1 missing, then 2 and 3 received.
        assert_eq!(out.ack.as_deref(), Some("1011 1 000 000011 00000001 11".replace(' ', "").as_str()));
    }

    #[test]
    fn fcs_failure_asks_for_the_whole_sdu() {
        let mut full = with_fcs("10101010");
        full.replace_range(0..1, "0");
        let mut rx = AlReceiver::new(AlSetup::parse(MXP600_SETUP).unwrap());
        let out = rx.receive(seg(true, true, 0, 0, &full));
        assert!(out.fcs_failed && out.delivered.is_empty());
        assert_eq!(out.ack.as_deref(), Some("1011 1 000 111111".replace(' ', "").as_str()));
    }

    #[test]
    fn later_sdu_waits_for_the_older_one() {
        let (s0, s1) = ("00001111", "11110000");
        let mut rx = AlReceiver::new(AlSetup::parse(MXP600_SETUP).unwrap());
        let out = rx.receive(seg(true, true, 1, 0, &with_fcs(s1)));
        assert!(out.delivered.is_empty());
        // Block for N(S)=0 (nothing yet: S(R)=0) then N(S)=1 (complete).
        assert_eq!(out.ack.as_deref(), Some("1011 1 000 000001 00000000 001 000000".replace(' ', "").as_str()));
        let out = rx.receive(seg(true, false, 0, 0, &with_fcs(s0)));
        assert_eq!(out.delivered, vec![s0.to_string(), s1.to_string()]);
    }

    #[test]
    fn repeated_sdu_below_window_is_acknowledged_again() {
        let sdu = with_fcs("0110");
        let mut rx = AlReceiver::new(AlSetup::parse(MXP600_SETUP).unwrap());
        rx.receive(seg(true, true, 0, 0, &sdu));
        let out = rx.receive(seg(true, true, 0, 0, &sdu));
        assert!(out.delivered.is_empty());
        assert_eq!(out.ack.as_deref(), Some("1011 1 000 000000".replace(' ', "").as_str()));
    }

    #[test]
    fn disc_and_reconnect_round_trip() {
        let d = AlDisc::parse("100001").unwrap();
        assert_eq!(d, AlDisc { acknowledged: true, link: 0, report: DISC_CLOSE });
        let reply = AlDisc { report: DISC_SUCCESS, ..d }.to_pdu().dump_bin_unformatted();
        assert_eq!(reply, "1111100000");
        let rc = AlReconnect::parse("10000").unwrap();
        assert_eq!(rc.report, RECONNECT_PROPOSE);
        assert_eq!(AlReconnect { report: RECONNECT_ACCEPT, ..rc }.to_pdu().dump_bin_unformatted(), "110010010");
    }
}
