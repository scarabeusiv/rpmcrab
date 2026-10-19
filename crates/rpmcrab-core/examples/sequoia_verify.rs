//! Evaluation harness for issue #779: verifies RPM package signatures
//! with sequoia-openpgp and reports per-signature outcomes as JSON
//! lines, for comparison against `rpm -Kv` and the #730 verifier.
//!
//! Usage: sequoia_verify --keys <keyfile>[,<keyfile>...] [--builder]
//!            [--hand] <rpm>...
//!
//! Per package one JSON object is printed:
//!   {"path": ..., "entries": bool,
//!    "sigs": [{"tag": 268, "scope": "header"|"header+payload",
//!              "hand": "none|[issuer-hex-or-null]",
//!              "parse": "ok"|"err", "ver": 3, "pk_algo": 1,
//!              "hash_algo": 10, "issuer": "low32hex"|null,
//!              "key": "found"|"missing",
//!              "verify": "good"|"bad"|"na",
//!              "builder_null": "...", "builder_std": "..."}]}
//!
//! "hand" is the #730 hand-written parser's verdict for the same blob
//! (a verbatim copy of its logic, kept here as the reference): "none"
//! means the hand parser rejects the packet as malformed; otherwise the
//! value is its extracted issuer (null = packet parses, no issuer).

use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use sequoia_openpgp as openpgp;
use openpgp::cert::{CertParser, KeyAmalgamation};
use openpgp::packet::prelude::*;
use openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
    VerificationLayer, VerificationResult,
};
use openpgp::parse::{PacketParser, Parse};
use openpgp::policy::{NullPolicy, Policy, StandardPolicy};
use openpgp::types::KeyFlags;
use openpgp::{Cert, KeyHandle};

// ---------- RPM container slicing (adapted from #730's signature.rs) --

const SIG_TAGS: [u32; 5] = [267, 268, 1002, 1005, 1006];
const LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];
const MAX_BLOB_BYTES: usize = 65_536;
const MAX_TOTAL_BLOB_BYTES: usize = 1_048_576;

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

struct SigEntry {
    tag: u32,
    offset: usize, // absolute file offset of the blob
    blob: Vec<u8>,
}

struct Sliced {
    entries: Vec<SigEntry>,
    has_entries: bool,
    header_range: (u64, u64),        // main header [start, end)
    header_payload_from: u64,       // start of main header
    file_len: u64,
}

fn slice_rpm(path: &Path) -> Option<Sliced> {
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    let mut lead = [0u8; 96];
    file.read_exact(&mut lead).ok()?;
    if lead[0..4] != LEAD_MAGIC {
        return None;
    }
    // Generic header reader: returns (index entries, header total size).
    let read_header = |file: &mut File, start: u64| -> Option<(Vec<[u8; 16]>, u64)> {
        file.seek(SeekFrom::Start(start)).ok()?;
        let mut preamble = [0u8; 16];
        file.read_exact(&mut preamble).ok()?;
        if preamble[0..3] != HEADER_MAGIC {
            return None;
        }
        let nindex = be_u32(&preamble[8..12]) as usize;
        let store_size = be_u32(&preamble[12..16]) as u64;
        if nindex > 100_000 {
            return None;
        }
        let mut index = vec![0u8; nindex * 16];
        file.read_exact(&mut index).ok()?;
        let mut entries = Vec::with_capacity(nindex);
        for e in index.as_chunks::<16>().0 {
            entries.push(*e);
        }
        Some((entries, 16 + nindex as u64 * 16 + store_size))
    };
    let (sig_index, sig_total) = read_header(&mut file, 96)?;
    let sig_store_start = 96 + 16 + sig_index.len() as u64 * 16;
    let sig_store_size = sig_total - 16 - sig_index.len() as u64 * 16;
    let main_start = 96 + sig_total.div_ceil(8) * 8;
    let (_, main_total) = read_header(&mut file, main_start)?;
    let mut entries = Vec::new();
    let mut has_entries = false;
    let mut total_bytes = 0usize;
    for entry in &sig_index {
        let tag = be_u32(&entry[0..4]);
        let entry_type = be_u32(&entry[4..8]);
        let offset = be_u32(&entry[8..12]) as usize;
        let count = be_u32(&entry[12..16]) as usize;
        if !SIG_TAGS.contains(&tag) || entry_type != 7 {
            continue;
        }
        has_entries = true;
        if offset + count > sig_store_size as usize
            || count > MAX_BLOB_BYTES
            || total_bytes + count > MAX_TOTAL_BLOB_BYTES
        {
            continue;
        }
        let mut blob = vec![0u8; count];
        file.seek(SeekFrom::Start(sig_store_start + offset as u64))
            .ok()?;
        file.read_exact(&mut blob).ok()?;
        total_bytes += count;
        entries.push(SigEntry {
            tag,
            offset: (sig_store_start + offset as u64) as usize,
            blob,
        });
    }
    Some(Sliced {
        entries,
        has_entries,
        header_range: (main_start, main_start + main_total),
        header_payload_from: main_start,
        file_len,
    })
}

// ---------- verbatim copy of #730's hand-written packet parser --------
// (reference implementation for the blob-level comparison)

struct HCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> HCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(count)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(be_u32(self.take(4)?))
    }
}

fn h_pgp_length(cur: &mut HCursor<'_>) -> Option<usize> {
    match cur.u8()? {
        first @ 0..=191 => Some(first as usize),
        first @ 192..=223 => {
            let second = cur.u8()?;
            Some(((first as usize - 192) << 8) + second as usize + 192)
        }
        255 => Some(cur.u32()? as usize),
        _ => None,
    }
}

fn h_parse_mpis(cur: &mut HCursor<'_>) -> Option<()> {
    let mut count = 0;
    while cur.remaining() > 0 {
        let bits = cur.u16()? as usize;
        cur.take(bits.div_ceil(8))?;
        count += 1;
    }
    if count == 0 { None } else { Some(()) }
}

fn h_issuer_from_subpackets(area: &[u8]) -> Option<Option<[u8; 8]>> {
    let mut cur = HCursor::new(area);
    let mut issuer = None;
    let mut from_fingerprint = None;
    while cur.remaining() > 0 {
        let len = h_pgp_length(&mut cur)?;
        if len == 0 {
            return None;
        }
        let subpacket = cur.take(len)?;
        let (kind, body) = subpacket.split_first()?;
        match kind {
            16 => {
                if body.len() != 8 {
                    return None;
                }
                if issuer.is_none() {
                    issuer = Some(body.try_into().expect("8 bytes"));
                }
            }
            33 => {
                let fingerprint = body.get(1..)?;
                if fingerprint.len() < 8 {
                    return None;
                }
                from_fingerprint = Some(
                    fingerprint[fingerprint.len() - 8..]
                        .try_into()
                        .expect("8 bytes"),
                );
            }
            _ => {}
        }
    }
    Some(issuer.or(from_fingerprint))
}

fn h_parse_sig_body(body: &[u8]) -> Option<Option<[u8; 8]>> {
    let mut cur = HCursor::new(body);
    match cur.u8()? {
        3 => {
            if cur.u8()? != 5 {
                return None;
            }
            cur.take(1)?;
            cur.take(4)?;
            let issuer: [u8; 8] = cur.take(8)?.try_into().expect("8 bytes");
            cur.take(1)?;
            cur.take(1)?;
            cur.take(2)?;
            h_parse_mpis(&mut cur)?;
            Some(Some(issuer))
        }
        version @ 4..=6 => {
            cur.take(1)?;
            cur.take(1)?;
            cur.take(1)?;
            let wide = version == 6;
            let hashed_len = if wide {
                cur.u32()? as usize
            } else {
                cur.u16()? as usize
            };
            let hashed = cur.take(hashed_len)?.to_vec();
            let unhashed_len = if wide {
                cur.u32()? as usize
            } else {
                cur.u16()? as usize
            };
            let unhashed = cur.take(unhashed_len)?.to_vec();
            cur.take(2)?;
            h_parse_mpis(&mut cur)?;
            let issuer = h_issuer_from_subpackets(&unhashed)?.or(h_issuer_from_subpackets(&hashed)?);
            Some(issuer)
        }
        _ => None,
    }
}

/// Returns None when the hand parser rejects the packet, else the
/// issuer it extracted (itself possibly None).
fn h_parse_sig_packet(blob: &[u8]) -> Option<Option<[u8; 8]>> {
    let mut cur = HCursor::new(blob);
    let first = cur.u8()?;
    if first & 0x80 == 0 {
        return None;
    }
    let mut length_delimited = true;
    let body = if first & 0x40 != 0 {
        if first & 0x3f != 2 {
            return None;
        }
        let len = h_pgp_length(&mut cur)?;
        cur.take(len)?
    } else {
        if (first >> 2) & 0x0f != 2 {
            return None;
        }
        match first & 0x03 {
            0 => {
                let len = cur.u8()? as usize;
                cur.take(len)?
            }
            1 => {
                let len = cur.u16()? as usize;
                cur.take(len)?
            }
            2 => {
                let len = cur.u32()? as usize;
                cur.take(len)?
            }
            _ => {
                length_delimited = false;
                &cur.buf[cur.pos..]
            }
        }
    };
    if length_delimited && cur.pos != blob.len() {
        return None;
    }
    h_parse_sig_body(body)
}

// ---------- sequoia side ----------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The issuer of a parsed signature the way #730 extracts it: unhashed
/// area first (issuer subpacket wins over issuer-fingerprint within an
/// area), then the hashed area; version 3 packets carry it in the body.
fn seq_issuer(sig: &Signature) -> Option<[u8; 8]> {
    fn area_issuer(area: &openpgp::packet::signature::subpacket::SubpacketArea)
        -> Option<[u8; 8]>
    {
        use openpgp::packet::signature::subpacket::{
            SubpacketTag, SubpacketValue,
        };
        let mut issuer = None;
        let mut from_fingerprint = None;
        for sub in area.iter(SubpacketTag::Issuer) {
            if issuer.is_none() {
                if let SubpacketValue::Issuer(key_id) = sub.value() {
                    issuer = Some(key_id.as_slice().try_into().ok()?);
                }
            }
        }
        for sub in area.iter(SubpacketTag::IssuerFingerprint) {
            if let SubpacketValue::IssuerFingerprint(fp) = sub.value() {
                let b = fp.as_slice();
                if b.len() >= 8 {
                    from_fingerprint =
                        Some(b[b.len() - 8..].try_into().expect("8 bytes"));
                }
            }
        }
        issuer.or(from_fingerprint)
    }
    if sig.version() == 3 {
        return sig.issuers().next().and_then(|h| match h {
            KeyHandle::KeyID(kid) => Some(kid.as_slice().try_into().ok()?),
            KeyHandle::Fingerprint(fp) => {
                let b = fp.as_slice();
                Some(b[b.len() - 8..].try_into().ok()?)
            }
        });
    }
    area_issuer(sig.unhashed_area())
        .or_else(|| area_issuer(sig.hashed_area()))
        .or_else(|| {
            sig.issuers().next().and_then(|h| match h {
                KeyHandle::KeyID(kid) => Some(kid.as_slice().try_into().ok()?),
                KeyHandle::Fingerprint(fp) => {
                    let b = fp.as_slice();
                    Some(b[b.len() - 8..].try_into().ok()?)
                }
            })
        })
}

/// Parse one blob as exactly one signature packet.
fn seq_parse(blob: &[u8]) -> Result<Signature, String> {
    let mut pp = PacketParser::from_bytes(blob.to_vec())
        .map_err(|e| e.to_string())?;
    match pp.next().map_err(|e| e.to_string())? {
        Some((Packet::Signature(sig), rest)) => {
            // The blob must be exactly this one packet.
            match rest.next().map_err(|e| e.to_string())? {
                None => Ok(sig),
                Some(_) => Err("trailing packets".into()),
            }
        }
        Some((other, _)) => Err(format!("packet tag {:?}", other.tag())),
        None => Err("empty".into()),
    }
}

fn find_key<'a>(certs: &'a [Cert], sig: &Signature) -> Option<KeyAmalgamation<'a>> {
    let issuers: Vec<KeyHandle> = sig.issuers().cloned().collect();
    for cert in certs {
        for ka in cert.keys() {
            let handle = ka.key_handle();
            if issuers.iter().any(|i| i.alias(&handle))
                || issuers.is_empty()
            {
                return Some(ka);
            }
        }
    }
    None
}

struct Helper<'a> {
    certs: &'a [Cert],
    outcome: String,
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self
            .certs
            .iter()
            .filter(|c| {
                c.keys().any(|ka| {
                    ids.iter().any(|id| id.alias(&ka.key_handle()))
                })
            })
            .cloned()
            .collect())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    match r {
                        VerificationResult::GoodChecksum(_) => {
                            self.outcome = "good".into()
                        }
                        VerificationResult::BadChecksum(_) => {
                            self.outcome = "bad".into()
                        }
                        VerificationResult::MissingKey(_) => {
                            self.outcome = "missing".into()
                        }
                        VerificationResult::MalformedSignature(_) => {
                            self.outcome = "malformed".into()
                        }
                        VerificationResult::UnknownSignature(_) => {
                            self.outcome = "unknown".into()
                        }
                        _ => self.outcome = "other".into(),
                    }
                }
            }
        }
        Ok(())
    }
}

fn builder_verify(
    policy: &dyn Policy,
    certs: &[Cert],
    blob: &[u8],
    path: &Path,
    range: (u64, u64),
) -> String {
    let helper = Helper {
        certs,
        outcome: "none".into(),
    };
    let built = DetachedVerifierBuilder::from_bytes(blob.to_vec())
        .and_then(|b| b.with_policy(policy, None, helper));
    let mut verifier = match built {
        Ok(v) => v,
        Err(e) => return format!("builderr:{e}"),
    };
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return format!("ioerr:{e}"),
    };
    if file.seek(SeekFrom::Start(range.0)).is_err() {
        return "ioerr:seek".into();
    }
    let mut src = file.take(range.1 - range.0);
    match verifier.verify(&mut src) {
        Ok(()) => verifier.into_helper().outcome,
        Err(e) => format!("verifyerr:{e}"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut key_files: Vec<String> = Vec::new();
    let mut use_builder = false;
    let mut use_hand = false;
    let mut rpms: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--keys" => {
                i += 1;
                key_files = args[i].split(',').map(str::to_string).collect();
            }
            "--builder" => use_builder = true,
            "--hand" => use_hand = true,
            other => rpms.push(other.to_string()),
        }
        i += 1;
    }
    let mut certs: Vec<Cert> = Vec::new();
    for kf in &key_files {
        let bytes = std::fs::read(kf).expect("read key file");
        for cert in CertParser::from_bytes(&bytes).expect("parse keyring") {
            certs.push(cert.expect("parse cert"));
        }
    }
    let null_policy = NullPolicy::new();
    let std_policy = StandardPolicy::new();
    for rpm in &rpms {
        let path = Path::new(rpm);
        let Some(sliced) = slice_rpm(path) else {
            println!("{{\"path\": {}, \"entries\": false, \"sigs\": [], \"unreadable_container\": true}}", json_str(rpm));
            continue;
        };
        let mut sig_json: Vec<String> = Vec::new();
        for entry in &sliced.entries {
            let scope = match entry.tag {
                267 | 268 => "header",
                _ => "header+payload",
            };
            let range = if scope == "header" {
                sliced.header_range
            } else {
                (sliced.header_payload_from, sliced.file_len)
            };
            // hand parser verdict
            let hand = if use_hand {
                match h_parse_sig_packet(&entry.blob) {
                    None => "\"none\"".to_string(),
                    Some(None) => "null".to_string(),
                    Some(Some(issuer)) => format!("\"{}\"", hex(&issuer[4..])),
                }
            } else {
                "null".to_string()
            };
            // sequoia parse + low-level verify
            let (parse, ver, pk, hash, issuer_s, key_s, verify_s) =
                match seq_parse(&entry.blob) {
                    Ok(sig) => {
                        let issuer = seq_issuer(&sig);
                        let issuer_s = match issuer {
                            Some(k) => format!("\"{}\"", hex(&k[4..])),
                            None => "null".into(),
                        };
                        let (key_s, verify_s) = match find_key(&certs, &sig) {
                            Some(ka) => {
                                let key = ka.key().clone().role_as_unspecified();
                                let mut ctx = match sig.hash_algo().context() {
                                    Ok(c) => c,
                                    Err(e) => {
                                        return;
                                    }
                                };
                                // stream the signed data through the hash
                                let v = (|| -> Result<(), String> {
                                    let mut f = File::open(path)
                                        .map_err(|e| e.to_string())?;
                                    f.seek(SeekFrom::Start(range.0))
                                        .map_err(|e| e.to_string())?;
                                    let mut src = f.take(range.1 - range.0);
                                    let mut buf = vec![0u8; 1 << 20];
                                    loop {
                                        let n = src
                                            .read(&mut buf)
                                            .map_err(|e| e.to_string())?;
                                        if n == 0 {
                                            break;
                                        }
                                        ctx.update(&buf[..n]);
                                    }
                                    Ok(())
                                })();
                                match v {
                                    Ok(()) => match sig.verify_hash(&key, ctx) {
                                        Ok(()) => ("found", "good"),
                                        Err(_) => ("found", "bad"),
                                    },
                                    Err(_) => ("found", "ioerr"),
                                }
                            }
                            None => ("missing", "na"),
                        };
                        (
                            "\"ok\"".to_string(),
                            sig.version().to_string(),
                            u8::from(sig.pk_algo()).to_string(),
                            u8::from(sig.hash_algo()).to_string(),
                            issuer_s,
                            key_s.to_string(),
                            verify_s.to_string(),
                        )
                    }
                    Err(e) => (
                        format!("\"err:{}\"", e.replace('"', "'")),
                        "null".into(),
                        "null".into(),
                        "null".into(),
                        "null".into(),
                        "na".into(),
                        "na".into(),
                    ),
                };
            let builder_fields = if use_builder {
                let bn = builder_verify(
                    &null_policy, &certs, &entry.blob, path, range,
                );
                let bs = builder_verify(
                    &std_policy, &certs, &entry.blob, path, range,
                );
                format!(", \"builder_null\": \"{bn}\", \"builder_std\": \"{bs}\"")
            } else {
                String::new()
            };
            let _ = entry.offset;
            sig_json.push(format!(
                "{{\"tag\": {}, \"scope\": \"{}\", \"hand\": {}, \"parse\": {}, \"ver\": {}, \"pk_algo\": {}, \"hash_algo\": {}, \"issuer\": {}, \"key\": \"{}\", \"verify\": \"{}\"{} }}",
                entry.tag, scope, hand, parse, ver, pk, hash, issuer_s, key_s, verify_s, builder_fields
            ));
        }
        println!(
            "{{\"path\": {}, \"entries\": {}, \"sigs\": [{}]}}",
            json_str(rpm),
            sliced.has_entries,
            sig_json.join(", ")
        );
    }
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
