//! Just enough DNS wire format for the diagnostic commands.
//!
//! The stub itself parses nothing — it forwards bytes (see [`crate::stub`]). This module exists
//! only so `dns-ai-svc test-doh` can build one query and describe one answer, which is what makes
//! it possible to prove the resolver is reachable and in scope **before** touching the machine's
//! DNS settings. Diagnosing a broken client after the adapters have been rewritten is much
//! harder than checking first.

use anyhow::{bail, Result};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_TXT: u16 = 16;

pub fn qtype_from_str(s: &str) -> Option<u16> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(TYPE_A),
        "AAAA" => Some(TYPE_AAAA),
        "CNAME" => Some(TYPE_CNAME),
        "TXT" => Some(TYPE_TXT),
        _ => None,
    }
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "?",
    }
}

pub fn build_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>> {
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00]); // RD
    m.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN / NS / AR

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            bail!("пустая метка в имени «{name}»");
        }
        if label.len() > 63 {
            bail!("метка длиннее 63 байт в имени «{name}»");
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0x00, 0x01]); // IN
    Ok(m)
}

#[derive(Debug)]
pub struct Summary {
    pub rcode: u8,
    pub answer_count: u16,
    /// One line per answer record, already formatted for a human.
    pub answers: Vec<String>,
}

pub fn summarize(msg: &[u8]) -> Result<Summary> {
    if msg.len() < 12 {
        bail!("ответ короче заголовка ({} байт)", msg.len());
    }
    let rcode = msg[3] & 0x0F;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);

    let mut i = 12;
    for _ in 0..qdcount {
        i = skip_name(msg, i)?;
        i += 4;
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        i = skip_name(msg, i)?;
        if i + 10 > msg.len() {
            bail!("ответ обрывается в заголовке записи");
        }
        let rtype = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let ttl = u32::from_be_bytes([msg[i + 4], msg[i + 5], msg[i + 6], msg[i + 7]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        let rdata = msg
            .get(i..i + rdlen)
            .ok_or_else(|| anyhow::anyhow!("ответ обрывается в данных записи"))?;
        answers.push(format!(
            "{:<6} ttl={ttl:<6} {}",
            type_name(rtype),
            rdata_text(msg, rtype, rdata)
        ));
        i += rdlen;
    }

    Ok(Summary {
        rcode,
        answer_count: ancount,
        answers,
    })
}

fn type_name(t: u16) -> &'static str {
    match t {
        TYPE_A => "A",
        TYPE_AAAA => "AAAA",
        TYPE_CNAME => "CNAME",
        TYPE_TXT => "TXT",
        _ => "прочее",
    }
}

fn rdata_text(msg: &[u8], rtype: u16, rdata: &[u8]) -> String {
    match rtype {
        TYPE_A if rdata.len() == 4 => {
            format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
        }
        TYPE_AAAA if rdata.len() == 16 => {
            let mut parts = Vec::new();
            for c in rdata.chunks(2) {
                parts.push(format!("{:x}", u16::from_be_bytes([c[0], c[1]])));
            }
            parts.join(":")
        }
        TYPE_TXT => {
            let mut out = Vec::new();
            let mut k = 0;
            while k < rdata.len() {
                let l = rdata[k] as usize;
                k += 1;
                if k + l > rdata.len() {
                    break;
                }
                out.push(String::from_utf8_lossy(&rdata[k..k + l]).into_owned());
                k += l;
            }
            format!("\"{}\"", out.join(""))
        }
        TYPE_CNAME => {
            // The offset of rdata inside the message is needed to follow compression pointers.
            let off = rdata.as_ptr() as usize - msg.as_ptr() as usize;
            read_name(msg, off).unwrap_or_else(|_| "<нечитаемое имя>".into())
        }
        _ => format!("{} байт", rdata.len()),
    }
}

fn skip_name(msg: &[u8], mut i: usize) -> Result<usize> {
    loop {
        let len = *msg
            .get(i)
            .ok_or_else(|| anyhow::anyhow!("имя выходит за границы сообщения"))?
            as usize;
        if len == 0 {
            return Ok(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            // A pointer is always the last thing in a name.
            return Ok(i + 2);
        }
        i += 1 + len;
    }
}

fn read_name(msg: &[u8], mut i: usize) -> Result<String> {
    let mut out = String::new();
    // A bounded number of jumps: a message that points into itself in a cycle would otherwise
    // spin here forever, and that is a shape a hostile answer can have.
    let mut jumps = 0;
    loop {
        let len = *msg
            .get(i)
            .ok_or_else(|| anyhow::anyhow!("имя выходит за границы сообщения"))?
            as usize;
        if len == 0 {
            return Ok(out);
        }
        if len & 0xC0 == 0xC0 {
            jumps += 1;
            if jumps > 16 {
                bail!("цикл указателей сжатия");
            }
            let lo = *msg
                .get(i + 1)
                .ok_or_else(|| anyhow::anyhow!("оборванный указатель"))?
                as usize;
            i = ((len & 0x3F) << 8) | lo;
            continue;
        }
        let end = i + 1 + len;
        let label = msg
            .get(i + 1..end)
            .ok_or_else(|| anyhow::anyhow!("метка выходит за границы"))?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        i = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trips_through_the_parser() {
        let q = build_query("example.com", TYPE_A, 0xBEEF).unwrap();
        assert_eq!(&q[0..2], &[0xBE, 0xEF]);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1);
        assert!(q.ends_with(&[0x00, 0x01, 0x00, 0x01]));
        // Zero answers, so summarising it exercises the question-skipping path.
        let s = summarize(&q).unwrap();
        assert_eq!(s.answer_count, 0);
    }

    #[test]
    fn rejects_a_malformed_name() {
        assert!(build_query("a..b", TYPE_A, 1).is_err());
        assert!(build_query(&"x".repeat(64), TYPE_A, 1).is_err());
    }

    #[test]
    fn parses_an_a_answer_with_a_compression_pointer() {
        let mut m = build_query("example.com", TYPE_A, 1).unwrap();
        m[3] = 0; // RCODE 0
        m[6] = 0;
        m[7] = 1; // ANCOUNT = 1
        m.extend_from_slice(&[0xC0, 0x0C]); // name -> offset 12
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01]); // IN
        m.extend_from_slice(&60u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[93, 184, 216, 34]);

        let s = summarize(&m).unwrap();
        assert_eq!(s.rcode, 0);
        assert_eq!(s.answer_count, 1);
        assert!(s.answers[0].contains("93.184.216.34"), "{:?}", s.answers);
    }

    #[test]
    fn a_pointer_cycle_does_not_hang() {
        // Two pointers aimed at each other: read_name must give up, not spin.
        let msg = vec![0xC0, 0x02, 0xC0, 0x00];
        assert!(read_name(&msg, 0).is_err());
    }
}
