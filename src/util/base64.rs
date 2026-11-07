//! Standard Base64 (RFC 4648 §4) with padding, used by the SSE frame format
//! and by the WebSocket handshake.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn decode_table() -> [i8; 256] {
    let mut t = [-1i8; 256];
    let mut i = 0;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as i8;
        i += 1;
    }
    t
}

static DECODE: [i8; 256] = decode_table();

pub fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

pub fn encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(encoded_len(data.len()));
    encode_into(data, &mut out);
    // The alphabet is ASCII by construction.
    String::from_utf8(out).expect("base64 output is ASCII")
}

pub fn encode_into(data: &[u8], out: &mut Vec<u8>) {
    let mut chunks = data.chunks_exact(3);
    for c in &mut chunks {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | c[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f]);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f]);
        out.push(ALPHABET[(n >> 6) as usize & 0x3f]);
        out.push(ALPHABET[n as usize & 0x3f]);
    }
    match chunks.remainder() {
        [a] => {
            let n = (*a as u32) << 16;
            out.push(ALPHABET[(n >> 18) as usize & 0x3f]);
            out.push(ALPHABET[(n >> 12) as usize & 0x3f]);
            out.push(b'=');
            out.push(b'=');
        }
        [a, b] => {
            let n = ((*a as u32) << 16) | ((*b as u32) << 8);
            out.push(ALPHABET[(n >> 18) as usize & 0x3f]);
            out.push(ALPHABET[(n >> 12) as usize & 0x3f]);
            out.push(ALPHABET[(n >> 6) as usize & 0x3f]);
            out.push(b'=');
        }
        _ => {}
    }
}

pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return Err("base64 length is not a multiple of 4".into());
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let mut i = 0;
    while i < b.len() {
        let quad = &b[i..i + 4];
        let mut vals = [0u8; 4];
        let mut pad = 0;
        for (k, &c) in quad.iter().enumerate() {
            if c == b'=' {
                // Padding is only legal in the last quad, and only in the last
                // one or two positions.
                if i + 4 != b.len() || k < 2 {
                    return Err("misplaced base64 padding".into());
                }
                pad += 1;
                vals[k] = 0;
                continue;
            }
            if pad > 0 {
                return Err("base64 padding before the end".into());
            }
            let v = DECODE[c as usize];
            if v < 0 {
                return Err("invalid base64 character".into());
            }
            vals[k] = v as u8;
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | vals[3] as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad == 0 {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 % 256) as u8).collect();
            let e = encode(&data);
            assert_eq!(e.len(), encoded_len(n));
            assert_eq!(decode(&e).unwrap(), data);
        }
    }

    #[test]
    fn known_values() {
        assert_eq!(encode(b"hello"), "aGVsbG8=");
        assert_eq!(encode(b"a"), "YQ==");
        assert_eq!(encode(b"ab"), "YWI=");
        assert_eq!(encode(b"abc"), "YWJj");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("aGVsbG8").is_err());
        assert!(decode("aGVs bG8=").is_err());
        assert!(decode("====").is_err());
    }
}
