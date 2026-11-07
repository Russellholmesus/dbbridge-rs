//! Framing: how one chunk of a byte stream becomes a WebSocket message or an
//! SSE data line, and back.

use crate::error::{Error, Result};
use crate::util::json::canonical_offset;
use crate::util::{base64, hex, sha256};

use super::{ERR_BAD_DIGEST, ERR_BAD_FRAME, MAX_FRAME_PAYLOAD, WS_DATA_TYPE, WS_HEADER_LEN};

/// A decoded DATA frame.
#[derive(Debug)]
pub struct Frame<'a> {
    pub epoch: u64,
    pub offset: u64,
    pub payload: &'a [u8],
}

pub fn encode_ws_frame(epoch: u64, offset: u64, payload: &[u8]) -> Result<Vec<u8>> {
    if epoch == 0 || payload.is_empty() || payload.len() > MAX_FRAME_PAYLOAD {
        return Err(Error::new(ERR_BAD_FRAME, "invalid frame range"));
    }
    if offset.checked_add(payload.len() as u64).is_none() {
        return Err(Error::new(ERR_BAD_FRAME, "frame offset overflow"));
    }
    let mut msg = Vec::with_capacity(WS_HEADER_LEN + payload.len());
    msg.push(WS_DATA_TYPE);
    msg.push(0); // flags
    msg.extend_from_slice(&[0, 0]); // reserved
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(&offset.to_be_bytes());
    msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    msg.extend_from_slice(&sha256::digest(payload));
    msg.extend_from_slice(payload);
    Ok(msg)
}

pub fn decode_ws_frame(msg: &[u8]) -> Result<Frame<'_>> {
    if msg.len() < WS_HEADER_LEN {
        return Err(Error::new(
            ERR_BAD_FRAME,
            "frame smaller than 56-byte header",
        ));
    }
    if msg[0] != WS_DATA_TYPE {
        return Err(Error::new(ERR_BAD_FRAME, "invalid frame type"));
    }
    if msg[1] != 0 || msg[2] != 0 || msg[3] != 0 {
        return Err(Error::new(
            ERR_BAD_FRAME,
            "invalid frame flags or reserved bytes",
        ));
    }
    let epoch = u64::from_be_bytes(msg[4..12].try_into().expect("8 bytes"));
    let offset = u64::from_be_bytes(msg[12..20].try_into().expect("8 bytes"));
    let length = u32::from_be_bytes(msg[20..24].try_into().expect("4 bytes")) as usize;
    if epoch == 0 || length == 0 || length > MAX_FRAME_PAYLOAD {
        return Err(Error::new(ERR_BAD_FRAME, "invalid frame range"));
    }
    if length != msg.len() - WS_HEADER_LEN {
        return Err(Error::new(ERR_BAD_FRAME, "frame length mismatch"));
    }
    if offset.checked_add(length as u64).is_none() {
        return Err(Error::new(ERR_BAD_FRAME, "frame offset overflow"));
    }
    let payload = &msg[WS_HEADER_LEN..];
    let sum = sha256::digest(payload);
    if sum[..] != msg[24..56] {
        return Err(Error::new(ERR_BAD_DIGEST, "frame sha256 mismatch"));
    }
    Ok(Frame {
        epoch,
        offset,
        payload,
    })
}

/// `<offset>:<length>:<sha256 hex>:<base64 payload>`
pub fn format_sse_data(offset: u64, payload: &[u8]) -> Result<String> {
    if payload.is_empty() || payload.len() > MAX_FRAME_PAYLOAD {
        return Err(Error::new(ERR_BAD_FRAME, "invalid frame range"));
    }
    if offset.checked_add(payload.len() as u64).is_none() {
        return Err(Error::new(ERR_BAD_FRAME, "frame offset overflow"));
    }
    Ok(format!(
        "{}:{}:{}:{}",
        offset,
        payload.len(),
        hex(&sha256::digest(payload)),
        base64::encode(payload)
    ))
}

pub fn parse_sse_data(line: &str) -> Result<(u64, Vec<u8>)> {
    let mut parts = line.splitn(4, ':');
    let (off_s, len_s, sha_s, b64_s) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => return Err(Error::new(ERR_BAD_FRAME, "invalid sse data format")),
        };
    let offset =
        canonical_offset(off_s).ok_or_else(|| Error::new(ERR_BAD_FRAME, "invalid sse offset"))?;
    let length = canonical_offset(len_s)
        .ok_or_else(|| Error::new(ERR_BAD_FRAME, "invalid sse length"))? as usize;
    if length == 0 || length > MAX_FRAME_PAYLOAD {
        return Err(Error::new(ERR_BAD_FRAME, "invalid sse length"));
    }
    if offset.checked_add(length as u64).is_none() {
        return Err(Error::new(ERR_BAD_FRAME, "sse offset overflow"));
    }
    if sha_s.len() != 64 || sha_s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Error::new(ERR_BAD_FRAME, "invalid sse digest"));
    }
    if b64_s.len() != base64::encoded_len(length) {
        // The length is in the message: this is what a carrier that re-framed
        // or truncated the payload looks like, and the numbers identify it.
        return Err(Error::new(
            ERR_BAD_FRAME,
            format!(
                "invalid base64 payload length: {} bytes for a {length}-byte frame, expected {}",
                b64_s.len(),
                base64::encoded_len(length)
            ),
        ));
    }
    let payload = base64::decode(b64_s).map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
    if payload.len() != length {
        return Err(Error::new(ERR_BAD_FRAME, "payload length mismatch"));
    }
    if base64::encode(&payload) != b64_s {
        return Err(Error::new(ERR_BAD_FRAME, "non-canonical base64 payload"));
    }
    if hex(&sha256::digest(&payload)) != sha_s {
        return Err(Error::new(ERR_BAD_DIGEST, "payload sha256 mismatch"));
    }
    Ok((offset, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::sha256;

    #[test]
    fn ws_frame_bytes_bind_header_offsets_digest_and_payload() {
        let epoch = 0x0102_0304_0506_0708;
        let offset = 0x1112_1314_1516_1718;
        let message = encode_ws_frame(epoch, offset, b"x").unwrap();
        assert_eq!(message.len(), WS_HEADER_LEN + 1);
        assert_eq!(message[0], WS_DATA_TYPE);
        assert_eq!(&message[1..4], &[0, 0, 0]);
        assert_eq!(&message[4..12], &epoch.to_be_bytes());
        assert_eq!(&message[12..20], &offset.to_be_bytes());
        assert_eq!(&message[20..24], &1u32.to_be_bytes());
        assert_eq!(&message[24..56], &sha256::digest(b"x"));
        assert_eq!(&message[WS_HEADER_LEN..], b"x");

        let decoded = decode_ws_frame(&message).unwrap();
        assert_eq!(decoded.epoch, epoch);
        assert_eq!(decoded.offset, offset);
        assert_eq!(decoded.payload, b"x");
    }

    #[test]
    fn ws_frame_decoder_rejects_reserved_zero_length_and_offset_overflow() {
        let valid = encode_ws_frame(1, 0, b"x").unwrap();

        let mut reserved = valid.clone();
        reserved[2] = 1;
        assert_eq!(decode_ws_frame(&reserved).unwrap_err().code, ERR_BAD_FRAME);

        let mut zero_length = valid.clone();
        zero_length.truncate(WS_HEADER_LEN);
        zero_length[20..24].copy_from_slice(&0u32.to_be_bytes());
        zero_length[24..56].copy_from_slice(&sha256::digest(b""));
        assert_eq!(
            decode_ws_frame(&zero_length).unwrap_err().code,
            ERR_BAD_FRAME
        );

        let mut overflow = valid;
        overflow[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(decode_ws_frame(&overflow).unwrap_err().code, ERR_BAD_FRAME);
    }

    #[test]
    fn ws_frame_encoder_enforces_max_payload_and_offset_range() {
        assert_eq!(encode_ws_frame(1, 0, b"").unwrap_err().code, ERR_BAD_FRAME);
        assert_eq!(
            encode_ws_frame(1, 0, &vec![0; MAX_FRAME_PAYLOAD + 1])
                .unwrap_err()
                .code,
            ERR_BAD_FRAME
        );
        assert_eq!(
            encode_ws_frame(1, u64::MAX, b"x").unwrap_err().code,
            ERR_BAD_FRAME
        );

        let payload = vec![0x5a; MAX_FRAME_PAYLOAD];
        let message = encode_ws_frame(1, 7, &payload).unwrap();
        let decoded = decode_ws_frame(&message).unwrap();
        assert_eq!(decoded.offset, 7);
        assert_eq!(decoded.payload.len(), MAX_FRAME_PAYLOAD);
        assert_eq!(decoded.payload, payload);
    }
}
