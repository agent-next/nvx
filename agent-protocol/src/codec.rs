// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use serde::Serialize;

pub const OPENVMM_OUTER_RECORD_MAX_BYTES: usize = 65_536;
pub const INNER_RECORD_MAX_BYTES: usize = 65_504;
pub const INNER_RECORD_HEADER_BYTES: usize = 20;
pub const MAX_STREAM_CHUNK_BYTES: usize = INNER_RECORD_MAX_BYTES - INNER_RECORD_HEADER_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InnerRecordKind {
    Control = 0,
    Stdin = 1,
    Stdout = 2,
    Stderr = 3,
}

impl InnerRecordKind {
    fn from_u8(value: u8) -> Result<Self, InnerRecordDecodeError> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Stdin),
            2 => Ok(Self::Stdout),
            3 => Ok(Self::Stderr),
            other => Err(InnerRecordDecodeError::UnknownKind(other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerRecord {
    pub exec_id: u32,
    pub kind: InnerRecordKind,
    pub end_of_stream: bool,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl InnerRecord {
    pub fn control<T: Serialize>(message: &T) -> Result<Self, InnerRecordEncodeError> {
        let payload =
            serde_json::to_vec(message).map_err(InnerRecordEncodeError::ControlSerialization)?;
        Ok(Self {
            exec_id: 0,
            kind: InnerRecordKind::Control,
            end_of_stream: false,
            sequence: 0,
            payload,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, InnerRecordEncodeError> {
        if self.kind != InnerRecordKind::Control && self.payload.len() > MAX_STREAM_CHUNK_BYTES {
            return Err(InnerRecordEncodeError::ChunkTooLarge);
        }
        let total_len = INNER_RECORD_HEADER_BYTES
            .checked_add(self.payload.len())
            .ok_or(InnerRecordEncodeError::LengthOverflow)?;
        if total_len > INNER_RECORD_MAX_BYTES {
            return Err(InnerRecordEncodeError::RecordTooLarge);
        }
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&(total_len as u32).to_be_bytes());
        out.extend_from_slice(&self.exec_id.to_be_bytes());
        out.push(self.kind as u8);
        out.push(u8::from(self.end_of_stream));
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, InnerRecordDecodeError> {
        if encoded.len() < INNER_RECORD_HEADER_BYTES {
            return Err(InnerRecordDecodeError::Truncated);
        }
        let declared_len = u32::from_be_bytes(encoded[..4].try_into().expect("header")) as usize;
        if declared_len != encoded.len() {
            return Err(InnerRecordDecodeError::LengthMismatch);
        }
        if declared_len > INNER_RECORD_MAX_BYTES {
            return Err(InnerRecordDecodeError::RecordTooLarge);
        }
        Ok(Self {
            exec_id: u32::from_be_bytes(encoded[4..8].try_into().expect("exec id")),
            kind: InnerRecordKind::from_u8(encoded[8])?,
            end_of_stream: encoded[9] == 1,
            sequence: u64::from_be_bytes(encoded[12..20].try_into().expect("sequence")),
            payload: encoded[INNER_RECORD_HEADER_BYTES..].to_vec(),
        })
    }
}

#[derive(Debug)]
pub enum InnerRecordEncodeError {
    ChunkTooLarge,
    LengthOverflow,
    RecordTooLarge,
    ControlSerialization(serde_json::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InnerRecordDecodeError {
    Truncated,
    LengthMismatch,
    UnknownKind(u8),
    RecordTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedRecordTooLargeError {
    pub encoded_len: usize,
    pub max_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_cap_stays_below_openvmm_outer_limit() {
        assert!(INNER_RECORD_MAX_BYTES < OPENVMM_OUTER_RECORD_MAX_BYTES);
    }

    #[test]
    fn stream_chunk_bound_uses_checked_arithmetic() {
        assert_eq!(
            MAX_STREAM_CHUNK_BYTES,
            INNER_RECORD_MAX_BYTES
                .checked_sub(INNER_RECORD_HEADER_BYTES)
                .expect("checked arithmetic")
        );
    }
}
