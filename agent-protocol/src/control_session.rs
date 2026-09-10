// Copyright(c) The microvm authors.
// Licensed under the MIT License.

use std::io::{self, Read, Write};

pub const CONTROL_HEADER_BYTES: usize = 44;
pub const CONTROL_MAX_DATA_BYTES: usize = 65_536;
pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
pub const CONTROL_PROTOCOL_MAGIC: [u8; 4] = *b"NVXS";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordType {
    GuestAttach = 1,
    HostAttach = 2,
    Reset = 3,
    Ack = 4,
    Data = 5,
    Wait = 6,
    Ready = 7,
    Error = 8,
}

impl TryFrom<u8> for RecordType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::GuestAttach),
            2 => Ok(Self::HostAttach),
            3 => Ok(Self::Reset),
            4 => Ok(Self::Ack),
            5 => Ok(Self::Data),
            6 => Ok(Self::Wait),
            7 => Ok(Self::Ready),
            8 => Ok(Self::Error),
            _ => Err(ProtocolError::InvalidType(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub record_type: RecordType,
    pub instance_id: [u8; 16],
    pub epoch: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn bootstrap(record_type: RecordType, payload: Vec<u8>) -> Self {
        Self {
            record_type,
            instance_id: [0; 16],
            epoch: 0,
            sequence: 0,
            payload,
        }
    }

    pub fn session(
        record_type: RecordType,
        instance_id: [u8; 16],
        epoch: u64,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            record_type,
            instance_id,
            epoch,
            sequence,
            payload,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidMagic,
    InvalidVersion(u16),
    InvalidType(u8),
    InvalidFlags(u8),
    InvalidPayloadLength {
        record_type: RecordType,
        length: u32,
    },
    InvalidErrorCode(u32),
    InvalidBootstrapIdentity,
    InvalidSnapshot(&'static str),
    LengthOverflow,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid control-session magic"),
            Self::InvalidVersion(version) => {
                write!(f, "unsupported control-session version {version}")
            }
            Self::InvalidType(value) => write!(f, "unknown control-session record type {value}"),
            Self::InvalidFlags(value) => {
                write!(f, "control-session flags must be zero, got {value}")
            }
            Self::InvalidPayloadLength {
                record_type,
                length,
            } => write!(f, "invalid payload length {length} for {record_type:?}"),
            Self::InvalidErrorCode(code) => write!(f, "invalid control-session error code {code}"),
            Self::InvalidBootstrapIdentity => {
                write!(f, "bootstrap record contains session identity")
            }
            Self::InvalidSnapshot(message) => write!(f, "invalid parser snapshot: {message}"),
            Self::LengthOverflow => write!(f, "encoded record length overflows platform size"),
        }
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParserSnapshot {
    pub header_bytes: Vec<u8>,
    pub header_count: usize,
    pub body_bytes: Vec<u8>,
    pub declared_body_len: Option<u32>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ParseProgress {
    pub consumed: usize,
    pub record: Option<Record>,
}

#[derive(Clone, Copy)]
struct ParsedHeader {
    record_type: RecordType,
    instance_id: [u8; 16],
    epoch: u64,
    sequence: u64,
    payload_len: usize,
}

#[derive(Clone, Debug)]
pub struct Parser {
    header: [u8; CONTROL_HEADER_BYTES],
    header_count: usize,
    body: Vec<u8>,
    declared_body_len: Option<usize>,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub fn new() -> Self {
        Self {
            header: [0; CONTROL_HEADER_BYTES],
            header_count: 0,
            body: Vec::new(),
            declared_body_len: None,
        }
    }

    pub fn accept(&mut self, input: &[u8]) -> Result<ParseProgress, ProtocolError> {
        let mut consumed = 0;
        if self.header_count < CONTROL_HEADER_BYTES {
            let take = (CONTROL_HEADER_BYTES - self.header_count).min(input.len());
            self.header[self.header_count..self.header_count + take]
                .copy_from_slice(&input[..take]);
            self.header_count += take;
            consumed += take;
            if self.header_count < CONTROL_HEADER_BYTES {
                return Ok(ParseProgress {
                    consumed,
                    record: None,
                });
            }
            let header = parse_header(&self.header)?;
            self.declared_body_len = Some(header.payload_len);
            if header.payload_len == 0 {
                let record = record_from_parts(header, Vec::new())?;
                self.reset();
                return Ok(ParseProgress {
                    consumed,
                    record: Some(record),
                });
            }
            self.body = Vec::with_capacity(header.payload_len);
        }

        let declared = self
            .declared_body_len
            .ok_or(ProtocolError::InvalidSnapshot(
                "missing declared body length",
            ))?;
        let remaining =
            declared
                .checked_sub(self.body.len())
                .ok_or(ProtocolError::InvalidSnapshot(
                    "body exceeds declared length",
                ))?;
        let available = &input[consumed..];
        let take = remaining.min(available.len());
        self.body.extend_from_slice(&available[..take]);
        consumed += take;
        if self.body.len() != declared {
            return Ok(ParseProgress {
                consumed,
                record: None,
            });
        }

        let header = parse_header(&self.header)?;
        let body = core::mem::take(&mut self.body);
        let record = record_from_parts(header, body)?;
        self.reset();
        Ok(ParseProgress {
            consumed,
            record: Some(record),
        })
    }

    pub fn snapshot(&self) -> ParserSnapshot {
        ParserSnapshot {
            header_bytes: self.header.to_vec(),
            header_count: self.header_count,
            body_bytes: self.body.clone(),
            declared_body_len: self.declared_body_len.map(|len| len as u32),
        }
    }

    pub fn restore(snapshot: ParserSnapshot) -> Result<Self, ProtocolError> {
        Self::validate_snapshot(&snapshot)?;
        let mut header = [0; CONTROL_HEADER_BYTES];
        header.copy_from_slice(&snapshot.header_bytes);
        let body_capacity = snapshot.declared_body_len.unwrap_or(0) as usize;
        let mut body = Vec::with_capacity(body_capacity);
        body.extend_from_slice(&snapshot.body_bytes);
        Ok(Self {
            header,
            header_count: snapshot.header_count,
            body,
            declared_body_len: snapshot.declared_body_len.map(|len| len as usize),
        })
    }

    pub fn validate_snapshot(snapshot: &ParserSnapshot) -> Result<(), ProtocolError> {
        if snapshot.header_bytes.len() != CONTROL_HEADER_BYTES {
            return Err(ProtocolError::InvalidSnapshot(
                "header storage must be exactly 44 bytes",
            ));
        }
        if snapshot.header_count > CONTROL_HEADER_BYTES {
            return Err(ProtocolError::InvalidSnapshot(
                "header count exceeds header length",
            ));
        }
        if snapshot.header_count < CONTROL_HEADER_BYTES {
            if snapshot.declared_body_len.is_some() || !snapshot.body_bytes.is_empty() {
                return Err(ProtocolError::InvalidSnapshot(
                    "partial header has body state",
                ));
            }
        } else {
            let mut header = [0; CONTROL_HEADER_BYTES];
            header.copy_from_slice(&snapshot.header_bytes);
            let parsed = parse_header(&header)?;
            let declared = snapshot
                .declared_body_len
                .ok_or(ProtocolError::InvalidSnapshot(
                    "complete header has no declared body length",
                ))?;
            if declared as usize != parsed.payload_len {
                return Err(ProtocolError::InvalidSnapshot(
                    "declared body length disagrees with header",
                ));
            }
            if parsed.payload_len == 0 || snapshot.body_bytes.len() >= parsed.payload_len {
                return Err(ProtocolError::InvalidSnapshot(
                    "complete record cannot remain in parser state",
                ));
            }
        }
        Ok(())
    }

    pub fn is_aligned(&self) -> bool {
        self.header_count == 0
    }

    fn reset(&mut self) {
        self.header_count = 0;
        self.header = [0; CONTROL_HEADER_BYTES];
        self.body.clear();
        self.declared_body_len = None;
    }
}

pub fn encode(record: &Record) -> Result<Vec<u8>, ProtocolError> {
    validate_record(record)?;
    let payload_len =
        u32::try_from(record.payload.len()).map_err(|_| ProtocolError::LengthOverflow)?;
    let total_len = CONTROL_HEADER_BYTES
        .checked_add(record.payload.len())
        .ok_or(ProtocolError::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&CONTROL_PROTOCOL_MAGIC);
    bytes.extend_from_slice(&CONTROL_PROTOCOL_VERSION.to_le_bytes());
    bytes.push(record.record_type as u8);
    bytes.push(0);
    bytes.extend_from_slice(&record.instance_id);
    bytes.extend_from_slice(&record.epoch.to_le_bytes());
    bytes.extend_from_slice(&record.sequence.to_le_bytes());
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&record.payload);
    Ok(bytes)
}

pub fn decode_exact(bytes: &[u8]) -> Result<Record, ProtocolError> {
    let mut parser = Parser::new();
    let progress = parser.accept(bytes)?;
    if progress.consumed != bytes.len() || !parser.is_aligned() {
        return Err(ProtocolError::InvalidSnapshot(
            "encoded record is truncated or contains trailing bytes",
        ));
    }
    progress.record.ok_or(ProtocolError::InvalidSnapshot(
        "encoded record is incomplete",
    ))
}

#[derive(Debug)]
pub enum SessionError {
    Io(io::Error),
    Protocol(ProtocolError),
    Closed,
    SequenceMismatch { expected: u64, actual: u64 },
    SessionIdentityMismatch,
    UnexpectedRecordType(RecordType),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Closed => write!(f, "control session transport closed"),
            Self::SequenceMismatch { expected, actual } => {
                write!(f, "sequence mismatch: expected {expected}, actual {actual}")
            }
            Self::SessionIdentityMismatch => write!(f, "session identity mismatch"),
            Self::UnexpectedRecordType(record_type) => {
                write!(f, "unexpected record type {record_type:?}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

impl From<io::Error> for SessionError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ProtocolError> for SessionError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAttachStatus {
    Wait,
    Ready,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEvent {
    Wait,
    Ready,
    Data(Vec<u8>),
    Reset { instance_id: [u8; 16], epoch: u64 },
    Error(u32),
}

pub struct HostControlSession<T: Read + Write> {
    io: T,
    parser: Parser,
    instance_id: Option<[u8; 16]>,
    epoch: Option<u64>,
    send_sequence: u64,
    recv_sequence: u64,
}

impl<T: Read + Write> HostControlSession<T> {
    pub fn new(io: T) -> Self {
        Self {
            io,
            parser: Parser::new(),
            instance_id: None,
            epoch: None,
            send_sequence: 0,
            recv_sequence: 0,
        }
    }

    pub fn send_host_attach(&mut self, capability: [u8; 32]) -> Result<(), SessionError> {
        let attach = Record::bootstrap(RecordType::HostAttach, capability.to_vec());
        self.write_record(&attach)
    }

    pub fn recv_attach_status(&mut self) -> Result<HostAttachStatus, SessionError> {
        let record = self.read_record_blocking()?;
        match record.record_type {
            RecordType::Wait => {
                self.track_remote_record(&record)?;
                Ok(HostAttachStatus::Wait)
            }
            RecordType::Ready => {
                self.track_remote_record(&record)?;
                Ok(HostAttachStatus::Ready)
            }
            RecordType::Error => Ok(HostAttachStatus::Ready),
            other => Err(SessionError::UnexpectedRecordType(other)),
        }
    }

    pub fn send_data(&mut self, payload: Vec<u8>) -> Result<u64, SessionError> {
        if self.instance_id.is_none() || self.epoch.is_none() {
            return Err(SessionError::SessionIdentityMismatch);
        }
        let sequence = self.send_sequence;
        let record = Record::session(
            RecordType::Data,
            self.instance_id.expect("checked"),
            self.epoch.expect("checked"),
            sequence,
            payload,
        );
        self.write_record(&record)?;
        self.send_sequence = self.send_sequence.saturating_add(1);
        Ok(sequence)
    }

    pub fn recv_event_blocking(&mut self) -> Result<HostEvent, SessionError> {
        let record = self.read_record_blocking()?;
        self.event_from_record(record)
    }

    pub fn try_recv_event(&mut self) -> Result<Option<HostEvent>, SessionError> {
        let record = match self.try_read_record()? {
            Some(record) => record,
            None => return Ok(None),
        };
        self.event_from_record(record).map(Some)
    }

    fn event_from_record(&mut self, record: Record) -> Result<HostEvent, SessionError> {
        match record.record_type {
            RecordType::Wait => {
                self.track_remote_record(&record)?;
                Ok(HostEvent::Wait)
            }
            RecordType::Ready => {
                self.track_remote_record(&record)?;
                Ok(HostEvent::Ready)
            }
            RecordType::Reset => {
                self.track_remote_record(&record)?;
                self.send_sequence = 0;
                Ok(HostEvent::Reset {
                    instance_id: record.instance_id,
                    epoch: record.epoch,
                })
            }
            RecordType::Data => {
                self.track_remote_record(&record)?;
                Ok(HostEvent::Data(record.payload))
            }
            RecordType::Error => {
                self.track_remote_record(&record)?;
                let code: [u8; 4] = record
                    .payload
                    .as_slice()
                    .try_into()
                    .map_err(|_| SessionError::UnexpectedRecordType(RecordType::Error))?;
                Ok(HostEvent::Error(u32::from_le_bytes(code)))
            }
            other => Err(SessionError::UnexpectedRecordType(other)),
        }
    }

    fn track_remote_record(&mut self, record: &Record) -> Result<(), SessionError> {
        if let Some(instance_id) = self.instance_id
            && record.instance_id != instance_id
        {
            return Err(SessionError::SessionIdentityMismatch);
        }
        if let Some(epoch) = self.epoch
            && record.epoch != epoch
        {
            return Err(SessionError::SessionIdentityMismatch);
        }
        if record.sequence != self.recv_sequence {
            return Err(SessionError::SequenceMismatch {
                expected: self.recv_sequence,
                actual: record.sequence,
            });
        }
        self.recv_sequence = self.recv_sequence.saturating_add(1);
        self.instance_id = Some(record.instance_id);
        self.epoch = Some(record.epoch);
        Ok(())
    }

    fn write_record(&mut self, record: &Record) -> Result<(), SessionError> {
        let encoded = encode(record)?;
        self.io.write_all(&encoded)?;
        self.io.flush()?;
        Ok(())
    }

    fn read_record_blocking(&mut self) -> Result<Record, SessionError> {
        loop {
            if let Some(record) = self.try_read_record()? {
                return Ok(record);
            }
        }
    }

    fn try_read_record(&mut self) -> Result<Option<Record>, SessionError> {
        let mut scratch = [0_u8; 4096];
        loop {
            let read = match self.io.read(&mut scratch) {
                Ok(size) => size,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(SessionError::Io(error)),
            };
            if read == 0 {
                return Err(SessionError::Closed);
            }
            let mut consumed = 0;
            while consumed < read {
                let progress = self.parser.accept(&scratch[consumed..read])?;
                consumed += progress.consumed;
                if let Some(record) = progress.record {
                    return Ok(Some(record));
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestEvent {
    Data(Vec<u8>),
    Reset { instance_id: [u8; 16], epoch: u64 },
}

pub struct GuestControlSession<T: Read + Write> {
    io: T,
    parser: Parser,
    attached: bool,
    instance_id: [u8; 16],
    epoch: u64,
    send_sequence: u64,
    recv_sequence: u64,
}

impl<T: Read + Write> GuestControlSession<T> {
    pub fn new(io: T) -> Self {
        Self {
            io,
            parser: Parser::new(),
            attached: false,
            instance_id: [0; 16],
            epoch: 0,
            send_sequence: 0,
            recv_sequence: 0,
        }
    }

    pub fn attach(&mut self) -> Result<(), SessionError> {
        self.attached = false;
        self.send_sequence = 0;
        self.recv_sequence = 0;
        self.instance_id = [0; 16];
        self.epoch = 0;
        self.write_record(&Record::bootstrap(RecordType::GuestAttach, Vec::new()))?;
        let record = self.read_record_blocking()?;
        if record.record_type != RecordType::Reset {
            return Err(SessionError::UnexpectedRecordType(record.record_type));
        }
        self.handle_reset(record)?;
        Ok(())
    }

    pub fn send_data(&mut self, payload: Vec<u8>) -> Result<u64, SessionError> {
        if !self.attached {
            return Err(SessionError::SessionIdentityMismatch);
        }
        let sequence = self.send_sequence;
        self.write_record(&Record::session(
            RecordType::Data,
            self.instance_id,
            self.epoch,
            sequence,
            payload,
        ))?;
        self.send_sequence = self.send_sequence.saturating_add(1);
        Ok(sequence)
    }

    pub fn try_recv_event(&mut self) -> Result<Option<GuestEvent>, SessionError> {
        let Some(record) = self.try_read_record()? else {
            return Ok(None);
        };
        self.event_from_record(record).map(Some)
    }

    pub fn recv_event_blocking(&mut self) -> Result<GuestEvent, SessionError> {
        let record = self.read_record_blocking()?;
        self.event_from_record(record)
    }

    fn event_from_record(&mut self, record: Record) -> Result<GuestEvent, SessionError> {
        match record.record_type {
            RecordType::Data => {
                self.validate_data_identity_and_sequence(&record)?;
                self.recv_sequence = self.recv_sequence.saturating_add(1);
                Ok(GuestEvent::Data(record.payload))
            }
            RecordType::Reset => {
                self.handle_reset(record.clone())?;
                Ok(GuestEvent::Reset {
                    instance_id: record.instance_id,
                    epoch: record.epoch,
                })
            }
            other => Err(SessionError::UnexpectedRecordType(other)),
        }
    }

    fn validate_data_identity_and_sequence(&self, record: &Record) -> Result<(), SessionError> {
        if !self.attached || record.instance_id != self.instance_id || record.epoch != self.epoch {
            return Err(SessionError::SessionIdentityMismatch);
        }
        if record.sequence != self.recv_sequence {
            return Err(SessionError::SequenceMismatch {
                expected: self.recv_sequence,
                actual: record.sequence,
            });
        }
        Ok(())
    }

    fn handle_reset(&mut self, record: Record) -> Result<(), SessionError> {
        self.instance_id = record.instance_id;
        self.epoch = record.epoch;
        self.recv_sequence = record.sequence.saturating_add(1);
        let ack = Record::session(
            RecordType::Ack,
            self.instance_id,
            self.epoch,
            record.sequence,
            Vec::new(),
        );
        self.write_record(&ack)?;
        self.send_sequence = record.sequence.saturating_add(1);
        self.attached = true;
        Ok(())
    }

    fn write_record(&mut self, record: &Record) -> Result<(), SessionError> {
        let encoded = encode(record)?;
        self.io.write_all(&encoded)?;
        self.io.flush()?;
        Ok(())
    }

    fn read_record_blocking(&mut self) -> Result<Record, SessionError> {
        loop {
            if let Some(record) = self.try_read_record()? {
                return Ok(record);
            }
        }
    }

    fn try_read_record(&mut self) -> Result<Option<Record>, SessionError> {
        let mut scratch = [0_u8; 4096];
        loop {
            let read = match self.io.read(&mut scratch) {
                Ok(size) => size,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(SessionError::Io(error)),
            };
            if read == 0 {
                return Err(SessionError::Closed);
            }
            let mut consumed = 0;
            while consumed < read {
                let progress = self.parser.accept(&scratch[consumed..read])?;
                consumed += progress.consumed;
                if let Some(record) = progress.record {
                    return Ok(Some(record));
                }
            }
        }
    }
}

fn parse_header(bytes: &[u8; CONTROL_HEADER_BYTES]) -> Result<ParsedHeader, ProtocolError> {
    if bytes[..4] != CONTROL_PROTOCOL_MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != CONTROL_PROTOCOL_VERSION {
        return Err(ProtocolError::InvalidVersion(version));
    }
    let record_type = RecordType::try_from(bytes[6])?;
    if bytes[7] != 0 {
        return Err(ProtocolError::InvalidFlags(bytes[7]));
    }
    let mut instance_id = [0; 16];
    instance_id.copy_from_slice(&bytes[8..24]);
    let epoch = u64::from_le_bytes(
        bytes[24..32]
            .try_into()
            .map_err(|_| ProtocolError::InvalidSnapshot("invalid epoch field"))?,
    );
    let sequence = u64::from_le_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| ProtocolError::InvalidSnapshot("invalid sequence field"))?,
    );
    let payload_len = u32::from_le_bytes(
        bytes[40..44]
            .try_into()
            .map_err(|_| ProtocolError::InvalidSnapshot("invalid payload_len field"))?,
    );
    validate_payload_length(record_type, payload_len)?;
    if matches!(
        record_type,
        RecordType::GuestAttach | RecordType::HostAttach
    ) && (instance_id != [0; 16] || epoch != 0 || sequence != 0)
    {
        return Err(ProtocolError::InvalidBootstrapIdentity);
    }
    Ok(ParsedHeader {
        record_type,
        instance_id,
        epoch,
        sequence,
        payload_len: payload_len as usize,
    })
}

fn record_from_parts(header: ParsedHeader, payload: Vec<u8>) -> Result<Record, ProtocolError> {
    let record = Record {
        record_type: header.record_type,
        instance_id: header.instance_id,
        epoch: header.epoch,
        sequence: header.sequence,
        payload,
    };
    validate_record(&record)?;
    Ok(record)
}

fn validate_record(record: &Record) -> Result<(), ProtocolError> {
    let payload_len =
        u32::try_from(record.payload.len()).map_err(|_| ProtocolError::LengthOverflow)?;
    validate_payload_length(record.record_type, payload_len)?;
    if matches!(
        record.record_type,
        RecordType::GuestAttach | RecordType::HostAttach
    ) && (record.instance_id != [0; 16] || record.epoch != 0 || record.sequence != 0)
    {
        return Err(ProtocolError::InvalidBootstrapIdentity);
    }
    if record.record_type == RecordType::Error {
        let code_bytes: [u8; 4] = record.payload.as_slice().try_into().map_err(|_| {
            ProtocolError::InvalidPayloadLength {
                record_type: RecordType::Error,
                length: payload_len,
            }
        })?;
        let code = u32::from_le_bytes(code_bytes);
        if !(1..=5).contains(&code) {
            return Err(ProtocolError::InvalidErrorCode(code));
        }
    }
    Ok(())
}

fn validate_payload_length(record_type: RecordType, payload_len: u32) -> Result<(), ProtocolError> {
    let valid = match record_type {
        RecordType::GuestAttach
        | RecordType::Reset
        | RecordType::Ack
        | RecordType::Wait
        | RecordType::Ready => payload_len == 0,
        RecordType::HostAttach => payload_len == 32,
        RecordType::Data => (1..=CONTROL_MAX_DATA_BYTES as u32).contains(&payload_len),
        RecordType::Error => payload_len == 4,
    };
    if valid {
        Ok(())
    } else {
        Err(ProtocolError::InvalidPayloadLength {
            record_type,
            length: payload_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[test]
    fn pinned_protocol_constants_remain_frozen() {
        assert_eq!(CONTROL_PROTOCOL_MAGIC, *b"NVXS");
        assert_eq!(CONTROL_PROTOCOL_VERSION, 1);
        assert_eq!(CONTROL_HEADER_BYTES, 44);
    }

    #[test]
    fn golden_vectors_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let vectors = include_str!("../test_data/control_session_protocol_v1_vectors.txt");
        let mut count = 0;
        for line in vectors.lines().filter(|line| !line.is_empty()) {
            let (name, hex) = line
                .split_once('|')
                .ok_or_else(|| format!("invalid vector line: {line}"))?;
            let bytes = decode_hex(hex)?;
            let record = decode_exact(&bytes)?;
            let expected_type = match name {
                "GUEST_ATTACH" => RecordType::GuestAttach,
                "HOST_ATTACH" => RecordType::HostAttach,
                "RESET" => RecordType::Reset,
                "ACK" => RecordType::Ack,
                "DATA_EMBEDDED_MAGIC" => RecordType::Data,
                "WAIT" => RecordType::Wait,
                "READY" => RecordType::Ready,
                "ERROR_AUTHENTICATION" => RecordType::Error,
                _ => return Err(format!("unknown vector name: {name}").into()),
            };
            assert_eq!(record.record_type, expected_type, "{name}");
            assert_eq!(encode(&record)?, bytes, "{name}");
            count += 1;
        }
        assert_eq!(count, 8);
        Ok(())
    }

    #[test]
    fn invalid_flags_and_lengths_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let cases = include_str!("../test_data/control_session_protocol_v1_cases.txt");
        for line in cases.lines().filter(|line| !line.is_empty()) {
            let fields = line.split('|').collect::<Vec<_>>();
            if let ["INVALID_HEADER", _name, hex] = fields.as_slice() {
                let bytes = decode_hex(hex)?;
                let mut parser = Parser::new();
                assert!(parser.accept(&bytes).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn in_memory_fixture_wait_then_ready_after_guest_ack() -> Result<(), Box<dyn std::error::Error>>
    {
        let capability = [0x5A; 32];
        let fixture = Arc::new(Mutex::new(FixtureBroker::new(capability)));
        let mut host = HostControlSession::new(FixtureEndpoint::host(fixture.clone()));
        let mut guest = GuestControlSession::new(FixtureEndpoint::guest(fixture));

        host.send_host_attach(capability)?;
        assert_eq!(host.recv_attach_status()?, HostAttachStatus::Wait);
        guest.attach()?;
        assert_eq!(host.recv_event_blocking()?, HostEvent::Ready);
        Ok(())
    }

    #[test]
    fn in_memory_fixture_data_sequence_and_stale_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
        let capability = [0x22; 32];
        let fixture = Arc::new(Mutex::new(FixtureBroker::new(capability)));
        let mut host = HostControlSession::new(FixtureEndpoint::host(fixture.clone()));
        let mut guest = GuestControlSession::new(FixtureEndpoint::guest(fixture.clone()));
        host.send_host_attach(capability)?;
        let _ = host.recv_attach_status()?;
        guest.attach()?;
        let _ = host.recv_event_blocking()?;
        host.send_data(b"first".to_vec())?;
        assert_eq!(
            guest.recv_event_blocking()?,
            GuestEvent::Data(b"first".to_vec())
        );
        fixture.lock().expect("fixture").inject_host_stale_data()?;
        let stale = guest.recv_event_blocking();
        assert!(matches!(stale, Err(SessionError::SequenceMismatch { .. })));
        Ok(())
    }

    #[test]
    fn in_memory_fixture_capability_mismatch_returns_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Arc::new(Mutex::new(FixtureBroker::new([0x11; 32])));
        let mut host = HostControlSession::new(FixtureEndpoint::host(fixture));
        host.send_host_attach([0x44; 32])?;
        assert_eq!(host.recv_event_blocking()?, HostEvent::Error(1));
        Ok(())
    }

    fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
        if !hex.len().is_multiple_of(2) {
            return Err("odd hex length".into());
        }
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).map_err(|error| error.to_string())?;
                u8::from_str_radix(text, 16).map_err(|error| error.to_string())
            })
            .collect()
    }

    #[derive(Clone)]
    struct FixtureBroker {
        capability: [u8; 32],
        instance_id: [u8; 16],
        epoch: u64,
        host_in: VecDeque<u8>,
        guest_in: VecDeque<u8>,
        guest_acked: bool,
        host_send_sequence: u64,
        host_recv_sequence: u64,
        guest_send_sequence: u64,
        guest_recv_sequence: u64,
    }

    impl FixtureBroker {
        fn new(capability: [u8; 32]) -> Self {
            Self {
                capability,
                instance_id: [7; 16],
                epoch: 1,
                host_in: VecDeque::new(),
                guest_in: VecDeque::new(),
                guest_acked: false,
                host_send_sequence: 0,
                host_recv_sequence: 0,
                guest_send_sequence: 0,
                guest_recv_sequence: 0,
            }
        }

        fn handle_from_host(&mut self, bytes: &[u8]) -> io::Result<()> {
            let record = decode_exact(bytes).map_err(protocol_to_io)?;
            match record.record_type {
                RecordType::HostAttach => {
                    if record.payload.as_slice() != self.capability {
                        self.push_host(Record::session(
                            RecordType::Error,
                            self.instance_id,
                            self.epoch,
                            self.host_send_sequence,
                            1_u32.to_le_bytes().to_vec(),
                        ))?;
                        self.host_send_sequence += 1;
                        return Ok(());
                    }
                    self.push_host(Record::session(
                        RecordType::Wait,
                        self.instance_id,
                        self.epoch,
                        self.host_send_sequence,
                        Vec::new(),
                    ))?;
                    self.host_send_sequence += 1;
                }
                RecordType::Data => {
                    if record.sequence != self.host_recv_sequence {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "stale host sequence",
                        ));
                    }
                    self.host_recv_sequence += 1;
                    self.push_guest(Record::session(
                        RecordType::Data,
                        self.instance_id,
                        self.epoch,
                        self.guest_send_sequence,
                        record.payload,
                    ))?;
                    self.guest_send_sequence += 1;
                }
                _ => {}
            }
            Ok(())
        }

        fn handle_from_guest(&mut self, bytes: &[u8]) -> io::Result<()> {
            let record = decode_exact(bytes).map_err(protocol_to_io)?;
            match record.record_type {
                RecordType::GuestAttach => {
                    self.push_guest(Record::session(
                        RecordType::Reset,
                        self.instance_id,
                        self.epoch,
                        self.guest_send_sequence,
                        Vec::new(),
                    ))?;
                    self.guest_send_sequence += 1;
                }
                RecordType::Ack => {
                    if record.sequence != self.guest_recv_sequence {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "stale guest ack",
                        ));
                    }
                    self.guest_recv_sequence += 1;
                    self.guest_acked = true;
                    self.push_host(Record::session(
                        RecordType::Ready,
                        self.instance_id,
                        self.epoch,
                        self.host_send_sequence,
                        Vec::new(),
                    ))?;
                    self.host_send_sequence += 1;
                }
                RecordType::Data => {
                    if record.sequence != self.guest_recv_sequence {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "stale guest data",
                        ));
                    }
                    self.guest_recv_sequence += 1;
                    self.push_host(Record::session(
                        RecordType::Data,
                        self.instance_id,
                        self.epoch,
                        self.host_send_sequence,
                        record.payload,
                    ))?;
                    self.host_send_sequence += 1;
                }
                _ => {}
            }
            Ok(())
        }

        fn push_host(&mut self, record: Record) -> io::Result<()> {
            self.host_in
                .extend(encode(&record).map_err(protocol_to_io)?);
            Ok(())
        }

        fn push_guest(&mut self, record: Record) -> io::Result<()> {
            self.guest_in
                .extend(encode(&record).map_err(protocol_to_io)?);
            Ok(())
        }

        fn inject_host_stale_data(&mut self) -> io::Result<()> {
            self.push_guest(Record::session(
                RecordType::Data,
                self.instance_id,
                self.epoch,
                self.guest_recv_sequence.saturating_add(5),
                b"stale".to_vec(),
            ))
        }
    }

    struct FixtureEndpoint {
        fixture: Arc<Mutex<FixtureBroker>>,
        leg: Leg,
    }

    #[derive(Clone, Copy)]
    enum Leg {
        Host,
        Guest,
    }

    impl FixtureEndpoint {
        fn host(fixture: Arc<Mutex<FixtureBroker>>) -> Self {
            Self {
                fixture,
                leg: Leg::Host,
            }
        }

        fn guest(fixture: Arc<Mutex<FixtureBroker>>) -> Self {
            Self {
                fixture,
                leg: Leg::Guest,
            }
        }
    }

    impl Read for FixtureEndpoint {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut broker = self.fixture.lock().expect("fixture");
            let queue = match self.leg {
                Leg::Host => &mut broker.host_in,
                Leg::Guest => &mut broker.guest_in,
            };
            let mut read = 0;
            while read < buf.len() {
                let Some(byte) = queue.pop_front() else {
                    break;
                };
                buf[read] = byte;
                read += 1;
            }
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "empty"));
            }
            Ok(read)
        }
    }

    impl Write for FixtureEndpoint {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut broker = self.fixture.lock().expect("fixture");
            match self.leg {
                Leg::Host => broker.handle_from_host(buf)?,
                Leg::Guest => broker.handle_from_guest(buf)?,
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn protocol_to_io(error: ProtocolError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    }
}
