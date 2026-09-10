use std::io::{Read, Write};
use std::time::Duration;

pub const CONTROL_PROTOCOL_MAGIC: u32 = 0x4E56_5843;
pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
pub const CONTROL_HEADER_BYTES: usize = 44;
pub const CONTROL_MAX_DATA_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ControlFrameKind {
    Attach = 1,
    Auth = 2,
    Ack = 3,
    Reset = 4,
    Data = 5,
    Wait = 6,
}

impl ControlFrameKind {
    fn from_u16(value: u16) -> Result<Self, ControlSessionError> {
        match value {
            1 => Ok(Self::Attach),
            2 => Ok(Self::Auth),
            3 => Ok(Self::Ack),
            4 => Ok(Self::Reset),
            5 => Ok(Self::Data),
            6 => Ok(Self::Wait),
            other => Err(ControlSessionError::Protocol(format!(
                "unknown control frame kind {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlFrame {
    pub kind: ControlFrameKind,
    pub sequence: u64,
    pub generation: u64,
    pub launch_nonce: [u8; 16],
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum ControlSessionError {
    Io(String),
    Protocol(String),
}

impl core::fmt::Display for ControlSessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(message) => write!(f, "{message}"),
            Self::Protocol(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ControlSessionError {}

impl From<std::io::Error> for ControlSessionError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

pub struct ControlSession<T: Read + Write> {
    transport: T,
    sequence: u64,
    generation: u64,
    launch_nonce: [u8; 16],
}

impl<T: Read + Write> ControlSession<T> {
    pub fn new(transport: T, generation: u64, launch_nonce: [u8; 16]) -> Self {
        Self {
            transport,
            sequence: 0,
            generation,
            launch_nonce,
        }
    }

    pub fn send_attach(&mut self, launch_capability: [u8; 32]) -> Result<u64, ControlSessionError> {
        let sequence = self.next_sequence();
        self.write_frame(ControlFrame {
            kind: ControlFrameKind::Attach,
            sequence,
            generation: self.generation,
            launch_nonce: self.launch_nonce,
            payload: launch_capability.to_vec(),
        })?;
        Ok(sequence)
    }

    pub fn send_auth(&mut self) -> Result<u64, ControlSessionError> {
        let sequence = self.next_sequence();
        self.write_frame(ControlFrame {
            kind: ControlFrameKind::Auth,
            sequence,
            generation: self.generation,
            launch_nonce: self.launch_nonce,
            payload: vec![],
        })?;
        Ok(sequence)
    }

    pub fn send_data(&mut self, payload: Vec<u8>) -> Result<u64, ControlSessionError> {
        if payload.len() > CONTROL_MAX_DATA_BYTES {
            return Err(ControlSessionError::Protocol(format!(
                "control data payload exceeds {} bytes",
                CONTROL_MAX_DATA_BYTES
            )));
        }
        let sequence = self.next_sequence();
        self.write_frame(ControlFrame {
            kind: ControlFrameKind::Data,
            sequence,
            generation: self.generation,
            launch_nonce: self.launch_nonce,
            payload,
        })?;
        Ok(sequence)
    }

    pub fn send_wait(&mut self) -> Result<u64, ControlSessionError> {
        let sequence = self.next_sequence();
        self.write_frame(ControlFrame {
            kind: ControlFrameKind::Wait,
            sequence,
            generation: self.generation,
            launch_nonce: self.launch_nonce,
            payload: vec![],
        })?;
        Ok(sequence)
    }

    pub fn send_reset(&mut self, next_generation: u64) -> Result<u64, ControlSessionError> {
        let sequence = self.next_sequence();
        self.write_frame(ControlFrame {
            kind: ControlFrameKind::Reset,
            sequence,
            generation: next_generation,
            launch_nonce: self.launch_nonce,
            payload: vec![],
        })?;
        self.generation = next_generation;
        self.sequence = 0;
        Ok(sequence)
    }

    pub fn read_frame(&mut self, _deadline: Duration) -> Result<ControlFrame, ControlSessionError> {
        let mut header = [0_u8; CONTROL_HEADER_BYTES];
        self.transport.read_exact(&mut header)?;
        let magic = u32::from_be_bytes(header[0..4].try_into().expect("magic"));
        if magic != CONTROL_PROTOCOL_MAGIC {
            return Err(ControlSessionError::Protocol(format!(
                "invalid control magic {magic:#x}"
            )));
        }
        let version = u16::from_be_bytes(header[4..6].try_into().expect("version"));
        if version != CONTROL_PROTOCOL_VERSION {
            return Err(ControlSessionError::Protocol(format!(
                "unsupported control protocol version {version}"
            )));
        }
        let kind =
            ControlFrameKind::from_u16(u16::from_be_bytes(header[6..8].try_into().expect("kind")))?;
        let sequence = u64::from_be_bytes(header[8..16].try_into().expect("sequence"));
        let generation = u64::from_be_bytes(header[16..24].try_into().expect("generation"));
        let mut launch_nonce = [0_u8; 16];
        launch_nonce.copy_from_slice(&header[24..40]);
        let payload_len = u32::from_be_bytes(header[40..44].try_into().expect("payload")) as usize;
        if payload_len > CONTROL_MAX_DATA_BYTES {
            return Err(ControlSessionError::Protocol(format!(
                "control payload exceeds max size: {payload_len}"
            )));
        }
        let mut payload = vec![0_u8; payload_len];
        self.transport.read_exact(&mut payload)?;
        Ok(ControlFrame {
            kind,
            sequence,
            generation,
            launch_nonce,
            payload,
        })
    }

    fn write_frame(&mut self, frame: ControlFrame) -> Result<(), ControlSessionError> {
        let mut encoded = Vec::with_capacity(CONTROL_HEADER_BYTES + frame.payload.len());
        encoded.extend_from_slice(&CONTROL_PROTOCOL_MAGIC.to_be_bytes());
        encoded.extend_from_slice(&CONTROL_PROTOCOL_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(frame.kind as u16).to_be_bytes());
        encoded.extend_from_slice(&frame.sequence.to_be_bytes());
        encoded.extend_from_slice(&frame.generation.to_be_bytes());
        encoded.extend_from_slice(&frame.launch_nonce);
        encoded.extend_from_slice(&(frame.payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&frame.payload);
        self.transport.write_all(&encoded)?;
        self.transport.flush()?;
        Ok(())
    }

    fn next_sequence(&mut self) -> u64 {
        let current = self.sequence;
        self.sequence = self.sequence.saturating_add(1);
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn pinned_protocol_constants_remain_frozen() {
        assert_eq!(CONTROL_PROTOCOL_VERSION, 1);
        assert_eq!(CONTROL_HEADER_BYTES, 44);
        assert_eq!(CONTROL_MAX_DATA_BYTES, 65_536);
    }

    #[test]
    fn frame_round_trip_uses_pinned_layout() {
        let nonce = [7_u8; 16];
        let mut io = Cursor::new(Vec::new());
        {
            let mut session = ControlSession::new(&mut io, 9, nonce);
            session
                .send_data(vec![1, 2, 3, 4])
                .expect("write control frame");
        }
        io.set_position(0);
        let mut session = ControlSession::new(io, 9, nonce);
        let frame = session
            .read_frame(Duration::from_secs(1))
            .expect("read frame");
        assert_eq!(frame.kind, ControlFrameKind::Data);
        assert_eq!(frame.sequence, 0);
        assert_eq!(frame.generation, 9);
        assert_eq!(frame.launch_nonce, nonce);
        assert_eq!(frame.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn send_data_rejects_oversized_payload() {
        let io = Cursor::new(Vec::new());
        let mut session = ControlSession::new(io, 1, [0; 16]);
        let result = session.send_data(vec![0_u8; CONTROL_MAX_DATA_BYTES + 1]);
        assert!(result.is_err());
    }

    #[test]
    fn reset_updates_generation_and_resets_sequence() {
        let mut io = Cursor::new(Vec::new());
        let mut session = ControlSession::new(&mut io, 5, [9; 16]);
        let first = session.send_wait().expect("wait frame");
        let reset_sequence = session.send_reset(6).expect("reset frame");
        let post_reset = session.send_wait().expect("wait frame after reset");
        assert_eq!(first, 0);
        assert_eq!(reset_sequence, 1);
        assert_eq!(post_reset, 0);
    }
}
