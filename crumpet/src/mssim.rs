//! The Microsoft TPM simulator TCP protocol ("mssim") as a [`Tbs`]
//! backend — a plain-TCP command port carrying framed TPM2
//! command/response buffers, matching what `tpmsim.rs` and Microsoft's
//! reference simulator speak, and what `tpm2-tss`'s `tcti-mssim` uses.
//!
//! Unlike the Windows TBS backends, this is a development/testing
//! transport: it talks to a simulator process rather than real TPM
//! hardware, and it works on any platform. It does not touch the
//! simulator's platform port (power/reset/NV signals) — only the command
//! port needed for [`Tbs::submit_command`].
//!
//! A freshly-started simulator has not run `TPM2_Startup` yet and will
//! reject other commands with `TPM_RC_INITIALIZE`; call
//! [`super::tbs::startup_clear`] once after [`Tbs::open`].

use std::env;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

use super::tbs::Tbs;

// TPM_TCP_PROTOCOL command codes used on the command port.
const TPM_SEND_COMMAND: u32 = 8;
const TPM_REMOTE_HANDSHAKE: u32 = 15;

const COMMAND_LOCALITY_ZERO: u8 = 0;

/// Default command port address, matching tpmsim.rs' and the Microsoft
/// simulator's default (the platform port is this port + 1, but this
/// backend never needs it).
pub const DEFAULT_ADDR: &str = "127.0.0.1:2321";

/// Overrides [`DEFAULT_ADDR`] for [`TbsMssim::open`] when set.
pub const ADDR_ENV_VAR: &str = "CRUMPET_MSSIM_ADDR";

/// Talks to an mssim-protocol TPM simulator over its command port.
pub struct TbsMssim {
    stream: Mutex<TcpStream>,
}

impl TbsMssim {
    /// Connects to a specific `host:port` command port and performs the
    /// mssim handshake.
    pub fn connect(addr: &str) -> Result<Self, Box<dyn Error>> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        handshake(&mut stream)?;
        Ok(Self {
            stream: Mutex::new(stream),
        })
    }
}

fn handshake(stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    write_u32(stream, TPM_REMOTE_HANDSHAKE)?;
    write_u32(stream, 1)?; // client version
    let _server_version = read_u32(stream)?;
    let ack = read_u32(stream)?;
    if ack != 0 {
        return Err(format!("mssim handshake failed: ack=0x{:08X}", ack).into());
    }
    Ok(())
}

impl Tbs for TbsMssim {
    /// Connects to the address in [`ADDR_ENV_VAR`], or [`DEFAULT_ADDR`] if
    /// that's unset. Use [`TbsMssim::connect`] to target a specific
    /// address without going through the environment.
    fn open() -> Result<Self, Box<dyn Error>> {
        let addr = env::var(ADDR_ENV_VAR).unwrap_or_else(|_| DEFAULT_ADDR.to_string());
        Self::connect(&addr)
    }

    fn submit_command(&self, command: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut stream = self.stream.lock().unwrap();

        write_u32(&mut stream, TPM_SEND_COMMAND)?;
        stream.write_all(&[COMMAND_LOCALITY_ZERO])?;
        write_u32(&mut stream, command.len() as u32)?;
        stream.write_all(command)?;

        let resp_len = read_u32(&mut stream)? as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp)?;
        let _ack = read_u32(&mut stream)?; // trailing success/failure ack

        Ok(resp)
    }
}

fn read_u32(s: &mut TcpStream) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    s.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn write_u32(s: &mut TcpStream, v: u32) -> std::io::Result<()> {
    s.write_all(&v.to_be_bytes())
}
