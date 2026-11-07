//! Small self-contained primitives: the std library has no hashing and no Base64, and the protocol needs both. Kept dependency-free on purpose.

pub mod base64;
pub mod json;
pub mod sha1;
pub mod sha256;
pub mod spec_json;

/// Stack reservation for a per-connection thread.
///
/// One thread per connection is the right shape for this workload — every
/// session is blocked on a socket most of the time — but the default 8 MiB
/// reservation is sized for deep recursion, and nothing here recurses. The
/// relay buffers live on the heap (`frame_size` bytes per direction), so the
/// only meaningful stack user is the 16 KiB read buffer in `BufferedConn::fill`.
/// 512 KiB leaves a wide margin and cuts the address space a few thousand
/// connections reserve from tens of gigabytes to a couple.
pub const CONNECTION_STACK: usize = 512 * 1024;

/// Spawns a per-connection thread with [`CONNECTION_STACK`].
pub fn spawn_connection<F>(f: F) -> std::io::Result<std::thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(CONNECTION_STACK)
        .spawn(|| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        })
}

/// Atomically increments `counter` when it is below `limit`; returns whether
/// it did (a compare-exchange loop, usable on the 1.75 MSRV).
pub fn increment_below(counter: &std::sync::atomic::AtomicUsize, limit: usize) -> bool {
    use std::sync::atomic::Ordering;
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(now) => current = now,
        }
    }
}

/// Lowercase hex encoding.
pub fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Fill `buf` from the operating system entropy source.
///
/// Linux deliberately uses the `getrandom(2)` libc entry point rather than
/// opening `/dev/urandom` for every request.  A short read is allowed, and an
/// interrupted call is retried.  Any other OS error is returned to the caller;
/// there is intentionally no clock or xorshift fallback.
fn os_random(buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::io;
        use std::os::raw::{c_int, c_void};

        extern "C" {
            fn getrandom(buf: *mut c_void, len: usize, flags: c_int) -> isize;
        }

        let mut filled = 0;
        while filled < buf.len() {
            let n = unsafe {
                getrandom(
                    buf[filled..].as_mut_ptr().cast::<c_void>(),
                    buf.len() - filled,
                    0,
                )
            };
            if n > 0 {
                filled += n as usize;
            } else if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "getrandom returned zero bytes",
                ));
            } else {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(4) {
                    continue;
                }
                return Err(err);
            }
        }
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom")?;
        file.read_exact(buf)
    }

    #[cfg(windows)]
    {
        use std::io;
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut core::ffi::c_void,
                buffer: *mut u8,
                len: u32,
                flags: u32,
            ) -> i32;
        }
        let len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "random request exceeds u32 length",
            )
        })?;
        let status =
            unsafe { BCryptGenRandom(core::ptr::null_mut(), buf.as_mut_ptr(), len, 0x0000_0002) };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status))
        }
    }

    #[cfg(not(any(target_os = "linux", all(unix, not(target_os = "linux")), windows)))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "OS random source is unsupported on this target",
        ))
    }
}

/// Random bytes from the OS entropy source.
///
/// Returns random bytes from the operating system entropy source, or the OS
/// error. Callers must propagate failure instead of substituting weak entropy.
pub fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    os_random(&mut buf)?;
    Ok(buf)
}

/// A uniformly distributed `u64`, for jitter in a retry delay.
pub fn random_u64() -> std::io::Result<u64> {
    let b = random_bytes(8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(&b);
    Ok(u64::from_le_bytes(a))
}

/// Random lowercase hex string of `n` bytes.
pub fn random_hex(n: usize) -> std::io::Result<String> {
    Ok(hex(&random_bytes(n)?))
}

/// Random identifier over the RFC 3986 unreserved alphabet, safe inside a path
/// segment or a query value without escaping.
pub fn random_id(n: usize) -> std::io::Result<String> {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let bytes = random_bytes(n)?;
    let mut s = String::with_capacity(n);
    for b in bytes {
        s.push(ALPHABET[(b & 0x1f) as usize] as char);
    }
    Ok(s)
}

/// Converts an OS entropy failure into the stable protocol/internal error used
/// by handlers that return a DBBridge response.
pub fn random_error(error: std::io::Error) -> crate::error::Error {
    crate::error::Error::new(
        crate::wire::ERR_INTERNAL_ERROR,
        format!("OS random source failed: {error}"),
    )
    .retryable(true)
}

pub fn spec_errno_text(e: &std::io::Error) -> String {
    let text = match e.raw_os_error() {
        Some(1) => "operation not permitted",
        Some(2) => "no such file or directory",
        Some(5) => "input/output error",
        Some(13) => "permission denied",
        Some(16) => "device or resource busy",
        Some(17) => "file exists",
        Some(18) => "invalid cross-device link",
        Some(20) => "not a directory",
        Some(21) => "is a directory",
        Some(22) => "invalid argument",
        Some(28) => "no space left on device",
        Some(30) => "read-only file system",
        Some(36) => "file name too long",
        Some(39) => "directory not empty",
        Some(40) => "too many levels of symbolic links",
        _ => {
            let s = e.to_string();
            return s.split(" (os error").next().unwrap_or(&s).to_lowercase();
        }
    };
    text.to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn os_random_has_no_clock_fallback() {
        let outputs: Vec<Vec<u8>> = (0..8).map(|_| super::random_bytes(32).unwrap()).collect();
        for (i, output) in outputs.iter().enumerate() {
            assert!(outputs[i + 1..].iter().all(|other| other != output));
        }
    }
}
