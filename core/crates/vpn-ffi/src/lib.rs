//! C ABI used by the PHP extension (see `include/php_vpn_core.h`).
//!
//! Rules: every entry point catches panics; Rust allocations are only freed
//! by the matching `*_free` function; strings are passed as pointer + length
//! and are not NUL-terminated unless stated.

#![allow(clippy::missing_safety_doc, non_camel_case_types)]

use std::ffi::{c_char, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::Duration;

use vpn_core::{Error, ErrorKind, Profile, RequestSpec, Response, Settings};

pub const VPN_ERROR_MESSAGE_SIZE: usize = 512;

#[repr(C)]
pub struct vpn_error {
    /// 0 on success, otherwise an `ErrorKind` value.
    pub code: i32,
    /// NUL-terminated message.
    pub message: [c_char; VPN_ERROR_MESSAGE_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct vpn_str {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct vpn_header {
    pub name: vpn_str,
    pub value: vpn_str,
}

#[repr(C)]
pub struct vpn_request_spec {
    pub method: vpn_str,
    pub url: vpn_str,
    pub headers: *const vpn_header,
    pub headers_len: usize,
    pub body: vpn_str,
    pub timeout: f64,
    pub connect_timeout: f64,
    pub max_redirects: u32,
    pub verify_tls: u8,
    pub allow_private: u8,
    pub allow_https_downgrade: u8,
    pub decode_content: u8,
    /// Empty = bundled Mozilla roots.
    pub ca_file: vpn_str,
    pub max_response_size: u64,
}

#[repr(C)]
pub struct vpn_settings {
    /// Empty = system temporary directory.
    pub lock_dir: vpn_str,
    pub session_ttl: f64,
    pub max_tunnels: u32,
}

pub struct vpn_profile(Profile);

pub struct vpn_response {
    inner: Response,
    url: String,
    remote: String,
}

const EMPTY: vpn_str = vpn_str {
    ptr: std::ptr::null(),
    len: 0,
};

fn out_str(s: &[u8]) -> vpn_str {
    vpn_str {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

unsafe fn bytes<'a>(s: vpn_str) -> &'a [u8] {
    if s.ptr.is_null() || s.len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(s.ptr, s.len)
    }
}

unsafe fn text<'a>(s: vpn_str, what: &str) -> Result<&'a str, Error> {
    std::str::from_utf8(bytes(s)).map_err(|_| Error::config(format!("{what} is not valid UTF-8")))
}

unsafe fn path<'a>(s: vpn_str) -> &'a Path {
    Path::new(OsStr::from_bytes(bytes(s)))
}

unsafe fn set_error(err: *mut vpn_error, e: &Error) {
    if err.is_null() {
        return;
    }
    let err = &mut *err;
    err.code = e.kind() as i32;
    let msg = e.message().as_bytes();
    let mut n = msg.len().min(VPN_ERROR_MESSAGE_SIZE - 1);
    // Do not cut a UTF-8 sequence in half.
    while n > 0 && n < msg.len() && (msg[n] & 0xc0) == 0x80 {
        n -= 1;
    }
    for (dst, src) in err.message.iter_mut().zip(&msg[..n]) {
        *dst = *src as c_char;
    }
    err.message[n] = 0;
}

unsafe fn clear_error(err: *mut vpn_error) {
    if !err.is_null() {
        (*err).code = 0;
        (*err).message[0] = 0;
    }
}

/// Runs `f`, converting errors and panics into `err` and a null result.
unsafe fn guarded<T>(err: *mut vpn_error, f: impl FnOnce() -> Result<T, Error>) -> *mut T {
    clear_error(err);
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Box::into_raw(Box::new(v)),
        Ok(Err(e)) => {
            set_error(err, &e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_error(
                err,
                &Error::new(ErrorKind::Internal, "internal error in php-vpn (panic)"),
            );
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn vpn_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[no_mangle]
pub unsafe extern "C" fn vpn_profile_from_file(
    file: vpn_str,
    enforce_permissions: u8,
    err: *mut vpn_error,
) -> *mut vpn_profile {
    guarded(err, || {
        Profile::from_file(path(file), enforce_permissions != 0).map(vpn_profile)
    })
}

#[no_mangle]
pub unsafe extern "C" fn vpn_profile_from_string(
    config: vpn_str,
    err: *mut vpn_error,
) -> *mut vpn_profile {
    guarded(err, || {
        let t = text(config, "the WireGuard profile")?;
        Profile::from_text(t).map(vpn_profile)
    })
}

#[no_mangle]
pub unsafe extern "C" fn vpn_profile_pool(
    members: *const *const vpn_profile,
    count: usize,
    err: *mut vpn_error,
) -> *mut vpn_profile {
    guarded(err, || {
        if members.is_null() || count == 0 {
            return Err(Error::config("a pool needs at least one profile"));
        }
        let parts: Vec<Profile> = std::slice::from_raw_parts(members, count)
            .iter()
            .map(|p| (&**p).0.clone())
            .collect();
        Profile::pool(&parts).map(vpn_profile)
    })
}

#[no_mangle]
pub unsafe extern "C" fn vpn_profile_free(profile: *mut vpn_profile) {
    if !profile.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(profile))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn vpn_profile_member_count(profile: *const vpn_profile) -> usize {
    if profile.is_null() {
        0
    } else {
        (&*profile).0.members().len()
    }
}

/// Closes this process's tunnels for the profile.
#[no_mangle]
pub unsafe extern "C" fn vpn_profile_close(profile: *const vpn_profile) {
    if !profile.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| vpn_core::close(&(&*profile).0)));
    }
}

fn json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_list(out: &mut String, items: &[String]) {
    out.push('[');
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_string(out, s);
    }
    out.push(']');
}

/// Non-secret description of the profile as a JSON array of objects. The
/// returned NUL-terminated string must be released with `vpn_string_free`.
#[no_mangle]
pub unsafe extern "C" fn vpn_profile_info_json(profile: *const vpn_profile) -> *mut c_char {
    if profile.is_null() {
        return std::ptr::null_mut();
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let mut out = String::from("[");
        for (i, m) in (&*profile).0.info().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"endpoint\":");
            json_string(&mut out, &m.endpoint);
            out.push_str(",\"addresses\":");
            json_list(&mut out, &m.addresses);
            out.push_str(",\"dns\":");
            json_list(&mut out, &m.dns);
            out.push_str(",\"allowed_ips\":");
            json_list(&mut out, &m.allowed_ips);
            out.push_str(&format!(",\"mtu\":{}", m.mtu));
            out.push_str(",\"public_key\":");
            json_string(&mut out, &m.public_key);
            out.push_str(",\"peer_public_key\":");
            json_string(&mut out, &m.peer_public_key);
            match m.session_age {
                Some(age) => out.push_str(&format!(",\"session_age\":{:.3}}}", age.as_secs_f64())),
                None => out.push_str(",\"session_age\":null}"),
            }
        }
        out.push(']');
        std::ffi::CString::new(out).map(|c| c.into_raw()).ok()
    }));
    r.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn vpn_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(std::ffi::CString::from_raw(s));
    }
}

fn seconds(v: f64, what: &str) -> Result<Duration, Error> {
    if v.is_finite() && v > 0.0 && v <= 86_400.0 {
        Ok(Duration::from_secs_f64(v))
    } else {
        Err(Error::config(format!(
            "{what} must be greater than 0 and at most 86400 seconds"
        )))
    }
}

#[no_mangle]
pub unsafe extern "C" fn vpn_request(
    profile: *const vpn_profile,
    spec: *const vpn_request_spec,
    settings: *const vpn_settings,
    err: *mut vpn_error,
) -> *mut vpn_response {
    guarded(err, || {
        if profile.is_null() || spec.is_null() || settings.is_null() {
            return Err(Error::internal("null argument"));
        }
        let s = &*spec;
        let headers = if s.headers.is_null() {
            &[][..]
        } else {
            std::slice::from_raw_parts(s.headers, s.headers_len)
        };
        let mut header_list = Vec::with_capacity(headers.len());
        for h in headers {
            let name = text(h.name, "a header name")?;
            header_list.push((name.to_string(), bytes(h.value).to_vec()));
        }
        let ca = bytes(s.ca_file);
        let request = RequestSpec {
            method: text(s.method, "the HTTP method")?.to_string(),
            url: text(s.url, "the URL")?.to_string(),
            headers: header_list,
            body: bytes(s.body).to_vec(),
            timeout: seconds(s.timeout, "timeout")?,
            connect_timeout: seconds(s.connect_timeout, "connect_timeout")?,
            max_redirects: s.max_redirects,
            verify_tls: s.verify_tls != 0,
            ca_file: (!ca.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(ca))),
            max_response_size: s.max_response_size,
            allow_private: s.allow_private != 0,
            allow_https_downgrade: s.allow_https_downgrade != 0,
            decode_content: s.decode_content != 0,
        };
        let st = &*settings;
        let lock_dir = bytes(st.lock_dir);
        let settings = Settings {
            lock_dir: (!lock_dir.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(lock_dir))),
            session_ttl: seconds(st.session_ttl, "php_vpn.session_ttl")?,
            max_tunnels: st.max_tunnels.max(1) as usize,
        };
        let inner = vpn_core::request(&(&*profile).0, &request, &settings)?;
        Ok(vpn_response {
            url: inner.effective_url.clone(),
            remote: inner.remote_ip.to_string(),
            inner,
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn vpn_response_status(r: *const vpn_response) -> u16 {
    (&*r).inner.status
}

#[no_mangle]
pub unsafe extern "C" fn vpn_response_body(r: *const vpn_response) -> vpn_str {
    out_str(&(&*r).inner.body)
}

#[no_mangle]
pub unsafe extern "C" fn vpn_response_url(r: *const vpn_response) -> vpn_str {
    out_str((&*r).url.as_bytes())
}

#[no_mangle]
pub unsafe extern "C" fn vpn_response_remote_ip(r: *const vpn_response) -> vpn_str {
    out_str((&*r).remote.as_bytes())
}

#[no_mangle]
pub unsafe extern "C" fn vpn_response_redirects(r: *const vpn_response) -> u32 {
    (&*r).inner.redirects
}

#[no_mangle]
pub unsafe extern "C" fn vpn_response_header_count(r: *const vpn_response) -> usize {
    (&*r).inner.headers.len()
}

/// Returns 0 and fills `name`/`value` for a valid index, -1 otherwise.
#[no_mangle]
pub unsafe extern "C" fn vpn_response_header(
    r: *const vpn_response,
    index: usize,
    name: *mut vpn_str,
    value: *mut vpn_str,
) -> i32 {
    let r = &*r;
    match r.inner.headers.get(index) {
        Some((n, v)) => {
            *name = out_str(n.as_bytes());
            *value = out_str(v);
            0
        }
        None => {
            *name = EMPTY;
            *value = EMPTY;
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn vpn_response_free(r: *mut vpn_response) {
    if !r.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(r))));
    }
}
