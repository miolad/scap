use std::{ffi::c_void, net::IpAddr};
use nix::libc;
use crate::{MsgMeta, ScapArgs, ScapCtx};

#[repr(C)]
#[allow(unused)] // No need to export this
pub enum FfiAddr {
    V4(libc::in_addr),
    V6(libc::in6_addr)
}

impl From<IpAddr> for FfiAddr {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(a) => Self::V4(libc::in_addr {
                s_addr: a.to_bits()
            }),
            IpAddr::V6(a) => Self::V6(libc::in6_addr {
                s6_addr: a.to_bits().to_ne_bytes()
            })
        }
    }
}

/// FFI-compatible metadata for intercepted socket messages
#[repr(C)]
pub struct FfiMsgMeta {
    /// Local IP address
    pub laddr: FfiAddr,
    /// Remote IP address
    pub raddr: FfiAddr,
    /// Local port in native byte order
    pub lport: u16,
    /// Remote port in native byte order
    pub rport: u16,
    /// Socket's Address Family, either `AF_INET` for IPv4 or `AF_INET6` for IPv6.
    /// Note that dual stack sockets will be marked as AF_INET6 but can carry IPv4 traffic, too.
    pub af: u16
}

impl From<MsgMeta> for FfiMsgMeta {
    fn from(value: MsgMeta) -> Self {
        Self {
            laddr: value.laddr.into(),
            raddr: value.raddr.into(),
            lport: value.lport,
            rport: value.rport,
            af: value.af
        }
    }
}

/// Initializes the capture session.
/// 
/// ## Arguments
///  - `args`: various initialization arguments. See [ScapArgs] for additional documentation
///  - `data_cbk`: Callback to be invoked for all new intercepted socket messages
/// 
/// ## Returns
/// An opaque context pointer, or NULL in case of errors.
/// Pass the context to [scap_release] to cleanly cleanup.
#[no_mangle]
pub extern "C" fn scap_init(
    args: ScapArgs,
    data_cbk: extern "C" fn(FfiMsgMeta, usize, *const u8)
) -> *mut c_void {
    let ctx = ScapCtx::init(
        args,
        move |meta, data| {
            data_cbk(meta.into(), data.len(), data.as_ptr());
        }
    ).unwrap(); // TODO: properly pass the error through

    Box::into_raw(Box::new(ctx)) as _
}

/// Releases a Scap context previously produced by [scap_init].
/// 
/// ## Arguments
///  - `ctx`: An opaque pointer previously returned by [scap_init]
/// 
/// ## Safety
/// `ctx` must have been previosly returned by a call to [scap_init]
#[no_mangle]
pub unsafe extern "C" fn scap_release(ctx: *mut c_void) {
    let _ = Box::from_raw(ctx as *mut ScapCtx);
}
