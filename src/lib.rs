mod err;
mod bpf {
    include!(concat!(env!("OUT_DIR"), "/prog.bpf.rs"));
}
mod common {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/common.rs"));
}

use std::{mem::{ManuallyDrop, MaybeUninit}, net::IpAddr, thread::JoinHandle};
use common::scap_msg;
use err::InitError;
use libbpf_rs::{skel::{OpenSkel, SkelBuilder}, Link, MapHandle, RingBufferBuilder};
use nix::libc::{AF_INET, AF_INET6};
use tokio::{io::unix::AsyncFd, sync::watch};

/// Opaque context.
/// Dropping it triggers automatic clean up.
pub struct ScapCtx {
    probe_link: ManuallyDrop<Link>,
    rb_cleaner_join_handle: Option<JoinHandle<()>>,
    rb_cleaner_term_tx: watch::Sender<bool>
}

/// Metadata for an intercepted socket message
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MsgMeta {
    /// Local IP address
    pub laddr: IpAddr,
    /// Remote IP address
    pub raddr: IpAddr,
    /// Local port in native byte order
    pub lport: u16,
    /// Remote port in native byte order
    pub rport: u16,
    /// Socket's Address Family, either `AF_INET` for IPv4 or `AF_INET6` for IPv6.
    /// Note that dual stack sockets will be marked as AF_INET6 but can carry IPv4 traffic, too.
    pub af: u16
}

/// Arguments for Scap initialization
pub struct ScapArgs {
    /// Size of the ringbuf map to move captured traffic from the
    /// kernel eBPF probes to the user-space controller
    pub ringbuf_size: u32
}

impl ScapCtx {
    /// Initializes the socket capture environment
    /// 
    /// # Arguments
    ///  - `args`: Various initialization arguments. See [ScapArgs] for additional documentation
    ///  - `data_cbk`: Callback to be invoked for all new socket intercepted socket messages
    pub fn init<F>(args: ScapArgs, mut data_cbk: F) -> Result<ScapCtx, InitError>
        where F: 'static + FnMut(MsgMeta, &[u8]) + Send
    {
        let skel_builder = bpf::ProgSkelBuilder::default();
        let mut obj = MaybeUninit::uninit();

        let mut open_skel = skel_builder.open(&mut obj)?;
        open_skel.maps.msg_ring.set_max_entries(args.ringbuf_size)?;

        let skel = open_skel.load()?;
        let probe_link = ManuallyDrop::new(skel.progs.sendmsg.attach()?);

        let (rb_cleaner_term_tx, mut rb_cleaner_term_rx) = watch::channel(false);
        let rb_handle = MapHandle::try_from(&skel.maps.msg_ring)?;

        let rb_cleaner_fn = move |data: &[u8]| {
            let data_len = data.len();
            assert!(data_len >= std::mem::size_of::<scap_msg>());

            let msg = unsafe { &*(data.as_ptr() as *const scap_msg) };
            assert!(data_len >= msg.size as usize + std::mem::size_of::<scap_msg>());

            let (laddr, raddr) = match msg.af as i32 {
                AF_INET  => (
                    IpAddr::from(unsafe { msg.laddr.in_.s_addr.to_ne_bytes() }),
                    IpAddr::from(unsafe { msg.raddr.in_.s_addr.to_ne_bytes() })
                ),
                AF_INET6 => (
                    IpAddr::from(unsafe { msg.laddr.in6.in6_u.u6_addr8 }),
                    IpAddr::from(unsafe { msg.raddr.in6.in6_u.u6_addr8 })
                ),
                _ => unreachable!()
            };

            let data = unsafe {
                std::slice::from_raw_parts(&raw const msg.data as *const u8, msg.size as _)
            };

            data_cbk(MsgMeta {
                laddr,
                raddr,
                lport: msg.lport,
                rport: u16::from_be(msg.rport),
                af: msg.af
            }, data);

            0
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(InitError::AsyncRuntime)?;

        let rb_cleaner_join_handle = std::thread::spawn(move || {
            runtime.block_on(async move {
                let mut rb_builder = RingBufferBuilder::new();
                rb_builder.add(&rb_handle, rb_cleaner_fn).unwrap();
                let rb = rb_builder.build().unwrap();
                let rb_epoll_fd = AsyncFd::new(rb.epoll_fd()).unwrap();

                loop {
                    tokio::select! {
                        Ok(mut readable_guard) = rb_epoll_fd.readable() => {
                            rb.consume().unwrap();
                            readable_guard.clear_ready();
                        },

                        _ = rb_cleaner_term_rx.wait_for(|term| *term) => {
                            break;
                        }
                    }
                }
            });
        });

        Ok(ScapCtx {
            probe_link,
            rb_cleaner_join_handle: Some(rb_cleaner_join_handle),
            rb_cleaner_term_tx
        })
    }
}

impl Drop for ScapCtx {
    fn drop(&mut self) {
        // Force dropping the probe link before joining the cleaner thread
        // to stop the message generation in the kernel.
        // This is in no way necessary but a little cleaner, imo
        unsafe {
            ManuallyDrop::drop(&mut self.probe_link);
        }

        if self.rb_cleaner_term_tx.send(true).is_ok() {
            self.rb_cleaner_join_handle
                .take()
                .unwrap() // Always present
                .join()
                .unwrap();
        }
    }
}
