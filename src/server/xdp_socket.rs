use std::{
    array,
    ffi::CString,
    io::Write,
    mem,
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ptr::{self, addr_of_mut, null, null_mut},
    slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

use anyhow::{bail, Result};
use libbpf_rs::libbpf_sys::*;
use libc::{
    c_void, if_nametoindex, pollfd, posix_memalign, sendto, sysconf, MSG_DONTWAIT, POLLIN,
    _SC_PAGESIZE,
};
use pnet::{
    packet::{
        ethernet::{EtherType, EtherTypes, MutableEthernetPacket},
        ip,
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{self, MutableIpv4Packet},
        udp::{self, MutableUdpPacket, Udp},
        MutablePacket, Packet,
    },
    util::MacAddr,
};

use super::{server::UmemCtrl, xdppass::*};
use crate::server::server::xsk_alloc_umem_frame;

const FRAME_SIZE: usize = XSK_UMEM__DEFAULT_FRAME_SIZE as usize;
const NUM_FRAMES: usize = 4096;

// fn xsk_alloc_umem_frame(umem_frame_addr: &mut [u64], umem_frame_free: &mut
// usize) -> u64 {     if *umem_frame_free == 0 {
//         return u64::MAX;
//     }
//     *umem_frame_free -= 1;
//     let frame = umem_frame_addr[*umem_frame_free];
//     umem_frame_addr[*umem_frame_free] = u64::MAX;
//     return frame;
// }

// fn __main() -> Result<()> {
//     let opts = Command::from_args();
//     let ifname = CString::new(opts.ifname).unwrap();
//     let ifindex = unsafe { if_nametoindex(ifname.as_ptr()) as i32 };

//     let (
//         (prog_fd, buffer_size, buffer, mut umem),
//         (mut fq, mut cq, mut rx, mut tx),
//         (xsk, mut umem_frame_free, mut umem_frame_addr),
//     ) = unsafe { setup(ifname) };

//     let running = Arc::new(AtomicBool::new(true));
//     let r = running.clone();
//     ctrlc::set_handler(move || {
//         r.store(false, Ordering::SeqCst);
//     })?;

//     let mut dgram_recv_buf = vec![0; 4096];
//     let mut prod_addr = 0;

//     while running.load(Ordering::SeqCst) {
//         unsafe {
//             let mut idx_rx = 0;
//             let mut idx_fq: u32 = 0;
//             let mut idx_tx: u32 = 0;

//             let received = peek_rx_ring(
//                 &mut idx_rx,
//                 &mut idx_fq,
//                 &mut rx,
//                 &mut fq,
//                 &mut umem_frame_free,
//                 &mut umem_frame_addr,
//             );

//             for _ in 0..received {
//                 if let Some((peer_addr, local_addr, local_mac, peer_mac,
// udp_payload)) =                     receive_packet(&mut rx, &mut idx_rx,
// buffer)                 {
//                     let new_payload = udp_payload;
//                     send_packet(
//                         &mut tx,
//                         &mut idx_tx,
//                         buffer,
//                         xsk.assume_init(),
//                         &mut umem_frame_addr,
//                         &mut umem_frame_free,
//                         local_mac,
//                         peer_mac,
//                         local_addr,
//                         peer_addr,
//                         new_payload.as_slice(),
//                     );
//                 }
//             }

//             _xsk_ring_cons__release(&mut rx, received);
//         }
//     }

//     unsafe {
//         let ret = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, ptr::null());
//         println!("bpf_xdp_detach: {}", ret);
//     }

//     Ok(())
// }

// #[allow(clippy::type_complexity)]
// pub(crate) unsafe fn setup(
//     ifname: CString,
// ) -> (
//     (
//         i32,
//         usize,
//         *mut libc::c_void,
//         *mut libbpf_rs::libbpf_sys::xsk_umem,
//     ),
//     (
//         libbpf_rs::libbpf_sys::xsk_ring_prod,
//         libbpf_rs::libbpf_sys::xsk_ring_cons,
//         libbpf_rs::libbpf_sys::xsk_ring_cons,
//         libbpf_rs::libbpf_sys::xsk_ring_prod,
//     ),
//     (
//         std::mem::MaybeUninit<*mut libbpf_rs::libbpf_sys::xsk_socket>,
//         usize,
//         [u64; NUM_FRAMES],
//     ),
// ) {
//     let ifindex = if_nametoindex(ifname.as_ptr()) as i32;
//     println!("ifindex: {ifindex}");

//     // bump_memlock_rlimit()?;

//     let skel_builder = XdppassSkelBuilder::default();
//     let open_skel = skel_builder.open().unwrap();
//     let skel = open_skel.load().unwrap();

//     let prog_fd = skel.progs().xdp_pass_prog().fd();
//     let maps = skel.maps();
//     println!("map fd: {}", maps.xsks_map().fd());

//     let buffer_size = FRAME_SIZE * NUM_FRAMES;
//     let mut buffer: *mut c_void = ptr::null_mut();

//     let page_size = sysconf(_SC_PAGESIZE) as usize;
//     println!("page size: {}", page_size);
//     let ret = posix_memalign(&mut buffer, page_size, buffer_size);
//     println!("posix_memalign: {}", ret);

//     let mut umem: MaybeUninit<*mut xsk_umem> = MaybeUninit::zeroed();
//     let mut fq: MaybeUninit<xsk_ring_prod> = MaybeUninit::zeroed();
//     let mut cq: MaybeUninit<xsk_ring_cons> = MaybeUninit::zeroed();

//     let ret = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
//     println!("bpf_set_link_xdp_fd: {}", ret);

//     let ret = xsk_umem__create(
//         umem.as_mut_ptr(),
//         buffer,
//         buffer_size as u64,
//         fq.as_mut_ptr(),
//         cq.as_mut_ptr(),
//         null(),
//     );
//     println!("xsk_umem__create: {}", ret);

//     let umem = unsafe { umem.assume_init() };
//     let mut fq = unsafe { fq.assume_init() };
//     let mut cq = unsafe { cq.assume_init() };

//     let mut xsk: MaybeUninit<*mut xsk_socket> = MaybeUninit::zeroed();
//     let mut rx: MaybeUninit<xsk_ring_cons> = MaybeUninit::zeroed();
//     let mut tx: MaybeUninit<xsk_ring_prod> = MaybeUninit::zeroed();

//     let mut config: MaybeUninit<xsk_socket_config> = MaybeUninit::zeroed();
//     addr_of_mut!((*config.as_mut_ptr()).rx_size).
// write(XSK_RING_CONS__DEFAULT_NUM_DESCS);     addr_of_mut!((*config.
// as_mut_ptr()).tx_size).write(XSK_RING_PROD__DEFAULT_NUM_DESCS);
//     addr_of_mut!((*config.as_mut_ptr()).libbpf_flags).
// write(XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD);     addr_of_mut!((*config.
// as_mut_ptr()).xdp_flags).write(XDP_FLAGS_SKB_MODE);     addr_of_mut!((*
// config.as_mut_ptr()).bind_flags).write((XDP_COPY | XDP_USE_NEED_WAKEUP) as
// u16);     let ret = xsk_socket__create(
//         xsk.as_mut_ptr(),
//         ifname.as_ptr(),
//         0,
//         umem,
//         rx.as_mut_ptr(),
//         tx.as_mut_ptr(),
//         config.as_ptr(),
//     );
//     println!("xsk_socket__create: {}", ret);

//     let ret = xsk_socket__update_xskmap(xsk.assume_init(),
// maps.xsks_map().fd());     println!("xsk_socket__update_xskmap: {}", ret);

//     let mut prog_id: u32 = 0;
//     let mut umem_frame_addr: [u64; NUM_FRAMES] = array::from_fn(|i| (i *
// FRAME_SIZE) as u64);     let mut umem_frame_free = NUM_FRAMES;
//     let mut idx: u32 = 0;

//     unsafe {
//         let ret = bpf_get_link_xdp_id(ifindex, &mut prog_id,
// XDP_FLAGS_SKB_MODE);         println!("bpf_get_link_xdp_id: {}, prog_id: {}",
// ret, prog_id);

//         let ret =
//             _xsk_ring_prod__reserve(&mut fq, XSK_RING_PROD__DEFAULT_NUM_DESCS
// as u64, &mut idx);         println!("xsk_ring_prod__reserve: {}, idx: {}",
// ret, idx);

//         for _ in 0..XSK_RING_PROD__DEFAULT_NUM_DESCS {
//             _xsk_ring_prod__fill_addr(&mut fq,
// idx).write(xsk_alloc_umem_frame(                 &mut umem_frame_addr,
//                 &mut umem_frame_free,
//             ));
//             idx += 1;
//         }

//         _xsk_ring_prod__submit(&mut fq, XSK_RING_PROD__DEFAULT_NUM_DESCS as
// u64);     }

//     let mut rx = unsafe { rx.assume_init() };
//     let mut tx = unsafe { tx.assume_init() };

//     (
//         (prog_fd, buffer_size, buffer, umem),
//         (fq, cq, rx, tx),
//         (xsk, umem_frame_free, umem_frame_addr),
//     )
// }

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn peek_rx_ring(
    idx_rx: &mut u32,
    idx_fq: &mut u32,
    rx: &mut xsk_ring_cons,
    fq: &mut xsk_ring_prod,
    umem_ctrl: &Mutex<UmemCtrl>,
) -> u64 {
    let received = _xsk_ring_cons__peek(rx, 64, idx_rx);
    if received == 0 {
        return 0;
    }

    info!(
        "[xdp] - xsk_ring_cons__peek: {}, idx_rx: {}",
        received, idx_rx
    );

    // Stuff the ring with as much frames as possible
    let mut umem_ctrl = umem_ctrl.lock().unwrap();
    let stock_frames = _xsk_prod_nb_free(fq, umem_ctrl.umem_frame_free as u32);
    if stock_frames > 0 {
        let ret = _xsk_ring_prod__reserve(fq, stock_frames as u64, idx_fq);
        info!(
            "xsk_ring_prod__reserve: {}, stock_frames: {}, idx_fq: {},
        umem_frame_free: {}",
            ret, stock_frames, idx_fq, umem_ctrl.umem_frame_free
        );

        for _ in 0..stock_frames {
            _xsk_ring_prod__fill_addr(fq, *idx_fq).write(xsk_alloc_umem_frame(&mut umem_ctrl));
            *idx_fq += 1;
        }
        _xsk_ring_prod__submit(fq, stock_frames as u64);
    }

    received
}

/// Return values:
/// - peer_addr
/// - local_addr
/// - local_mac
/// - peer_mac
/// - udp_payload
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn receive_packet(
    rx: &mut xsk_ring_cons,
    idx_rx: &mut u32,
    buffer: *mut c_void,
) -> Option<(SocketAddr, SocketAddr, MacAddr, MacAddr, Vec<u8>)> {
    let desc = _xsk_ring_cons__rx_desc(rx, *idx_rx);
    *idx_rx += 1;
    let addr = (*desc).addr;
    let len = (*desc).len as usize;
    let ptr = _xsk_umem__get_data(buffer, addr);
    let data = slice::from_raw_parts_mut(ptr as *mut u8, len);
    let mut eth = MutableEthernetPacket::new(data)?;
    let mut ip = MutableIpv4Packet::new(eth.payload_mut())?;
    let peer_ip = ip.get_source();
    let local_ip = ip.get_destination();
    let udp = MutableUdpPacket::new(ip.payload_mut())?;

    let udp_payload = udp.payload().to_owned();

    let peer_addr = SocketAddr::V4(SocketAddrV4::new(peer_ip, udp.get_source()));
    let local_addr = SocketAddr::V4(SocketAddrV4::new(local_ip, udp.get_destination()));
    let local_mac = eth.get_destination();
    let peer_mac = eth.get_source();

    info!(
        "received packet from {:?}, payload size {:?}",
        peer_addr,
        udp_payload.len()
    );

    Some((peer_addr, local_addr, local_mac, peer_mac, udp_payload))
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn send_packet(
    tx: *mut xsk_ring_prod,
    umem: *mut c_void,
    xsk: *const xsk_socket,
    umem_ctrl: &Mutex<UmemCtrl>,
    source_mac: MacAddr,
    dest_mac: MacAddr,
    source_addr: SocketAddr,
    dest_addr: SocketAddr,
    payload: &[u8],
) {
    let mut idx_tx: u32 = 0;
    // if ret > 0 {
    let mut udp = MutableUdpPacket::owned(vec![0; payload.len() + 8]).unwrap();
    udp.set_payload(payload);
    udp.set_source(source_addr.port());
    udp.set_destination(dest_addr.port());
    udp.set_length((payload.len() as u16 + 8));
    udp.set_checksum(0);
    let udp = udp.consume_to_immutable();
    info!("{:?}", udp);
    let udp_buf = udp.packet();

    let ip_len = udp_buf.len() + 20;
    let mut ip = MutableIpv4Packet::owned(vec![0; ip_len]).unwrap();
    ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip.set_header_length(5);
    ip.set_version(4);
    ip.set_ttl(64);
    ip.set_total_length(udp_buf.len() as u16 + 20);
    ip.set_payload(udp_buf);
    ip.set_source(extract_ipv4(&source_addr));
    ip.set_destination(extract_ipv4(&dest_addr));
    ip.set_checksum(ipv4::checksum(&ip.to_immutable()));
    let ip = ip.consume_to_immutable();
    info!("{:?}", ip);
    let ip_buf = ip.packet();

    let mut eth = MutableEthernetPacket::owned(vec![0; ip_buf.len() + 64]).unwrap();
    eth.set_source(source_mac);
    eth.set_destination(dest_mac);
    eth.set_ethertype(EtherTypes::Ipv4);
    eth.set_payload(ip_buf);
    info!("{:?}", eth);
    let eth = eth.consume_to_immutable();
    let eth_buf = eth.packet();

    let addr = xsk_alloc_umem_frame(&mut umem_ctrl.lock().unwrap());
    let data_ptr = _xsk_umem__get_data(umem, addr);
    ptr::copy_nonoverlapping(eth_buf.as_ptr(), data_ptr as *mut u8, eth_buf.len());

    let umem_ctrl = umem_ctrl.lock().unwrap();
    let ret = _xsk_ring_prod__reserve(tx, 1, &mut idx_tx);
    info!(
        "xsk_ring_prod__reserve: {}, idx_tx: {}, addr: {}, thread_id: {:?}",
        ret,
        idx_tx,
        addr,
        thread::current().id()
    );
    _xsk_ring_prod__fill_addr(tx, idx_tx).write(addr);
    let desc = _xsk_ring_prod__tx_desc(tx, idx_tx);
    (*desc).len = eth_buf.len() as _;
    _xsk_ring_prod__submit(tx, 1);
    drop(umem_ctrl);

    info!("data write finished");

    info!("submit finished");
    sendto(xsk_socket__fd(xsk), null(), 0, MSG_DONTWAIT, null(), 0);
    info!("sendto finished");
    // }
}

fn extract_ipv4(socket_addr: &SocketAddr) -> Ipv4Addr {
    match socket_addr {
        SocketAddr::V4(v4) => *v4.ip(),
        SocketAddr::V6(_) => todo!(),
    }
}
