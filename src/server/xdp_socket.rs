use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ptr::{self, null},
    slice,
    sync::Mutex,
    thread,
};

use libbpf_rs::libbpf_sys::*;
use libc::{c_void, sendto, MSG_DONTWAIT};
use pnet::{
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{self, MutableIpv4Packet},
        udp::MutableUdpPacket,
        MutablePacket, Packet,
    },
    util::MacAddr,
};

use super::server::UmemCtrl;
use crate::server::server::xsk_alloc_umem_frame;

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
    let mut udp = MutableUdpPacket::owned(vec![0; payload.len() + 8]).unwrap();
    udp.set_payload(payload);
    udp.set_source(source_addr.port());
    udp.set_destination(dest_addr.port());
    udp.set_length(payload.len() as u16 + 8);
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

    let mut idx_tx: u32 = 0;
    let ret = _xsk_ring_prod__reserve(tx, 1, &mut idx_tx);

    let addr = xsk_alloc_umem_frame(&mut *umem_ctrl.lock().unwrap());
    let data_ptr = _xsk_umem__get_data(umem, addr);
    ptr::copy_nonoverlapping(eth_buf.as_ptr(), data_ptr as *mut u8, eth_buf.len());

    // _xsk_ring_prod__fill_addr(tx, idx_tx).write(addr);
    let umem_ctrl = umem_ctrl.lock().unwrap();
    let desc = _xsk_ring_prod__tx_desc(tx, idx_tx);
    (*desc).addr = addr;
    (*desc).len = eth_buf.len() as _;

    _xsk_ring_prod__submit(tx, 1);
    drop(umem_ctrl);
    sendto(xsk_socket__fd(xsk), null(), 0, MSG_DONTWAIT, null(), 0);
}

fn extract_ipv4(socket_addr: &SocketAddr) -> Ipv4Addr {
    match socket_addr {
        SocketAddr::V4(v4) => *v4.ip(),
        SocketAddr::V6(_) => todo!(),
    }
}
