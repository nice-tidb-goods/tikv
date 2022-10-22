// Copyright 2016 TiKV Project Authors. Licensed under Apache-2.0.

use std::{
    array, i32,
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr},
    ptr::{self, addr_of_mut, null, null_mut},
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use api_version::KvFormat;
use byteorder::{ByteOrder, LittleEndian};
use engine_traits::KvEngine;
use futures::{compat::Stream01CompatExt, stream::StreamExt};
use futures_executor::block_on;
use grpcio::{ChannelBuilder, Environment, ResourceQuota, Server as GrpcServer, ServerBuilder};
use grpcio_health::{create_health, HealthService, ServingStatus};
use kvproto::{
    kvrpcpb::{CommandPri, IsolationLevel},
    tikvpb::*,
};
use libbpf_rs::libbpf_sys::*;
use libc::{c_void, posix_memalign, sysconf, _SC_PAGESIZE};
use raftstore::{
    router::RaftStoreRouter,
    store::{CheckLeaderTask, RegionSnapshot, SnapManager},
};
use rand::prelude::*;
use security::SecurityManager;
use tikv_kv::{with_tls_engine, Statistics};
use tikv_util::{
    config::VersionTrack,
    sys::{get_global_memory_usage, record_global_memory_usage},
    timer::GLOBAL_TIMER_HANDLE,
    worker::{LazyWorker, Scheduler, Worker},
    Either,
};
use tokio::runtime::{Builder as RuntimeBuilder, Handle as RuntimeHandle, Runtime};
use tokio_timer::timer::Handle;
use txn_types::{Key, TimeStamp, TsSet};

use crate::storage::txn::store::Store;

const FRAME_SIZE: usize = XSK_UMEM__DEFAULT_FRAME_SIZE as usize;
const NUM_FRAMES: usize = 4096;

use super::{
    load_statistics::*,
    metrics::{MEMORY_USAGE_GAUGE, SERVER_INFO_GAUGE_VEC},
    raft_client::{ConnectionBuilder, RaftClient},
    resolve::StoreAddrResolver,
    service::*,
    snap::{Runner as SnapHandler, Task as SnapTask},
    transport::ServerTransport,
    xdp_socket::*,
    Config, Error, Result,
};
use crate::{
    coprocessor::Endpoint,
    coprocessor_v2,
    read_pool::ReadPool,
    server::{gc_worker::GcWorker, xdppass::XdppassSkelBuilder, Proxy},
    storage::{lock_manager::LockManager, Engine, SnapshotStore, Storage},
    tikv_util::sys::thread::ThreadBuildWrapper,
};

const LOAD_STATISTICS_SLOTS: usize = 4;
const LOAD_STATISTICS_INTERVAL: Duration = Duration::from_millis(100);
const MEMORY_USAGE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
pub const GRPC_THREAD_PREFIX: &str = "grpc-server";
pub const READPOOL_NORMAL_THREAD_PREFIX: &str = "store-read-norm";
pub const STATS_THREAD_PREFIX: &str = "transport-stats";

/// The TiKV server
///
/// It hosts various internal components, including gRPC, the raftstore router
/// and a snapshot worker.
pub struct Server<T: RaftStoreRouter<E::Local> + 'static, S: StoreAddrResolver + 'static, E: Engine>
{
    env: Arc<Environment>,
    /// A GrpcServer builder or a GrpcServer.
    ///
    /// If the listening port is configured, the server will be started lazily.
    builder_or_server: Option<Either<ServerBuilder, GrpcServer>>,
    grpc_mem_quota: ResourceQuota,
    local_addr: SocketAddr,
    // Transport.
    trans: ServerTransport<T, S, E::Local>,
    raft_router: T,
    // For sending/receiving snapshots.
    snap_mgr: SnapManager,
    snap_worker: LazyWorker<SnapTask>,

    // Currently load statistics is done in the thread.
    stats_pool: Option<Runtime>,
    grpc_thread_load: Arc<ThreadLoadPool>,
    yatp_read_pool: Option<ReadPool>,
    debug_thread_pool: Arc<Runtime>,
    health_service: HealthService,
    timer: Handle,
}

impl<T: RaftStoreRouter<E::Local> + Unpin, S: StoreAddrResolver + 'static, E: Engine>
    Server<T, S, E>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new<L: LockManager, F: KvFormat>(
        store_id: u64,
        cfg: &Arc<VersionTrack<Config>>,
        security_mgr: &Arc<SecurityManager>,
        storage: Storage<E, L, F>,
        copr: Endpoint<E>,
        copr_v2: coprocessor_v2::Endpoint,
        raft_router: T,
        resolver: S,
        snap_mgr: SnapManager,
        gc_worker: GcWorker<E, T>,
        check_leader_scheduler: Scheduler<CheckLeaderTask>,
        env: Arc<Environment>,
        yatp_read_pool: Option<ReadPool>,
        debug_thread_pool: Arc<Runtime>,
        health_service: HealthService,
    ) -> Result<Self> {
        // A helper thread (or pool) for transport layer.
        let stats_pool = if cfg.value().stats_concurrency > 0 {
            Some(
                RuntimeBuilder::new_multi_thread()
                    .thread_name(STATS_THREAD_PREFIX)
                    .worker_threads(cfg.value().stats_concurrency)
                    .after_start_wrapper(|| {})
                    .before_stop_wrapper(|| {})
                    .build()
                    .unwrap(),
            )
        } else {
            None
        };
        let grpc_thread_load = Arc::new(ThreadLoadPool::with_threshold(
            cfg.value().heavy_load_threshold,
        ));

        let snap_worker = Worker::new("snap-handler");
        let lazy_worker = snap_worker.lazy_build("snap-handler");

        info!("start toy service!");
        let toy_services = unsafe { start_toy_service(storage.clone()) };
        thread::Builder::new()
            .name("toy-service".to_string())
            .spawn(move || block_on(toy_services))
            .unwrap();
        // debug_thread_pool.spawn_blocking(move || async { toy_services.await });

        let proxy = Proxy::new(security_mgr.clone(), &env, Arc::new(cfg.value().clone()));
        let kv_service = KvService::new(
            store_id,
            storage,
            gc_worker,
            copr,
            copr_v2,
            raft_router.clone(),
            lazy_worker.scheduler(),
            check_leader_scheduler,
            Arc::clone(&grpc_thread_load),
            cfg.value().enable_request_batch,
            proxy,
            cfg.value().reject_messages_on_memory_ratio,
        );

        let addr = SocketAddr::from_str(&cfg.value().addr)?;
        let ip = format!("{}", addr.ip());
        let mem_quota = ResourceQuota::new(Some("ServerMemQuota"))
            .resize_memory(cfg.value().grpc_memory_pool_quota.0 as usize);
        let channel_args = ChannelBuilder::new(Arc::clone(&env))
            .stream_initial_window_size(cfg.value().grpc_stream_initial_window_size.0 as i32)
            .max_concurrent_stream(cfg.value().grpc_concurrent_stream)
            .max_receive_message_len(-1)
            .set_resource_quota(mem_quota.clone())
            .max_send_message_len(-1)
            .http2_max_ping_strikes(i32::MAX) // For pings without data from clients.
            .keepalive_time(cfg.value().grpc_keepalive_time.into())
            .keepalive_timeout(cfg.value().grpc_keepalive_timeout.into())
            .build_args();

        let builder = {
            let mut sb = ServerBuilder::new(Arc::clone(&env))
                .channel_args(channel_args)
                .register_service(create_tikv(kv_service))
                .register_service(create_health(health_service.clone()));
            sb = security_mgr.bind(sb, &ip, addr.port());
            Either::Left(sb)
        };

        let conn_builder = ConnectionBuilder::new(
            env.clone(),
            Arc::clone(cfg),
            security_mgr.clone(),
            resolver,
            raft_router.clone(),
            lazy_worker.scheduler(),
            grpc_thread_load.clone(),
        );
        let raft_client = RaftClient::new(conn_builder);

        let trans = ServerTransport::new(raft_client);
        health_service.set_serving_status("", ServingStatus::NotServing);

        let svr = Server {
            env: Arc::clone(&env),
            builder_or_server: Some(builder),
            grpc_mem_quota: mem_quota,
            local_addr: addr,
            trans,
            raft_router,
            snap_mgr,
            snap_worker: lazy_worker,
            stats_pool,
            grpc_thread_load,
            yatp_read_pool,
            debug_thread_pool,
            health_service,
            timer: GLOBAL_TIMER_HANDLE.clone(),
        };

        Ok(svr)
    }

    pub fn get_debug_thread_pool(&self) -> &RuntimeHandle {
        self.debug_thread_pool.handle()
    }

    pub fn get_snap_worker_scheduler(&self) -> Scheduler<SnapTask> {
        self.snap_worker.scheduler()
    }

    pub fn transport(&self) -> ServerTransport<T, S, E::Local> {
        self.trans.clone()
    }

    pub fn env(&self) -> Arc<Environment> {
        self.env.clone()
    }

    pub fn get_grpc_mem_quota(&self) -> &ResourceQuota {
        &self.grpc_mem_quota
    }

    /// Register a gRPC service.
    /// Register after starting, it fails and returns the service.
    pub fn register_service(&mut self, svc: grpcio::Service) -> Option<grpcio::Service> {
        match self.builder_or_server.take() {
            Some(Either::Left(mut builder)) => {
                builder = builder.register_service(svc);
                self.builder_or_server = Some(Either::Left(builder));
                None
            }
            Some(server) => {
                self.builder_or_server = Some(server);
                Some(svc)
            }
            None => Some(svc),
        }
    }

    /// Build gRPC server and bind to address.
    pub fn build_and_bind(&mut self) -> Result<SocketAddr> {
        let sb = self.builder_or_server.take().unwrap().left().unwrap();
        let server = sb.build()?;
        let (host, port) = server.bind_addrs().next().unwrap();
        let addr = SocketAddr::new(IpAddr::from_str(host)?, port);
        self.local_addr = addr;
        self.builder_or_server = Some(Either::Right(server));
        Ok(addr)
    }

    /// Starts the TiKV server.
    /// Notice: Make sure call `build_and_bind` first.
    pub fn start(
        &mut self,
        cfg: Arc<VersionTrack<Config>>,
        security_mgr: Arc<SecurityManager>,
    ) -> Result<()> {
        let snap_runner = SnapHandler::new(
            Arc::clone(&self.env),
            self.snap_mgr.clone(),
            self.raft_router.clone(),
            security_mgr,
            Arc::clone(&cfg),
        );
        self.snap_worker.start(snap_runner);

        let mut grpc_server = self.builder_or_server.take().unwrap().right().unwrap();
        info!("listening on addr"; "addr" => &self.local_addr);
        grpc_server.start();
        self.builder_or_server = Some(Either::Right(grpc_server));

        // Note this should be called only after grpc server is started.
        let mut grpc_load_stats = {
            let tl = Arc::clone(&self.grpc_thread_load);
            ThreadLoadStatistics::new(LOAD_STATISTICS_SLOTS, GRPC_THREAD_PREFIX, tl)
        };
        if let Some(ref p) = self.stats_pool {
            let mut delay = self
                .timer
                .interval(Instant::now(), LOAD_STATISTICS_INTERVAL)
                .compat();
            p.spawn(async move {
                while let Some(Ok(i)) = delay.next().await {
                    grpc_load_stats.record(i);
                }
            });
            let mut delay = self
                .timer
                .interval(Instant::now(), MEMORY_USAGE_REFRESH_INTERVAL)
                .compat();
            p.spawn(async move {
                while let Some(Ok(_)) = delay.next().await {
                    record_global_memory_usage();
                    MEMORY_USAGE_GAUGE.set(get_global_memory_usage() as i64);
                }
            });
        };

        let startup_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Other(box_err!("Clock may have gone backwards")))?
            .as_secs();

        SERVER_INFO_GAUGE_VEC
            .with_label_values(&[
                &("v".to_owned() + env!("CARGO_PKG_VERSION")),
                option_env!("TIKV_BUILD_GIT_HASH").unwrap_or("None"),
            ])
            .set(startup_ts as i64);
        self.health_service
            .set_serving_status("", ServingStatus::Serving);

        info!("TiKV is ready to serve");
        Ok(())
    }

    /// Stops the TiKV server.
    pub fn stop(&mut self) -> Result<()> {
        self.snap_worker.stop();
        if let Some(Either::Right(mut server)) = self.builder_or_server.take() {
            server.shutdown();
        }
        if let Some(pool) = self.stats_pool.take() {
            pool.shutdown_background();
        }
        let _ = self.yatp_read_pool.take();
        self.health_service.shutdown();
        Ok(())
    }

    // Return listening address, this may only be used for outer test
    // to get the real address because we may use "127.0.0.1:0"
    // in test to avoid port conflict.
    pub fn listening_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

pub struct UmemCtrl {
    pub umem_frame_addr: [u64; NUM_FRAMES],
    pub umem_frame_free: usize,
}

impl UmemCtrl {
    pub fn new() -> Mutex<UmemCtrl> {
        Mutex::new(UmemCtrl {
            umem_frame_addr: array::from_fn(|i| (i * FRAME_SIZE) as u64),
            umem_frame_free: NUM_FRAMES,
        })
    }
}

pub fn xsk_alloc_umem_frame(umem_ctrl: &mut UmemCtrl) -> u64 {
    if umem_ctrl.umem_frame_free == 0 {
        return u64::MAX;
    }
    umem_ctrl.umem_frame_free -= 1;
    let frame = umem_ctrl.umem_frame_addr[umem_ctrl.umem_frame_free];
    umem_ctrl.umem_frame_addr[umem_ctrl.umem_frame_free] = u64::MAX;
    return frame;
}

pub fn xsk_free_umem_frame(umem_ctrl: &mut UmemCtrl, frame: u64) {
    umem_ctrl.umem_frame_addr[umem_ctrl.umem_frame_free] = frame;
    umem_ctrl.umem_frame_free += 1;
}

async unsafe fn start_toy_service<E, L, F>(storage: Storage<E, L, F>)
where
    E: Engine,
    L: LockManager,
    F: KvFormat,
{
    let ifname = std::ffi::CString::new("wlan0").unwrap();
    let ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) as i32 };

    info!("ifindex"; "index" => ifindex);

    let read_pool = storage.read_pool.clone();

    // bump_memlock_rlimit()?;

    let skel_builder = XdppassSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();
    let skel = open_skel.load().unwrap();

    let prog_fd = skel.progs().xdp_pass_prog().fd();
    let maps = skel.maps();
    info!("map fd: {}", maps.xsks_map().fd());

    let buffer_size = FRAME_SIZE * NUM_FRAMES;
    let mut buffer: *mut c_void = ptr::null_mut();

    let page_size = sysconf(_SC_PAGESIZE) as usize;
    info!("page size: {}", page_size);
    let ret = posix_memalign(&mut buffer, page_size, buffer_size);
    info!("posix_memalign: {}", ret);

    let mut umem: MaybeUninit<*mut xsk_umem> = MaybeUninit::zeroed();
    let mut fq: xsk_ring_prod = MaybeUninit::zeroed().assume_init();
    let mut cq: xsk_ring_cons = MaybeUninit::zeroed().assume_init();

    let ret = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
    info!("bpf_set_link_xdp_fd: {}", ret);

    let ret = xsk_umem__create(
        umem.as_mut_ptr(),
        buffer,
        buffer_size as u64,
        &mut fq,
        &mut cq,
        null(),
    );
    println!("xsk_umem__create: {}", ret);

    let umem = unsafe { umem.assume_init() };
    let mut rng = rand::thread_rng();

    let mut xsk: *mut xsk_socket = null_mut();
    let mut rx: xsk_ring_cons = MaybeUninit::zeroed().assume_init();
    let mut tx: xsk_ring_prod = MaybeUninit::zeroed().assume_init();

    let mut config: MaybeUninit<xsk_socket_config> = MaybeUninit::zeroed();
    addr_of_mut!((*config.as_mut_ptr()).rx_size).write(XSK_RING_CONS__DEFAULT_NUM_DESCS);
    addr_of_mut!((*config.as_mut_ptr()).tx_size).write(XSK_RING_PROD__DEFAULT_NUM_DESCS);
    addr_of_mut!((*config.as_mut_ptr()).libbpf_flags).write(XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD);
    addr_of_mut!((*config.as_mut_ptr()).xdp_flags).write(XDP_FLAGS_SKB_MODE);
    addr_of_mut!((*config.as_mut_ptr()).bind_flags).write((XDP_COPY | XDP_USE_NEED_WAKEUP) as u16);
    let ret = xsk_socket__create(
        &mut xsk,
        ifname.as_ptr(),
        0,
        umem,
        &mut rx,
        &mut tx,
        config.as_ptr(),
    );
    info!("xsk_socket__create: {}", ret);

    let ret = xsk_socket__update_xskmap(xsk, maps.xsks_map().fd());
    info!("xsk_socket__update_xskmap: {}", ret);

    let mut prog_id: u32 = 0;
    let umem_ctrl = Arc::new(UmemCtrl::new());
    let mut idx: u32 = 0;

    unsafe {
        let ret = bpf_get_link_xdp_id(ifindex, &mut prog_id, XDP_FLAGS_SKB_MODE);
        println!("info: {}, prog_id: {}", ret, prog_id);

        let ret =
            _xsk_ring_prod__reserve(&mut fq, XSK_RING_PROD__DEFAULT_NUM_DESCS as u64, &mut idx);
        println!("info: {}, idx: {}", ret, idx);

        let mut umem_ctrl = umem_ctrl.lock().unwrap();
        for _ in 0..XSK_RING_PROD__DEFAULT_NUM_DESCS {
            _xsk_ring_prod__fill_addr(&mut fq, idx).write(xsk_alloc_umem_frame(&mut *umem_ctrl));
            idx += 1;
        }
        drop(umem_ctrl);

        _xsk_ring_prod__submit(&mut fq, XSK_RING_PROD__DEFAULT_NUM_DESCS as u64);
    }

    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    // let r = running.clone();
    // ctrlc::set_handler(move || {
    //     r.store(false, std::sync::atomic::Ordering::SeqCst);
    // })
    // .unwrap();

    let mut prod_addr = 0;

    loop {
        unsafe {
            let mut idx_rx = 0;
            let mut idx_fq: u32 = 0;
            let mut idx_cq: u32 = 0;

            let completed = _xsk_ring_cons__peek(&mut cq, 64, &mut idx_cq);
            if completed > 0 {
                let mut umem_ctrl = umem_ctrl.lock().unwrap();
                for _ in 0..completed {
                    let addr = _xsk_ring_cons__comp_addr(&mut cq, idx_cq).read();
                    xsk_free_umem_frame(&mut umem_ctrl, addr);
                    idx_cq += 1;
                }
                _xsk_ring_cons__release(&mut cq, completed);
            }
            let received = peek_rx_ring(&mut idx_rx, &mut idx_fq, &mut rx, &mut fq, &umem_ctrl);

            for _ in 0..received {
                if let Some((peer_addr, local_addr, local_mac, peer_mac, mut udp_payload)) =
                    receive_packet(&mut rx, &mut idx_rx, buffer, &umem_ctrl)
                {
                    let key = Key::from_raw(&udp_payload[16..]);
                    let tx = &mut tx as *mut _ as usize;
                    let xsk = xsk as usize;
                    let buffer = buffer as usize;
                    let umem_ctrl = umem_ctrl.clone();
                    read_pool
                        .spawn(
                            async move {
                                let tx = tx as *mut xsk_ring_prod;
                                let xsk = xsk as *mut xsk_socket;
                                let buffer = buffer as *mut c_void;
                                let snapshot = with_tls_engine(|engine: &E| {
                                    engine.kv_engine().unwrap().snapshot()
                                });
                                let snapshot = RegionSnapshot::from_snapshot(
                                    Arc::new(snapshot),
                                    Default::default(),
                                );
                                let snap_store = SnapshotStore::new(
                                    snapshot,
                                    TimeStamp::max(),
                                    IsolationLevel::Si,
                                    true,
                                    TsSet::Empty,
                                    TsSet::Empty,
                                    false,
                                );
                                let mut statistics = Statistics::default();
                                let res = snap_store.get(&key, &mut statistics).unwrap();
                                let value = res.unwrap_or(vec![]);
                                LittleEndian::write_u64(
                                    &mut udp_payload[8..16],
                                    value.len() as u64,
                                );
                                udp_payload.truncate(16);
                                udp_payload.extend_from_slice(&value);
                                send_packet(
                                    tx,
                                    buffer,
                                    xsk,
                                    &umem_ctrl,
                                    local_mac,
                                    peer_mac,
                                    local_addr,
                                    peer_addr,
                                    &udp_payload,
                                );
                            },
                            CommandPri::High,
                            rng.gen(),
                        )
                        .unwrap();
                }
            }

            libbpf_rs::libbpf_sys::_xsk_ring_cons__release(&mut rx, received);
        }
    }

    #[allow(unreachable_code)]
    unsafe {
        let ret = libbpf_rs::libbpf_sys::bpf_xdp_detach(
            ifindex,
            libbpf_rs::libbpf_sys::XDP_FLAGS_SKB_MODE,
            std::ptr::null(),
        );
        println!("bpf_xdp_detach: {}", ret);
    }
}

#[cfg(any(test, feature = "testexport"))]
pub mod test_router {
    use std::sync::mpsc::*;

    use engine_rocks::{RocksEngine, RocksSnapshot};
    use engine_traits::{KvEngine, Snapshot};
    use kvproto::raft_serverpb::RaftMessage;
    use raftstore::{store::*, Result as RaftStoreResult};

    use super::*;

    #[derive(Clone)]
    pub struct TestRaftStoreRouter {
        tx: Sender<usize>,
        significant_msg_sender: Sender<SignificantMsg<RocksSnapshot>>,
    }

    impl TestRaftStoreRouter {
        pub fn new(
            tx: Sender<usize>,
            significant_msg_sender: Sender<SignificantMsg<RocksSnapshot>>,
        ) -> TestRaftStoreRouter {
            TestRaftStoreRouter {
                tx,
                significant_msg_sender,
            }
        }
    }

    impl StoreRouter<RocksEngine> for TestRaftStoreRouter {
        fn send(&self, _: StoreMsg<RocksEngine>) -> RaftStoreResult<()> {
            let _ = self.tx.send(1);
            Ok(())
        }
    }

    impl<S: Snapshot> ProposalRouter<S> for TestRaftStoreRouter {
        fn send(
            &self,
            _: RaftCommand<S>,
        ) -> std::result::Result<(), crossbeam::channel::TrySendError<RaftCommand<S>>> {
            let _ = self.tx.send(1);
            Ok(())
        }
    }

    impl<EK: KvEngine> CasualRouter<EK> for TestRaftStoreRouter {
        fn send(&self, _: u64, _: CasualMessage<EK>) -> RaftStoreResult<()> {
            let _ = self.tx.send(1);
            Ok(())
        }
    }

    impl SignificantRouter<RocksEngine> for TestRaftStoreRouter {
        fn significant_send(
            &self,
            _: u64,
            msg: SignificantMsg<RocksSnapshot>,
        ) -> RaftStoreResult<()> {
            let _ = self.significant_msg_sender.send(msg);
            Ok(())
        }
    }

    impl RaftStoreRouter<RocksEngine> for TestRaftStoreRouter {
        fn send_raft_msg(&self, _: RaftMessage) -> RaftStoreResult<()> {
            let _ = self.tx.send(1);
            Ok(())
        }

        fn broadcast_normal(&self, _: impl FnMut() -> PeerMsg<RocksEngine>) {
            let _ = self.tx.send(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{atomic::*, *},
        time::Duration,
    };

    use engine_rocks::RocksSnapshot;
    use grpcio::EnvBuilder;
    use kvproto::raft_serverpb::RaftMessage;
    use raftstore::{
        coprocessor::region_info_accessor::MockRegionInfoProvider,
        store::{transport::Transport, *},
    };
    use resource_metering::ResourceTagFactory;
    use security::SecurityConfig;
    use tikv_util::quota_limiter::QuotaLimiter;
    use tokio::runtime::Builder as TokioBuilder;

    use super::{
        super::{
            resolve::{Callback as ResolveCallback, StoreAddrResolver},
            Config, Result,
        },
        *,
    };
    use crate::{
        config::CoprReadPoolConfig,
        coprocessor::{self, readpool_impl},
        server::TestRaftStoreRouter,
        storage::{lock_manager::DummyLockManager, TestStorageBuilderApiV1},
    };

    #[derive(Clone)]
    struct MockResolver {
        quick_fail: Arc<AtomicBool>,
        addr: Arc<Mutex<Option<String>>>,
    }

    impl StoreAddrResolver for MockResolver {
        fn resolve(&self, _: u64, cb: ResolveCallback) -> Result<()> {
            if self.quick_fail.load(Ordering::SeqCst) {
                return Err(box_err!("quick fail"));
            }
            let addr = self.addr.lock().unwrap();
            cb(addr
                .as_ref()
                .map(|s| s.to_owned())
                .ok_or(box_err!("not set")));
            Ok(())
        }
    }

    fn is_unreachable_to(
        msg: &SignificantMsg<RocksSnapshot>,
        region_id: u64,
        to_peer_id: u64,
    ) -> bool {
        if let SignificantMsg::Unreachable {
            region_id: r_id,
            to_peer_id: p_id,
        } = *msg
        {
            region_id == r_id && to_peer_id == p_id
        } else {
            false
        }
    }

    // if this failed, unset the environmental variables 'http_proxy' and
    // 'https_proxy', and retry.
    #[test]
    fn test_peer_resolve() {
        let mock_store_id = 5;
        let cfg = Config {
            addr: "127.0.0.1:0".to_owned(),
            ..Default::default()
        };

        let storage = TestStorageBuilderApiV1::new(DummyLockManager)
            .build()
            .unwrap();

        let (tx, rx) = mpsc::channel();
        let (significant_msg_sender, significant_msg_receiver) = mpsc::channel();
        let router = TestRaftStoreRouter::new(tx, significant_msg_sender);
        let env = Arc::new(
            EnvBuilder::new()
                .cq_count(1)
                .name_prefix(thd_name!(GRPC_THREAD_PREFIX))
                .build(),
        );

        let (tx, _rx) = mpsc::channel();
        let mut gc_worker = GcWorker::new(
            storage.get_engine(),
            router.clone(),
            tx,
            Default::default(),
            Default::default(),
            Arc::new(MockRegionInfoProvider::new(Vec::new())),
        );
        gc_worker.start(mock_store_id).unwrap();

        let quick_fail = Arc::new(AtomicBool::new(false));
        let cfg = Arc::new(VersionTrack::new(cfg));
        let security_mgr = Arc::new(SecurityManager::new(&SecurityConfig::default()).unwrap());

        let cop_read_pool = ReadPool::from(readpool_impl::build_read_pool_for_test(
            &CoprReadPoolConfig::default_for_test(),
            storage.get_engine(),
        ));
        let copr = coprocessor::Endpoint::new(
            &cfg.value().clone(),
            cop_read_pool.handle(),
            storage.get_concurrency_manager(),
            ResourceTagFactory::new_for_test(),
            Arc::new(QuotaLimiter::default()),
        );
        let copr_v2 = coprocessor_v2::Endpoint::new(&coprocessor_v2::Config::default());
        let debug_thread_pool = Arc::new(
            TokioBuilder::new_multi_thread()
                .thread_name(thd_name!("debugger"))
                .worker_threads(1)
                .after_start_wrapper(|| {})
                .before_stop_wrapper(|| {})
                .build()
                .unwrap(),
        );
        let addr = Arc::new(Mutex::new(None));
        let (check_leader_scheduler, _) = tikv_util::worker::dummy_scheduler();
        let mut server = Server::new(
            mock_store_id,
            &cfg,
            &security_mgr,
            storage,
            copr,
            copr_v2,
            router.clone(),
            MockResolver {
                quick_fail: Arc::clone(&quick_fail),
                addr: Arc::clone(&addr),
            },
            SnapManager::new(""),
            gc_worker,
            check_leader_scheduler,
            env,
            None,
            debug_thread_pool,
            HealthService::default(),
        )
        .unwrap();

        server.build_and_bind().unwrap();
        server.start(cfg, security_mgr).unwrap();

        let mut trans = server.transport();
        router.report_unreachable(0, 0).unwrap();
        let mut resp = significant_msg_receiver.try_recv().unwrap();
        assert!(is_unreachable_to(&resp, 0, 0), "{:?}", resp);

        let mut msg = RaftMessage::default();
        msg.set_region_id(1);
        trans.send(msg.clone()).unwrap();
        trans.flush();
        resp = significant_msg_receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        assert!(is_unreachable_to(&resp, 1, 0), "{:?}", resp);

        *addr.lock().unwrap() = Some(format!("{}", server.listening_addr()));

        trans.send(msg.clone()).unwrap();
        trans.flush();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();

        msg.mut_to_peer().set_store_id(2);
        msg.set_region_id(2);
        quick_fail.store(true, Ordering::SeqCst);
        trans.send(msg).unwrap();
        trans.flush();
        resp = significant_msg_receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        assert!(is_unreachable_to(&resp, 2, 0), "{:?}", resp);
        server.stop().unwrap();
    }
}
