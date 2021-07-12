extern crate futures;

use std::collections::HashMap;
use std::future::Future;
use std::ops::FnOnce;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::Once;
use std::thread;

use futures::future;
use tokio::runtime::Runtime;

use crate::error::{VcxError, VcxErrorKind, VcxResult};

lazy_static! {
    static ref THREADPOOL: Mutex<HashMap<u32, Runtime>> = Default::default();
}

static TP_INIT: Once = Once::new();

pub static mut TP_HANDLE: u32 = 0;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadpoolConfig {
    pub num_threads: Option<usize>,
}

pub fn init_threadpool(config: &str) -> VcxResult<()> {
    let config: ThreadpoolConfig = serde_json::from_str(config)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Failed to deserialize threadpool config {:?}, err: {:?}", config, err)))?;
    init_runtime(config);
    Ok(())
}

pub fn init_runtime(config: ThreadpoolConfig) {
    if config.num_threads == Some(0) {
        warn!("init_runtime >>> threadpool_size was set to 0; every FFI call will executed on a new thread!");
    } else {
        let num_threads = config.num_threads.unwrap_or(4);
        warn!("init_runtime >>> threadpool is using {} threads.", num_threads);
        TP_INIT.call_once(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .thread_name_fn(|| {
                    static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
                    let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
                    format!("tokio-worker-vcxffi-{}", id)
                })
                .on_thread_start(|| debug!("Starting tokio runtime worker thread for vcx ffi."))
                .worker_threads(num_threads)
                .build()
                .unwrap();

            THREADPOOL.lock().unwrap().insert(1, rt);
            info!("Tokio runtime with threaded scheduler has been created.");

            unsafe { TP_HANDLE = 1; }
        });
    }
}

pub fn execute<F>(closure: F)
    where
        F: FnOnce() -> Result<(), ()> + Send + 'static {
    if TP_INIT.is_completed() {
        execute_on_tokio(future::lazy(|_| closure()));
    } else {
        thread::spawn(closure);
    }
}

fn execute_on_tokio<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static {
    let handle;
    unsafe { handle = TP_HANDLE; }
    match THREADPOOL.lock().unwrap().get(&handle) {
        Some(rt) => {
            rt.spawn(future);
        }
        None => panic!("Tokio runtime not found! Forgot to call init_runtime?"),
    }
}
