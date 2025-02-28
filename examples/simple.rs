use std::sync::{Arc, Barrier};
use scap::ScapArgs;

fn main() -> anyhow::Result<()> {
    let _ctx = scap::ScapCtx::init(ScapArgs {
        ringbuf_size: 1 << 22
    }, |meta, data| {
        println!("meta={meta:?}, data={:?}", &data[..10]);
    })?;

    let barrier = Arc::new(Barrier::new(2));
    let handler_barrier = Arc::clone(&barrier);
    ctrlc::set_handler(move || {
        handler_barrier.wait();
    })?;

    barrier.wait();

    Ok(())
}
