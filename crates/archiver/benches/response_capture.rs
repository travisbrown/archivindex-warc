//! Incremental response framing with small and header-heavy HTTP messages.

use std::hint::black_box;
use std::time::Duration;

use archivindex_archiver::recorder::framing::ResponseCapture;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn response_capture(criterion: &mut Criterion) {
    let small = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".to_vec();
    let large = format!(
        "HTTP/1.1 200 OK\r\nX-Long: {}\r\nContent-Length: 4\r\n\r\nbody",
        "a".repeat(24 * 1024)
    )
    .into_bytes();
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;name={}\r\nbody\r\n0\r\n\r\n",
        "a".repeat(24 * 1024)
    )
    .into_bytes();
    let mut group = criterion.benchmark_group("response_capture");
    for (name, response) in [
        ("small", small),
        ("large_header", large),
        ("large_chunk_extension", chunked),
    ] {
        group.sample_size(if name == "large_chunk_extension" {
            10
        } else {
            100
        });
        group.throughput(Throughput::Bytes(response.len() as u64));
        for chunk_size in [1, 16, 8192] {
            group.bench_with_input(
                BenchmarkId::new(name, chunk_size),
                &chunk_size,
                |bench, &chunk_size| {
                    bench.iter(|| {
                        let mut capture = ResponseCapture::new(false, None);
                        for chunk in black_box(&response).chunks(chunk_size) {
                            capture.push(chunk).unwrap();
                        }
                        assert!(capture.is_done());
                        black_box(capture.into_parts())
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().warm_up_time(Duration::from_millis(300)).measurement_time(Duration::from_secs(1));
    targets = response_capture
}
criterion_main!(benches);
