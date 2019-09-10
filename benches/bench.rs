#![feature(bench)]
extern crate criterion;

mod bench {
    use criterion::Criterion;

    #[bench]
    fn bench_generate_key(c: &mut Criterion) {
        // execute
    }

    #[bench]
    fn bench_generate_signature(c: &mut Criterion) {
        // execute
    }

    criterion_group! {
        name = keygen;
        config = Criterion::default().sample_size(10);
        targets =
        self::bench_generate_key,
        self::bench_generate_signature
    }
}

criterion_main!(bench::keygen);
