use crate::args::{Args, GenerationMode};
use regex::Regex;

pub fn run_gpu_mode(args: &Args, re: &Regex) -> Result<(), String> {
    if args.mode != GenerationMode::PrivateKey {
        return Err(
            "CUDA requires --mode private-key (mnemonic derivation remains CPU-only)".into(),
        );
    }
    #[cfg(feature = "cuda")]
    {
        cuda::run(args, re)
    }
    #[cfg(not(feature = "cuda"))]
    {
        let _ = re;
        Err("Rebuild with cargo build --release --features cuda".into())
    }
}

#[cfg(feature = "cuda")]
mod cuda {
    use super::*;
    use crate::{address::private_key, args::BlockchainType, utils::found_result};
    use rand::RngCore;
    use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Signing};
    use std::{
        ffi::{c_char, c_void, CStr},
        str::FromStr,
        time::{Duration, Instant},
    };

    // Entry points from cuda/vanity.cu, linked into this executable by build.rs.
    extern "C" {
        fn vag_cuda_create(
            device: i32,
            lanes: u32,
            table: *const Point,
            value: *const u8,
            mask: *const u8,
            out: *mut *mut c_void,
        ) -> i32;
        fn vag_cuda_seed(engine: *mut c_void, points: *const Point) -> i32;
        fn vag_cuda_scan(
            engine: *mut c_void,
            hits: *mut Hit,
            capacity: u32,
            stats: *mut BatchStats,
        ) -> i32;
        fn vag_cuda_destroy(engine: *mut c_void) -> i32;
        fn vag_cuda_error(code: i32) -> *const c_char;
    }

    const BATCH: usize = 128;
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Point {
        x: [u32; 8],
        y: [u32; 8],
    }
    impl From<PublicKey> for Point {
        fn from(public: PublicKey) -> Self {
            let bytes = public.serialize_uncompressed();
            let mut point = Self::default();
            for i in 0..8 {
                point.x[7 - i] =
                    u32::from_be_bytes(bytes[1 + 4 * i..5 + 4 * i].try_into().unwrap());
                point.y[7 - i] =
                    u32::from_be_bytes(bytes[33 + 4 * i..37 + 4 * i].try_into().unwrap());
            }
            point
        }
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Hit {
        lane: u32,
        step: u32,
        hash: [u8; 20],
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct BatchStats {
        hits: u32,
        processed: u32,
        kernel_ms: f32,
    }
    struct Engine {
        handle: *mut c_void,
        lanes: usize,
        hits: Vec<Hit>,
        stats: BatchStats,
    }
    impl Engine {
        fn new(
            device: i32,
            lanes: usize,
            value: &[u8; 20],
            mask: &[u8; 20],
        ) -> Result<Self, String> {
            if !(1..=65536).contains(&lanes) {
                return Err("--gpu-lanes must be between 1 and 65536".into());
            }
            // The ABI is defined in cuda/vanity.cu; all allocations outlive these calls.
            let secp = Secp256k1::signing_only();
            let table: Vec<Point> = (1..=BATCH)
                .map(|i| PublicKey::from_secret_key(&secp, &small_secret(i as u64)).into())
                .collect();
            let mut handle = std::ptr::null_mut();
            let status = unsafe {
                vag_cuda_create(
                    device,
                    lanes as u32,
                    table.as_ptr(),
                    value.as_ptr(),
                    mask.as_ptr(),
                    &mut handle,
                )
            };
            if status != 0 {
                return Err(unsafe { error_message(status) });
            }
            Ok(Self {
                handle,
                lanes,
                hits: vec![Hit::default(); lanes * BATCH],
                stats: BatchStats::default(),
            })
        }
        fn check(&self, status: i32) -> Result<(), String> {
            if status == 0 {
                Ok(())
            } else {
                Err(unsafe { error_message(status) })
            }
        }
        fn seed<C: Signing>(
            &mut self,
            keys: &[SecretKey],
            secp: &Secp256k1<C>,
        ) -> Result<(), String> {
            assert_eq!(keys.len(), self.lanes);
            let mut points = vec![Point::default(); keys.len()];
            // Seed multiplication is the only CPU-heavy CUDA setup step. Share the
            // immutable secp context and parallelize large uploads without touching
            // the per-batch hot path.
            let workers = if keys.len() >= 2048 {
                num_cpus::get().min(16)
            } else {
                1
            };
            let chunk = keys.len().div_ceil(workers);
            std::thread::scope(|scope| {
                for (keys, points) in keys.chunks(chunk).zip(points.chunks_mut(chunk)) {
                    scope.spawn(move || {
                        for (key, point) in keys.iter().zip(points) {
                            *point = PublicKey::from_secret_key(secp, key).into();
                        }
                    });
                }
            });
            self.check(unsafe { vag_cuda_seed(self.handle, points.as_ptr()) })
        }
        fn scan(&mut self) -> Result<&[Hit], String> {
            let mut stats = BatchStats::default();
            let status = unsafe {
                vag_cuda_scan(
                    self.handle,
                    self.hits.as_mut_ptr(),
                    self.hits.len() as u32,
                    &mut stats,
                )
            };
            self.check(status)?;
            if stats.hits > stats.processed
                || stats.processed as usize > self.hits.len()
                || !stats.kernel_ms.is_finite()
                || stats.kernel_ms < 0.0
            {
                return Err("CUDA returned invalid batch statistics".into());
            }
            self.stats = stats;
            Ok(&self.hits[..stats.hits as usize])
        }
    }
    impl Drop for Engine {
        fn drop(&mut self) {
            unsafe {
                vag_cuda_destroy(self.handle);
            }
        }
    }

    unsafe fn error_message(code: i32) -> String {
        CStr::from_ptr(vag_cuda_error(code))
            .to_string_lossy()
            .into_owned()
    }
    fn small_secret(n: u64) -> SecretKey {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        SecretKey::from_byte_array(&bytes).unwrap()
    }
    fn advance(key: SecretKey, n: u64) -> Result<SecretKey, String> {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        key.add_tweak(&Scalar::from_be_bytes(bytes).unwrap())
            .map_err(|e| e.to_string())
    }

    // Only recognize forms whose raw-nibble constraints are provably necessary.
    // Every other regex falls back to CPU matching without dropping candidates.
    fn filter(pattern: &str) -> ([u8; 20], [u8; 20]) {
        let mut value = [0; 20];
        let mut mask = [0; 20];
        let is_hex = |s: &str| s.bytes().all(|c| c.is_ascii_hexdigit());
        let (prefix, suffix) = if let Some(rest) = pattern.strip_prefix("^0x") {
            if let Some((left, right)) = rest.split_once(".*") {
                let right = if right.is_empty() {
                    ""
                } else if let Some(r) = right.strip_suffix('$') {
                    r
                } else {
                    return (value, mask);
                };
                (left, right)
            } else if let Some(exact) = rest.strip_suffix('$') {
                if exact.len() != 40 {
                    return (value, mask);
                }
                (exact, "")
            } else {
                (rest, "")
            }
        } else if let Some(suffix) = pattern.strip_suffix('$') {
            ("", suffix)
        } else {
            return (value, mask);
        };
        if !is_hex(prefix) || !is_hex(suffix) || prefix.len() + suffix.len() > 40 {
            return (value, mask);
        }
        for (start, part) in [(0, prefix), (40 - suffix.len(), suffix)] {
            for (i, c) in part.bytes().enumerate() {
                let n = (c as char).to_digit(16).unwrap() as u8;
                let offset = start + i;
                let shift = if offset % 2 == 0 { 4 } else { 0 };
                value[offset / 2] |= n << shift;
                mask[offset / 2] |= 15 << shift;
            }
        }
        (value, mask)
    }

    fn verify(device: i32) -> Result<(), String> {
        let secp = Secp256k1::signing_only();
        // Exercise doubling, the point at infinity, scalar wraparound and random points.
        let mut near_order =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap();
        near_order[31] -= 1; // n-1; the first candidate is infinity.
        let keys = [
            small_secret(1),
            small_secret(128),
            SecretKey::from_slice(&near_order).unwrap(),
            private_key::random_secret(&mut rand::thread_rng()),
        ];
        let mut engine = Engine::new(device, keys.len(), &[0; 20], &[0; 20])?;
        engine.seed(&keys, &secp)?;
        for batch in 0..2 {
            let hits = engine.scan()?;
            let mut seen = vec![false; keys.len() * BATCH];
            for hit in hits {
                if hit.lane as usize >= keys.len() || !(1..=BATCH as u32).contains(&hit.step) {
                    return Err("CUDA self-test: invalid index".into());
                }
                let index = hit.lane as usize * BATCH + hit.step as usize - 1;
                if seen[index] {
                    return Err("CUDA self-test: duplicate candidate".into());
                }
                seen[index] = true;
                let secret = advance(
                    keys[hit.lane as usize],
                    (batch * BATCH) as u64 + hit.step as u64,
                )?;
                if private_key::eth_hash(&PublicKey::from_secret_key(&secp, &secret)) != hit.hash {
                    return Err("CUDA self-test: address mismatch".into());
                }
            }
            for (lane, key) in keys.iter().enumerate() {
                for step in 1..=BATCH {
                    let valid = advance(*key, (batch * BATCH + step) as u64).is_ok();
                    if seen[lane * BATCH + step - 1] != valid {
                        return Err("CUDA self-test: missing candidate".into());
                    }
                }
            }
            let valid = seen.iter().filter(|present| **present).count();
            if engine.stats.processed as usize != valid {
                return Err("CUDA self-test: incorrect device candidate count".into());
            }
        }
        Ok(())
    }

    pub fn run(args: &Args, re: &Regex) -> Result<(), String> {
        let chain = BlockchainType::from_str(&args.chain)?;
        if !matches!(chain, BlockchainType::Ethereum | BlockchainType::Tron) {
            return Err(
                "CUDA currently supports eth and trx/tron; use CPU --mode private-key for other chains"
                    .into(),
            );
        }
        if args.gpu_platform < 0 {
            return Err("--gpu-platform is a nonnegative CUDA device index".into());
        }
        if !(1..=65536).contains(&args.gpu_lanes) {
            return Err("--gpu-lanes must be between 1 and 65536".into());
        }
        verify(args.gpu_platform)?;
        println!("CUDA self-test passed (CPU cross-check, 2 batches).");
        let (value, mask) = if matches!(chain, BlockchainType::Ethereum) {
            filter(&args.regex)
        } else {
            ([0; 20], [0; 20])
        };
        println!(
            "CUDA device {}, lanes {}, batch {} addresses, matching: {}",
            args.gpu_platform,
            args.gpu_lanes,
            args.gpu_lanes * BATCH,
            if mask.iter().any(|m| *m != 0) {
                "GPU hex filter + CPU regex verification"
            } else {
                "CPU regex (all GPU hashes transferred)"
            }
        );
        let mut engine = Engine::new(args.gpu_platform, args.gpu_lanes, &value, &mask)?;
        let mut rng = rand::thread_rng();
        let mut secp = Secp256k1::signing_only();
        let mut blind = [0; 32];
        rng.fill_bytes(&mut blind);
        secp.seeded_randomize(&blind);
        let start = Instant::now();
        let mut last_display = start;
        let mut count = 0u64;
        let mut matches = 0u64;
        let mut kernel_ms = 0.0f64;
        let mut offset = 0u64;
        let mut keys: Vec<SecretKey> = (0..args.gpu_lanes)
            .map(|_| private_key::random_secret(&mut rng))
            .collect();
        engine.seed(&keys, &secp)?;
        loop {
            if args.benchmark
                && start.elapsed() >= Duration::from_secs(args.benchmark_seconds as u64)
            {
                break;
            }
            engine.scan()?;
            count += engine.stats.processed as u64;
            kernel_ms += f64::from(engine.stats.kernel_ms);
            let hits = &engine.hits[..engine.stats.hits as usize];
            let mut found = false;
            for hit in hits {
                let address = private_key::address_from_hash(&hit.hash, &chain, args.case);
                if re.is_match(&address) {
                    matches += 1;
                    if args.benchmark {
                        continue;
                    }
                    if hit.lane as usize >= keys.len() || !(1..=BATCH as u32).contains(&hit.step) {
                        return Err("CUDA returned an invalid candidate index".into());
                    }
                    let secret = advance(keys[hit.lane as usize], offset + hit.step as u64)?;
                    let public = PublicKey::from_secret_key(&secp, &secret);
                    if private_key::secp_address(&public, &chain, args.case) != address {
                        return Err("GPU result failed CPU verification; no wallet saved".into());
                    }
                    found_result(
                        &args.webhook,
                        start.elapsed(),
                        String::new(),
                        address,
                        hex::encode(secret.secret_bytes()),
                        args.chain.clone(),
                    );
                    if !args.looping {
                        return Ok(());
                    }
                    found = true;
                    break;
                }
            }
            offset += BATCH as u64;
            // Never export multiple related scalars from a lane: retire ALL lane
            // seeds after a hit. A leaked wallet must not reveal subsequent wallets.
            if found || offset >= u32::MAX as u64 {
                keys.iter_mut()
                    .for_each(|key| *key = private_key::random_secret(&mut rng));
                engine.seed(&keys, &secp)?;
                offset = 0;
            }
            if last_display.elapsed() >= Duration::from_secs(1) {
                eprint!(
                    "\rHashrate: {:.2} addresses/s",
                    count as f64 / start.elapsed().as_secs_f64()
                );
                last_display = Instant::now();
            }
        }
        eprintln!();
        println!("Benchmark: {count} addresses in {:.3}s = {:.2} addresses/s (includes seed upload, transfers and matching; excludes CUDA initialization/self-test)",start.elapsed().as_secs_f64(),count as f64/start.elapsed().as_secs_f64());
        println!("Matching candidates: {matches} (no wallets saved)");
        println!(
            "CUDA kernel time: {:.3}s (device event timing)",
            kernel_ms / 1000.0
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rand::{rngs::StdRng, SeedableRng};

        fn independent_hash(secret: SecretKey) -> [u8; 20] {
            // A separate, pure-Rust EC implementation checks the C secp256k1
            // oracle and the CUDA implementation against each other.
            let key = libsecp256k1::SecretKey::parse(&secret.secret_bytes()).unwrap();
            let public = libsecp256k1::PublicKey::from_secret_key(&key);
            let mut hash = [0; 32];
            crate::address::ethereum::keccak_hash(public, &mut hash);
            hash[12..].try_into().unwrap()
        }
        #[test]
        fn hex_filters_are_conservative() {
            let (v, m) = filter("^0xAbc.*123$");
            assert_eq!(&v[..2], &[0xab, 0xc0]);
            assert_eq!(&m[..2], &[0xff, 0xf0]);
            assert_eq!(&v[18..], &[1, 0x23]);
            assert_eq!(&m[18..], &[15, 255]);
            for regex in [
                "^0x[a-f]",
                "(?i)^0xab",
                "^0xab|cd$",
                "^0xab.*cd",
                "^0x00$",
                "^0x(a|b)",
            ] {
                assert_eq!(filter(regex).1, [0; 20]);
            }
        }

        #[test]
        fn filters_never_drop_regex_matches() {
            let secp = Secp256k1::signing_only();
            let mut rng = StdRng::seed_from_u64(0xfeed);
            let hashes: Vec<_> = (0..256)
                .map(|_| {
                    private_key::eth_hash(&PublicKey::from_secret_key(
                        &secp,
                        &private_key::random_secret(&mut rng),
                    ))
                })
                .collect();
            for case in [false, true] {
                for pattern in [
                    "^0x",
                    "^0xa",
                    "^0xA.*b$",
                    "^0xa.*",
                    "^0xab.*$",
                    "f$",
                    "^0x[0-9]",
                    "^0xa|b$",
                    "(?i)^0xAB",
                    "^0x a",
                    "^0x.*$",
                    "[a-f]{2}$",
                ] {
                    let re = regex::RegexBuilder::new(pattern)
                        .case_insensitive(!case)
                        .ignore_whitespace(true)
                        .build()
                        .unwrap();
                    let (value, mask) = filter(pattern);
                    for hash in &hashes {
                        let address =
                            private_key::address_from_hash(hash, &BlockchainType::Ethereum, case);
                        if re.is_match(&address) {
                            assert!(
                                (0..20).all(|i| hash[i] & mask[i] == value[i]),
                                "filter rejected a match: {pattern}"
                            );
                        }
                    }
                }
            }
        }
        #[test]
        #[ignore = "requires an NVIDIA GPU and a build with --features cuda"]
        fn cuda_matches_cpu() {
            verify(0).unwrap();
            let secp = Secp256k1::signing_only();
            let mut rng = StdRng::seed_from_u64(0xc0da);
            // Cross a CUDA block boundary and exercise infinity at a batch boundary.
            let mut keys: Vec<_> = (0..129)
                .map(|_| private_key::random_secret(&mut rng))
                .collect();
            keys[0] = small_secret(128).negate();
            keys[1] = small_secret(1);
            let expected: Vec<_> = (0..3)
                .map(|batch| {
                    keys.iter()
                        .flat_map(|key| {
                            (1..=BATCH)
                                .map(|step| {
                                    advance(*key, (batch * BATCH + step) as u64).ok().map(
                                        |secret| {
                                            private_key::eth_hash(&PublicKey::from_secret_key(
                                                &secp, &secret,
                                            ))
                                        },
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            for pattern in ["", "^0xa", "abc$", "^0x1.*2$", "^0x123.*"] {
                let (value, mask) = filter(pattern);
                let mut engine = Engine::new(0, keys.len(), &value, &mask).unwrap();
                engine.seed(&keys, &secp).unwrap();
                for addresses in &expected {
                    let mut seen = vec![false; keys.len() * BATCH];
                    for hit in engine.scan().unwrap() {
                        assert!((1..=BATCH as u32).contains(&hit.step));
                        let index = hit.lane as usize * BATCH + hit.step as usize - 1;
                        assert!(!seen[index], "duplicate result");
                        seen[index] = true;
                        assert_eq!(Some(hit.hash), addresses[index]);
                    }
                    for (index, address) in addresses.iter().enumerate() {
                        let wanted = address
                            .is_some_and(|hash| (0..20).all(|i| hash[i] & mask[i] == value[i]));
                        assert_eq!(
                            seen[index], wanted,
                            "filter dropped or added a candidate: {pattern}"
                        );
                    }
                    assert_eq!(
                        engine.stats.processed as usize,
                        addresses.iter().flatten().count()
                    );
                }
            }
            check_engine_isolation(&secp);
            check_center_boundaries(&secp);
            check_long_sequence(&secp);
            check_full_batches(&secp, &mut rng);
            println!("CUDA: filtered completeness, engine isolation, 256 consecutive batches, full buffers through 65536 lanes passed");
        }

        fn check_center_boundaries(secp: &Secp256k1<secp256k1::SignOnly>) {
            // Cover every +/- table collision, infinity in the batch center,
            // and infinity when advancing that center into the next batch.
            let keys: Vec<_> = (1..=256)
                .map(|i| small_secret(i).negate())
                .chain((1..=128).map(small_secret))
                .collect();
            let mut engine = Engine::new(0, keys.len(), &[0; 20], &[0; 20]).unwrap();
            engine.seed(&keys, secp).unwrap();
            for batch in 0..3 {
                let mut seen = vec![false; keys.len() * BATCH];
                for hit in engine.scan().unwrap() {
                    assert!((hit.lane as usize) < keys.len());
                    assert!((1..=BATCH as u32).contains(&hit.step));
                    let index = hit.lane as usize * BATCH + hit.step as usize - 1;
                    assert!(!seen[index], "duplicate boundary candidate");
                    seen[index] = true;
                    let secret = advance(
                        keys[hit.lane as usize],
                        (batch * BATCH) as u64 + u64::from(hit.step),
                    )
                    .expect("infinity must not be returned");
                    assert_eq!(hit.hash, independent_hash(secret));
                }
                for (lane, key) in keys.iter().enumerate() {
                    for step in 1..=BATCH {
                        assert_eq!(
                            seen[lane * BATCH + step - 1],
                            advance(*key, (batch * BATCH + step) as u64).is_ok(),
                            "missing or extra boundary candidate"
                        );
                    }
                }
                assert_eq!(
                    engine.stats.processed as usize,
                    seen.iter().filter(|&&valid| valid).count()
                );
            }
            println!("CUDA: 147456 boundary candidate positions checked independently");
        }

        fn check_engine_isolation(secp: &Secp256k1<secp256k1::SignOnly>) {
            let keys = [small_secret(1), small_secret(128).negate()];
            let mut first = Engine::new(0, 2, &[0; 20], &[0; 20]).unwrap();
            first.seed(&keys, secp).unwrap();
            let (value, mask) = filter("^0xa");
            let mut second = Engine::new(0, 2, &value, &mask).unwrap();
            second.seed(&keys, secp).unwrap();
            // Creating the filtered engine must not change the first engine's mask.
            assert_eq!(first.scan().unwrap().len(), 255);
            assert_eq!(first.stats.processed, 255);
            for hit in second.scan().unwrap() {
                assert_eq!(hit.hash[0] & 0xf0, 0xa0);
            }
            assert_eq!(second.stats.processed, 255);
            // Undersized host memory is rejected without writing OR advancing state.
            let mut guard = Hit {
                lane: 0xdeadbeef,
                ..Hit::default()
            };
            let mut stats = BatchStats::default();
            let error = unsafe { vag_cuda_scan(first.handle, &mut guard, 1, &mut stats) };
            assert_ne!(error, 0);
            assert_eq!(guard.lane, 0xdeadbeef);
            let hits = first.scan().unwrap();
            assert_eq!(hits.len(), 256);
            for hit in hits {
                assert_eq!(
                    hit.hash,
                    independent_hash(
                        advance(keys[hit.lane as usize], 128 + hit.step as u64).unwrap()
                    )
                );
            }
            // Reinitialization starts a fresh sequence at offset zero.
            first.seed(&keys, secp).unwrap();
            assert_eq!(first.scan().unwrap().len(), 255);
        }

        // Keep deliberate CUDA API errors separate from memory-sanitizer runs.
        #[test]
        #[ignore = "requires an NVIDIA GPU and a build with --features cuda"]
        fn cuda_rejects_invalid_device() {
            assert!(Engine::new(i32::MAX, 1, &[0; 20], &[0; 20]).is_err());
        }

        fn check_long_sequence(secp: &Secp256k1<secp256k1::SignOnly>) {
            let mut rng = StdRng::seed_from_u64(0x10c0);
            let mut keys: Vec<_> = (0..129)
                .map(|_| private_key::random_secret(&mut rng))
                .collect();
            keys[0] = small_secret(128).negate();
            let mut engine = Engine::new(0, keys.len(), &[0; 20], &[0; 20]).unwrap();
            engine.seed(&keys, secp).unwrap();
            let mut total = 0u64;
            for batch in 0..256u64 {
                let hits = engine.scan().unwrap();
                let mut seen = vec![false; keys.len() * BATCH];
                for hit in hits {
                    assert!((1..=BATCH as u32).contains(&hit.step));
                    let index = hit.lane as usize * BATCH + hit.step as usize - 1;
                    assert!(!seen[index]);
                    seen[index] = true;
                    // Both endpoints in every lane and rotating interior samples.
                    if hit.step == 1
                        || hit.step == 128
                        || (index + batch as usize).is_multiple_of(509)
                    {
                        let key = advance(keys[hit.lane as usize], batch * 128 + hit.step as u64)
                            .unwrap();
                        assert_eq!(hit.hash, independent_hash(key));
                    }
                }
                assert_eq!(engine.stats.hits, engine.stats.processed);
                assert_eq!(
                    engine.stats.processed as usize,
                    keys.len() * BATCH - usize::from(batch == 0)
                );
                total += u64::from(engine.stats.processed);
            }
            assert_eq!(total, 129 * 128 * 256 - 1);
        }

        fn check_full_batches(secp: &Secp256k1<secp256k1::SignOnly>, rng: &mut StdRng) {
            // Small and partial blocks, parallel seed setup, maximum allocation,
            // and the worst case where every candidate is copied back.
            for lanes in [1, 127, 128, 129, 2048, 16384, 32768, 65536] {
                let keys: Vec<_> = (0..lanes)
                    .map(|_| private_key::random_secret(rng))
                    .collect();
                let mut engine = Engine::new(0, lanes, &[0; 20], &[0; 20]).unwrap();
                engine.seed(&keys, secp).unwrap();
                let hits = engine.scan().unwrap();
                assert_eq!(hits.len(), lanes * BATCH);
                let mut seen = vec![false; lanes * BATCH];
                for hit in hits {
                    assert!((1..=BATCH as u32).contains(&hit.step));
                    let index = hit.lane as usize * BATCH + hit.step as usize - 1;
                    assert!(!seen[index]);
                    seen[index] = true;
                    if hit.step == 1 || hit.step == 128 {
                        assert_eq!(
                            hit.hash,
                            independent_hash(
                                advance(keys[hit.lane as usize], hit.step as u64).unwrap()
                            )
                        );
                    }
                }
                assert!(seen.iter().all(|seen| *seen));
                assert_eq!(engine.stats.processed as usize, lanes * BATCH);
                assert!(engine.stats.kernel_ms > 0.0);
            }
        }
    }
}
