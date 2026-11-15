#![no_main]

use ferrum_crypto::barrier::{BarrierAad, CanonicalPath};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 || data.len() > 65_536 {
        return;
    }

    let mut version_bytes = [0_u8; 8];
    version_bytes.copy_from_slice(&data[..8]);
    let version = u64::from_be_bytes(version_bytes).max(1);
    let path_bytes = &data[8..];
    let Ok(path) = CanonicalPath::new(path_bytes.to_vec()) else {
        return;
    };

    let encoded = BarrierAad::new(&path, version).expect("valid path/version encode");
    let repeated = BarrierAad::new(&path, version).expect("same input encodes");
    assert_eq!(encoded, repeated);

    let next_version = version.checked_add(1).unwrap_or(1);
    let other_version = BarrierAad::new(&path, next_version).expect("nonzero version encodes");
    assert_ne!(encoded, other_version);

    let mut changed_path = path_bytes.to_vec();
    changed_path[0] ^= 0x01;
    let changed_path = CanonicalPath::new(changed_path).expect("nonempty path");
    let other_path = BarrierAad::new(&changed_path, version).expect("changed path encodes");
    assert_ne!(encoded, other_path);
});
