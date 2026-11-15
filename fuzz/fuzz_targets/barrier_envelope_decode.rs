#![no_main]

use ferrum_crypto::barrier::BarrierEnvelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }

    if let Ok(envelope) = BarrierEnvelope::decode(data) {
        let encoded = envelope.encode();
        assert_eq!(encoded.as_slice(), data);
        let decoded = BarrierEnvelope::decode(&encoded)
            .expect("an accepted canonical FBE1 envelope decodes again");
        assert_eq!(decoded, envelope);
    }
});
