//! Padmé length padding (Nikitin et al., PETS 2019) with a 64-byte floor, so
//! ciphertext length leaks at most ~12% and short secrets are indistinguishable.

const MIN_PADDED: usize = 64;

/// Padmé: round `len` up so that only the top O(log log len) bits are significant.
pub fn padme(len: usize) -> usize {
    if len < 2 {
        return len;
    }
    let l = len as u64;
    let e = 63 - l.leading_zeros() as u64; // floor(log2 L)
    let s = 64 - e.leading_zeros() as u64; // floor(log2 E) + 1
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    ((l + mask) & !mask) as usize
}

/// ISO/IEC 7816-4 style: data || 0x80 || 0x00*, to the Padmé size.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let target = padme(data.len() + 1).max(MIN_PADDED);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(data);
    out.push(0x80);
    out.resize(target, 0);
    out
}

pub fn unpad(data: &[u8]) -> crate::Result<&[u8]> {
    let end = data
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(crate::Error::Format)?;
    if data[end] != 0x80 {
        return Err(crate::Error::Format);
    }
    Ok(&data[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn padme_known_values() {
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(64), 64);
        assert_eq!(padme(1000), 1024);
        // Overhead never exceeds ~12% for larger sizes.
        for l in [5000usize, 70_000, 1_234_567] {
            let p = padme(l);
            assert!(p >= l && (p - l) as f64 / l as f64 <= 0.12, "{l} -> {p}");
        }
    }

    #[test]
    fn short_inputs_are_indistinguishable() {
        assert_eq!(pad(b"a").len(), pad(b"correct horse battery").len());
    }

    proptest! {
        #[test]
        fn roundtrip(data in proptest::collection::vec(any::<u8>(), 0..5000)) {
            let p = pad(&data);
            prop_assert!(p.len() >= data.len() + 1);
            prop_assert_eq!(unpad(&p).unwrap(), &data[..]);
        }
    }
}
