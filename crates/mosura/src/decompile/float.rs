//! A minimal port of Ghidra's `FloatFormat` (`float.cc`) — just enough to print a float-typed
//! constant the way `PrintC::push_float` (`printc.cc:1380`) does: decode the IEEE encoding to a
//! host `double`, classify it, and render `INFINITY`/`NAN` or the shortest round-tripping decimal
//! (forcing a trailing `.0` so the literal reads as floating point, e.g. `0` → `0.0`).

/// Ghidra `FloatFormat::floatclass`.
enum FloatClass {
    Normal,
    Zero,
    Infinity,
    Nan,
}

fn classify(f: f64) -> FloatClass {
    if f.is_nan() {
        FloatClass::Nan
    } else if f.is_infinite() {
        FloatClass::Infinity
    } else if f == 0.0 {
        FloatClass::Zero
    } else {
        FloatClass::Normal
    }
}

/// Ghidra `FloatFormat::getHostFloat`: decode an IEEE `size`-byte encoding into a host `f64`, its
/// sign bit, and its class. Sizes 4 and 8 use the host's own IEEE formats (`f32`/`f64::from_bits`).
/// The x87 80-bit (`float10`) and `float16` formats are not exercised by *immediate* constants in
/// the corpus (those values arrive through memory, never as a p-code constant, which is capped at
/// 8 bytes anyway), so they fall back to reinterpreting the low 8 bytes.
fn get_host_float(encoding: u64, size: u32) -> (f64, bool, FloatClass) {
    match size {
        4 => {
            let f = f32::from_bits(encoding as u32) as f64;
            (f, (encoding >> 31) & 1 != 0, classify(f))
        }
        _ => {
            let f = f64::from_bits(encoding);
            (f, (encoding >> 63) & 1 != 0, classify(f))
        }
    }
}

/// Ghidra `FloatFormat::getHostFloat`: decode a `size`-byte IEEE encoding to a host `f64`.
pub fn to_host(encoding: u64, size: u32) -> f64 {
    get_host_float(encoding, size).0
}

/// Ghidra `FloatFormat::getEncoding`: encode a host `f64` back into a `size`-byte IEEE pattern
/// (rounding to `float` precision for `size == 4`). Sizes other than 4 use the host `f64` format;
/// `float10`/`float16` immediates do not arise in constant folding here.
pub fn encode(host: f64, size: u32) -> u64 {
    match size {
        4 => (host as f32).to_bits() as u64,
        _ => host.to_bits(),
    }
}

/// Ghidra `FloatFormat::printDecimal`: the shortest decimal that round-trips back to `host`. Rust's
/// default float formatting already yields the shortest round-tripping representation, so this is
/// `{host}` plus Ghidra's trailing-`.0` rule (append `.0` when the result carries neither a decimal
/// point nor an exponent, so an integer-valued float still reads as floating point).
fn print_decimal(host: f64) -> String {
    let s = format!("{host}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s
    } else {
        format!("{s}.0")
    }
}

/// Ghidra `PrintC::push_float` (`printc.cc:1380`): render a float-typed constant from its `size`-byte
/// IEEE `encoding`.
pub fn push_float(encoding: u64, size: u32) -> String {
    let (host, sign, class) = get_host_float(encoding, size);
    match class {
        FloatClass::Infinity => if sign { "-INFINITY" } else { "INFINITY" }.to_string(),
        FloatClass::Nan => if sign { "-NAN" } else { "NAN" }.to_string(),
        FloatClass::Normal | FloatClass::Zero => print_decimal(host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_prints_as_float_literal() {
        assert_eq!(push_float(0, 8), "0.0");
        assert_eq!(push_float(0, 4), "0.0");
    }

    #[test]
    fn normal_values_round_trip_shortest() {
        assert_eq!(push_float((1.5f64).to_bits(), 8), "1.5");
        assert_eq!(push_float((2.0f64).to_bits(), 8), "2.0");
        assert_eq!(push_float((0.5f32).to_bits() as u64, 4), "0.5");
    }

    #[test]
    fn inf_and_nan_tokens() {
        assert_eq!(push_float(f64::INFINITY.to_bits(), 8), "INFINITY");
        assert_eq!(push_float(f64::NEG_INFINITY.to_bits(), 8), "-INFINITY");
        assert_eq!(push_float(f64::NAN.to_bits(), 8), "NAN");
    }
}
