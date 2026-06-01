use crate::KyriotesCsk2Error;
use crate::core::rights::Rights;
use crate::core::temporal::TemporalPolicy;

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

pub fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

pub fn put_rights(out: &mut Vec<u8>, rights: Rights) {
    put_u16(out, rights.bits());
}

pub fn put_temporal_policy(out: &mut Vec<u8>, policy: &TemporalPolicy) {
    match policy {
        TemporalPolicy::Historical(e) => {
            out.push(0x01);
            put_u64(out, *e);
        }
        TemporalPolicy::Current => {
            out.push(0x02);
        }
        TemporalPolicy::Window { start, end } => {
            out.push(0x03);
            put_u64(out, *start);
            put_u64(out, *end);
        }
        TemporalPolicy::ResealRequired { after } => {
            out.push(0x04);
            put_u64(out, *after);
        }
    }
}

pub fn take_u16(input: &[u8], cursor: &mut usize) -> Result<u16, KyriotesCsk2Error> {
    if input.len().saturating_sub(*cursor) < 2 {
        return Err(KyriotesCsk2Error::Parse("unexpected EOF while reading u16"));
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&input[*cursor..*cursor + 2]);
    *cursor += 2;
    Ok(u16::from_le_bytes(buf))
}

pub fn take_u32(input: &[u8], cursor: &mut usize) -> Result<u32, KyriotesCsk2Error> {
    if input.len().saturating_sub(*cursor) < 4 {
        return Err(KyriotesCsk2Error::Parse("unexpected EOF while reading u32"));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_le_bytes(buf))
}

pub fn take_u64(input: &[u8], cursor: &mut usize) -> Result<u64, KyriotesCsk2Error> {
    if input.len().saturating_sub(*cursor) < 8 {
        return Err(KyriotesCsk2Error::Parse("unexpected EOF while reading u64"));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&input[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(u64::from_le_bytes(buf))
}

pub fn take_bytes(input: &[u8], cursor: &mut usize) -> Result<Vec<u8>, KyriotesCsk2Error> {
    let len = take_u32(input, cursor)? as usize;
    if input.len().saturating_sub(*cursor) < len {
        return Err(KyriotesCsk2Error::Parse(
            "unexpected EOF while reading bytes",
        ));
    }
    let out = input[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

pub fn take_bytes_limited(
    input: &[u8],
    cursor: &mut usize,
    max_len: usize,
) -> Result<Vec<u8>, KyriotesCsk2Error> {
    let len = take_u32(input, cursor)? as usize;
    if len > max_len {
        return Err(KyriotesCsk2Error::Parse(
            "field exceeds maximum allowed length",
        ));
    }
    if input.len().saturating_sub(*cursor) < len {
        return Err(KyriotesCsk2Error::Parse(
            "unexpected EOF while reading bytes",
        ));
    }
    let out = input[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

pub fn take_fixed<const N: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], KyriotesCsk2Error> {
    let bytes = take_bytes(input, cursor)?;
    if bytes.len() != N {
        return Err(KyriotesCsk2Error::Parse("fixed-size field length mismatch"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn take_fixed_limited<const N: usize>(
    input: &[u8],
    cursor: &mut usize,
    max_len: usize,
) -> Result<[u8; N], KyriotesCsk2Error> {
    let bytes = take_bytes_limited(input, cursor, max_len)?;
    if bytes.len() != N {
        return Err(KyriotesCsk2Error::Parse("fixed-size field length mismatch"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn take_str(input: &[u8], cursor: &mut usize) -> Result<String, KyriotesCsk2Error> {
    let bytes = take_bytes(input, cursor)?;
    String::from_utf8(bytes).map_err(|_| KyriotesCsk2Error::Parse("invalid UTF-8 string"))
}

pub fn take_str_limited(
    input: &[u8],
    cursor: &mut usize,
    max_len: usize,
) -> Result<String, KyriotesCsk2Error> {
    let bytes = take_bytes_limited(input, cursor, max_len)?;
    String::from_utf8(bytes).map_err(|_| KyriotesCsk2Error::Parse("invalid UTF-8 string"))
}

pub fn take_rights(input: &[u8], cursor: &mut usize) -> Result<Rights, KyriotesCsk2Error> {
    Ok(Rights(take_u16(input, cursor)?))
}

pub fn take_temporal_policy(
    input: &[u8],
    cursor: &mut usize,
) -> Result<TemporalPolicy, KyriotesCsk2Error> {
    if input.len().saturating_sub(*cursor) < 1 {
        return Err(KyriotesCsk2Error::Parse(
            "unexpected EOF while reading temporal policy tag",
        ));
    }
    let tag = input[*cursor];
    *cursor += 1;
    match tag {
        0x01 => Ok(TemporalPolicy::Historical(take_u64(input, cursor)?)),
        0x02 => Ok(TemporalPolicy::Current),
        0x03 => {
            let start = take_u64(input, cursor)?;
            let end = take_u64(input, cursor)?;
            Ok(TemporalPolicy::Window { start, end })
        }
        0x04 => Ok(TemporalPolicy::ResealRequired {
            after: take_u64(input, cursor)?,
        }),
        _ => Err(KyriotesCsk2Error::Parse("unknown temporal policy tag")),
    }
}
