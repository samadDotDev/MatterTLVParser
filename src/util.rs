use crate::errors::TLVError;
use log::error;
use nom::bits::{bits, complete::take};
use nom::error::Error;
use nom::number::complete::{
    le_f32, le_f64, le_i16, le_i32, le_i64, le_i8, le_u16, le_u32, le_u64, le_u8,
};
use nom::sequence::tuple;
use nom::IResult;
use std::str::from_utf8;

pub fn split_byte_into_2_parts(
    input: &[u8],
    proportions: (usize, usize),
) -> IResult<&[u8], (u8, u8)> {
    bits::<_, _, Error<(&[u8], usize)>, _, _>(tuple((take(proportions.0), take(proportions.1))))(
        input,
    )
}

pub fn parse_u8(bytes: &[u8]) -> Result<(&[u8], u8), TLVError> {
    let (remaining_bytes, value) = le_u8::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse u8 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_u16(bytes: &[u8]) -> Result<(&[u8], u16), TLVError> {
    let (remaining_bytes, value) = le_u16::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse u16 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_u32(bytes: &[u8]) -> Result<(&[u8], u32), TLVError> {
    let (remaining_bytes, value) = le_u32::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse u32 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_u64(bytes: &[u8]) -> Result<(&[u8], u64), TLVError> {
    let (remaining_bytes, value) = le_u64::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse u64 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_i8(bytes: &[u8]) -> Result<(&[u8], i8), TLVError> {
    let (remaining_bytes, value) = le_i8::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse i8 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_i16(bytes: &[u8]) -> Result<(&[u8], i16), TLVError> {
    let (remaining_bytes, value) = le_i16::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse i16 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_i32(bytes: &[u8]) -> Result<(&[u8], i32), TLVError> {
    let (remaining_bytes, value) = le_i32::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse i32 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_i64(bytes: &[u8]) -> Result<(&[u8], i64), TLVError> {
    let (remaining_bytes, value) = le_i64::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse i64 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_f32(bytes: &[u8]) -> Result<(&[u8], f32), TLVError> {
    let (remaining_bytes, value) = le_f32::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse f32 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_f64(bytes: &[u8]) -> Result<(&[u8], f64), TLVError> {
    let (remaining_bytes, value) = le_f64::<_, Error<&[u8]>>(bytes).map_err(|e| {
        error!("Failed to parse f64 {}", e);
        TLVError::ParseError
    })?;
    Ok((remaining_bytes, value))
}

pub fn parse_str(utf8_bytes: &[u8]) -> Result<&str, TLVError> {
    let str = from_utf8(utf8_bytes).map_err(|e| {
        error!("Failed to parse bytes for str: {}", e);
        TLVError::ParseError
    })?;
    Ok(str)
}
