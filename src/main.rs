#![allow(dead_code)] // Temporarily disable unused code warnings for the binary

use crate::types::{
    TLVBoolean, TLVElementType, TLVError, TLVFloatingPoint, TLVNull, TLVPrimitiveLengthType,
    TLVSignedInteger, TLVType, TLVUnsignedInteger,
};
use log::error;
use nom::bits::{bits, complete::take};
use nom::error::Error;
use nom::number::complete::{
    le_f32, le_f64, le_i16, le_i32, le_i64, le_i8, le_u16, le_u32, le_u64, le_u8,
};
use nom::sequence::tuple;
use nom::{Finish, IResult};

mod tags;
mod types;

struct TLVReader {
    payload: Vec<u8>,
    len_read: usize,
}

impl TLVReader {
    fn new(payload: &[u8]) -> Self {
        Self {
            payload: payload.to_owned(),
            len_read: 0,
        }
    }

    fn current_element(&self, offset: usize) -> &[u8] {
        self.payload[(self.len_read + offset)..].as_ref()
    }

    fn split_byte_into_2_parts(
        input: &[u8],
        proportions: (usize, usize),
    ) -> IResult<&[u8], (u8, u8)> {
        bits::<_, _, Error<(&[u8], usize)>, _, _>(tuple((take(proportions.0), take(proportions.1))))(
            input,
        )
    }

    fn split_byte_into_3_parts(
        input: &[u8],
        proportions: (usize, usize, usize),
    ) -> IResult<&[u8], (u8, u8, u8)> {
        bits::<_, _, Error<(&[u8], usize)>, _, _>(tuple((
            take(proportions.0),
            take(proportions.1),
            take(proportions.2),
        )))(input)
    }

    fn parse_control_byte(&self) -> Result<(&[u8], (u8, u8)), TLVError> {
        Self::split_byte_into_2_parts(self.current_element(0), (3usize, 5usize))
            .finish()
            .map_err(|e| {
                error!("Cannot parse control byte {}", e.code.description());
                TLVError::ParseError
            })
    }

    fn parse_control_byte_with_field_size(&self) -> Result<(&[u8], (u8, u8, u8)), TLVError> {
        Self::split_byte_into_3_parts(self.current_element(0), (3usize, 3usize, 2usize))
            .finish()
            .map_err(|e| {
                error!("Cannot parse control byte {}", e.code.description());
                TLVError::ParseError
            })
    }

    fn tlv_type(&self) -> Result<TLVType, TLVError> {
        let (_, (_, element_type_byte)) = self.parse_control_byte()?;
        let element_type = TLVElementType::try_from(element_type_byte)?;
        let tlv_type = TLVType::try_from(element_type)?;
        Ok(tlv_type)
    }

    fn parse_len(&self, len_bytes_count: usize) -> Result<usize, TLVError> {
        let bytes_after_control_byte = self.current_element(1);
        Ok(match len_bytes_count {
            1 => {
                le_u8::<_, Error<&[u8]>>(bytes_after_control_byte)
                    .map_err(|e| {
                        error!("Failed to parse u8: {}", e);
                        TLVError::ParseError
                    })?
                    .1 as usize
            }
            2 => {
                le_u16::<_, Error<&[u8]>>(bytes_after_control_byte)
                    .map_err(|e| {
                        error!("Failed to parse u16: {}", e);
                        TLVError::ParseError
                    })?
                    .1 as usize
            }
            4 => {
                le_u32::<_, Error<&[u8]>>(bytes_after_control_byte)
                    .map_err(|e| {
                        error!("Failed to parse u32: {}", e);
                        TLVError::ParseError
                    })?
                    .1 as usize
            }
            8 => {
                le_u64::<_, Error<&[u8]>>(bytes_after_control_byte)
                    .map_err(|e| {
                        error!("Failed to parse u64: {}", e);
                        TLVError::ParseError
                    })?
                    .1 as usize
            }
            _ => return Err(TLVError::InvalidLen),
        })
    }

    fn next(&mut self) -> Result<(), TLVError> {
        let tlv_type = self.tlv_type()?;
        let element_len = match tlv_type {
            TLVType::Container(_) => todo!("Skip to the End of Container"),
            TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(predetermined_len_type)) => {
                predetermined_len_type.value_octets_count()
            }
            TLVType::Primitive(TLVPrimitiveLengthType::Specified(specified_len_type)) => {
                let len_octets = specified_len_type.length_octets_count();
                let val_octets = self.parse_len(len_octets)?;
                len_octets + val_octets
            }
        };
        let len_to_skip = element_len + 1; // Element (Length + Value bytes) + Control byte
        if len_to_skip > self.payload.len() {
            Err(TLVError::OverRun)
        } else if len_to_skip == self.payload.len() - 1 {
            Err(TLVError::EndOfTLV)
        } else {
            self.len_read += len_to_skip;
            Ok(())
        }
    }

    fn read_u8(&self) -> Result<u8, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVUnsignedInteger::UInt8 as u8 {
            let (_, value) = le_u8::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse u8 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u16(&self) -> Result<u16, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVUnsignedInteger::UInt16 as u8 {
            let (_, value) = le_u16::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse u16 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u32(&self) -> Result<u32, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVUnsignedInteger::UInt32 as u8 {
            let (_, value) = le_u32::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse u32 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u64(&self) -> Result<u64, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVUnsignedInteger::UInt64 as u8 {
            let (_, value) = le_u64::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse u64 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i8(&self) -> Result<i8, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVSignedInteger::Int8 as u8 {
            let (_, value) = le_i8::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse i8 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i16(&self) -> Result<i16, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVSignedInteger::Int16 as u8 {
            let (_, value) = le_i16::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse i16 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i32(&self) -> Result<i32, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVSignedInteger::Int32 as u8 {
            let (_, value) = le_i32::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse i32 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i64(&self) -> Result<i64, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVSignedInteger::Int64 as u8 {
            let (_, value) = le_i64::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse i64 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_f32(&self) -> Result<f32, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVFloatingPoint::FloatingPointNumber32 as u8 {
            let (_, value) = le_f32::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse f32 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_f64(&self) -> Result<f64, TLVError> {
        let (remaining_bytes, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVFloatingPoint::FloatingPointNumber64 as u8 {
            let (_, value) = le_f64::<_, Error<&[u8]>>(remaining_bytes).map_err(|e| {
                error!("Failed to parse f64 {}", e);
                TLVError::ParseError
            })?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_bool(&self) -> Result<bool, TLVError> {
        let (_, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVBoolean::BooleanTrue as u8 {
            Ok(true)
        } else if element_type_byte == TLVBoolean::BooleanFalse as u8 {
            Ok(false)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_null(&self) -> Result<(), TLVError> {
        let (_, (_, element_type_byte)) = self.parse_control_byte()?;
        if element_type_byte == TLVNull::Null as u8 {
            Ok(())
        } else {
            Err(TLVError::InvalidType)
        }
    }
}

fn main() {
    print!("Run tests instead")
}

#[cfg(test)]
mod tests {
    use crate::tags::TLVTagControl;
    use crate::types::TLVFieldSize;

    use super::*;

    #[test]
    fn test_parse_control_byte() {
        // Unsigned Integer, 8-octet, value 40000000000
        let test_bytes = &[0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00];
        let tlv_reader = TLVReader::new(test_bytes);
        let (remaining_bytes, (tag_control, element_type)) = tlv_reader
            .parse_control_byte()
            .expect("Cannot parse control byte");
        assert_eq!(tag_control << 5, TLVTagControl::Anonymous as u8);
        assert_eq!(element_type, TLVElementType::UInt64 as u8);
        assert_eq!(
            remaining_bytes,
            [0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_parse_control_byte_with_field_size() {
        // Unsigned Integer, 8-octet, value 40000000000
        let test_bytes = &[0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00];
        let tlv_reader = TLVReader::new(test_bytes);
        let (remaining_bytes, (tag_control, tlv_type, field_size)) = tlv_reader
            .parse_control_byte_with_field_size()
            .expect("Cannot parse control byte");
        assert_eq!(tag_control, TLVTagControl::Anonymous as u8);
        assert_eq!(
            ((tlv_type << 2) | field_size),
            TLVUnsignedInteger::UInt64 as u8
        );
        assert_eq!(field_size, TLVFieldSize::EightByte as u8);
        assert_eq!((1 << field_size) as usize, remaining_bytes.len());
        assert_eq!(
            remaining_bytes,
            [0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_read_u8() {
        let test_bytes = &[0x04, 0xFF]; // Unsigned Integer, 1-octet, value 255
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(tlv_reader.read_u8().expect("Failed to read u8"), 255);
    }

    #[test]
    fn test_read_u16() {
        let test_bytes = &[0x05, 0xFF, 0xFF]; // Unsigned Integer, 2-octet, value 65535
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(tlv_reader.read_u16().expect("Failed to read u16"), 65535);
    }

    #[test]
    fn test_read_u32() {
        // Unsigned Integer, 4-octet, value 237998115
        let test_bytes = &[0x06, 0x23, 0x90, 0x2f, 0x0E];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_u32().expect("Failed to read u32"),
            237998115
        );
    }

    #[test]
    fn test_read_u64() {
        // Unsigned Integer, 8-octet, value 40000000000
        let test_bytes = &[0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_u64().expect("Failed to read u64"),
            40000000000
        );
    }

    #[test]
    fn test_read_i8() {
        let test_bytes = &[0x00, 0xFF]; // Signed Integer, 1-octet, value -1
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(tlv_reader.read_i8().expect("Failed to read i8"), -1);
    }

    #[test]
    fn test_read_i16() {
        let test_bytes = &[0x01, 0x0F, 0xFF]; // Signed Integer, 2-octet, value -241
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(tlv_reader.read_i16().expect("Failed to read i16"), -241);
    }

    #[test]
    fn test_read_i32() {
        // Signed Integer, 4-octet, value 237998115
        let test_bytes = &[0x02, 0x23, 0x90, 0x2f, 0x0E];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_i32().expect("Failed to read i32"),
            237998115
        );
    }

    #[test]
    fn test_read_i64() {
        // Signed Integer, 8-octet, value 40000000000
        let test_bytes = &[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_i64().expect("Failed to read i64"),
            40000000000
        );
    }

    #[test]
    fn test_read_f32() {
        // Single precision floating point 17.9
        let test_bytes = &[0x0a, 0x33, 0x33, 0x8f, 0x41];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(tlv_reader.read_f32().expect("Failed to read f32"), 17.9);

        // Single precision floating point infinity (∞)
        let test_bytes = &[0x0a, 0x00, 0x00, 0x80, 0x7f];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_f32().expect("Failed to read f32"),
            f32::INFINITY
        );

        // Single precision floating point negative infinity (-∞)
        let test_bytes = &[0x0a, 0x00, 0x00, 0x80, 0xff];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_f32().expect("Failed to read f32"),
            f32::NEG_INFINITY
        );
    }

    #[test]
    fn test_read_f64() {
        // Double precision floating point 17.9
        let test_bytes = &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(tlv_reader.read_f64().expect("Failed to read f64"), 17.9);

        // Double precision floating point infinity (∞)
        let test_bytes = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_f64().expect("Failed to read f64"),
            f64::INFINITY
        );

        // Double precision floating point negative infinity (-∞)
        let test_bytes = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_f64().expect("Failed to read f64"),
            f64::NEG_INFINITY
        );
    }

    #[test]
    fn test_read_bool() {
        let test_bytes = &[0x08]; // Boolean false
        let tlv_reader = TLVReader::new(test_bytes);
        assert!(!tlv_reader.read_bool().expect("Failed to read bool"));

        let test_bytes = &[0x09]; // Boolean true
        let tlv_reader = TLVReader::new(test_bytes);
        assert!(tlv_reader.read_bool().expect("Failed to read bool"));
    }

    #[test]
    fn test_read_null() {
        let test_bytes = &[0x14]; // Null
        let tlv_reader = TLVReader::new(test_bytes);
        tlv_reader.read_null().expect("Failed to read null");
    }

    #[test]
    fn test_read_sequence() {
        // Unsigned Integer, 8-octet, value 40000000000
        // + Unsigned Integer, 1-octet, value 255
        // + Signed Integer, 4-octet, value -904534
        let test_bytes = &[
            0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00, 0x04, 0xFF, 0x02, 0xAA, 0x32,
            0xF2, 0xFF,
        ];
        let mut tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_u64().expect("Failed to read u64"),
            40000000000
        );
        tlv_reader
            .next()
            .expect("Failed to move pointer to next element");
        assert_eq!(tlv_reader.read_u8().expect("Failed to read u8"), 255);
        tlv_reader
            .next()
            .expect("Failed to move pointer to next element");
        assert_eq!(tlv_reader.read_i32().expect("Failed to read i32"), -904534);
    }
}
