#![allow(dead_code)] // Until the Library is used

use crate::errors::TLVError;
use crate::tags::TLVTag;
use crate::types::{ElementType, PrimitiveLengthType, SpecifiedLenPrimitive, TLVType};
use crate::{tags, util};
use log::error;
use nom::Finish;
use std::cmp::Ordering;

struct TLVReader {
    bytes: Vec<u8>,
    bytes_read: usize,
}

impl TLVReader {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_owned(),
            bytes_read: 0,
        }
    }

    fn current_element(&self) -> &[u8] {
        self.bytes[(self.bytes_read)..].as_ref()
    }

    fn parse_control_byte(&self) -> Result<(&[u8], (u8, u8)), TLVError> {
        util::split_byte_into_2_parts(self.current_element(), (3usize, 5usize))
            .finish()
            .map_err(|e| {
                error!("Cannot parse control byte {}", e.code.description());
                TLVError::ParseError
            })
    }

    fn parse_control(&self) -> Result<(&[u8], TLVTag, TLVType), TLVError> {
        let (remaining_bytes, (tag_control_byte, element_type_byte)) = self.parse_control_byte()?;
        let (remaining_bytes, tlv_tag) = tags::parse_tag(
            tag_control_byte << tags::CONTROL_BYTE_SHIFT,
            remaining_bytes,
        )?;
        let tlv_type = Self::tlv_type(element_type_byte)?;
        Ok((remaining_bytes, tlv_tag, tlv_type))
    }

    fn parse_primitive_len(
        primitive_length_type: PrimitiveLengthType,
        remaining_bytes: &[u8],
    ) -> Result<(&[u8], usize, usize), TLVError> {
        Ok(match primitive_length_type {
            PrimitiveLengthType::Predetermined(predetermined_len_type) => (
                remaining_bytes,
                0,
                predetermined_len_type.value_octets_count(),
            ),
            PrimitiveLengthType::Specified(specified_len_type) => {
                let len_field_size = specified_len_type.length_field_size();
                let (remaining_bytes, value_octets_count) =
                    len_field_size.parse_field_size(remaining_bytes)?;
                (remaining_bytes, len_field_size as usize, value_octets_count)
            }
        })
    }

    fn tlv_type(element_type_byte: u8) -> Result<TLVType, TLVError> {
        let element_type = ElementType::try_from(element_type_byte)?;
        let tlv_type = TLVType::try_from(element_type)?;
        Ok(tlv_type)
    }

    fn next(&mut self) -> Result<(), TLVError> {
        let (remaining_bytes, tlv_tag, tlv_type) = self.parse_control()?;
        let length_and_value_octets_count = match tlv_type {
            TLVType::Container(_) => todo!("Skip to the End of Container"),
            TLVType::Primitive(primitive_length_type) => {
                let (_, length_octets_count, value_octets_count) =
                    Self::parse_primitive_len(primitive_length_type, remaining_bytes)?;
                length_octets_count + value_octets_count
            }
        };
        let element_len = length_and_value_octets_count + tlv_tag.octets_count() as usize + 1; // +1 for control byte
        let next_element = self.bytes_read + element_len;
        match next_element.cmp(&self.bytes.len()) {
            Ordering::Greater => Err(TLVError::UnderRun),
            Ordering::Equal => Err(TLVError::EndOfTLV),
            Ordering::Less => {
                self.bytes_read = next_element;
                Ok(())
            }
        }
    }

    fn read_tag(&self) -> Result<TLVTag, TLVError> {
        let (_, tlv_tag, _) = self.parse_control()?;
        Ok(tlv_tag)
    }

    fn read_u8(&self) -> Result<u8, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::UInt8)? {
            let (_, value) = util::parse_u8(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u16(&self) -> Result<u16, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::UInt16)? {
            let (_, value) = util::parse_u16(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u32(&self) -> Result<u32, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::UInt32)? {
            let (_, value) = util::parse_u32(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u64(&self) -> Result<u64, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::UInt64)? {
            let (_, value) = util::parse_u64(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i8(&self) -> Result<i8, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::Int8)? {
            let (_, value) = util::parse_i8(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i16(&self) -> Result<i16, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::Int16)? {
            let (_, value) = util::parse_i16(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i32(&self) -> Result<i32, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::Int32)? {
            let (_, value) = util::parse_i32(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i64(&self) -> Result<i64, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::Int64)? {
            let (_, value) = util::parse_i64(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_f32(&self) -> Result<f32, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::FloatingPointNumber32)? {
            let (_, value) = util::parse_f32(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_f64(&self) -> Result<f64, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::FloatingPointNumber64)? {
            let (_, value) = util::parse_f64(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_bool(&self) -> Result<bool, TLVError> {
        let (_, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::BooleanTrue)? {
            Ok(true)
        } else if tlv_type == TLVType::try_from(ElementType::BooleanFalse)? {
            Ok(false)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_null(&self) -> Result<(), TLVError> {
        let (_, _, tlv_type) = self.parse_control()?;
        if tlv_type == TLVType::try_from(ElementType::Null)? {
            Ok(())
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_byte_str(&self) -> Result<Vec<u8>, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        let field_size = match tlv_type {
            TLVType::Primitive(PrimitiveLengthType::Specified(
                SpecifiedLenPrimitive::ByteString(string),
            )) => string.length_field_size(),
            _ => return Err(TLVError::InvalidType),
        };
        Ok(field_size
            .extract_field_sized_bytes(remaining_bytes)?
            .to_vec())
    }

    fn read_char_str(&self) -> Result<String, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control()?;
        let field_size = match tlv_type {
            TLVType::Primitive(PrimitiveLengthType::Specified(
                SpecifiedLenPrimitive::UTF8String(string),
            )) => string.length_field_size(),
            _ => return Err(TLVError::InvalidType),
        };
        let value = field_size.extract_field_sized_bytes(remaining_bytes)?;
        Ok(util::parse_str(value)?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::{CommonProfileLength, FullyQualifiedProfileLength, TagControl};

    #[test]
    fn test_parse_control_byte() {
        // Unsigned Integer, 8-octet, value 40000000000
        let test_bytes = &[0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00];
        let tlv_reader = TLVReader::new(test_bytes);
        let (remaining_bytes, (tag_control, element_type)) = tlv_reader
            .parse_control_byte()
            .expect("Cannot parse control byte");
        assert_eq!(
            tag_control << tags::CONTROL_BYTE_SHIFT,
            TagControl::Anonymous as u8
        );
        assert_eq!(element_type, ElementType::UInt64 as u8);
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
    fn test_read_u8_tagged() {
        // Anonymous tag, Unsigned Integer, 1-octet value, 42U
        let test_bytes = &[0x04, 0x2a];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_tag().expect("Failed to read tag"),
            TLVTag::Anonymous
        );
        assert_eq!(tlv_reader.read_u8().expect("Failed to read u8"), 42);

        // Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U
        let test_bytes = &[0x24, 0x01, 0x2a];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_tag().expect("Failed to read tag"),
            TLVTag::ContextSpecific(1)
        );
        assert_eq!(tlv_reader.read_u8().expect("Failed to read u8"), 42);

        // Common profile tag 1, Unsigned Integer, 1-octet value, CHIP::1 = 42U
        let test_bytes = &[0x44, 0x01, 0x00, 0x2a];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_tag().expect("Failed to read tag"),
            TLVTag::CommonProfile(CommonProfileLength::TwoOctets { tag_number: 1 })
        );
        assert_eq!(tlv_reader.read_u8().expect("Failed to read u8"), 42);

        // Common profile tag 100000, Unsigned Integer, 1-octet value, CHIP::100000 = 42U
        let test_bytes = &[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_tag().expect("Failed to read tag"),
            TLVTag::CommonProfile(CommonProfileLength::FourOctets { tag_number: 100000 })
        );
        assert_eq!(tlv_reader.read_u8().expect("Failed to read u8"), 42);

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 2-octet tag 1, Unsigned Integer, 1-octet value 42, 65521::57069:1 = 42U
        let test_bytes = &[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_tag().expect("Failed to read tag"),
            TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::SixOctets {
                vendor_id: 65521,
                profile_number: 57069,
                tag_number: 1
            })
        );
        assert_eq!(tlv_reader.read_u8().expect("Failed to read u8"), 42);

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 4-octet tag 0xAA55FEED/2857762541,
        // Unsigned Integer, 1-octet value 42, 65521::57069:2857762541 = 42U
        let test_bytes = &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader.read_tag().expect("Failed to read tag"),
            TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::EightOctets {
                vendor_id: 65521,
                profile_number: 57069,
                tag_number: 2857762541
            })
        );
        assert_eq!(tlv_reader.read_u8().expect("Failed to read u8"), 42);
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
        let expected: f32 = 17.9;
        let actual = tlv_reader.read_f32().expect("Failed to read f32");
        assert!((expected - actual).abs() < f32::EPSILON);

        // Single precision floating point infinity (∞)
        let test_bytes = &[0x0a, 0x00, 0x00, 0x80, 0x7f];
        let tlv_reader = TLVReader::new(test_bytes);
        let infinity = tlv_reader.read_f32().expect("Failed to read f32");
        assert!(infinity.is_sign_positive());
        assert!(infinity.is_infinite());

        // Single precision floating point negative infinity (-∞)
        let test_bytes = &[0x0a, 0x00, 0x00, 0x80, 0xff];
        let tlv_reader = TLVReader::new(test_bytes);
        let infinity = tlv_reader.read_f32().expect("Failed to read f32");
        assert!(infinity.is_sign_negative());
        assert!(infinity.is_infinite());
    }

    #[test]
    fn test_read_f64() {
        // Double precision floating point 17.9
        let test_bytes = &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40];
        let tlv_reader = TLVReader::new(test_bytes);
        let expected: f64 = 17.9;
        let actual = tlv_reader.read_f64().expect("Failed to read f64");
        assert!((expected - actual).abs() < f64::EPSILON);

        // Double precision floating point infinity (∞)
        let test_bytes = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f];
        let tlv_reader = TLVReader::new(test_bytes);
        let infinity = tlv_reader.read_f64().expect("Failed to read f64");
        assert!(infinity.is_sign_positive());
        assert!(infinity.is_infinite());

        // Double precision floating point negative infinity (-∞)
        let test_bytes = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff];
        let tlv_reader = TLVReader::new(test_bytes);
        let infinity = tlv_reader.read_f64().expect("Failed to read f64");
        assert!(infinity.is_sign_negative());
        assert!(infinity.is_infinite());
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
    fn test_read_byte_str() {
        // Octet String, 1-octet length specifying 5 octets 00 01 02 03 04
        let test_bytes = &[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader
                .read_byte_str()
                .expect("Failed to read byte string"),
            [0x00, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn test_read_char_str() {
        // UTF-8 String, 1-octet length, "Hello!"
        let test_bytes = &[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21];
        let tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader
                .read_char_str()
                .expect("Failed to read character string"),
            "Hello!"
        );

        // UTF-8 String, 1-octet length, "Tschüs"
        let test_bytes = &[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73];
        let mut tlv_reader = TLVReader::new(test_bytes);
        assert_eq!(
            tlv_reader
                .read_char_str()
                .expect("Failed to read character string"),
            "Tschüs"
        );
        assert_eq!(
            tlv_reader.next().expect_err("Sequence End is expected"),
            TLVError::EndOfTLV
        );
    }

    #[test]
    fn test_read_sequence() {
        // Unsigned Integer, 8-octet, value 40000000000
        // + Unsigned Integer, 1-octet, value 255
        // + Signed Integer, 4-octet, value -904534
        // + Boolean true
        // + Null
        // + Double precision floating point negative infinity (-∞)
        // + UTF-8 String, 1-octet length, "The End."
        let test_bytes = &[
            0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00, 0x04, 0xFF, 0x02, 0xAA, 0x32,
            0xF2, 0xFF, 0x09, 0x14, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0c,
            0x08, 0x54, 0x68, 0x65, 0x20, 0x45, 0x6e, 0x64, 0x2e,
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

        tlv_reader
            .next()
            .expect("Failed to move pointer to next element");
        assert!(tlv_reader.read_bool().expect("Failed to read bool"));

        tlv_reader
            .next()
            .expect("Failed to move pointer to next element");
        tlv_reader.read_null().expect("Failed to read null byte");

        tlv_reader
            .next()
            .expect("Failed to move pointer to next element");
        let infinity = tlv_reader.read_f64().expect("Failed to read f64");
        assert!(infinity.is_sign_negative());
        assert!(infinity.is_infinite());

        tlv_reader
            .next()
            .expect("Failed to move pointer to next element");
        assert_eq!(
            tlv_reader
                .read_char_str()
                .expect("Failed to read character string"),
            "The End."
        );

        assert_eq!(
            tlv_reader.next().expect_err("Sequence End is expected"),
            TLVError::EndOfTLV
        );
    }
}
