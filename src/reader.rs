use crate::errors::TLVError;
use crate::tags::{
    CommonProfileLength, FullyQualifiedProfileLength, ImplicitProfileLength, TLVTag, TLVTagControl,
};
use crate::types::{
    TLVElementType, TLVFieldSize, TLVPrimitiveLengthType, TLVSpecifiedLengthType, TLVType,
};
use log::error;
use nom::bits::{bits, complete::take};
use nom::error::Error;
use nom::number::complete::{
    le_f32, le_f64, le_i16, le_i32, le_i64, le_i8, le_u16, le_u32, le_u64, le_u8,
};
use nom::sequence::tuple;
use nom::{Finish, IResult};
use std::str::from_utf8;

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

    fn parse_field_size(
        field_size: TLVFieldSize,
        bytes: &[u8],
    ) -> Result<(&[u8], usize), TLVError> {
        let len_octets_count = field_size.len();
        if len_octets_count > bytes.len() {
            return Err(TLVError::UnderRun);
        }
        Ok(match field_size {
            TLVFieldSize::OneByte => {
                let (remaining_bytes, u8_value) = Self::parse_u8(bytes)?;
                (remaining_bytes, u8_value as usize)
            }
            TLVFieldSize::TwoBytes => {
                let (remaining_bytes, u16_value) = Self::parse_u16(bytes)?;
                (remaining_bytes, u16_value as usize)
            }
            TLVFieldSize::FourBytes => {
                let (remaining_bytes, u32_value) = Self::parse_u32(bytes)?;
                (remaining_bytes, u32_value as usize)
            }
            TLVFieldSize::EightBytes => {
                let (remaining_bytes, u64_value) = Self::parse_u64(bytes)?;
                (remaining_bytes, u64_value as usize)
            }
        })
    }

    fn parse_primitive_len(
        primitive_length_type: TLVPrimitiveLengthType,
        remaining_bytes: &[u8],
    ) -> Result<(&[u8], usize, usize), TLVError> {
        Ok(match primitive_length_type {
            TLVPrimitiveLengthType::Predetermined(predetermined_len_type) => (
                remaining_bytes,
                0,
                predetermined_len_type.value_octets_count(),
            ),
            TLVPrimitiveLengthType::Specified(specified_len_type) => {
                let len_field_size = specified_len_type.length_field_size();
                let (remaining_bytes, value_octets_count) =
                    Self::parse_field_size(len_field_size.clone(), remaining_bytes)?;
                (remaining_bytes, len_field_size.len(), value_octets_count)
            }
        })
    }

    fn tlv_type(element_type_byte: u8) -> Result<TLVType, TLVError> {
        let element_type = TLVElementType::try_from(element_type_byte)?;
        let tlv_type = TLVType::try_from(element_type)?;
        Ok(tlv_type)
    }

    fn parse_tag(
        tag_control_byte: u8,
        remaining_bytes: &[u8],
    ) -> Result<(&[u8], TLVTag), TLVError> {
        let tag_control = TLVTagControl::try_from(tag_control_byte)?;
        let (remaining_bytes, tlv_tag) = match tag_control {
            TLVTagControl::Anonymous => (remaining_bytes, TLVTag::Anonymous),
            TLVTagControl::ContextSpecific => {
                let (remaining_bytes, tag_number) = Self::parse_u8(remaining_bytes)?;
                (remaining_bytes, TLVTag::ContextSpecific(tag_number))
            }
            TLVTagControl::CommonProfile2Bytes => {
                let (remaining_bytes, tag_number) = Self::parse_u16(remaining_bytes)?;
                (
                    remaining_bytes,
                    TLVTag::CommonProfile(CommonProfileLength::TwoOctets { tag_number }),
                )
            }
            TLVTagControl::CommonProfile4Bytes => {
                let (remaining_bytes, tag_number) = Self::parse_u32(remaining_bytes)?;
                (
                    remaining_bytes,
                    TLVTag::CommonProfile(CommonProfileLength::FourOctets { tag_number }),
                )
            }
            TLVTagControl::ImplicitProfile2Bytes => {
                let (remaining_bytes, tag_number) = Self::parse_u16(remaining_bytes)?;
                (
                    remaining_bytes,
                    TLVTag::ImplicitProfile(ImplicitProfileLength::TwoOctets { tag_number }),
                )
            }
            TLVTagControl::ImplicitProfile4Bytes => {
                let (remaining_bytes, tag_number) = Self::parse_u32(remaining_bytes)?;
                (
                    remaining_bytes,
                    TLVTag::ImplicitProfile(ImplicitProfileLength::FourOctets { tag_number }),
                )
            }
            TLVTagControl::FullyQualified6Bytes => {
                let (remaining_bytes, vendor_id) = Self::parse_u16(remaining_bytes)?;
                let (remaining_bytes, profile_number) = Self::parse_u16(remaining_bytes)?;
                let (remaining_bytes, tag_number) = Self::parse_u16(remaining_bytes)?;
                (
                    remaining_bytes,
                    TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::SixOctets {
                        vendor_id,
                        profile_number,
                        tag_number,
                    }),
                )
            }
            TLVTagControl::FullyQualified8Bytes => {
                let (remaining_bytes, vendor_id) = Self::parse_u16(remaining_bytes)?;
                let (remaining_bytes, profile_number) = Self::parse_u16(remaining_bytes)?;
                let (remaining_bytes, tag_number) = Self::parse_u32(remaining_bytes)?;
                (
                    remaining_bytes,
                    TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::EightOctets {
                        vendor_id,
                        profile_number,
                        tag_number,
                    }),
                )
            }
        };
        Ok((remaining_bytes, tlv_tag))
    }

    fn parse_control_byte_for_tag_and_type(&self) -> Result<(&[u8], TLVTag, TLVType), TLVError> {
        let (remaining_bytes, (tag_control_byte, element_type_byte)) = self.parse_control_byte()?;
        let (remaining_bytes, tlv_tag) = Self::parse_tag(tag_control_byte << 5, remaining_bytes)?;
        let tlv_type = Self::tlv_type(element_type_byte)?;
        Ok((remaining_bytes, tlv_tag, tlv_type))
    }

    fn next(&mut self) -> Result<(), TLVError> {
        let (remaining_bytes, tlv_tag, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        let length_and_value_octets_count = match tlv_type {
            TLVType::Container(_) => todo!("Skip to the End of Container"),
            TLVType::Primitive(primitive_length_type) => {
                let (_, length_octets_count, value_octets_count) =
                    Self::parse_primitive_len(primitive_length_type, remaining_bytes)?;
                length_octets_count + value_octets_count
            }
        };
        let element_len = length_and_value_octets_count + tlv_tag.octets_count() as usize + 1; // +1 for control byte
        let next_element = self.len_read + element_len;
        if next_element > self.payload.len() {
            Err(TLVError::UnderRun)
        } else if next_element == self.payload.len() {
            Err(TLVError::EndOfTLV)
        } else {
            self.len_read = next_element;
            Ok(())
        }
    }

    fn read_tag(&self) -> Result<TLVTag, TLVError> {
        let (_, tlv_tag, _) = self.parse_control_byte_for_tag_and_type()?;
        Ok(tlv_tag)
    }

    fn parse_u8(bytes: &[u8]) -> Result<(&[u8], u8), TLVError> {
        let (remaining_bytes, value) = le_u8::<_, Error<&[u8]>>(bytes).map_err(|e| {
            error!("Failed to parse u8 {}", e);
            TLVError::ParseError
        })?;
        Ok((remaining_bytes, value))
    }

    fn parse_u16(bytes: &[u8]) -> Result<(&[u8], u16), TLVError> {
        let (remaining_bytes, value) = le_u16::<_, Error<&[u8]>>(bytes).map_err(|e| {
            error!("Failed to parse u16 {}", e);
            TLVError::ParseError
        })?;
        Ok((remaining_bytes, value))
    }

    fn parse_u32(bytes: &[u8]) -> Result<(&[u8], u32), TLVError> {
        let (remaining_bytes, value) = le_u32::<_, Error<&[u8]>>(bytes).map_err(|e| {
            error!("Failed to parse u32 {}", e);
            TLVError::ParseError
        })?;
        Ok((remaining_bytes, value))
    }

    fn parse_u64(bytes: &[u8]) -> Result<(&[u8], u64), TLVError> {
        let (remaining_bytes, value) = le_u64::<_, Error<&[u8]>>(bytes).map_err(|e| {
            error!("Failed to parse u64 {}", e);
            TLVError::ParseError
        })?;
        Ok((remaining_bytes, value))
    }

    fn read_u8(&self) -> Result<u8, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::UInt8)? {
            let (_, value) = Self::parse_u8(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u16(&self) -> Result<u16, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::UInt16)? {
            let (_, value) = Self::parse_u16(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u32(&self) -> Result<u32, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::UInt32)? {
            let (_, value) = Self::parse_u32(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_u64(&self) -> Result<u64, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::UInt64)? {
            let (_, value) = Self::parse_u64(remaining_bytes)?;
            Ok(value)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_i8(&self) -> Result<i8, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::Int8)? {
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
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::Int16)? {
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
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::Int32)? {
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
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::Int64)? {
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
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::FloatingPointNumber32)? {
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
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::FloatingPointNumber64)? {
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
        let (_, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::BooleanTrue)? {
            Ok(true)
        } else if tlv_type == TLVType::try_from(TLVElementType::BooleanFalse)? {
            Ok(false)
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_null(&self) -> Result<(), TLVError> {
        let (_, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        if tlv_type == TLVType::try_from(TLVElementType::Null)? {
            Ok(())
        } else {
            Err(TLVError::InvalidType)
        }
    }

    fn read_byte_str(&self) -> Result<&[u8], TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        let field_size = match tlv_type {
            TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                TLVSpecifiedLengthType::ByteString(string),
            )) => string.length_field_size(),
            _ => return Err(TLVError::InvalidType),
        };
        let (remaining_bytes, value_len) = Self::parse_field_size(field_size, remaining_bytes)?;
        if value_len > remaining_bytes.len() {
            return Err(TLVError::UnderRun);
        }
        Ok(remaining_bytes[..value_len].as_ref())
    }

    fn read_char_str(&self) -> Result<&str, TLVError> {
        let (remaining_bytes, _, tlv_type) = self.parse_control_byte_for_tag_and_type()?;
        let field_size = match tlv_type {
            TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                TLVSpecifiedLengthType::UTF8String(string),
            )) => string.length_field_size(),
            _ => return Err(TLVError::InvalidType),
        };
        let (remaining_bytes, value_len) = Self::parse_field_size(field_size, remaining_bytes)?;
        if value_len > remaining_bytes.len() {
            return Err(TLVError::UnderRun);
        }
        let value = remaining_bytes[..value_len].as_ref();
        let value_str = from_utf8(value).map_err(|e| {
            error!("{}", e);
            TLVError::ParseError
        })?;
        Ok(value_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::TLVTagControl;
    use crate::types::TLVFieldSize;

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
        assert_eq!(((tlv_type << 2) | field_size), TLVElementType::UInt64 as u8);
        assert_eq!(field_size, TLVFieldSize::EightBytes as u8);
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
        assert_eq!(
            tlv_reader.read_f64().expect("Failed to read f64"),
            f64::NEG_INFINITY
        );

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
