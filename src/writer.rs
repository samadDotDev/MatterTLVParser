#![allow(dead_code)] // Until the Library is used

use crate::tags::{tag_bytes, TLVTag, TagControl};
use crate::types::ElementType;
use bytes::Bytes;

trait TLVEncode {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8>;
    fn encode_tlv(&self) -> Vec<u8> {
        self.encode_tlv_with_tag(TLVTag::Anonymous)
    }
}

fn encode_primitive(
    tag: TLVTag,
    element_type: ElementType,
    len_bytes: &[u8],
    val_bytes: &[u8],
) -> Vec<u8> {
    let mut element = Vec::new();
    let tag_control = TagControl::from(tag.clone()) as u8;
    let tag_bytes = tag_bytes(tag);
    let control_byte = tag_control | element_type as u8;
    element.push(control_byte);
    element.extend_from_slice(&tag_bytes);
    element.extend_from_slice(len_bytes);
    element.extend_from_slice(val_bytes);
    element
}

impl TLVEncode for i8 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(tag, ElementType::Int8, &[], val_bytes.as_ref())
    }
}

impl TLVEncode for i16 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(tag, ElementType::Int16, &[], val_bytes.as_ref())
    }
}

impl TLVEncode for i32 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(tag, ElementType::Int32, &[], val_bytes.as_ref())
    }
}

impl TLVEncode for i64 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(tag, ElementType::Int64, &[], val_bytes.as_ref())
    }
}
impl TLVEncode for u8 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(tag, ElementType::UInt8, &[], val_bytes.as_ref())
    }
}

impl TLVEncode for u16 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(tag, ElementType::UInt16, &[], val_bytes.as_ref())
    }
}

impl TLVEncode for u32 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(tag, ElementType::UInt32, &[], val_bytes.as_ref())
    }
}

impl TLVEncode for u64 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(tag, ElementType::UInt64, &[], val_bytes.as_ref())
    }
}

impl TLVEncode for f32 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(
            tag,
            ElementType::FloatingPointNumber32,
            &[],
            val_bytes.as_ref(),
        )
    }
}

impl TLVEncode for f64 {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_le_bytes();
        encode_primitive(
            tag,
            ElementType::FloatingPointNumber64,
            &[],
            val_bytes.as_ref(),
        )
    }
}

impl TLVEncode for bool {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let element_type = if *self {
            ElementType::BooleanTrue
        } else {
            ElementType::BooleanFalse
        };
        encode_primitive(tag, element_type, &[], &[])
    }
}

impl TLVEncode for String {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.clone().into_bytes();
        let val_len = val_bytes.len();
        let (element_type, len_bytes) = if val_len <= u8::MAX as usize {
            (
                ElementType::UTF8String1ByteLength,
                (val_len as u8).to_le_bytes().to_vec(),
            )
        } else if val_len <= u16::MAX as usize {
            (
                ElementType::UTF8String2ByteLength,
                (val_len as u16).to_le_bytes().to_vec(),
            )
        } else if val_len <= u32::MAX as usize {
            (
                ElementType::UTF8String4ByteLength,
                (val_len as u32).to_le_bytes().to_vec(),
            )
        } else {
            (
                ElementType::UTF8String8ByteLength,
                (val_len as u64).to_le_bytes().to_vec(),
            )
        };
        encode_primitive(
            tag,
            element_type,
            len_bytes.as_slice(),
            val_bytes.as_slice(),
        )
    }
}

impl TLVEncode for Bytes {
    fn encode_tlv_with_tag(&self, tag: TLVTag) -> Vec<u8> {
        let val_bytes = self.to_vec();
        let val_len = val_bytes.len();
        let (element_type, len_bytes) = if val_len <= u8::MAX as usize {
            (
                ElementType::ByteString1ByteLength,
                (val_len as u8).to_le_bytes().to_vec(),
            )
        } else if val_len <= u16::MAX as usize {
            (
                ElementType::ByteString2ByteLength,
                (val_len as u16).to_le_bytes().to_vec(),
            )
        } else if val_len <= u32::MAX as usize {
            (
                ElementType::ByteString4ByteLength,
                (val_len as u32).to_le_bytes().to_vec(),
            )
        } else {
            (
                ElementType::ByteString8ByteLength,
                (val_len as u64).to_le_bytes().to_vec(),
            )
        };
        encode_primitive(
            tag,
            element_type,
            len_bytes.as_slice(),
            val_bytes.as_slice(),
        )
    }
}

pub fn encode_null_with_tag(tag: TLVTag) -> Vec<u8> {
    encode_primitive(tag, ElementType::Null, &[], &[])
}

pub fn encode_null() -> Vec<u8> {
    encode_null_with_tag(TLVTag::Anonymous)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::{CommonProfileLength, FullyQualifiedProfileLength};

    #[test]
    fn test_write_u8_tagged() {
        // Anonymous tag, Unsigned Integer, 1-octet value, 42U
        let test_output = &[0x04, 0x2a];
        let test_input: u8 = 42;
        assert_eq!(
            test_input.encode_tlv_with_tag(TLVTag::Anonymous),
            test_output
        );

        // Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U
        let test_output = &[0x24, 0x01, 0x2a];
        assert_eq!(
            test_input.encode_tlv_with_tag(TLVTag::ContextSpecific(1)),
            test_output
        );

        // Common profile tag 1, Unsigned Integer, 1-octet value, CHIP::1 = 42U
        let test_output = &[0x44, 0x01, 0x00, 0x2a];
        assert_eq!(
            test_input.encode_tlv_with_tag(TLVTag::CommonProfile(CommonProfileLength::TwoOctets {
                tag_number: 1
            })),
            test_output
        );

        // Common profile tag 100000, Unsigned Integer, 1-octet value, CHIP::100000 = 42U
        let test_output = &[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a];
        assert_eq!(
            test_input.encode_tlv_with_tag(TLVTag::CommonProfile(
                CommonProfileLength::FourOctets { tag_number: 100000 }
            )),
            test_output
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 2-octet tag 1, Unsigned Integer, 1-octet value 42, 65521::57069:1 = 42U
        let test_output = &[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a];
        assert_eq!(
            test_input.encode_tlv_with_tag(TLVTag::FullyQualifiedProfile(
                FullyQualifiedProfileLength::SixOctets {
                    vendor_id: 65521,
                    profile_number: 57069,
                    tag_number: 1
                }
            )),
            test_output
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 4-octet tag 0xAA55FEED/2857762541,
        // Unsigned Integer, 1-octet value 42, 65521::57069:2857762541 = 42U
        let test_output = &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a];
        assert_eq!(
            test_input.encode_tlv_with_tag(TLVTag::FullyQualifiedProfile(
                FullyQualifiedProfileLength::EightOctets {
                    vendor_id: 65521,
                    profile_number: 57069,
                    tag_number: 2857762541
                }
            )),
            test_output
        );
    }

    #[test]
    fn test_write_u8() {
        let test_output = &[0x04, 0xFF]; // Unsigned Integer, 1-octet, value 255
        let test_input: u8 = 255;
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_u16() {
        let test_output = &[0x05, 0xFF, 0xFF]; // Unsigned Integer, 2-octet, value 65535
        let test_input: u16 = 65535;
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_u32() {
        // Unsigned Integer, 4-octet, value 237998115
        let test_output = &[0x06, 0x23, 0x90, 0x2f, 0x0E];
        let test_input: u32 = 237998115;
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_u64() {
        // Unsigned Integer, 8-octet, value 40000000000
        let test_output = &[0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00];
        let test_input: u64 = 40000000000;
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_f32() {
        // Single precision floating point 17.9
        let test_output = &[0x0a, 0x33, 0x33, 0x8f, 0x41];
        let test_input: f32 = 17.9;
        assert_eq!(test_input.encode_tlv(), test_output);

        // Single precision floating point infinity (∞)
        let test_output = &[0x0a, 0x00, 0x00, 0x80, 0x7f];
        let test_input = f32::INFINITY;
        assert_eq!(test_input.encode_tlv(), test_output);

        // Single precision floating point negative infinity (-∞)
        let test_output = &[0x0a, 0x00, 0x00, 0x80, 0xff];
        let test_input = f32::NEG_INFINITY;
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_f64() {
        // Double precision floating point 17.9
        let test_output = &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40];
        let test_input: f64 = 17.9;
        assert_eq!(test_input.encode_tlv(), test_output);

        // Double precision floating point infinity (∞)
        let test_output = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f];
        let test_input: f64 = f64::INFINITY;
        assert_eq!(test_input.encode_tlv(), test_output);

        // Double precision floating point negative infinity (-∞)
        let test_output = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff];
        let test_input: f64 = f64::NEG_INFINITY;
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_char_str() {
        // UTF-8 String, 1-octet length, "Hello!"
        let test_output = &[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21];
        let test_input = String::from("Hello!");
        assert_eq!(test_input.encode_tlv(), test_output);

        // UTF-8 String, 1-octet length, "Tschüs"
        let test_output = &[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73];
        let test_input = String::from("Tschüs");
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_byte_str() {
        // Octet String, 1-octet length specifying 5 octets 00 01 02 03 04
        let test_output = &[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let test_input = Bytes::from(vec![0x00, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_bool() {
        // Boolean false
        let test_output = &[0x08];
        let test_input = false;
        assert_eq!(test_input.encode_tlv(), test_output);

        // Boolean true
        let test_output = &[0x09];
        let test_input = true;
        assert_eq!(test_input.encode_tlv(), test_output);
    }

    #[test]
    fn test_write_null() {
        // Anonymous tag, Null
        let test_output = &[0x14];
        assert_eq!(encode_null(), test_output);
        assert_eq!(encode_null_with_tag(TLVTag::Anonymous), test_output);

        // Context tag 1 = Null
        let test_output = &[0x34, 0x01];
        assert_eq!(
            encode_null_with_tag(TLVTag::ContextSpecific(1)),
            test_output
        );

        // Common profile tag 1, CHIP::1 = Null
        let test_output = &[0x54, 0x01, 0x00];
        assert_eq!(
            encode_null_with_tag(TLVTag::CommonProfile(CommonProfileLength::TwoOctets {
                tag_number: 1
            })),
            test_output
        );

        // Common profile tag 100000, CHIP::100000 = Null
        let test_output = &[0x74, 0xa0, 0x86, 0x01, 0x00];
        assert_eq!(
            encode_null_with_tag(TLVTag::CommonProfile(CommonProfileLength::FourOctets {
                tag_number: 100000
            })),
            test_output
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 2-octet tag 1, 65521::57069:1 = Null
        let test_output = &[0xd4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00];
        assert_eq!(
            encode_null_with_tag(TLVTag::FullyQualifiedProfile(
                FullyQualifiedProfileLength::SixOctets {
                    vendor_id: 65521,
                    profile_number: 57069,
                    tag_number: 1
                }
            )),
            test_output
        );

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 4-octet tag 0xAA55FEED/2857762541, 65521::57069:2857762541 = Null
        let test_output = &[0xf4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa];
        assert_eq!(
            encode_null_with_tag(TLVTag::FullyQualifiedProfile(
                FullyQualifiedProfileLength::EightOctets {
                    vendor_id: 65521,
                    profile_number: 57069,
                    tag_number: 2857762541
                }
            )),
            test_output
        );
    }
}
