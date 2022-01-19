#![allow(dead_code)] // Until the Library is used

use crate::errors::TLVError;
use crate::tags::{tag_bytes, TLVTag, TagControl};
use crate::types::{ElementType, TLVPrimitive};
use std::io::Write;

struct TLVWriter<'a> {
    buffer: &'a mut Vec<u8>,
}

impl<'a> Write for TLVWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buffer.flush()
    }
}

impl<'a> TLVWriter<'a> {
    pub fn new(buffer: &'a mut Vec<u8>) -> Self {
        Self { buffer }
    }

    pub fn write_primitive<T>(&mut self, value: T) -> Result<usize, TLVError>
    where
        T: TLVPrimitive,
    {
        self.write_primitive_with_tag(TLVTag::Anonymous, value)
    }

    pub fn write_primitive_with_tag<T>(&mut self, tag: TLVTag, value: T) -> Result<usize, TLVError>
    where
        T: TLVPrimitive,
    {
        let (element_type, len_bytes, val_bytes) = T::parse_value(value);
        self.write_element(
            tag,
            element_type,
            len_bytes.as_slice(),
            val_bytes.as_slice(),
        )
    }

    pub fn write_null_with_tag(&mut self, tag: TLVTag) -> bool {
        self.write_element(tag, ElementType::Null, &[], &[]).is_ok()
    }

    pub fn write_null(&mut self) -> bool {
        self.write_null_with_tag(TLVTag::Anonymous)
    }

    fn write_element(
        &mut self,
        tag: TLVTag,
        element_type: ElementType,
        len_bytes: &[u8],
        val_bytes: &[u8],
    ) -> Result<usize, TLVError> {
        let mut element_bytes = Vec::new();
        let tag_control = TagControl::from(tag.clone()) as u8;
        let tag_bytes = tag_bytes(tag);
        let control_byte = tag_control | element_type as u8;
        element_bytes.push(control_byte);
        element_bytes.extend_from_slice(&tag_bytes);
        element_bytes.extend_from_slice(len_bytes);
        element_bytes.extend_from_slice(val_bytes);

        self.write(element_bytes.as_ref())
            .map_err(|e| TLVError::Internal(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::{CommonProfileLength, FullyQualifiedProfileLength};

    #[test]
    fn test_write() {
        let test_output = &[0xFF, 0xFF];
        let test_input: u16 = 65535;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        let intermediate_bytes = test_input.to_le_bytes();
        assert_eq!(intermediate_bytes.as_ref(), test_output);
        assert_eq!(
            tlv_writer
                .write(intermediate_bytes.as_ref())
                .expect("Write failed"),
            intermediate_bytes.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u8_tagged() {
        // Anonymous tag, Unsigned Integer, 1-octet value, 42U
        let test_output = &[0x04, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive_with_tag(TLVTag::Anonymous, test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U
        let test_output = &[0x24, 0x01, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive_with_tag(TLVTag::ContextSpecific(1), test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // Common profile tag 1, Unsigned Integer, 1-octet value, CHIP::1 = 42U
        let test_output = &[0x44, 0x01, 0x00, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive_with_tag(
                    TLVTag::CommonProfile(CommonProfileLength::TwoOctets { tag_number: 1 }),
                    test_input
                )
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // Common profile tag 100000, Unsigned Integer, 1-octet value, CHIP::100000 = 42U
        let test_output = &[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive_with_tag(
                    TLVTag::CommonProfile(CommonProfileLength::FourOctets { tag_number: 100000 }),
                    test_input
                )
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 2-octet tag 1, Unsigned Integer, 1-octet value 42, 65521::57069:1 = 42U
        let test_output = &[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive_with_tag(
                    TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::SixOctets {
                        vendor_id: 65521,
                        profile_number: 57069,
                        tag_number: 1
                    }),
                    test_input
                )
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 4-octet tag 0xAA55FEED/2857762541,
        // Unsigned Integer, 1-octet value 42, 65521::57069:2857762541 = 42U
        let test_output = &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive_with_tag(
                    TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::EightOctets {
                        vendor_id: 65521,
                        profile_number: 57069,
                        tag_number: 2857762541
                    }),
                    test_input
                )
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u8() {
        let test_output = &[0x04, 0xFF]; // Unsigned Integer, 1-octet, value 255
        let test_input: u8 = 255;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u16() {
        let test_output = &[0x05, 0xFF, 0xFF]; // Unsigned Integer, 2-octet, value 65535
        let test_input: u16 = 65535;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u32() {
        // Unsigned Integer, 4-octet, value 237998115
        let test_output = &[0x06, 0x23, 0x90, 0x2f, 0x0E];
        let test_input: u32 = 237998115;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u64() {
        // Unsigned Integer, 8-octet, value 40000000000
        let test_output = &[0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00];
        let test_input: u64 = 40000000000;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_f32() {
        // Single precision floating point 17.9
        let test_output = &[0x0a, 0x33, 0x33, 0x8f, 0x41];
        let test_input: f32 = 17.9;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // Single precision floating point infinity (∞)
        let test_output = &[0x0a, 0x00, 0x00, 0x80, 0x7f];
        let test_input = f32::INFINITY;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
        assert_eq!(buffer.as_slice(), test_output);

        // Single precision floating point negative infinity (-∞)
        let test_output = &[0x0a, 0x00, 0x00, 0x80, 0xff];
        let test_input = f32::NEG_INFINITY;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_f64() {
        // Double precision floating point 17.9
        let test_output = &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40];
        let test_input: f64 = 17.9;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // Double precision floating point infinity (∞)
        let test_output = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f];
        let test_input: f64 = f64::INFINITY;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
        assert_eq!(buffer.as_slice(), test_output);

        // Double precision floating point negative infinity (-∞)
        let test_output = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff];
        let test_input: f64 = f64::NEG_INFINITY;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_char_str() {
        // UTF-8 String, 1-octet length, "Hello!"
        let test_output = &[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21];
        let test_input = String::from("Hello!");
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // UTF-8 String, 1-octet length, "Tschüs"
        let test_output = &[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73];
        let test_input = String::from("Tschüs");
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_byte_str() {
        // Octet String, 1-octet length specifying 5 octets 00 01 02 03 04
        let test_output = &[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let test_input = Vec::from([0x00, 0x01, 0x02, 0x03, 0x04]);
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_bool() {
        // Boolean false
        let test_output = &[0x08];
        let test_input = false;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);

        // Boolean true
        let test_output = &[0x09];
        let test_input = true;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert_eq!(
            tlv_writer
                .write_primitive(test_input)
                .expect("Write Failed"),
            test_output.len()
        );
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_null() {
        let test_output = &[0x14];
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_null());
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_sequence() {
        // Unsigned Integer, 8-octet, value 40000000000
        // + Unsigned Integer, 1-octet, value 255
        // + Signed Integer, 4-octet, value -904534
        // + Boolean true
        // + Null
        // + Double precision floating point negative infinity (-∞)
        // + UTF-8 String, 1-octet length, "The End."
        let test_output = &[
            0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00, 0x04, 0xFF, 0x02, 0xAA, 0x32,
            0xF2, 0xFF, 0x09, 0x14, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0c,
            0x08, 0x54, 0x68, 0x65, 0x20, 0x45, 0x6e, 0x64, 0x2e,
        ];

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        let test_input: u64 = 40000000000;
        tlv_writer
            .write_primitive(test_input)
            .expect("Write Failed");

        let test_input: u8 = 255;
        tlv_writer
            .write_primitive(test_input)
            .expect("Write Failed");

        let test_input: i32 = -904534;
        tlv_writer
            .write_primitive(test_input)
            .expect("Write Failed");

        let test_input = true;
        tlv_writer
            .write_primitive(test_input)
            .expect("Write Failed");

        assert!(tlv_writer.write_null());

        let test_input = f64::NEG_INFINITY;
        tlv_writer
            .write_primitive(test_input)
            .expect("Write Failed");

        let test_input = String::from("The End.");
        tlv_writer
            .write_primitive(test_input)
            .expect("Write Failed");

        assert_eq!(buffer.as_slice(), test_output);
    }
}
