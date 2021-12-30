#![allow(dead_code)] // Until the Library is used

use crate::tags::{tag_bytes, TLVTag, TagControl};
use crate::types::TLVNumeric;
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

    pub fn write_numeric<T>(&mut self, value: T) -> bool
    where
        T: TLVNumeric + TLVNumeric<ValueType = T>,
    {
        self.write_numeric_with_tag(TLVTag::Anonymous, value)
    }

    pub fn write_numeric_with_tag<T>(&mut self, tag: TLVTag, value: T) -> bool
    where
        T: TLVNumeric + TLVNumeric<ValueType = T>,
    {
        let tag_control = TagControl::from(tag.clone()) as u8;
        let element_type = value.element_type_byte();

        let mut element_bytes = Vec::new();
        let control_byte = tag_control | element_type;
        element_bytes.push(control_byte);
        let tag_bytes = tag_bytes(tag);
        element_bytes.extend_from_slice(&tag_bytes);
        let val_bytes = T::value_to_bytes(value);
        element_bytes.extend_from_slice(&val_bytes);

        let written = self.write(element_bytes.as_ref());
        // Is there a nicer way to unwrap result and return bool early if Err?
        written.is_ok() && element_bytes.len() == written.unwrap()
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
        assert!(tlv_writer.write_numeric_with_tag(TLVTag::Anonymous, test_input));
        assert_eq!(buffer.as_slice(), test_output);

        // Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U
        let test_output = &[0x24, 0x01, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric_with_tag(TLVTag::ContextSpecific(1), test_input));
        assert_eq!(buffer.as_slice(), test_output);

        // Common profile tag 1, Unsigned Integer, 1-octet value, CHIP::1 = 42U
        let test_output = &[0x44, 0x01, 0x00, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric_with_tag(
            TLVTag::CommonProfile(CommonProfileLength::TwoOctets { tag_number: 1 }),
            test_input
        ));
        assert_eq!(buffer.as_slice(), test_output);

        // Common profile tag 100000, Unsigned Integer, 1-octet value, CHIP::100000 = 42U
        let test_output = &[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric_with_tag(
            TLVTag::CommonProfile(CommonProfileLength::FourOctets { tag_number: 100000 }),
            test_input
        ));
        assert_eq!(buffer.as_slice(), test_output);

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 2-octet tag 1, Unsigned Integer, 1-octet value 42, 65521::57069:1 = 42U
        let test_output = &[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric_with_tag(
            TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::SixOctets {
                vendor_id: 65521,
                profile_number: 57069,
                tag_number: 1
            }),
            test_input
        ));
        assert_eq!(buffer.as_slice(), test_output);

        // Fully qualified tag, Vendor ID 0xFFF1/65521, profile number 0xDEED/57069,
        // 4-octet tag 0xAA55FEED/2857762541,
        // Unsigned Integer, 1-octet value 42, 65521::57069:2857762541 = 42U
        let test_output = &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a];
        let test_input: u8 = 42;
        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric_with_tag(
            TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::EightOctets {
                vendor_id: 65521,
                profile_number: 57069,
                tag_number: 2857762541
            }),
            test_input
        ));
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u8() {
        let test_output = &[0x04, 0xFF]; // Unsigned Integer, 1-octet, value 255
        let test_input: u8 = 255;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u16() {
        let test_output = &[0x05, 0xFF, 0xFF]; // Unsigned Integer, 2-octet, value 65535
        let test_input: u16 = 65535;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u32() {
        // Unsigned Integer, 4-octet, value 237998115
        let test_output = &[0x06, 0x23, 0x90, 0x2f, 0x0E];
        let test_input: u32 = 237998115;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_u64() {
        // Unsigned Integer, 8-octet, value 40000000000
        let test_output = &[0x07, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00];
        let test_input: u64 = 40000000000;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());

        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_f32() {
        // Single precision floating point 17.9
        let test_output = &[0x0a, 0x33, 0x33, 0x8f, 0x41];
        let test_input: f32 = 17.9;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);

        // Single precision floating point infinity (∞)
        let test_output = &[0x0a, 0x00, 0x00, 0x80, 0x7f];
        let test_input = f32::INFINITY;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);
        assert_eq!(buffer.as_slice(), test_output);

        // Single precision floating point negative infinity (-∞)
        let test_output = &[0x0a, 0x00, 0x00, 0x80, 0xff];
        let test_input = f32::NEG_INFINITY;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);
    }

    #[test]
    fn test_write_f64() {
        // Double precision floating point 17.9
        let test_output = &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40];
        let test_input: f64 = 17.9;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);

        // Double precision floating point infinity (∞)
        let test_output = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f];
        let test_input: f64 = f64::INFINITY;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);
        assert_eq!(buffer.as_slice(), test_output);

        // Double precision floating point negative infinity (-∞)
        let test_output = &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff];
        let test_input: f64 = f64::NEG_INFINITY;

        let mut buffer = Vec::new();
        let mut tlv_writer = TLVWriter::new(buffer.as_mut());
        assert!(tlv_writer.write_numeric(test_input));
        assert_eq!(buffer.as_slice(), test_output);
    }
}
