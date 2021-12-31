use crate::errors::TLVError;
use crate::util;
use num::FromPrimitive;

#[derive(Debug, num_derive::ToPrimitive, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum ElementType {
    Int8 = 0x00,
    Int16 = 0x01,
    Int32 = 0x02,
    Int64 = 0x03,
    UInt8 = 0x04,
    UInt16 = 0x05,
    UInt32 = 0x06,
    UInt64 = 0x07,
    BooleanFalse = 0x08,
    BooleanTrue = 0x09,
    FloatingPointNumber32 = 0x0A,
    FloatingPointNumber64 = 0x0B,
    UTF8String1ByteLength = 0x0C,
    UTF8String2ByteLength = 0x0D,
    UTF8String4ByteLength = 0x0E,
    UTF8String8ByteLength = 0x0F,
    ByteString1ByteLength = 0x10,
    ByteString2ByteLength = 0x11,
    ByteString4ByteLength = 0x12,
    ByteString8ByteLength = 0x13,
    Null = 0x14,
    Structure = 0x15,
    Array = 0x16,
    List = 0x17,
    EndOfContainer = 0x18,
}

impl TryFrom<u8> for ElementType {
    type Error = TLVError;

    fn try_from(element_type: u8) -> Result<Self, Self::Error> {
        let element_type = Self::from_u8(element_type).ok_or(TLVError::InvalidType)?;
        Ok(element_type)
    }
}

#[derive(Debug, PartialEq)]
pub enum SignedInteger {
    Int8,
    Int16,
    Int32,
    Int64,
}

#[derive(PartialEq, Debug)]
pub enum UnsignedInteger {
    UInt8,
    UInt16,
    UInt32,
    UInt64,
}

#[derive(Debug, PartialEq)]
pub enum FloatingPoint {
    FloatingPointNumber32,
    FloatingPointNumber64,
}

#[derive(Debug, PartialEq)]
pub enum PredeterminedLenPrimitive {
    SignedInteger(SignedInteger),
    UnsignedInteger(UnsignedInteger),
    FloatingPointNumber(FloatingPoint),
    Boolean(bool), // Value inferred during Type parsing
    Null,
}

#[derive(Debug, PartialEq)]
pub enum UTF8StrLen {
    OneOctet,
    TwoOctets,
    FourOctets,
    EightOctets,
}

#[derive(Debug, PartialEq)]
pub enum ByteStrLen {
    OneOctet,
    TwoOctets,
    FourOctets,
    EightOctets,
}

#[derive(Debug, PartialEq)]
pub enum SpecifiedLenPrimitive {
    UTF8String(UTF8StrLen),
    ByteString(ByteStrLen),
}

#[derive(Debug, PartialEq)]
pub enum PrimitiveLengthType {
    Predetermined(PredeterminedLenPrimitive),
    Specified(SpecifiedLenPrimitive),
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum ContainerType {
    Structure = 0x15,
    Array = 0x16,
    List = 0x17,
}

#[derive(Debug, PartialEq)]
pub enum TLVType {
    Primitive(PrimitiveLengthType),
    Container(ContainerType),
}

impl TryFrom<ElementType> for TLVType {
    type Error = TLVError;

    fn try_from(element_type: ElementType) -> Result<Self, Self::Error> {
        Ok(match element_type {
            ElementType::Int8 => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::SignedInteger(SignedInteger::Int8),
            )),
            ElementType::Int16 => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::SignedInteger(SignedInteger::Int16),
            )),
            ElementType::Int32 => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::SignedInteger(SignedInteger::Int32),
            )),
            ElementType::Int64 => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::SignedInteger(SignedInteger::Int64),
            )),

            ElementType::UInt8 => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::UnsignedInteger(UnsignedInteger::UInt8),
            )),
            ElementType::UInt16 => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::UnsignedInteger(UnsignedInteger::UInt16),
            )),
            ElementType::UInt32 => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::UnsignedInteger(UnsignedInteger::UInt32),
            )),
            ElementType::UInt64 => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::UnsignedInteger(UnsignedInteger::UInt64),
            )),

            ElementType::BooleanFalse => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::Boolean(false),
            )),
            ElementType::BooleanTrue => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::Boolean(true),
            )),

            ElementType::FloatingPointNumber32 => TLVType::Primitive(
                PrimitiveLengthType::Predetermined(PredeterminedLenPrimitive::FloatingPointNumber(
                    FloatingPoint::FloatingPointNumber32,
                )),
            ),
            ElementType::FloatingPointNumber64 => TLVType::Primitive(
                PrimitiveLengthType::Predetermined(PredeterminedLenPrimitive::FloatingPointNumber(
                    FloatingPoint::FloatingPointNumber64,
                )),
            ),

            ElementType::UTF8String1ByteLength => {
                TLVType::Primitive(PrimitiveLengthType::Specified(
                    SpecifiedLenPrimitive::UTF8String(UTF8StrLen::OneOctet),
                ))
            }
            ElementType::UTF8String2ByteLength => {
                TLVType::Primitive(PrimitiveLengthType::Specified(
                    SpecifiedLenPrimitive::UTF8String(UTF8StrLen::TwoOctets),
                ))
            }
            ElementType::UTF8String4ByteLength => {
                TLVType::Primitive(PrimitiveLengthType::Specified(
                    SpecifiedLenPrimitive::UTF8String(UTF8StrLen::FourOctets),
                ))
            }
            ElementType::UTF8String8ByteLength => {
                TLVType::Primitive(PrimitiveLengthType::Specified(
                    SpecifiedLenPrimitive::UTF8String(UTF8StrLen::EightOctets),
                ))
            }

            ElementType::ByteString1ByteLength => {
                TLVType::Primitive(PrimitiveLengthType::Specified(
                    SpecifiedLenPrimitive::ByteString(ByteStrLen::OneOctet),
                ))
            }
            ElementType::ByteString2ByteLength => {
                TLVType::Primitive(PrimitiveLengthType::Specified(
                    SpecifiedLenPrimitive::ByteString(ByteStrLen::TwoOctets),
                ))
            }
            ElementType::ByteString4ByteLength => {
                TLVType::Primitive(PrimitiveLengthType::Specified(
                    SpecifiedLenPrimitive::ByteString(ByteStrLen::FourOctets),
                ))
            }
            ElementType::ByteString8ByteLength => {
                TLVType::Primitive(PrimitiveLengthType::Specified(
                    SpecifiedLenPrimitive::ByteString(ByteStrLen::EightOctets),
                ))
            }

            ElementType::Null => TLVType::Primitive(PrimitiveLengthType::Predetermined(
                PredeterminedLenPrimitive::Null,
            )),
            ElementType::Structure => TLVType::Container(ContainerType::Structure),
            ElementType::Array => TLVType::Container(ContainerType::Array),
            ElementType::List => TLVType::Container(ContainerType::List),
            _ => return Err(TLVError::InvalidType),
        })
    }
}

impl PredeterminedLenPrimitive {
    pub(crate) fn value_octets_count(&self) -> usize {
        match self {
            PredeterminedLenPrimitive::SignedInteger(signed_int) => match signed_int {
                SignedInteger::Int8 => 1,
                SignedInteger::Int16 => 2,
                SignedInteger::Int32 => 4,
                SignedInteger::Int64 => 8,
            },
            PredeterminedLenPrimitive::UnsignedInteger(unsigned_int) => match unsigned_int {
                UnsignedInteger::UInt8 => 1,
                UnsignedInteger::UInt16 => 2,
                UnsignedInteger::UInt32 => 4,
                UnsignedInteger::UInt64 => 8,
            },
            PredeterminedLenPrimitive::Boolean(_) => 0,
            PredeterminedLenPrimitive::FloatingPointNumber(floating_point) => {
                match floating_point {
                    FloatingPoint::FloatingPointNumber32 => 4,
                    FloatingPoint::FloatingPointNumber64 => 8,
                }
            }
            PredeterminedLenPrimitive::Null => 0,
        }
    }
}

impl ByteStrLen {
    pub(crate) fn length_field_size(&self) -> TLVFieldSize {
        match self {
            ByteStrLen::OneOctet => TLVFieldSize::OneOctet,
            ByteStrLen::TwoOctets => TLVFieldSize::TwoOctets,
            ByteStrLen::FourOctets => TLVFieldSize::FourOctets,
            ByteStrLen::EightOctets => TLVFieldSize::EightOctets,
        }
    }
}

impl UTF8StrLen {
    pub(crate) fn length_field_size(&self) -> TLVFieldSize {
        match self {
            UTF8StrLen::OneOctet => TLVFieldSize::OneOctet,
            UTF8StrLen::TwoOctets => TLVFieldSize::TwoOctets,
            UTF8StrLen::FourOctets => TLVFieldSize::FourOctets,
            UTF8StrLen::EightOctets => TLVFieldSize::EightOctets,
        }
    }
}

impl SpecifiedLenPrimitive {
    pub(crate) fn length_field_size(&self) -> TLVFieldSize {
        match self {
            SpecifiedLenPrimitive::UTF8String(utf8_string) => utf8_string.length_field_size(),
            SpecifiedLenPrimitive::ByteString(byte_string) => byte_string.length_field_size(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, num_derive::ToPrimitive, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum TLVFieldSize {
    OneOctet = 0,
    TwoOctets = 1,
    FourOctets = 2,
    EightOctets = 3,
}

impl TLVFieldSize {
    pub fn len_octets_count(&self) -> usize {
        match self {
            TLVFieldSize::OneOctet => 1,
            TLVFieldSize::TwoOctets => 2,
            TLVFieldSize::FourOctets => 4,
            TLVFieldSize::EightOctets => 8,
        }
    }

    pub fn parse_field_size<'a>(&self, bytes: &'a [u8]) -> Result<(&'a [u8], usize), TLVError> {
        let len_octets_count = self.len_octets_count();
        if len_octets_count > bytes.len() {
            return Err(TLVError::UnderRun);
        }
        Ok(match self {
            TLVFieldSize::OneOctet => {
                let (remaining_bytes, u8_value) = util::parse_u8(bytes)?;
                (remaining_bytes, u8_value as usize)
            }
            TLVFieldSize::TwoOctets => {
                let (remaining_bytes, u16_value) = util::parse_u16(bytes)?;
                (remaining_bytes, u16_value as usize)
            }
            TLVFieldSize::FourOctets => {
                let (remaining_bytes, u32_value) = util::parse_u32(bytes)?;
                (remaining_bytes, u32_value as usize)
            }
            TLVFieldSize::EightOctets => {
                let (remaining_bytes, u64_value) = util::parse_u64(bytes)?;
                (remaining_bytes, u64_value as usize)
            }
        })
    }

    pub fn extract_field_sized_bytes<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], TLVError> {
        let (remaining_bytes, value_len) = self.parse_field_size(bytes)?;
        if value_len > remaining_bytes.len() {
            Err(TLVError::UnderRun)
        } else {
            Ok(remaining_bytes[..value_len].as_ref())
        }
    }
}

impl TryFrom<u8> for TLVFieldSize {
    type Error = TLVError;

    fn try_from(field_size: u8) -> Result<Self, Self::Error> {
        let field_size = Self::from_u8(field_size).ok_or(TLVError::InvalidType)?;
        Ok(field_size)
    }
}

pub trait TLVPrimitive {
    type ValueType;
    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>);
}

impl TLVPrimitive for String {
    type ValueType = String;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let val_bytes = value.into_bytes();
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
        (element_type, len_bytes, val_bytes)
    }
}

impl TLVPrimitive for Vec<u8> {
    type ValueType = Vec<u8>;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let val_len = value.len();

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

        (element_type, len_bytes, value)
    }
}

impl TLVPrimitive for bool {
    type ValueType = bool;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = if value {
            ElementType::BooleanTrue
        } else {
            ElementType::BooleanFalse
        };
        (element_type, vec![], vec![])
    }
}

impl TLVPrimitive for u8 {
    type ValueType = u8;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::UInt8;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for u16 {
    type ValueType = u16;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::UInt16;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for u32 {
    type ValueType = u32;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::UInt32;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for u64 {
    type ValueType = u64;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::UInt64;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for i8 {
    type ValueType = i8;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::Int8;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for i16 {
    type ValueType = i16;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::Int16;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for i32 {
    type ValueType = i32;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::Int32;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for i64 {
    type ValueType = i64;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::Int64;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for f32 {
    type ValueType = f32;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::FloatingPointNumber32;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}

impl TLVPrimitive for f64 {
    type ValueType = f64;

    fn parse_value(value: Self::ValueType) -> (ElementType, Vec<u8>, Vec<u8>) {
        let element_type = ElementType::FloatingPointNumber64;
        let val_bytes = value.to_le_bytes().to_vec();
        (element_type, vec![], val_bytes)
    }
}
