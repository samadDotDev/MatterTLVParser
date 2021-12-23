use crate::errors::TLVError;
use num::FromPrimitive;

#[derive(Debug, num_derive::ToPrimitive, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum TLVElementType {
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

impl TryFrom<u8> for TLVElementType {
    type Error = TLVError;

    fn try_from(element_type: u8) -> Result<Self, Self::Error> {
        let element_type = Self::from_u8(element_type).ok_or(TLVError::InvalidType)?;
        Ok(element_type)
    }
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum TLVSignedInteger {
    Int8,
    Int16,
    Int32,
    Int64,
}

#[derive(PartialEq, Debug)]
#[repr(u8)]
pub enum TLVUnsignedInteger {
    UInt8,
    UInt16,
    UInt32,
    UInt64,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum TLVFloatingPoint {
    FloatingPointNumber32,
    FloatingPointNumber64,
}

#[derive(Debug, PartialEq)]
pub enum TLVPredeterminedLengthType {
    SignedInteger(TLVSignedInteger),
    UnsignedInteger(TLVUnsignedInteger),
    FloatingPointNumber(TLVFloatingPoint),
    Boolean(bool), // Value inferred during Type parsing
    Null,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum TLVUTF8StrLenBytes {
    UTF8String1ByteLength,
    UTF8String2ByteLength,
    UTF8String4ByteLength,
    UTF8String8ByteLength,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum TLVByteStrLenBytes {
    ByteString1ByteLength,
    ByteString2ByteLength,
    ByteString4ByteLength,
    ByteString8ByteLength,
}

#[derive(Debug, PartialEq)]
pub enum TLVSpecifiedLengthType {
    UTF8String(TLVUTF8StrLenBytes),
    ByteString(TLVByteStrLenBytes),
}

#[derive(Debug, PartialEq)]
pub enum TLVPrimitiveLengthType {
    Predetermined(TLVPredeterminedLengthType),
    Specified(TLVSpecifiedLengthType),
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum TLVContainerType {
    Structure = 0x15,
    Array = 0x16,
    List = 0x17,
}

#[derive(Debug, PartialEq)]
pub enum TLVType {
    Primitive(TLVPrimitiveLengthType),
    Container(TLVContainerType),
}

impl TryFrom<TLVElementType> for TLVType {
    type Error = TLVError;

    fn try_from(element_type: TLVElementType) -> Result<Self, Self::Error> {
        Ok(match element_type {
            TLVElementType::Int8 => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::SignedInteger(TLVSignedInteger::Int8),
            )),
            TLVElementType::Int16 => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::SignedInteger(TLVSignedInteger::Int16),
            )),
            TLVElementType::Int32 => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::SignedInteger(TLVSignedInteger::Int32),
            )),
            TLVElementType::Int64 => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::SignedInteger(TLVSignedInteger::Int64),
            )),

            TLVElementType::UInt8 => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::UnsignedInteger(TLVUnsignedInteger::UInt8),
            )),
            TLVElementType::UInt16 => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::UnsignedInteger(TLVUnsignedInteger::UInt16),
            )),
            TLVElementType::UInt32 => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::UnsignedInteger(TLVUnsignedInteger::UInt32),
            )),
            TLVElementType::UInt64 => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::UnsignedInteger(TLVUnsignedInteger::UInt64),
            )),

            TLVElementType::BooleanFalse => TLVType::Primitive(
                TLVPrimitiveLengthType::Predetermined(TLVPredeterminedLengthType::Boolean(false)),
            ),
            TLVElementType::BooleanTrue => TLVType::Primitive(
                TLVPrimitiveLengthType::Predetermined(TLVPredeterminedLengthType::Boolean(true)),
            ),

            TLVElementType::FloatingPointNumber32 => {
                TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                    TLVPredeterminedLengthType::FloatingPointNumber(
                        TLVFloatingPoint::FloatingPointNumber32,
                    ),
                ))
            }
            TLVElementType::FloatingPointNumber64 => {
                TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                    TLVPredeterminedLengthType::FloatingPointNumber(
                        TLVFloatingPoint::FloatingPointNumber64,
                    ),
                ))
            }

            TLVElementType::UTF8String1ByteLength => {
                TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                    TLVSpecifiedLengthType::UTF8String(TLVUTF8StrLenBytes::UTF8String1ByteLength),
                ))
            }
            TLVElementType::UTF8String2ByteLength => {
                TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                    TLVSpecifiedLengthType::UTF8String(TLVUTF8StrLenBytes::UTF8String2ByteLength),
                ))
            }
            TLVElementType::UTF8String4ByteLength => {
                TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                    TLVSpecifiedLengthType::UTF8String(TLVUTF8StrLenBytes::UTF8String4ByteLength),
                ))
            }
            TLVElementType::UTF8String8ByteLength => {
                TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                    TLVSpecifiedLengthType::UTF8String(TLVUTF8StrLenBytes::UTF8String8ByteLength),
                ))
            }

            TLVElementType::ByteString1ByteLength => {
                TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                    TLVSpecifiedLengthType::ByteString(TLVByteStrLenBytes::ByteString1ByteLength),
                ))
            }
            TLVElementType::ByteString2ByteLength => {
                TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                    TLVSpecifiedLengthType::ByteString(TLVByteStrLenBytes::ByteString2ByteLength),
                ))
            }
            TLVElementType::ByteString4ByteLength => {
                TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                    TLVSpecifiedLengthType::ByteString(TLVByteStrLenBytes::ByteString4ByteLength),
                ))
            }
            TLVElementType::ByteString8ByteLength => {
                TLVType::Primitive(TLVPrimitiveLengthType::Specified(
                    TLVSpecifiedLengthType::ByteString(TLVByteStrLenBytes::ByteString8ByteLength),
                ))
            }

            TLVElementType::Null => TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                TLVPredeterminedLengthType::Null,
            )),
            TLVElementType::Structure => TLVType::Container(TLVContainerType::Structure),
            TLVElementType::Array => TLVType::Container(TLVContainerType::Array),
            TLVElementType::List => TLVType::Container(TLVContainerType::List),
            _ => return Err(TLVError::InvalidType),
        })
    }
}

impl TLVPredeterminedLengthType {
    pub(crate) fn value_octets_count(&self) -> usize {
        match self {
            TLVPredeterminedLengthType::SignedInteger(signed_int) => match signed_int {
                TLVSignedInteger::Int8 => 1,
                TLVSignedInteger::Int16 => 2,
                TLVSignedInteger::Int32 => 4,
                TLVSignedInteger::Int64 => 8,
            },
            TLVPredeterminedLengthType::UnsignedInteger(unsigned_int) => match unsigned_int {
                TLVUnsignedInteger::UInt8 => 1,
                TLVUnsignedInteger::UInt16 => 2,
                TLVUnsignedInteger::UInt32 => 4,
                TLVUnsignedInteger::UInt64 => 8,
            },
            TLVPredeterminedLengthType::Boolean(_) => 0,
            TLVPredeterminedLengthType::FloatingPointNumber(floating_point) => match floating_point
            {
                TLVFloatingPoint::FloatingPointNumber32 => 4,
                TLVFloatingPoint::FloatingPointNumber64 => 8,
            },
            TLVPredeterminedLengthType::Null => 0,
        }
    }
}

impl TLVByteStrLenBytes {
    pub(crate) fn length_field_size(&self) -> TLVFieldSize {
        match self {
            TLVByteStrLenBytes::ByteString1ByteLength => TLVFieldSize::OneByte,
            TLVByteStrLenBytes::ByteString2ByteLength => TLVFieldSize::TwoBytes,
            TLVByteStrLenBytes::ByteString4ByteLength => TLVFieldSize::FourBytes,
            TLVByteStrLenBytes::ByteString8ByteLength => TLVFieldSize::EightBytes,
        }
    }
}

impl TLVUTF8StrLenBytes {
    pub(crate) fn length_field_size(&self) -> TLVFieldSize {
        match self {
            TLVUTF8StrLenBytes::UTF8String1ByteLength => TLVFieldSize::OneByte,
            TLVUTF8StrLenBytes::UTF8String2ByteLength => TLVFieldSize::TwoBytes,
            TLVUTF8StrLenBytes::UTF8String4ByteLength => TLVFieldSize::FourBytes,
            TLVUTF8StrLenBytes::UTF8String8ByteLength => TLVFieldSize::EightBytes,
        }
    }
}

impl TLVSpecifiedLengthType {
    pub(crate) fn length_field_size(&self) -> TLVFieldSize {
        match self {
            TLVSpecifiedLengthType::UTF8String(utf8_string) => utf8_string.length_field_size(),
            TLVSpecifiedLengthType::ByteString(byte_string) => byte_string.length_field_size(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, num_derive::ToPrimitive, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum TLVFieldSize {
    OneByte = 0,
    TwoBytes = 1,
    FourBytes = 2,
    EightBytes = 3,
}

impl TLVFieldSize {
    pub fn len(&self) -> usize {
        match self {
            TLVFieldSize::OneByte => 1,
            TLVFieldSize::TwoBytes => 2,
            TLVFieldSize::FourBytes => 4,
            TLVFieldSize::EightBytes => 8,
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
