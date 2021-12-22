use num::{FromPrimitive, ToPrimitive};

#[derive(Debug)]
pub enum TLVError {
    OverRun,
    EndOfTLV,
    InvalidType,
    InvalidLen,
    ParseError,
}

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

impl TLVElementType {
    pub fn as_u8(&self) -> u8 {
        ToPrimitive::to_u8(self).expect("TLVElementType failed to convert to primitive")
    }
}

impl TryFrom<u8> for TLVElementType {
    type Error = TLVError;

    fn try_from(element_type: u8) -> Result<Self, Self::Error> {
        let element_type = Self::from_u8(element_type).ok_or(TLVError::InvalidType)?;
        Ok(element_type)
    }
}

#[derive(PartialEq)]
#[repr(u8)]
pub enum TLVSignedInteger {
    Int8 = 0x00,
    Int16 = 0x01,
    Int32 = 0x02,
    Int64 = 0x03,
}

#[derive(PartialEq, Debug)]
#[repr(u8)]
pub enum TLVUnsignedInteger {
    UInt8 = 0x04,
    UInt16 = 0x05,
    UInt32 = 0x06,
    UInt64 = 0x07,
}

#[derive(PartialEq)]
#[repr(u8)]
pub enum TLVBoolean {
    BooleanFalse = 0x08,
    BooleanTrue = 0x09,
}

#[derive(PartialEq)]
#[repr(u8)]
pub enum TLVFloatingPoint {
    FloatingPointNumber32 = 0x0A,
    FloatingPointNumber64 = 0x0B,
}

#[derive(PartialEq)]
#[repr(u8)]
pub enum TLVNull {
    Null = 0x14,
}

#[derive(PartialEq)]
pub enum TLVPredeterminedLengthType {
    SignedInteger(TLVSignedInteger),
    UnsignedInteger(TLVUnsignedInteger),
    Boolean(TLVBoolean),
    FloatingPointNumber(TLVFloatingPoint),
    Null(TLVNull), // [E0658]: custom discriminant values are not allowed in enums with tuple or struct variants
}

#[derive(PartialEq)]
#[repr(u8)]
pub enum TLVUTF8StrLenBytes {
    UTF8String1ByteLength = 0x0C,
    UTF8String2ByteLength = 0x0D,
    UTF8String4ByteLength = 0x0E,
    UTF8String8ByteLength = 0x0F,
}

#[derive(PartialEq)]
#[repr(u8)]
pub enum TLVByteStrLenBytes {
    ByteString1ByteLength = 0x10,
    ByteString2ByteLength = 0x11,
    ByteString4ByteLength = 0x12,
    ByteString8ByteLength = 0x13,
}

#[derive(PartialEq)]
pub enum TLVSpecifiedLengthType {
    UTF8String(TLVUTF8StrLenBytes),
    ByteString(TLVByteStrLenBytes),
}

#[derive(PartialEq)]
pub enum TLVPrimitiveLengthType {
    Predetermined(TLVPredeterminedLengthType),
    Specified(TLVSpecifiedLengthType),
}

#[derive(PartialEq)]
#[repr(u8)]
pub enum TLVContainerType {
    Structure = 0x15,
    Array = 0x16,
    List = 0x17,
}

#[derive(PartialEq)]
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

            TLVElementType::BooleanFalse => {
                TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                    TLVPredeterminedLengthType::Boolean(TLVBoolean::BooleanFalse),
                ))
            }
            TLVElementType::BooleanTrue => {
                TLVType::Primitive(TLVPrimitiveLengthType::Predetermined(
                    TLVPredeterminedLengthType::Boolean(TLVBoolean::BooleanTrue),
                ))
            }

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
                TLVPredeterminedLengthType::Null(TLVNull::Null),
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
            TLVPredeterminedLengthType::Null(_) => 0,
        }
    }
}

impl TLVSpecifiedLengthType {
    pub(crate) fn length_octets_count(&self) -> usize {
        match self {
            TLVSpecifiedLengthType::UTF8String(len_bytes) => match len_bytes {
                TLVUTF8StrLenBytes::UTF8String1ByteLength => 1,
                TLVUTF8StrLenBytes::UTF8String2ByteLength => 2,
                TLVUTF8StrLenBytes::UTF8String4ByteLength => 4,
                TLVUTF8StrLenBytes::UTF8String8ByteLength => 8,
            },
            TLVSpecifiedLengthType::ByteString(len_bytes) => match len_bytes {
                TLVByteStrLenBytes::ByteString1ByteLength => 1,
                TLVByteStrLenBytes::ByteString2ByteLength => 2,
                TLVByteStrLenBytes::ByteString4ByteLength => 4,
                TLVByteStrLenBytes::ByteString8ByteLength => 8,
            },
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum TLVFieldSize {
    OneByte = 0,
    TwoByte = 1,
    FourByte = 2,
    EightByte = 3,
}
