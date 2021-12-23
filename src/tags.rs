use crate::errors::TLVError;
use num::FromPrimitive;

#[derive(Debug, num_derive::ToPrimitive, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum TLVTagControl {
    Anonymous = 0x00,
    ContextSpecific = 0x20,
    CommonProfile2Bytes = 0x40,
    CommonProfile4Bytes = 0x60,
    ImplicitProfile2Bytes = 0x80,
    ImplicitProfile4Bytes = 0xA0,
    FullyQualified6Bytes = 0xC0,
    FullyQualified8Bytes = 0xE0,
}

impl TryFrom<u8> for TLVTagControl {
    type Error = TLVError;

    fn try_from(tag_control_byte: u8) -> Result<Self, Self::Error> {
        let tag_control = Self::from_u8(tag_control_byte).ok_or(TLVError::InvalidTag)?;
        Ok(tag_control)
    }
}

#[derive(Debug, PartialEq)]
pub enum CommonProfileLength {
    TwoOctets { tag_number: u16 },
    FourOctets { tag_number: u32 },
}

#[derive(Debug, PartialEq)]
pub enum ImplicitProfileLength {
    TwoOctets { tag_number: u16 },
    FourOctets { tag_number: u32 },
}

#[derive(Debug, PartialEq)]
pub enum FullyQualifiedProfileLength {
    SixOctets {
        vendor_id: u16,
        profile_number: u16,
        tag_number: u16,
    },
    EightOctets {
        vendor_id: u16,
        profile_number: u16,
        tag_number: u32,
    },
}

#[derive(Debug, PartialEq)]
pub enum TLVTag {
    Anonymous,
    ContextSpecific(u8),
    CommonProfile(CommonProfileLength),
    ImplicitProfile(ImplicitProfileLength),
    FullyQualifiedProfile(FullyQualifiedProfileLength),
}

impl TLVTag {
    pub fn octets_count(&self) -> u8 {
        match self {
            TLVTag::Anonymous => 0,
            TLVTag::ContextSpecific(_) => 1,
            TLVTag::CommonProfile(profile) => match profile {
                CommonProfileLength::TwoOctets { tag_number: _ } => 2,
                CommonProfileLength::FourOctets { tag_number: _ } => 4,
            },
            TLVTag::ImplicitProfile(profile) => match profile {
                ImplicitProfileLength::TwoOctets { tag_number: _ } => 2,
                ImplicitProfileLength::FourOctets { tag_number: _ } => 4,
            },
            TLVTag::FullyQualifiedProfile(profile) => match profile {
                FullyQualifiedProfileLength::SixOctets {
                    vendor_id: _,
                    profile_number: _,
                    tag_number: _,
                } => 6,
                FullyQualifiedProfileLength::EightOctets {
                    vendor_id: _,
                    profile_number: _,
                    tag_number: _,
                } => 8,
            },
        }
    }
}
