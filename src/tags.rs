use crate::errors::TLVError;
use crate::util;
use num::FromPrimitive;

pub const CONTROL_BYTE_SHIFT: u8 = 5;

#[derive(Debug, num_derive::ToPrimitive, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum TagControl {
    Anonymous = 0x00,
    ContextSpecific = 0x20,
    CommonProfile2Bytes = 0x40,
    CommonProfile4Bytes = 0x60,
    ImplicitProfile2Bytes = 0x80,
    ImplicitProfile4Bytes = 0xA0,
    FullyQualified6Bytes = 0xC0,
    FullyQualified8Bytes = 0xE0,
}

impl TryFrom<u8> for TagControl {
    type Error = TLVError;

    fn try_from(tag_control_byte: u8) -> Result<Self, Self::Error> {
        let tag_control = Self::from_u8(tag_control_byte).ok_or(TLVError::InvalidTag)?;
        Ok(tag_control)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum CommonProfileLength {
    TwoOctets { tag_number: u16 },
    FourOctets { tag_number: u32 },
}

#[derive(Debug, PartialEq, Clone)]
pub enum ImplicitProfileLength {
    TwoOctets { tag_number: u16 },
    FourOctets { tag_number: u32 },
}

#[derive(Debug, PartialEq, Clone)]
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

#[derive(Debug, PartialEq, Clone)]
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

pub fn parse_tag(
    tag_control_byte: u8,
    remaining_bytes: &[u8],
) -> Result<(&[u8], TLVTag), TLVError> {
    let tag_control = TagControl::try_from(tag_control_byte)?;
    let (remaining_bytes, tlv_tag) = match tag_control {
        TagControl::Anonymous => (remaining_bytes, TLVTag::Anonymous),
        TagControl::ContextSpecific => {
            let (remaining_bytes, tag_number) = util::parse_u8(remaining_bytes)?;
            (remaining_bytes, TLVTag::ContextSpecific(tag_number))
        }
        TagControl::CommonProfile2Bytes => {
            let (remaining_bytes, tag_number) = util::parse_u16(remaining_bytes)?;
            (
                remaining_bytes,
                TLVTag::CommonProfile(CommonProfileLength::TwoOctets { tag_number }),
            )
        }
        TagControl::CommonProfile4Bytes => {
            let (remaining_bytes, tag_number) = util::parse_u32(remaining_bytes)?;
            (
                remaining_bytes,
                TLVTag::CommonProfile(CommonProfileLength::FourOctets { tag_number }),
            )
        }
        TagControl::ImplicitProfile2Bytes => {
            let (remaining_bytes, tag_number) = util::parse_u16(remaining_bytes)?;
            (
                remaining_bytes,
                TLVTag::ImplicitProfile(ImplicitProfileLength::TwoOctets { tag_number }),
            )
        }
        TagControl::ImplicitProfile4Bytes => {
            let (remaining_bytes, tag_number) = util::parse_u32(remaining_bytes)?;
            (
                remaining_bytes,
                TLVTag::ImplicitProfile(ImplicitProfileLength::FourOctets { tag_number }),
            )
        }
        TagControl::FullyQualified6Bytes => {
            let (remaining_bytes, vendor_id) = util::parse_u16(remaining_bytes)?;
            let (remaining_bytes, profile_number) = util::parse_u16(remaining_bytes)?;
            let (remaining_bytes, tag_number) = util::parse_u16(remaining_bytes)?;
            (
                remaining_bytes,
                TLVTag::FullyQualifiedProfile(FullyQualifiedProfileLength::SixOctets {
                    vendor_id,
                    profile_number,
                    tag_number,
                }),
            )
        }
        TagControl::FullyQualified8Bytes => {
            let (remaining_bytes, vendor_id) = util::parse_u16(remaining_bytes)?;
            let (remaining_bytes, profile_number) = util::parse_u16(remaining_bytes)?;
            let (remaining_bytes, tag_number) = util::parse_u32(remaining_bytes)?;
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

impl From<TLVTag> for TagControl {
    fn from(tag: TLVTag) -> Self {
        match tag {
            TLVTag::Anonymous => TagControl::Anonymous,
            TLVTag::ContextSpecific(_) => TagControl::ContextSpecific,
            TLVTag::CommonProfile(profile_len) => match profile_len {
                CommonProfileLength::TwoOctets { .. } => TagControl::CommonProfile2Bytes,
                CommonProfileLength::FourOctets { .. } => TagControl::CommonProfile4Bytes,
            },
            TLVTag::ImplicitProfile(profile_len) => match profile_len {
                ImplicitProfileLength::TwoOctets { .. } => TagControl::ImplicitProfile2Bytes,
                ImplicitProfileLength::FourOctets { .. } => TagControl::ImplicitProfile4Bytes,
            },
            TLVTag::FullyQualifiedProfile(profile_len) => match profile_len {
                FullyQualifiedProfileLength::SixOctets { .. } => TagControl::FullyQualified6Bytes,
                FullyQualifiedProfileLength::EightOctets { .. } => TagControl::FullyQualified8Bytes,
            },
        }
    }
}

pub fn tag_bytes(tag: TLVTag) -> Vec<u8> {
    match tag {
        TLVTag::Anonymous => vec![],
        TLVTag::ContextSpecific(tag_number) => tag_number.to_le_bytes().to_vec(),
        TLVTag::CommonProfile(profile_len) => match profile_len {
            CommonProfileLength::TwoOctets { tag_number } => tag_number.to_le_bytes().to_vec(),
            CommonProfileLength::FourOctets { tag_number } => tag_number.to_le_bytes().to_vec(),
        },
        TLVTag::ImplicitProfile(profile_len) => match profile_len {
            ImplicitProfileLength::TwoOctets { tag_number } => tag_number.to_le_bytes().to_vec(),
            ImplicitProfileLength::FourOctets { tag_number } => tag_number.to_le_bytes().to_vec(),
        },
        TLVTag::FullyQualifiedProfile(profile_len) => match profile_len {
            FullyQualifiedProfileLength::SixOctets {
                vendor_id,
                profile_number,
                tag_number,
            } => {
                let mut bytes = vendor_id.to_le_bytes().to_vec();
                bytes.extend_from_slice(&profile_number.to_le_bytes());
                bytes.extend_from_slice(&tag_number.to_le_bytes());
                bytes
            }
            FullyQualifiedProfileLength::EightOctets {
                vendor_id,
                profile_number,
                tag_number,
            } => {
                let mut bytes = vendor_id.to_le_bytes().to_vec();
                bytes.extend_from_slice(&profile_number.to_le_bytes());
                bytes.extend_from_slice(&tag_number.to_le_bytes());
                bytes
            }
        },
    }
}
