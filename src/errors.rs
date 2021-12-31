#[derive(Debug, PartialEq)]
pub enum TLVError {
    UnderRun,
    EndOfTLV,
    InvalidTag,
    InvalidType,
    ParseError,
    Internal(String),
}
