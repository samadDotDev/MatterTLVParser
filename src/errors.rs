#[derive(Debug, PartialEq)]
pub enum TLVError {
    OverRun,
    EndOfTLV,
    InvalidType,
    InvalidLen,
    ParseError,
}
