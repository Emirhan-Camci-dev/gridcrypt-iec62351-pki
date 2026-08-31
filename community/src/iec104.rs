use nom::{
    number::complete::{le_u16, u8},
    IResult,
};

#[derive(Debug, PartialEq)]
pub enum FrameType {
    IFrame, // Information transfer
    SFrame, // Supervisory functions
    UFrame, // Unnumbered control functions
}

#[derive(Debug)]
pub struct ApciHeader {
    pub start_byte: u8,
    pub length: u8,
    pub frame_type: FrameType,
}

#[derive(Debug)]
pub struct AsduHeader {
    pub type_id: u8,
    pub sq_num: u8,
    pub cause_of_transmission: u16,
    pub common_address: u16,
}

/// Parses the APCI (Application Protocol Control Information) header
pub fn parse_apci(input: &[u8]) -> IResult<&[u8], ApciHeader> {
    let (input, start_byte) = u8(input)?;
    let (input, length) = u8(input)?;
    let (input, ctrl1) = u8(input)?;
    let (input, _ctrl2) = u8(input)?;
    let (input, _ctrl3) = u8(input)?;
    let (input, _ctrl4) = u8(input)?;

    let frame_type = if (ctrl1 & 0x01) == 0 {
        FrameType::IFrame
    } else if (ctrl1 & 0x03) == 1 {
        FrameType::SFrame
    } else {
        FrameType::UFrame
    };

    Ok((
        input,
        ApciHeader {
            start_byte,
            length,
            frame_type,
        },
    ))
}

/// Parses the ASDU (Application Service Data Unit) header
pub fn parse_asdu(input: &[u8]) -> IResult<&[u8], AsduHeader> {
    let (input, type_id) = u8(input)?;
    let (input, sq_num) = u8(input)?;
    let (input, cause_of_transmission) = le_u16(input)?;
    let (input, common_address) = le_u16(input)?;

    Ok((
        input,
        AsduHeader {
            type_id,
            sq_num,
            cause_of_transmission,
            common_address,
        },
    ))
}

/// Checks if the ASDU is a critical control command that requires cryptographic signing
/// Type 45: C_SC_NA_1 (Single command)
/// Type 46: C_DC_NA_1 (Double command - Breaker Open/Close)
/// Type 58: C_SC_TA_1 (Single command with time tag)
/// Type 59: C_DC_TA_1 (Double command with time tag)
pub fn is_critical_command(type_id: u8) -> bool {
    matches!(type_id, 45 | 46 | 58 | 59)
}
