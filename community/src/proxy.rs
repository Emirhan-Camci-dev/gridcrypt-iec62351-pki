use crate::error::GridCryptError;
use crate::iec104::{is_critical_command, parse_apci, parse_asdu, FrameType};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Zero-allocation IEC 60870-5-104 APDU interceptor
pub struct Iec104Interceptor<'a> {
    secret_key: &'a [u8],
}

impl<'a> Iec104Interceptor<'a> {
    pub fn new(secret_key: &'a [u8]) -> Self {
        Self { secret_key }
    }

    /// Parses the packet and validates SCADA commands with zero dynamic memory allocation
    pub fn verify_packet(&self, payload: &[u8], signature: &[u8]) -> Result<(), GridCryptError> {
        // 1. Parse APCI header (6 bytes)
        let (remaining, apci) = parse_apci(payload).map_err(|_| GridCryptError::MalformedPacket)?;

        // Ensure it's an IEC 104 packet (starts with 0x68)
        if apci.start_byte != 0x68 {
            return Err(GridCryptError::MalformedPacket);
        }

        // We only care about I-Frames containing ASDUs (Information Transfer)
        if apci.frame_type != FrameType::IFrame {
            // S-Frames and U-Frames are control frames, no signature required for these
            return Ok(());
        }

        // 2. Parse ASDU header
        let (_, asdu) = parse_asdu(remaining).map_err(|_| GridCryptError::MalformedPacket)?;

        // 3. Check if this is a critical control command (Breaker Trip/Close)
        if is_critical_command(asdu.type_id) {
            // Cryptographic validation required
            let mut mac = HmacSha256::new_from_slice(self.secret_key)
                .map_err(|_| GridCryptError::InvalidSignature)?;

            // We hash the entire payload to prevent manipulation of the APCI or ASDU
            mac.update(payload);

            // Sub-100µs deterministic verification (software level)
            mac.verify_slice(signature)
                .map_err(|_| GridCryptError::UnauthorizedCommand)?;
        }

        Ok(())
    }
}
