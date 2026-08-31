#[derive(Debug)]
pub enum GridCryptError {
    InvalidSignature,
    MalformedPacket,
    UnauthorizedCommand,
}
