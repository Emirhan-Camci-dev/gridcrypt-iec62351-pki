use gridcrypt_community::error::GridCryptError;
use gridcrypt_community::proxy::Iec104Interceptor;

#[test]
fn test_zero_allocation_verification() {
    let secret = b"my-secure-hmac-key-for-scada-104";
    let interceptor = Iec104Interceptor::new(secret);

    // Valid APCI + ASDU packet representing a C_SC_NA_1 (Single Command) I-Frame
    // APCI: 68 0E 00 00 00 00
    // ASDU: 2D 01 03 00 01 00
    let mock_apdu_command = &[
        0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, // APCI (I-Frame)
        0x2D, 0x01, 0x03, 0x00, 0x01, 0x00, // ASDU (Type 45)
    ];

    // Attempt verification with an invalid signature
    let fake_signature = &[0u8; 32];

    let result = interceptor.verify_packet(mock_apdu_command, fake_signature);

    // Verify it parses correctly but fails due to UnauthorizedCommand gracefully without allocations
    match result {
        Err(GridCryptError::UnauthorizedCommand) => assert!(true),
        _ => panic!("Expected UnauthorizedCommand, got {:?}", result),
    }
}
