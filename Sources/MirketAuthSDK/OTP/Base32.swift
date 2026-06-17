import Foundation

/// RFC 4648 Base32 decoder (for TOTP secrets).
///
/// Uses the standard Base32 alphabet compatible with Google Authenticator. Tolerant of padding
/// ('='), spaces, and upper/lowercase differences.
enum Base32 {

    /// The RFC 4648 standard alphabet.
    private static let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /// Character -> 5-bit value mapping (built once).
    private static let charMap: [Character: UInt8] = {
        var map = [Character: UInt8]()
        for (index, char) in alphabet.enumerated() {
            map[char] = UInt8(index)
        }
        return map
    }()

    /// Decodes the Base32 text into raw `Data`.
    ///
    /// - Returns: The decoded data; `nil` if it contains invalid characters.
    static func decode(_ string: String) -> Data? {
        // Strip padding and spaces, convert to uppercase.
        let normalized = string
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: " ", with: "")
            .uppercased()

        if normalized.isEmpty { return Data() }

        var output = [UInt8]()
        var buffer: UInt32 = 0
        var bitsLeft = 0

        for char in normalized {
            guard let value = charMap[char] else {
                return nil // invalid character
            }
            buffer = (buffer << 5) | UInt32(value)
            bitsLeft += 5
            if bitsLeft >= 8 {
                bitsLeft -= 8
                output.append(UInt8((buffer >> UInt32(bitsLeft)) & 0xff))
            }
        }

        return Data(output)
    }
}
