import Foundation
import CommonCrypto

/// The HMAC algorithm used in TOTP generation.
///
/// Because CryptoKit requires iOS 13+ (and iOS 11 support is required), HMAC operations are
/// performed with `CommonCrypto`, which is also available on iOS 11.
public enum TOTPAlgorithm: String, Codable, CaseIterable {
    case sha1   = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"

    /// Resolves from the `algorithm` parameter in `otpauth://` URIs (case-insensitive).
    init?(uriValue: String) {
        switch uriValue.uppercased() {
        case "SHA1":   self = .sha1
        case "SHA256": self = .sha256
        case "SHA512": self = .sha512
        default:       return nil
        }
    }

    fileprivate var ccAlgorithm: CCHmacAlgorithm {
        switch self {
        case .sha1:   return CCHmacAlgorithm(kCCHmacAlgSHA1)
        case .sha256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
        case .sha512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
        }
    }

    fileprivate var digestLength: Int {
        switch self {
        case .sha1:   return Int(CC_SHA1_DIGEST_LENGTH)
        case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
        case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
        }
    }
}

/// RFC 6238 (TOTP) / RFC 4226 (HOTP) compliant code generator.
enum TOTPGenerator {

    /// Generates the TOTP code for the specified time.
    ///
    /// - Parameters:
    ///   - base32Secret: The Base32-encoded shared secret.
    ///   - date: The moment for which the code is generated (default: now).
    ///   - digits: The number of digits to generate (usually 6 or 8).
    ///   - period: The time window (seconds, usually 30).
    ///   - algorithm: The HMAC algorithm.
    /// - Returns: A zero-padded code string of length `digits`.
    static func generate(base32Secret: String,
                         date: Date = Date(),
                         digits: Int,
                         period: TimeInterval,
                         algorithm: TOTPAlgorithm) throws -> String {
        guard let key = Base32.decode(base32Secret) else {
            throw MirketAuthError.invalidBase32
        }
        guard period > 0, digits > 0 else {
            throw MirketAuthError.totpGenerationFailed
        }

        let counter = UInt64(floor(date.timeIntervalSince1970 / period))
        return code(key: key, counter: counter, digits: digits, algorithm: algorithm)
    }

    /// RFC 4226 HOTP — the counter-based core.
    private static func code(key: Data,
                             counter: UInt64,
                             digits: Int,
                             algorithm: TOTPAlgorithm) -> String {
        // Convert the counter to 8 big-endian bytes.
        var bigEndianCounter = counter.bigEndian
        let counterData = Data(bytes: &bigEndianCounter, count: MemoryLayout<UInt64>.size)

        // Compute the HMAC.
        var hmac = [UInt8](repeating: 0, count: algorithm.digestLength)
        key.withUnsafeBytes { keyBytes in
            counterData.withUnsafeBytes { msgBytes in
                CCHmac(algorithm.ccAlgorithm,
                       keyBytes.baseAddress, key.count,
                       msgBytes.baseAddress, counterData.count,
                       &hmac)
            }
        }

        // RFC 4226 dynamic truncation.
        let offset = Int(hmac[hmac.count - 1] & 0x0f)
        let binary =
            (UInt32(hmac[offset]     & 0x7f) << 24) |
            (UInt32(hmac[offset + 1] & 0xff) << 16) |
            (UInt32(hmac[offset + 2] & 0xff) << 8)  |
             UInt32(hmac[offset + 3] & 0xff)

        let modulo = UInt32(pow(10, Double(digits)))
        let otp = binary % modulo

        // Zero-padded text.
        return String(format: "%0\(digits)u", otp)
    }
}
