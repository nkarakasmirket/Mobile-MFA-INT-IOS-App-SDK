import Foundation

/// The TOTP parameters resolved from an `otpauth://totp/...` URI.
struct OTPAuthParameters {
    /// The Base32-encoded secret (required).
    let secret: String
    /// The algorithm if specified in the URI, otherwise `nil`.
    let algorithm: TOTPAlgorithm?
    /// The number of digits if specified in the URI, otherwise `nil`.
    let digits: Int?
    /// The period (seconds) if specified in the URI, otherwise `nil`.
    let period: TimeInterval?
}

/// The `otpauth://` URI parser.
///
/// Example shape:
/// `otpauth://totp/<label>?secret=<BASE32>&issuer=<issuer>`
enum OTPAuthURIParser {

    /// Parses the URI and returns the TOTP parameters.
    ///
    /// - Throws: `MirketAuthError.missingSecret` if `secret` is not found.
    static func parse(_ uri: String) throws -> OTPAuthParameters {
        guard let components = URLComponents(string: uri),
              let queryItems = components.queryItems else {
            throw MirketAuthError.missingSecret
        }

        func value(for name: String) -> String? {
            // otpauth parameters may be case-insensitive.
            queryItems.first { $0.name.lowercased() == name.lowercased() }?.value
        }

        guard let secret = value(for: "secret"), !secret.isEmpty else {
            throw MirketAuthError.missingSecret
        }

        let algorithm = value(for: "algorithm").flatMap { TOTPAlgorithm(uriValue: $0) }
        let digits = value(for: "digits").flatMap { Int($0) }
        let period = value(for: "period").flatMap { Double($0) }

        return OTPAuthParameters(secret: secret,
                                 algorithm: algorithm,
                                 digits: digits,
                                 period: period)
    }
}
