import Foundation

/// The public error type used throughout MirketAuthSDK.
public enum MirketAuthError: Error {
    /// An error occurring at the network layer (URLSession transport error, etc.).
    case network(Error)
    /// The HTTP response is not in the expected form (not an HTTPURLResponse, body unreadable, etc.).
    case invalidResponse
    /// The server returned an HTTP status code other than 2xx.
    case apiError(statusCode: Int)
    /// The response has no `qrcode` field or it could not be resolved.
    case missingQRCode
    /// The `secret` parameter was not found in the `otpauth://` URI.
    case missingSecret
    /// The Base32 secret could not be decoded.
    case invalidBase32
    /// An error occurred during TOTP generation.
    case totpGenerationFailed
    /// No stored secret was found for the given apiKey + userName (`register` must be called first).
    case notRegistered
    /// The Keychain operation failed (with the OSStatus code).
    case keychain(OSStatus)
}

extension MirketAuthError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .network(let error):
            return "Network error: \(error.localizedDescription)"
        case .invalidResponse:
            return "An invalid response was received from the server."
        case .apiError(let statusCode):
            return "Server error (HTTP \(statusCode))."
        case .missingQRCode:
            return "No qrcode information was found in the response."
        case .missingSecret:
            return "The secret parameter was not found in the otpauth URI."
        case .invalidBase32:
            return "The secret could not be decoded as Base32."
        case .totpGenerationFailed:
            return "The TOTP code could not be generated."
        case .notRegistered:
            return "No registration was found for this apiKey/userName. register must be called first."
        case .keychain(let status):
            return "Keychain error (OSStatus \(status))."
        }
    }
}
