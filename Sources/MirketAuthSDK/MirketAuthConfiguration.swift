import Foundation

/// MirketAuthSDK configuration.
///
/// The default values are RFC 6238 compliant (Google Authenticator compatible): 6 digits / 30 sec / SHA1.
/// If the `otpauth://` URI carries these parameters, they take precedence; otherwise the defaults
/// defined here are used.
public struct MirketAuthConfiguration {

    /// The endpoint to which the registration request will be sent.
    public var registrationURL: URL

    /// The name of the HTTP header in which the apiKey will be sent.
    public var apiKeyHeaderField: String

    /// The default number of TOTP digits.
    public var defaultDigits: Int

    /// The default TOTP period (seconds).
    public var defaultPeriod: TimeInterval

    /// The default TOTP algorithm.
    public var defaultAlgorithm: TOTPAlgorithm

    public init(registrationURL: URL,
                apiKeyHeaderField: String = "mirket-api-key",
                defaultDigits: Int = 6,
                defaultPeriod: TimeInterval = 30,
                defaultAlgorithm: TOTPAlgorithm = .sha1) {
        self.registrationURL = registrationURL
        self.apiKeyHeaderField = apiKeyHeaderField
        self.defaultDigits = defaultDigits
        self.defaultPeriod = defaultPeriod
        self.defaultAlgorithm = defaultAlgorithm
    }
}
