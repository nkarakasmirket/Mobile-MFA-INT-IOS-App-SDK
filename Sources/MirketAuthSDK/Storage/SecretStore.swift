import Foundation

/// A TOTP secret record stored on the device.
///
/// So that `getTOTPCode` can work entirely offline, the resolved TOTP parameters are stored
/// together with the secret.
struct StoredSecret: Codable, Equatable {
    /// The Base32-encoded shared secret.
    let secret: String
    let digits: Int
    let period: TimeInterval
    let algorithm: TOTPAlgorithm
}

/// The secret storage abstraction.
///
/// The default implementation is the Keychain (`KeychainSecretStore`). Thanks to this protocol,
/// one can switch to a UserDefaults-based implementation if needed / for testing.
///
/// Records are indexed by the `apiKey` + `userName` pair.
protocol SecretStore {
    func save(_ secret: StoredSecret, apiKey: String, userName: String) throws
    func load(apiKey: String, userName: String) -> StoredSecret?
    func delete(apiKey: String, userName: String) throws
}

extension SecretStore {
    /// Generates a unique, non-colliding account key for apiKey + userName.
    /// The length prefix prevents separator injection (e.g. values containing ':').
    func accountKey(apiKey: String, userName: String) -> String {
        return "\(apiKey.count):\(apiKey):\(userName)"
    }
}
