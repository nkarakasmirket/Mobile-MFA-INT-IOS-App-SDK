import Foundation
import Security

/// The Keychain-based (default) implementation of `SecretStore`.
///
/// Because the secret is a sensitive cryptographic secret, it is stored encrypted in the Keychain
/// (`kSecClassGenericPassword`) rather than in UserDefaults. Compatible with iOS 11+.
struct KeychainSecretStore: SecretStore {

    /// The Keychain `kSecAttrService` value — all SDK records are grouped under this service.
    private let service: String

    init(service: String = "com.mirket.authsdk") {
        self.service = service
    }

    func save(_ secret: StoredSecret, apiKey: String, userName: String) throws {
        let data = try JSONEncoder().encode(secret)
        let account = accountKey(apiKey: apiKey, userName: userName)

        // First delete the existing record (if any), then add — so the update is idempotent.
        let deleteQuery = baseQuery(account: account)
        SecItemDelete(deleteQuery as CFDictionary)

        var addQuery = baseQuery(account: account)
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw MirketAuthError.keychain(status)
        }
    }

    func load(apiKey: String, userName: String) -> StoredSecret? {
        let account = accountKey(apiKey: apiKey, userName: userName)
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return try? JSONDecoder().decode(StoredSecret.self, from: data)
    }

    func delete(apiKey: String, userName: String) throws {
        let account = accountKey(apiKey: apiKey, userName: userName)
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        // Do not treat it as an error if the record does not exist.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw MirketAuthError.keychain(status)
        }
    }

    // MARK: - Helpers

    private func baseQuery(account: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}
