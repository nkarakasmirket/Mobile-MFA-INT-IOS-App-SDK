import Foundation

/// The main entry point of MirketAuthSDK.
///
/// It offers two core capabilities:
/// 1. `register(apiKey:userName:completion:)` — Registers with the system, extracts the secret
///    from the returned `otpauth://` QR content, stores it on the device (Keychain), and returns
///    the current TOTP code.
/// 2. `getTOTPCode(apiKey:userName:)` — Generates a TOTP offline using a previously stored secret.
///
/// The async/await version of `register` is only available on iOS 13+ (Swift concurrency does not
/// back-deploy to iOS 11/12). On iOS 11/12 the completion-handler version must be used.
public final class MirketAuth {

    private let configuration: MirketAuthConfiguration
    private let apiClient: AuthAPIClient
    private let store: SecretStore

    /// Initializes the SDK with the given configuration.
    ///
    /// The registration endpoint URL (and, optionally, the TOTP defaults and the api-key header
    /// field name) are supplied here — the SDK does not hardcode any server URL or credentials.
    ///
    /// ```swift
    /// let config = MirketAuthConfiguration(
    ///     registrationURL: URL(string: "https://<your-host>/api/external-mobile-auth")!
    /// )
    /// let auth = MirketAuth(configuration: config)
    /// ```
    public convenience init(configuration: MirketAuthConfiguration) {
        self.init(configuration: configuration,
                  apiClient: AuthAPIClient(configuration: configuration),
                  store: KeychainSecretStore())
    }

    /// Convenience initializer that only takes the registration endpoint URL and uses the default
    /// TOTP parameters (6 digits / 30s / SHA1) and the default `mirket-api-key` header field.
    public convenience init(registrationURL: URL) {
        self.init(configuration: MirketAuthConfiguration(registrationURL: registrationURL))
    }

    /// Initializer with injectable dependencies (for testing).
    init(configuration: MirketAuthConfiguration,
         apiClient: AuthAPIClient,
         store: SecretStore) {
        self.configuration = configuration
        self.apiClient = apiClient
        self.store = store
    }

    // MARK: - Register (iOS 11+ — completion handler)

    /// Registers with the system and returns the current TOTP code.
    ///
    /// Flow: API call → parse `qrcode` → save the secret to the Keychain → generate the TOTP.
    /// Because the secret is stored on the device, subsequent `getTOTPCode` calls work offline.
    ///
    /// - Parameters:
    ///   - apiKey: Sent in the `mirket-api-key` header; part of the registration index.
    ///   - userName: Sent in the JSON body; part of the registration index.
    ///   - completion: There is no main-thread guarantee (URLSession callback thread). On success,
    ///     the generated TOTP code is returned.
    public func register(apiKey: String,
                         userName: String,
                         completion: @escaping (Result<String, MirketAuthError>) -> Void) {
        apiClient.register(apiKey: apiKey, userName: userName) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let qrcode):
                do {
                    let params = try OTPAuthURIParser.parse(qrcode)
                    let stored = StoredSecret(
                        secret: params.secret,
                        digits: params.digits ?? self.configuration.defaultDigits,
                        period: params.period ?? self.configuration.defaultPeriod,
                        algorithm: params.algorithm ?? self.configuration.defaultAlgorithm
                    )
                    try self.store.save(stored, apiKey: apiKey, userName: userName)

                    let code = try TOTPGenerator.generate(
                        base32Secret: stored.secret,
                        digits: stored.digits,
                        period: stored.period,
                        algorithm: stored.algorithm
                    )
                    completion(.success(code))
                } catch let error as MirketAuthError {
                    completion(.failure(error))
                } catch {
                    completion(.failure(.totpGenerationFailed))
                }
            }
        }
    }

    // MARK: - Register (iOS 13+ — async/await)

    /// The async/await version of `register`. iOS 13+ only.
    @available(iOS 13.0, macOS 10.15, *)
    public func register(apiKey: String, userName: String) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            register(apiKey: apiKey, userName: userName) { result in
                continuation.resume(with: result)
            }
        }
    }

    // MARK: - getTOTPCode (offline)

    /// Generates the current TOTP code using a previously stored secret. Works entirely offline.
    ///
    /// - Returns: The TOTP code on success; `.notRegistered` if there is no registration.
    public func getTOTPCode(apiKey: String, userName: String) -> Result<String, MirketAuthError> {
        guard let stored = store.load(apiKey: apiKey, userName: userName) else {
            return .failure(.notRegistered)
        }
        do {
            let code = try TOTPGenerator.generate(
                base32Secret: stored.secret,
                digits: stored.digits,
                period: stored.period,
                algorithm: stored.algorithm
            )
            return .success(code)
        } catch let error as MirketAuthError {
            return .failure(error)
        } catch {
            return .failure(.totpGenerationFailed)
        }
    }

    // MARK: - Export (verification / exporting)

    /// Returns the stored raw Base32 secret.
    ///
    /// For example, it can be used to add the same account to Google Authenticator via "manual key
    /// entry" and verify by comparing the codes.
    ///
    /// - Returns: The Base32 secret; `.notRegistered` if there is no registration.
    public func exportSecret(apiKey: String, userName: String) -> Result<String, MirketAuthError> {
        guard let stored = store.load(apiKey: apiKey, userName: userName) else {
            return .failure(.notRegistered)
        }
        return .success(stored.secret)
    }

    /// Generates a standard `otpauth://totp/...` URI from the stored registration.
    ///
    /// This URI can be turned into a QR code, or copied directly, and imported into apps such as
    /// Google Authenticator. The stored TOTP parameters (digits/period/algorithm) are included in
    /// the URI.
    ///
    /// - Parameter issuer: The name used in the label/issuer field (default "Mirket").
    /// - Returns: The `otpauth://` URI text; `.notRegistered` if there is no registration.
    public func exportOTPAuthURI(apiKey: String,
                                 userName: String,
                                 issuer: String = "Mirket") -> Result<String, MirketAuthError> {
        guard let stored = store.load(apiKey: apiKey, userName: userName) else {
            return .failure(.notRegistered)
        }
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = "totp"
        components.path = "/\(issuer):\(userName)"
        components.queryItems = [
            URLQueryItem(name: "secret", value: stored.secret),
            URLQueryItem(name: "issuer", value: issuer),
            URLQueryItem(name: "algorithm", value: stored.algorithm.rawValue),
            URLQueryItem(name: "digits", value: String(stored.digits)),
            URLQueryItem(name: "period", value: String(Int(stored.period)))
        ]
        guard let uri = components.url?.absoluteString else {
            return .failure(.invalidResponse)
        }
        return .success(uri)
    }

    /// Deletes the corresponding registration from the device.
    @discardableResult
    public func removeRegistration(apiKey: String, userName: String) -> Result<Void, MirketAuthError> {
        do {
            try store.delete(apiKey: apiKey, userName: userName)
            return .success(())
        } catch let error as MirketAuthError {
            return .failure(error)
        } catch {
            return .failure(.keychain(errSecParam))
        }
    }
}
