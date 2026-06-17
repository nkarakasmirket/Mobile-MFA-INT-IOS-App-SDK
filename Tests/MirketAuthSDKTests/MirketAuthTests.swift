import XCTest
@testable import MirketAuthSDK

final class MirketAuthTests: XCTestCase {

    private let exampleQRCode = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"

    private func makeConfig() -> MirketAuthConfiguration {
        MirketAuthConfiguration(registrationURL: URL(string: "https://example.com/auth")!)
    }

    func testRegisterStoresSecretAndReturnsCode() {
        let session = StubHTTPSession(
            data: try! JSONSerialization.data(withJSONObject: ["qrcode": exampleQRCode])
        )
        let config = makeConfig()
        let store = InMemorySecretStore()
        let sut = MirketAuth(configuration: config,
                             apiClient: AuthAPIClient(configuration: config, session: session),
                             store: store)

        let exp = expectation(description: "register")
        sut.register(apiKey: "API_KEY", userName: "alice") { result in
            switch result {
            case .success(let code):
                XCTAssertEqual(code.count, 6) // default 6 digits
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)

        // Was the secret stored?
        let stored = store.load(apiKey: "API_KEY", userName: "alice")
        XCTAssertEqual(stored?.secret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(stored?.digits, 6)
        XCTAssertEqual(stored?.algorithm, .sha1)
    }

    func testRegisterSendsApiKeyHeaderAndUsernameBody() {
        let session = StubHTTPSession(
            data: try! JSONSerialization.data(withJSONObject: ["qrcode": exampleQRCode])
        )
        let config = makeConfig()
        let sut = MirketAuth(configuration: config,
                             apiClient: AuthAPIClient(configuration: config, session: session),
                             store: InMemorySecretStore())

        let exp = expectation(description: "register")
        sut.register(apiKey: "SECRET_KEY", userName: "alice") { _ in exp.fulfill() }
        wait(for: [exp], timeout: 1)

        let request = session.capture.lastRequest
        XCTAssertEqual(request?.value(forHTTPHeaderField: "mirket-api-key"), "SECRET_KEY")
        let body = try! JSONSerialization.jsonObject(with: request!.httpBody!) as! [String: String]
        XCTAssertEqual(body["username"], "alice")
    }

    func testGetTOTPCodeOfflineAfterRegister() {
        let store = InMemorySecretStore()
        try! store.save(StoredSecret(secret: "JBSWY3DPEHPK3PXP",
                                     digits: 6, period: 30, algorithm: .sha1),
                        apiKey: "API_KEY", userName: "alice")
        let config = makeConfig()
        let sut = MirketAuth(configuration: config,
                             apiClient: AuthAPIClient(configuration: config, session: StubHTTPSession()),
                             store: store)

        let result = sut.getTOTPCode(apiKey: "API_KEY", userName: "alice")
        switch result {
        case .success(let code): XCTAssertEqual(code.count, 6)
        case .failure(let error): XCTFail("Unexpected error: \(error)")
        }
    }

    func testExportSecretReturnsStoredSecret() {
        let store = InMemorySecretStore()
        try! store.save(StoredSecret(secret: "JBSWY3DPEHPK3PXP",
                                     digits: 6, period: 30, algorithm: .sha1),
                        apiKey: "API_KEY", userName: "alice")
        let config = makeConfig()
        let sut = MirketAuth(configuration: config,
                             apiClient: AuthAPIClient(configuration: config, session: StubHTTPSession()),
                             store: store)

        guard case .success(let secret) = sut.exportSecret(apiKey: "API_KEY", userName: "alice") else {
            return XCTFail("expected secret")
        }
        XCTAssertEqual(secret, "JBSWY3DPEHPK3PXP")
    }

    func testExportOTPAuthURIIsParseableRoundTrip() throws {
        let store = InMemorySecretStore()
        try! store.save(StoredSecret(secret: "JBSWY3DPEHPK3PXP",
                                     digits: 6, period: 30, algorithm: .sha1),
                        apiKey: "API_KEY", userName: "alice")
        let config = makeConfig()
        let sut = MirketAuth(configuration: config,
                             apiClient: AuthAPIClient(configuration: config, session: StubHTTPSession()),
                             store: store)

        guard case .success(let uri) = sut.exportOTPAuthURI(apiKey: "API_KEY", userName: "alice") else {
            return XCTFail("expected uri")
        }
        XCTAssertTrue(uri.hasPrefix("otpauth://totp/"))
        // The generated URI must be re-parseable and yield the same secret/parameters.
        let params = try OTPAuthURIParser.parse(uri)
        XCTAssertEqual(params.secret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(params.algorithm, .sha1)
        XCTAssertEqual(params.digits, 6)
        XCTAssertEqual(params.period, 30)
    }

    func testExportSecretNotRegistered() {
        let config = makeConfig()
        let sut = MirketAuth(configuration: config,
                             apiClient: AuthAPIClient(configuration: config, session: StubHTTPSession()),
                             store: InMemorySecretStore())
        guard case .failure(.notRegistered) = sut.exportSecret(apiKey: "X", userName: "Y") else {
            return XCTFail("expected notRegistered")
        }
    }

    func testGetTOTPCodeNotRegistered() {
        let config = makeConfig()
        let sut = MirketAuth(configuration: config,
                             apiClient: AuthAPIClient(configuration: config, session: StubHTTPSession()),
                             store: InMemorySecretStore())
        let result = sut.getTOTPCode(apiKey: "X", userName: "Y")
        guard case .failure(.notRegistered) = result else {
            return XCTFail("expected notRegistered, got: \(result)")
        }
    }

    func testRegisterApiErrorPropagates() {
        let session = StubHTTPSession(data: Data(), statusCode: 401)
        let config = makeConfig()
        let sut = MirketAuth(configuration: config,
                             apiClient: AuthAPIClient(configuration: config, session: session),
                             store: InMemorySecretStore())

        let exp = expectation(description: "register")
        sut.register(apiKey: "API_KEY", userName: "alice") { result in
            guard case .failure(.apiError(let statusCode)) = result else {
                return XCTFail("expected apiError, got: \(result)")
            }
            XCTAssertEqual(statusCode, 401)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)
    }
}
