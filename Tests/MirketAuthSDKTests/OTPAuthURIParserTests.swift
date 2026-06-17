import XCTest
@testable import MirketAuthSDK

final class OTPAuthURIParserTests: XCTestCase {

    /// Parses a representative otpauth URI.
    func testParsesRealWorldExample() throws {
        let uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        let params = try OTPAuthURIParser.parse(uri)
        XCTAssertEqual(params.secret, "JBSWY3DPEHPK3PXP")
        // This example specifies no algorithm/digits/period -> nil (defaults are used).
        XCTAssertNil(params.algorithm)
        XCTAssertNil(params.digits)
        XCTAssertNil(params.period)
    }

    func testParsesOptionalParameters() throws {
        let uri = "otpauth://totp/Acme?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60"
        let params = try OTPAuthURIParser.parse(uri)
        XCTAssertEqual(params.secret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(params.algorithm, .sha256)
        XCTAssertEqual(params.digits, 8)
        XCTAssertEqual(params.period, 60)
    }

    func testMissingSecretThrows() {
        let uri = "otpauth://totp/Acme?issuer=Acme"
        XCTAssertThrowsError(try OTPAuthURIParser.parse(uri)) { error in
            XCTAssertEqual(error as? MirketAuthError, MirketAuthError.missingSecret)
        }
    }
}
