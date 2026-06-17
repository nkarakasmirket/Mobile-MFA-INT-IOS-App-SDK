import XCTest
@testable import MirketAuthSDK

final class TOTPGeneratorTests: XCTestCase {

    // RFC 6238 Appendix B: SHA1 seed = ASCII "12345678901234567890" (20 bytes).
    // Base32 equivalent:
    private let sha1Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    /// RFC 6238 Appendix B test vectors (SHA1, 8 digits, 30s).
    func testRFC6238SHA1Vectors() throws {
        let vectors: [(time: TimeInterval, code: String)] = [
            (59,          "94287082"),
            (1111111109,  "07081804"),
            (1111111111,  "14050471"),
            (1234567890,  "89005924"),
            (2000000000,  "69279037"),
            (20000000000, "65353130")
        ]
        for vector in vectors {
            let code = try TOTPGenerator.generate(
                base32Secret: sha1Secret,
                date: Date(timeIntervalSince1970: vector.time),
                digits: 8,
                period: 30,
                algorithm: .sha1
            )
            XCTAssertEqual(code, vector.code, "wrong code for T=\(vector.time)")
        }
    }

    func testSixDigitDefaultFormat() throws {
        let code = try TOTPGenerator.generate(
            base32Secret: sha1Secret,
            date: Date(timeIntervalSince1970: 59),
            digits: 6,
            period: 30,
            algorithm: .sha1
        )
        // 8-digit vector 94287082 -> last 6 digits.
        XCTAssertEqual(code, "287082")
        XCTAssertEqual(code.count, 6)
    }

    func testInvalidBase32Throws() {
        XCTAssertThrowsError(try TOTPGenerator.generate(
            base32Secret: "0118999", // invalid base32
            digits: 6, period: 30, algorithm: .sha1
        )) { error in
            XCTAssertEqual(error as? MirketAuthError, MirketAuthError.invalidBase32)
        }
    }

    func testDeterministicWithinSamePeriod() throws {
        let t1 = Date(timeIntervalSince1970: 1020) // counter = 34
        let t2 = Date(timeIntervalSince1970: 1049) // same 30s window [1020, 1050)
        let c1 = try TOTPGenerator.generate(base32Secret: sha1Secret, date: t1, digits: 6, period: 30, algorithm: .sha1)
        let c2 = try TOTPGenerator.generate(base32Secret: sha1Secret, date: t2, digits: 6, period: 30, algorithm: .sha1)
        XCTAssertEqual(c1, c2)
    }
}

extension MirketAuthError: Equatable {
    public static func == (lhs: MirketAuthError, rhs: MirketAuthError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidResponse, .invalidResponse),
             (.missingQRCode, .missingQRCode),
             (.missingSecret, .missingSecret),
             (.invalidBase32, .invalidBase32),
             (.totpGenerationFailed, .totpGenerationFailed),
             (.notRegistered, .notRegistered):
            return true
        case let (.apiError(a), .apiError(b)):
            return a == b
        case let (.keychain(a), .keychain(b)):
            return a == b
        case let (.network(a), .network(b)):
            return (a as NSError) == (b as NSError)
        default:
            return false
        }
    }
}
