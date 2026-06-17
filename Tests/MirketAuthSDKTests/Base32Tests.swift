import XCTest
@testable import MirketAuthSDK

final class Base32Tests: XCTestCase {

    // RFC 4648 §10 test vectors.
    func testRFC4648Vectors() {
        let cases: [(String, String)] = [
            ("", ""),
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar")
        ]
        for (input, expected) in cases {
            let decoded = Base32.decode(input)
            XCTAssertEqual(decoded, expected.data(using: .utf8), "Base32 decode failed: \(input)")
        }
    }

    func testLowercaseAndSpacesTolerated() {
        XCTAssertEqual(Base32.decode("mzxw6ytb"), "fooba".data(using: .utf8))
        XCTAssertEqual(Base32.decode("MZX W6Y TB"), "fooba".data(using: .utf8))
    }

    func testInvalidCharacterReturnsNil() {
        // '1' ve '8' standart alfabede yok.
        XCTAssertNil(Base32.decode("MZXW6YT1"))
    }
}
