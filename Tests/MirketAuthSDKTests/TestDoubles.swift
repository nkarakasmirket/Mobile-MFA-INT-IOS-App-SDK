import Foundation
@testable import MirketAuthSDK

/// In-memory SecretStore (for tests).
final class InMemorySecretStore: SecretStore {
    private var storage = [String: StoredSecret]()

    func save(_ secret: StoredSecret, apiKey: String, userName: String) throws {
        storage[accountKey(apiKey: apiKey, userName: userName)] = secret
    }

    func load(apiKey: String, userName: String) -> StoredSecret? {
        storage[accountKey(apiKey: apiKey, userName: userName)]
    }

    func delete(apiKey: String, userName: String) throws {
        storage[accountKey(apiKey: apiKey, userName: userName)] = nil
    }
}

/// A stub HTTP session that returns a fixed response (for tests).
struct StubHTTPSession: HTTPSession {
    var data: Data?
    var statusCode: Int = 200
    var error: Error?

    /// Captures the sent request (for header/body assertions).
    final class Capture {
        var lastRequest: URLRequest?
    }
    let capture = Capture()

    func performDataTask(with request: URLRequest,
                         completion: @escaping (Data?, URLResponse?, Error?) -> Void) {
        capture.lastRequest = request
        if let error = error {
            completion(nil, nil, error)
            return
        }
        let response = HTTPURLResponse(url: request.url!,
                                       statusCode: statusCode,
                                       httpVersion: nil,
                                       headerFields: nil)
        completion(data, response, nil)
    }
}
