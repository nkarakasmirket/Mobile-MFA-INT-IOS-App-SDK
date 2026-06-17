import Foundation

/// A minimal abstraction that performs HTTP requests (injectable for testability).
protocol HTTPSession {
    func performDataTask(with request: URLRequest,
                         completion: @escaping (Data?, URLResponse?, Error?) -> Void)
}

extension URLSession: HTTPSession {
    func performDataTask(with request: URLRequest,
                         completion: @escaping (Data?, URLResponse?, Error?) -> Void) {
        dataTask(with: request, completionHandler: completion).resume()
    }
}

/// The client that sends the registration request to the `external-mobile-auth` endpoint.
struct AuthAPIClient {

    private let configuration: MirketAuthConfiguration
    private let session: HTTPSession

    init(configuration: MirketAuthConfiguration, session: HTTPSession = URLSession.shared) {
        self.configuration = configuration
        self.session = session
    }

    /// Sends the registration request and returns the `otpauth://` QR content from the response.
    ///
    /// - Parameters:
    ///   - apiKey: Sent in the `mirket-api-key` header.
    ///   - userName: Sent in the JSON body as `{"username": ...}`.
    ///   - completion: On success the `qrcode` text, otherwise a `MirketAuthError`.
    func register(apiKey: String,
                  userName: String,
                  completion: @escaping (Result<String, MirketAuthError>) -> Void) {
        var request = URLRequest(url: configuration.registrationURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(apiKey, forHTTPHeaderField: configuration.apiKeyHeaderField)

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: ["username": userName])
        } catch {
            completion(.failure(.invalidResponse))
            return
        }

        session.performDataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(.network(error)))
                return
            }
            guard let http = response as? HTTPURLResponse else {
                completion(.failure(.invalidResponse))
                return
            }
            guard (200..<300).contains(http.statusCode) else {
                completion(.failure(.apiError(statusCode: http.statusCode)))
                return
            }
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(.failure(.invalidResponse))
                return
            }
            guard let qrcode = json["qrcode"] as? String, !qrcode.isEmpty else {
                completion(.failure(.missingQRCode))
                return
            }
            completion(.success(qrcode))
        }
    }
}
