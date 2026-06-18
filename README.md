# MirketAuthSDK

A lightweight, **zero-dependency** TOTP (Time-based One-Time Password) multi-factor
authentication library for iOS, distributed via Swift Package Manager.

- **Minimum deployment target: iOS 11.**
- No third-party dependencies — uses only `Foundation`, `Security` (Keychain) and `CommonCrypto`.
- RFC 6238 / RFC 4226 compliant; codes are interoperable with Google Authenticator and similar apps.
- Secrets are stored securely in the **Keychain** and work **offline** after registration.

---

## Features

| Capability | Method |
|---|---|
| Register a user and obtain the first TOTP code | `register(apiKey:userName:completion:)` (also `async` on iOS 13+) |
| Generate the current TOTP code offline | `getTOTPCode(apiKey:userName:)` |
| Export the raw Base32 secret | `exportSecret(apiKey:userName:)` |
| Export a standard `otpauth://` URI (for QR / manual import) | `exportOTPAuthURI(apiKey:userName:issuer:)` |
| Remove a stored registration | `removeRegistration(apiKey:userName:)` |

---

## Requirements

| | |
|---|---|
| Platform | iOS 11.0+ |
| Swift | 5.5+ |
| Xcode | 13+ |

> **Why iOS 11 and not lower for everything?**
> `async/await` (Swift Concurrency) does **not** back-deploy below iOS 13, so the primary API is
> completion-handler based and the `async` variant is gated behind `@available(iOS 13.0, *)`.
> `CryptoKit` also requires iOS 13, so HMAC is implemented with **`CommonCrypto`**, which is
> available on iOS 11.

---

## Installation

### Swift Package Manager (Xcode)

1. In Xcode: **File ▸ Add Package Dependencies…**
2. Enter the repository URL:
   ```
   https://github.com/nkarakasmirket/Mobile-MFA-INT-IOS-App-SDK.git
   ```
3. Choose a version rule (e.g. **Up to Next Major Version** → `1.0.0`).
4. Add the **MirketAuthSDK** product to your target.

### Package.swift

```swift
dependencies: [
    .package(
        url: "https://github.com/nkarakasmirket/Mobile-MFA-INT-IOS-App-SDK.git",
        from: "1.0.0"
    )
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "MirketAuthSDK", package: "Mobile-MFA-INT-IOS-App-SDK")
        ]
    )
]
```

---

## Configuration

The SDK does **not** hardcode any server URL or credentials. You supply the registration endpoint
when you create the instance:

```swift
import MirketAuthSDK

// Minimal: just the endpoint (uses defaults — 6 digits / 30s / SHA1, "mirket-api-key" header).
let auth = MirketAuth(
    registrationURL: URL(string: "https://<your-host>/api/external-mobile-auth")!
)

// Or with full control:
let config = MirketAuthConfiguration(
    registrationURL: URL(string: "https://<your-host>/api/external-mobile-auth")!,
    apiKeyHeaderField: "mirket-api-key", // HTTP header used to send the apiKey
    defaultDigits: 6,
    defaultPeriod: 30,
    defaultAlgorithm: .sha1
)
let auth = MirketAuth(configuration: config)
```

> If the `otpauth://` URI returned by the server carries its own `algorithm` / `digits` / `period`
> values, those take precedence over the configured defaults.

---

## Usage

### 1. Register (iOS 11+ — completion handler)

Sends a `POST` request to the configured endpoint with the `apiKey` in the configured header and
`{"username": "<userName>"}` in the JSON body. It parses the returned `otpauth://` QR content,
stores the secret in the Keychain, and returns the current TOTP code.

```swift
auth.register(apiKey: "YOUR_API_KEY", userName: "alice") { result in
    // No main-thread guarantee — dispatch UI updates to the main queue.
    DispatchQueue.main.async {
        switch result {
        case .success(let code):
            print("Current TOTP code: \(code)")
        case .failure(let error):
            print("Registration failed: \(error.localizedDescription)")
        }
    }
}
```

### 1b. Register (iOS 13+ — async/await)

```swift
if #available(iOS 13.0, *) {
    do {
        let code = try await auth.register(apiKey: "YOUR_API_KEY", userName: "alice")
        print(code)
    } catch {
        print(error.localizedDescription)
    }
}
```

### 2. Get a TOTP code (offline)

After a successful registration the secret lives in the Keychain, so codes can be generated
without any network access — even after the app is relaunched.

```swift
switch auth.getTOTPCode(apiKey: "YOUR_API_KEY", userName: "alice") {
case .success(let code):
    print("TOTP: \(code)")
case .failure(let error):
    print(error.localizedDescription) // e.g. .notRegistered
}
```

### 3. Export the secret (e.g. to verify against Google Authenticator)

```swift
// Raw Base32 secret — paste into Google Authenticator via "Enter a setup key".
if case .success(let secret) = auth.exportSecret(apiKey: "YOUR_API_KEY", userName: "alice") {
    print(secret)
}

// Full otpauth:// URI — render as a QR code or import directly.
if case .success(let uri) = auth.exportOTPAuthURI(apiKey: "YOUR_API_KEY", userName: "alice") {
    print(uri) // otpauth://totp/<label>?secret=<BASE32>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
}
```

---

## Server contract

```
POST <registrationURL>
Header:  <apiKeyHeaderField>: <apiKey>     // default header name: "mirket-api-key"
Header:  Content-Type: application/json
Body:    { "username": "<userName>" }

200 OK:
{ "qrcode": "otpauth://totp/<label>?secret=<BASE32>&issuer=<...>" }
```

The SDK extracts the `secret` query parameter (Base32) from the `qrcode` field and uses it to
generate TOTP codes.

---

## How it works

1. `register` calls the endpoint and receives an `otpauth://` URI in the `qrcode` field.
2. The `secret` (and any `algorithm`/`digits`/`period`) is parsed from that URI.
3. A `StoredSecret` (secret + resolved TOTP parameters) is saved to the Keychain, indexed by the
   `apiKey` + `userName` pair, so multiple accounts can be stored side by side.
4. TOTP codes are computed locally (RFC 6238) — no further network calls are needed.

---

## Error handling

All public methods return `Result<…, MirketAuthError>`. `MirketAuthError` cases include:
`network`, `invalidResponse`, `apiError(statusCode:)`, `missingQRCode`, `missingSecret`,
`invalidBase32`, `totpGenerationFailed`, `notRegistered`, and `keychain(OSStatus)`.
It conforms to `LocalizedError`, so `error.localizedDescription` gives a human-readable message.

---

## Security notes

- Secrets are stored in the Keychain as `kSecClassGenericPassword` with
  `kSecAttrAccessibleAfterFirstUnlock` accessibility — not in `UserDefaults`.
- The SDK never persists the `apiKey`; it is only used per-request and as part of the storage index.

---

## License

Proprietary © Mirket. All rights reserved.
