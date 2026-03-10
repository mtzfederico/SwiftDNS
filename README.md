# SwiftDNS

SwiftDNS is a DNS client library written in Swift. It is able to decode, encode, and send DNS requests using UDP, TCP, DoH, and DoT.

> [!NOTE]
> The library is still being tested and the API may change at any point. All 4 connection types are working properly. 

# Installation

You can install it with [Swift Package Manager](https://swift.org/package-manager/).

```swift
/// Package.swift
/// ...
dependencies: [
    .package(url: "https://github.com/mtzfederico/SwiftDNS.git", branch: "main"),
]
/// ...
```

1. In Xcode, open your project and navigate to **File** → **Swift Packages** → **Add Package Dependency...**
2. Paste the repository URL (`https://github.com/mtzfederico/SwiftDNS`) and click **Next**.
3. For **Rules**, select **Branch** (with branch set to `main`).
4. Click **Finish**.


# Usage

```swift
let server = "https://dns.quad9.net/dns-query"
var client = DNSClient(server: server, connectionType: .dnsOverHTTPS)
  
Task {
    do {
        let result = try await client.query(host: "google.com", type: .AAAA)
        print(result.description)
    } catch(let error) {
        print("Error: \(error)")
    }
}
```

# Logging
To get logs from SwiftDNS, you can add this to your AppDelegate's didFinishLaunchingWithOptions function.
```swift
import Logging

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // Set logging used by SwiftDNS
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = .trace
            return handler
        }
        ...
        return true
    }
    ...
}
```
