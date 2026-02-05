# SwiftDNS

SwiftDNS is a DNS client library written in Swift. It is able to decode, encode, and send DNS requests using UDP, TCP, DoH, and DoT.

> [!NOTE]
> Currently the only method that is reliably working is DNS over HTTPS. If you have experience with NWConnection, I would gladly accept PRs.

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

