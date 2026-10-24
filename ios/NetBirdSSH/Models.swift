import Foundation

enum AuthMethod: String, Codable, CaseIterable, Identifiable {
    case key, password
    var id: String { rawValue }
    var title: String { self == .key ? "SSH Key" : "Password" }
}

struct Host: Identifiable, Codable, Hashable {
    var id = UUID()
    var name = ""
    var address = ""
    var port = 22
    var username = ""
    var authMethod: AuthMethod = .key
    var keyID: UUID?
    /// Route the connection through the embedded NetBird tunnel.
    var viaNetbird = true
    var group = ""
    /// SHA256 fingerprint the user accepted on first connect (TOFU).
    var knownFingerprint = ""

    var displayName: String { name.isEmpty ? address : name }
    var secretAccount: String { "hostpw.\(id.uuidString)" }
}

struct KeyRecord: Identifiable, Codable, Hashable {
    var id = UUID()
    var name: String
    var type: String
    var publicKey: String
    var fingerprint: String
    /// Private key is protected by a passphrase.
    var encrypted: Bool
    /// Reading the key from the Keychain requires Face ID / passcode.
    var requireBiometrics: Bool

    var secretAccount: String { "key.\(id.uuidString)" }
    var passphraseAccount: String { "keypass.\(id.uuidString)" }
}
