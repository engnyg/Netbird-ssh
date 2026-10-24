import Foundation
import NBSSHKit

/// Hosts and key metadata live in a JSON file; every secret (private keys,
/// passphrases, passwords) lives in the Keychain.
@MainActor
final class Store: ObservableObject {
    @Published var hosts: [Host] = [] { didSet { save() } }
    @Published var keys: [KeyRecord] = [] { didSet { save() } }

    private struct Snapshot: Codable {
        var hosts: [Host]
        var keys: [KeyRecord]
    }

    private let url: URL = {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("store.json")
    }()
    private var loading = false

    init() {
        loading = true
        if let data = try? Data(contentsOf: url),
           let snap = try? JSONDecoder().decode(Snapshot.self, from: data) {
            hosts = snap.hosts
            keys = snap.keys
        }
        loading = false
    }

    private func save() {
        guard !loading else { return }
        let snap = Snapshot(hosts: hosts, keys: keys)
        if let data = try? JSONEncoder().encode(snap) {
            try? data.write(to: url, options: [.atomic, .completeFileProtection])
        }
    }

    func key(for host: Host) -> KeyRecord? {
        keys.first { $0.id == host.keyID }
    }

    func upsert(_ host: Host, password: String?) {
        if let i = hosts.firstIndex(where: { $0.id == host.id }) { hosts[i] = host } else { hosts.append(host) }
        if let password, !password.isEmpty {
            try? Keychain.setString(password, account: host.secretAccount)
        } else if host.authMethod != .password {
            Keychain.delete(account: host.secretAccount)
        }
    }

    func delete(host: Host) {
        Keychain.delete(account: host.secretAccount)
        hosts.removeAll { $0.id == host.id }
    }

    func setFingerprint(_ fp: String, for hostID: UUID) {
        if let i = hosts.firstIndex(where: { $0.id == hostID }) { hosts[i].knownFingerprint = fp }
    }

    // MARK: Keys

    /// Generates a key pair on device and stores the private half in the Keychain.
    func generateKey(name: String, type: String, passphrase: String, biometrics: Bool) throws -> KeyRecord {
        var err: NSError?
        let info = NBSSHKitGenerateKey(type, name, passphrase, &err)
        if let err { throw err }
        guard let info else { throw NSError(domain: "NetBirdSSH", code: 1) }
        return try add(info, name: name, passphrase: passphrase, biometrics: biometrics)
    }

    /// Imports a PEM private key (OpenSSH / PKCS#1 / PKCS#8).
    func importKey(name: String, pem: String, passphrase: String, biometrics: Bool) throws -> KeyRecord {
        var err: NSError?
        let info = NBSSHKitParsePrivateKey(pem, passphrase, &err)
        if let err { throw err }
        guard let info else { throw NSError(domain: "NetBirdSSH", code: 1) }
        return try add(info, name: name, passphrase: passphrase, biometrics: biometrics)
    }

    private func add(_ info: NBSSHKitKeyInfo, name: String, passphrase: String, biometrics: Bool) throws -> KeyRecord {
        let record = KeyRecord(name: name, type: info.type, publicKey: info.publicKey,
                               fingerprint: info.fingerprint, encrypted: info.encrypted,
                               requireBiometrics: biometrics)
        try Keychain.setString(info.privateKey, account: record.secretAccount, requireUserPresence: biometrics)
        if info.encrypted, !passphrase.isEmpty {
            try Keychain.setString(passphrase, account: record.passphraseAccount, requireUserPresence: biometrics)
        }
        keys.append(record)
        return record
    }

    func delete(key: KeyRecord) {
        Keychain.delete(account: key.secretAccount)
        Keychain.delete(account: key.passphraseAccount)
        for i in hosts.indices where hosts[i].keyID == key.id { hosts[i].keyID = nil }
        keys.removeAll { $0.id == key.id }
    }
}
