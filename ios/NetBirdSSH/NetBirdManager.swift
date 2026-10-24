import Foundation
import NBSSHKit

struct Peer: Identifiable, Hashable {
    var id: String { fqdn }
    let fqdn: String
    let ip: String
    let status: String
}

/// Owns the embedded (userspace) NetBird peer. No VPN profile or Network
/// Extension is involved: the tunnel only carries this app's own sockets, and
/// it stops when iOS suspends the app.
@MainActor
final class NetBirdManager: ObservableObject {
    enum State: Equatable {
        case disconnected, connecting, connected
        case failed(String)
    }

    @Published private(set) var state: State = .disconnected
    @Published private(set) var peers: [Peer] = []

    @Published var managementURL: String { didSet { defaults.set(managementURL, forKey: "mgmtURL") } }
    @Published var deviceName: String { didSet { defaults.set(deviceName, forKey: "deviceName") } }
    @Published var autoConnect: Bool { didSet { defaults.set(autoConnect, forKey: "autoConnect") } }

    private let defaults = UserDefaults.standard
    private static let setupKeyAccount = "netbird.setupkey"
    private(set) var network: NBSSHKitNetwork?

    init() {
        managementURL = defaults.string(forKey: "mgmtURL") ?? "https://api.netbird.io:443"
        deviceName = defaults.string(forKey: "deviceName") ?? "ios-ssh"
        autoConnect = defaults.object(forKey: "autoConnect") as? Bool ?? false
    }

    var savedSetupKey: String { Keychain.getString(account: Self.setupKeyAccount) ?? "" }
    var isConnected: Bool { state == .connected }

    func saveSetupKey(_ key: String) {
        if key.isEmpty { Keychain.delete(account: Self.setupKeyAccount) }
        else { try? Keychain.setString(key, account: Self.setupKeyAccount) }
    }

    private var dataDir: String {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("netbird").path
    }

    func connect() async {
        guard state != .connecting, state != .connected else { return }
        state = .connecting
        let (name, url, key, dir) = (deviceName, managementURL, savedSetupKey, dataDir)
        do {
            let net: NBSSHKitNetwork = try await Task.detached(priority: .userInitiated) {
                var err: NSError?
                guard let n = NBSSHKitNewNetwork(name, key, url, dir, &err) else {
                    throw err ?? NSError(domain: "NetBirdSSH", code: 2)
                }
                try n.start(60)
                return n
            }.value
            network = net
            state = .connected
            await refreshPeers()
        } catch {
            network = nil
            state = .failed(error.localizedDescription)
        }
    }

    func disconnect() async {
        guard let net = network else { state = .disconnected; return }
        network = nil
        peers = []
        state = .disconnected
        await Task.detached { try? net.stop() }.value
    }

    func refreshPeers() async {
        guard let net = network else { return }
        let raw: String = await Task.detached {
            var err: NSError?
            let out = net.peers(&err)
            return err == nil ? out : ""
        }.value
        peers = raw.split(separator: "\n").compactMap { line in
            let f = line.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard f.count == 3 else { return nil }
            return Peer(fqdn: f[0], ip: f[1], status: f[2])
        }.sorted { $0.fqdn < $1.fqdn }
    }
}
