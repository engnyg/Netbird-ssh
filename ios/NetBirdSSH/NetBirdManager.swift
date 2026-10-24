import Foundation
import NBSSHKit

struct SSOPrompt: Identifiable {
    let id = UUID()
    let url: URL
    /// Non-empty for the device-code flow: the code to enter on the login page.
    let userCode: String
}

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
    @Published var ssoPrompt: SSOPrompt?
    @Published private(set) var signingIn = false
    private var loginNetwork: NBSSHKitNetwork?
    private var ssoListener: SSOBridge?

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

    // MARK: Account (SSO) login

    /// Signs in with the account configured on the management server's identity
    /// provider (Google, Microsoft, Okta, ...), then brings the tunnel up.
    func signInWithAccount(deviceCode: Bool) {
        guard !signingIn, state != .connecting, state != .connected else { return }
        var err: NSError?
        guard let net = NBSSHKitNewNetwork(deviceName, "", managementURL, dataDir, &err) else {
            state = .failed(err?.localizedDescription ?? "Could not prepare login")
            return
        }
        let bridge = SSOBridge(owner: self)
        loginNetwork = net
        ssoListener = bridge
        signingIn = true
        state = .disconnected
        net.loginSSO(bridge, forceDeviceAuth: deviceCode)
    }

    func cancelSignIn() {
        loginNetwork?.cancelLogin()
        finishSignIn(error: nil)
    }

    fileprivate func showLogin(url: String, code: String) {
        guard let u = URL(string: url) else { return }
        ssoPrompt = SSOPrompt(url: u, userCode: code)
    }

    fileprivate func finishSignIn(error: String?) {
        ssoPrompt = nil
        signingIn = false
        loginNetwork = nil
        ssoListener = nil
        guard let error else { return }          // cancelled by the user
        if error.isEmpty {
            Task { await connect() }              // signed in
        } else {
            state = .failed(error)
        }
    }

    /// Forgets this device's NetBird registration (e.g. after switching servers).
    func resetRegistration() async {
        await disconnect()
        // Keep logs/ so a problem can still be diagnosed afterwards.
        for name in ["netbird.json", "netbird.state"] {
            try? FileManager.default.removeItem(atPath: (dataDir as NSString).appendingPathComponent(name))
        }
        state = .disconnected
    }

    /// Collects the engine log and any Go crash output into one text file the
    /// user can share when something goes wrong.
    func diagnosticsFile() -> URL? {
        let dir = (dataDir as NSString).appendingPathComponent("logs")
        var out = "NetBird SSH diagnostics\nmanagement: \(managementURL)\ndevice: \(deviceName)\n\n"
        var found = false
        for name in ["crash.prev.log", "crash.log", "netbird.prev.log", "netbird.log"] {
            let path = (dir as NSString).appendingPathComponent(name)
            guard let data = FileManager.default.contents(atPath: path), !data.isEmpty else { continue }
            found = true
            let text = String(decoding: data.suffix(150_000), as: UTF8.self)
            out += "===== \(name) =====\n\(text)\n\n"
        }
        guard found else { return nil }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("netbirdssh-diagnostics.txt")
        do { try out.write(to: url, atomically: true, encoding: .utf8) } catch { return nil }
        return url
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

private final class SSOBridge: NSObject, NBSSHKitSSOListenerProtocol {
    weak var owner: NetBirdManager?
    init(owner: NetBirdManager) { self.owner = owner }

    func onURL(_ loginURL: String?, userCode: String?) {
        let (u, c) = (loginURL ?? "", userCode ?? "")
        Task { @MainActor [weak owner] in owner?.showLogin(url: u, code: c) }
    }

    func onDone(_ errMsg: String?) {
        let msg = errMsg ?? ""
        Task { @MainActor [weak owner] in owner?.finishSignIn(error: msg) }
    }
}
