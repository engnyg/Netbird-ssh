import Foundation
import NBSSHKit
import SwiftTerm

struct HostKeyPrompt: Identifiable {
    let id = UUID()
    let host: String
    let keyType: String
    let fingerprint: String
    /// Non-empty when the server presented a different key than the trusted one.
    let known: String
    let respond: (Bool) -> Void
}

/// One live SSH connection: bridges Go's output callbacks to SwiftTerm and the
/// terminal's keystrokes back to Go.
@MainActor
final class TerminalSession: NSObject, ObservableObject {
    enum State: Equatable {
        case idle, connecting, connected
        case closed(String)
    }

    @Published var state: State = .idle
    @Published var title = ""
    @Published var prompt: HostKeyPrompt?

    let host: Host
    private let store: Store
    private let netbird: NetBirdManager
    private var session: NBSSHKitSession?
    private let io = DispatchQueue(label: "ssh.io")

    weak var terminalView: SwiftTerm.TerminalView? {
        didSet { flushPending() }
    }
    private var pending: [UInt8] = []
    private var cols = 80, rows = 24

    init(host: Host, store: Store, netbird: NetBirdManager) {
        self.host = host
        self.store = store
        self.netbird = netbird
        super.init()
    }

    // MARK: Connect

    func connect() async {
        guard state == .idle || isClosed else { return }
        state = .connecting
        if host.viaNetbird, !netbird.isConnected { await netbird.connect() }
        if host.viaNetbird, !netbird.isConnected {
            state = .closed("NetBird is not connected. Check the NetBird tab.")
            return
        }

        // Collect secrets first (may show Face ID).
        let host = self.host
        let key = store.key(for: host)
        let auth = NBSSHKitAuthConfig()
        auth.knownFingerprint = host.knownFingerprint
        let secrets: (String, String, String)? = await Task.detached {
            switch host.authMethod {
            case .password:
                guard let pw = Keychain.getString(account: host.secretAccount) else { return nil }
                return (pw, "", "")
            case .key:
                guard let key, let pem = Keychain.getString(account: key.secretAccount, reason: "Unlock key “\(key.name)”")
                else { return nil }
                let pass = key.encrypted ? (Keychain.getString(account: key.passphraseAccount) ?? "") : ""
                return ("", pem, pass)
            }
        }.value
        guard let (pw, pem, pass) = secrets else {
            state = .closed(host.authMethod == .password ? "No saved password for this host." : "No usable SSH key selected for this host.")
            return
        }
        auth.password = pw
        auth.privateKey = pem
        auth.passphrase = pass

        let network = netbird.network
        let viaNetbird = host.viaNetbird
        let (cols, rows) = (self.cols, self.rows)
        let handler = HostKeyBridge(owner: self)
        let sess = NBSSHKitNewSession(Listener(owner: self))
        session = sess
        do {
            try await Task.detached {
                try sess?.connect(network, viaNetbird: viaNetbird, host: host.address, port: host.port,
                                  user: host.username, auth: auth, hk: handler)
                try sess?.start(cols, rows: rows)
            }.value
            state = .connected
            if let fp = handler.acceptedFingerprint { store.setFingerprint(fp, for: host.id) }
        } catch {
            sess?.close()
            session = nil
            state = .closed(error.localizedDescription)
        }
    }

    var isClosed: Bool { if case .closed = state { return true } else { return false } }

    func disconnect() {
        session?.close()
        session = nil
        if !isClosed { state = .closed("Disconnected") }
    }

    func reconnect() async {
        disconnect()
        state = .idle
        terminalView?.feed(text: "\r\n\u{1b}[2m--- reconnecting ---\u{1b}[0m\r\n")
        await connect()
    }

    // MARK: Terminal I/O

    func send(_ bytes: ArraySlice<UInt8>) {
        let data = Data(bytes)
        let s = session
        io.async { try? s?.write(data) }
    }

    func resize(cols: Int, rows: Int) {
        self.cols = cols
        self.rows = rows
        let s = session
        io.async { try? s?.resize(cols, rows: rows) }
    }

    fileprivate func receive(_ data: Data) {
        let bytes = [UInt8](data)
        if let view = terminalView {
            view.feed(byteArray: bytes[...])
        } else {
            pending.append(contentsOf: bytes)
        }
    }

    private func flushPending() {
        guard let view = terminalView, !pending.isEmpty else { return }
        view.feed(byteArray: pending[...])
        pending.removeAll()
    }

    fileprivate func remoteClosed(_ reason: String) {
        session = nil
        state = .closed(reason)
    }
}

// MARK: - Go callbacks (called on Go threads)

private final class Listener: NSObject, NBSSHKitSessionListenerProtocol {
    weak var owner: TerminalSession?
    init(owner: TerminalSession) { self.owner = owner }

    func onData(_ data: Data?) {
        guard let data else { return }
        Task { @MainActor [weak owner] in owner?.receive(data) }
    }

    func onClose(_ reason: String?) {
        Task { @MainActor [weak owner] in owner?.remoteClosed(reason ?? "Connection closed") }
    }
}

/// Blocks the Go handshake thread until the user answers the host-key prompt.
private final class HostKeyBridge: NSObject, NBSSHKitHostKeyHandlerProtocol {
    weak var owner: TerminalSession?
    private(set) var acceptedFingerprint: String?
    init(owner: TerminalSession) { self.owner = owner }

    func verify(_ host: String?, keyType: String?, fingerprint: String?, knownFingerprint: String?) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        var accepted = false
        let fp = fingerprint ?? ""
        let prompt = HostKeyPrompt(host: host ?? "", keyType: keyType ?? "", fingerprint: fp,
                                   known: knownFingerprint ?? "") { ok in
            accepted = ok
            semaphore.signal()
        }
        Task { @MainActor [weak owner] in
            if let owner { owner.prompt = prompt } else { semaphore.signal() }
        }
        semaphore.wait()
        if accepted { acceptedFingerprint = fp }
        return accepted
    }
}
