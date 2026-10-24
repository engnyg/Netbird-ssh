import SafariServices
import SwiftUI

struct NetBirdView: View {
    @EnvironmentObject var netbird: NetBirdManager
    @EnvironmentObject var store: Store
    @State private var setupKey = ""
    @State private var addHost: Host?
    @State private var useDeviceCode = false
    @State private var confirmReset = false
    @State private var diagnostics: URL?

    var body: some View {
        NavigationStack {
            Form {
                Section("Status") {
                    HStack {
                        Circle().fill(color).frame(width: 10, height: 10)
                        Text(label)
                        Spacer()
                        if netbird.state == .connecting { ProgressView() }
                    }
                    if case .failed(let msg) = netbird.state {
                        Text(msg).font(.footnote).foregroundStyle(.red)
                    }
                    Button(netbird.isConnected ? "Disconnect" : "Connect",
                           role: netbird.isConnected ? .destructive : nil) {
                        Task { netbird.isConnected ? await netbird.disconnect() : await netbird.connect() }
                    }
                    .disabled(netbird.state == .connecting)
                    Toggle("Connect on launch", isOn: $netbird.autoConnect)
                }

                Section(header: Text("Server"),
                        footer: Text("Self-hosted? Change the management URL, then use “Reset registration” before signing in to the new server.")) {
                    TextField("Management URL", text: $netbird.managementURL)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    TextField("Device name", text: $netbird.deviceName)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                }

                if !netbird.isConnected {
                    Section(header: Text("Sign in"),
                            footer: Text("Account login opens your NetBird identity provider (Google, Microsoft, Okta, ...). Turn on “Use device code” if the sign-in page does not complete. A setup key is only needed the first time; the device then stays registered.")) {
                        Button {
                            netbird.signInWithAccount(deviceCode: useDeviceCode)
                        } label: {
                            Label("Sign in with account", systemImage: "person.crop.circle")
                        }
                        .disabled(netbird.signingIn || netbird.state == .connecting)
                        Toggle("Use device code", isOn: $useDeviceCode)
                        SecureField("…or paste a setup key", text: $setupKey)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .onChange(of: setupKey) { netbird.saveSetupKey($0) }
                    }
                }

                Section {
                    Button("Reset registration", role: .destructive) { confirmReset = true }
                        .disabled(netbird.signingIn)
                    if let diagnostics {
                        ShareLink(item: diagnostics) { Label("Export logs", systemImage: "doc.text.magnifyingglass") }
                    }
                }

                if netbird.isConnected {
                    Section("Peers") {
                        ForEach(netbird.peers) { peer in
                            Button {
                                addHost = Host(name: peer.fqdn.components(separatedBy: ".").first ?? peer.fqdn,
                                               address: peer.ip, username: "root")
                            } label: {
                                VStack(alignment: .leading) {
                                    Text(peer.fqdn).foregroundStyle(.primary)
                                    Text("\(peer.ip) · \(peer.status)").font(.caption.monospaced()).foregroundStyle(.secondary)
                                }
                            }
                        }
                        if netbird.peers.isEmpty { Text("No peers visible yet.").foregroundStyle(.secondary) }
                    }
                }

                Section(footer: Text("The tunnel runs inside this app (no VPN profile). iOS pauses it when the app is in the background; sessions reconnect when you return.")) { EmptyView() }
            }
            .navigationTitle("NetBird")
            .toolbar {
                if netbird.isConnected {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button { Task { await netbird.refreshPeers() } } label: { Image(systemName: "arrow.clockwise") }
                    }
                }
            }
            .onAppear { setupKey = netbird.savedSetupKey; diagnostics = netbird.diagnosticsFile() }
            .onChange(of: netbird.state) { _ in diagnostics = netbird.diagnosticsFile() }
            .onDisappear { netbird.saveSetupKey(setupKey) }
            .sheet(item: $addHost) { HostEditView(host: $0) }
            .sheet(item: $netbird.ssoPrompt, onDismiss: {
                if netbird.signingIn { netbird.cancelSignIn() }
            }) { prompt in
                SSOSheet(prompt: prompt) { netbird.cancelSignIn() }
            }
            .confirmationDialog("Forget this device's NetBird registration?", isPresented: $confirmReset,
                                titleVisibility: .visible) {
                Button("Reset registration", role: .destructive) { Task { await netbird.resetRegistration() } }
            } message: {
                Text("You will need to sign in again. Hosts and keys are kept.")
            }
        }
    }

    private var label: String {
        switch netbird.state {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .failed: return "Failed"
        }
    }
    private var color: Color {
        switch netbird.state {
        case .connected: return .green
        case .connecting: return .orange
        case .failed: return .red
        case .disconnected: return .gray
        }
    }
}

/// Shows the identity provider's page inside the app so the app stays in the
/// foreground while the login completes. For the device-code flow the code is
/// shown above the page.
private struct SSOSheet: View {
    let prompt: SSOPrompt
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Sign in").font(.headline)
                Spacer()
                Button("Cancel", action: onCancel)
            }
            .padding()
            if !prompt.userCode.isEmpty {
                VStack(spacing: 6) {
                    Text("Enter this code on the page below").font(.footnote).foregroundStyle(.secondary)
                    Text(prompt.userCode).font(.system(.title, design: .monospaced).bold()).textSelection(.enabled)
                    Button("Copy code") { UIPasteboard.general.string = prompt.userCode }
                        .buttonStyle(.bordered)
                }
                .padding(.bottom, 12)
            }
            SafariView(url: prompt.url)
        }
    }
}

private struct SafariView: UIViewControllerRepresentable {
    let url: URL
    func makeUIViewController(context: Context) -> SFSafariViewController {
        let config = SFSafariViewController.Configuration()
        config.barCollapsingEnabled = false
        return SFSafariViewController(url: url, configuration: config)
    }
    func updateUIViewController(_ vc: SFSafariViewController, context: Context) {}
}
