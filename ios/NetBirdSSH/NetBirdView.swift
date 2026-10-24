import SwiftUI

struct NetBirdView: View {
    @EnvironmentObject var netbird: NetBirdManager
    @EnvironmentObject var store: Store
    @State private var setupKey = ""
    @State private var addHost: Host?

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

                Section(header: Text("Account"),
                        footer: Text("Create a setup key in the NetBird dashboard (Setup Keys). It is only needed the first time; the device then stays registered. Self-hosted? Change the management URL.")) {
                    TextField("Management URL", text: $netbird.managementURL)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    TextField("Device name", text: $netbird.deviceName)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("Setup key", text: $setupKey)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .onChange(of: setupKey) { netbird.saveSetupKey($0) }
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
            .onAppear { setupKey = netbird.savedSetupKey }
            .onDisappear { netbird.saveSetupKey(setupKey) }
            .sheet(item: $addHost) { HostEditView(host: $0) }
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
