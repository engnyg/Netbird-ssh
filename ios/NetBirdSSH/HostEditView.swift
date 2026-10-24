import SwiftUI

struct HostEditView: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var netbird: NetBirdManager
    @Environment(\.dismiss) private var dismiss

    @State var host: Host
    @State private var password = ""
    @State private var portText = ""

    private var canSave: Bool {
        !host.address.trimmingCharacters(in: .whitespaces).isEmpty && !host.username.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Host") {
                    TextField("Label (optional)", text: $host.name)
                    TextField("Address or NetBird name / IP", text: $host.address)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Port", text: $portText).keyboardType(.numberPad)
                    TextField("Group (optional)", text: $host.group)
                    Toggle("Connect through NetBird", isOn: $host.viaNetbird)
                    if host.viaNetbird && !netbird.peers.isEmpty {
                        Menu("Pick NetBird peer") {
                            ForEach(netbird.peers) { peer in
                                Button("\(peer.fqdn) — \(peer.ip)") {
                                    host.address = peer.ip
                                    if host.name.isEmpty { host.name = peer.fqdn.components(separatedBy: ".").first ?? peer.fqdn }
                                }
                            }
                        }
                    }
                }
                Section("Authentication") {
                    TextField("Username", text: $host.username)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Picker("Method", selection: $host.authMethod) {
                        ForEach(AuthMethod.allCases) { Text($0.title).tag($0) }
                    }.pickerStyle(.segmented)
                    if host.authMethod == .password {
                        SecureField("Password", text: $password)
                    } else {
                        Picker("Key", selection: $host.keyID) {
                            Text("None").tag(UUID?.none)
                            ForEach(store.keys) { Text($0.name).tag(Optional($0.id)) }
                        }
                        if store.keys.isEmpty {
                            Text("Create or import a key in the Keys tab first.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
                if !host.knownFingerprint.isEmpty {
                    Section("Trusted host key") {
                        Text(host.knownFingerprint).font(.caption.monospaced())
                        Button("Forget host key", role: .destructive) { host.knownFingerprint = "" }
                    }
                }
            }
            .navigationTitle(host.name.isEmpty ? "New Host" : host.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        host.port = Int(portText) ?? 22
                        host.address = host.address.trimmingCharacters(in: .whitespaces)
                        store.upsert(host, password: password)
                        dismiss()
                    }.disabled(!canSave)
                }
            }
            .onAppear {
                portText = String(host.port)
                if host.authMethod == .password {
                    password = Keychain.getString(account: host.secretAccount) ?? ""
                }
            }
        }
    }
}
