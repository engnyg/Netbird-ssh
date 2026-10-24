import SwiftUI
import UniformTypeIdentifiers

struct KeysView: View {
    @EnvironmentObject var store: Store
    @State private var sheet: Sheet?

    enum Sheet: Identifiable {
        case generate, importKey
        var id: Self { self }
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(store.keys) { key in
                    NavigationLink { KeyDetailView(key: key) } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(key.name).font(.headline)
                                if key.requireBiometrics { Image(systemName: "faceid").font(.caption) }
                                if key.encrypted { Image(systemName: "lock.fill").font(.caption) }
                            }
                            Text("\(key.type.uppercased()) · \(key.fingerprint)")
                                .font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                }
                .onDelete { idx in idx.map { store.keys[$0] }.forEach(store.delete(key:)) }
                if store.keys.isEmpty {
                    Text("Generate a key on this device, or import an existing private key.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Keys")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Generate Key", systemImage: "wand.and.stars") { sheet = .generate }
                        Button("Import Key", systemImage: "square.and.arrow.down") { sheet = .importKey }
                    } label: { Image(systemName: "plus") }
                }
            }
            .sheet(item: $sheet) { s in
                switch s {
                case .generate: GenerateKeyView()
                case .importKey: ImportKeyView()
                }
            }
        }
    }
}

struct KeyDetailView: View {
    let key: KeyRecord
    @State private var copied = false

    var body: some View {
        Form {
            Section("Public key") {
                Text(key.publicKey).font(.caption.monospaced()).textSelection(.enabled)
                Button(copied ? "Copied" : "Copy public key", systemImage: "doc.on.doc") {
                    UIPasteboard.general.string = key.publicKey
                    copied = true
                }
                ShareLink(item: key.publicKey) { Label("Share public key", systemImage: "square.and.arrow.up") }
            }
            Section("Details") {
                LabeledContent("Type", value: key.type.uppercased())
                LabeledContent("Fingerprint") { Text(key.fingerprint).font(.caption.monospaced()) }
                LabeledContent("Passphrase", value: key.encrypted ? "Yes" : "No")
                LabeledContent("Face ID", value: key.requireBiometrics ? "Required" : "Off")
            }
            Section(footer: Text("Add the public key to ~/.ssh/authorized_keys on the server.")) { EmptyView() }
        }
        .navigationTitle(key.name)
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct GenerateKeyView: View {
    @EnvironmentObject var store: Store
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var type = "ed25519"
    @State private var passphrase = ""
    @State private var biometrics = true
    @State private var error: String?
    @State private var working = false

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name", text: $name)
                Picker("Type", selection: $type) {
                    Text("Ed25519 (recommended)").tag("ed25519")
                    Text("ECDSA P-256").tag("ecdsa")
                    Text("RSA 4096").tag("rsa")
                }
                SecureField("Passphrase (optional)", text: $passphrase)
                Toggle("Require Face ID / passcode", isOn: $biometrics)
                if let error { Text(error).foregroundStyle(.red).font(.footnote) }
            }
            .navigationTitle("Generate Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(working ? "…" : "Generate") { generate() }
                        .disabled(name.isEmpty || working)
                }
            }
        }
    }

    private func generate() {
        working = true
        let (n, t, p, b) = (name, type, passphrase, biometrics)
        Task {
            do {
                _ = try store.generateKey(name: n, type: t, passphrase: p, biometrics: b)
                dismiss()
            } catch {
                self.error = error.localizedDescription
                working = false
            }
        }
    }
}

struct ImportKeyView: View {
    @EnvironmentObject var store: Store
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var pem = ""
    @State private var passphrase = ""
    @State private var biometrics = true
    @State private var error: String?
    @State private var pickFile = false

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name", text: $name)
                Section("Private key") {
                    TextEditor(text: $pem)
                        .font(.caption.monospaced()).frame(minHeight: 140)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    HStack {
                        Button("Paste", systemImage: "doc.on.clipboard") { pem = UIPasteboard.general.string ?? pem }
                        Spacer()
                        Button("Choose file…", systemImage: "folder") { pickFile = true }
                    }.buttonStyle(.borderless)
                }
                SecureField("Passphrase (if encrypted)", text: $passphrase)
                Toggle("Require Face ID / passcode", isOn: $biometrics)
                if let error { Text(error).foregroundStyle(.red).font(.footnote) }
            }
            .navigationTitle("Import Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Import") {
                        do {
                            _ = try store.importKey(name: name, pem: pem, passphrase: passphrase, biometrics: biometrics)
                            dismiss()
                        } catch { self.error = error.localizedDescription }
                    }.disabled(name.isEmpty || pem.isEmpty)
                }
            }
            .fileImporter(isPresented: $pickFile, allowedContentTypes: [.data, .text, .plainText]) { result in
                guard case .success(let url) = result else { return }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                if let text = try? String(contentsOf: url, encoding: .utf8) {
                    pem = text
                    if name.isEmpty { name = url.deletingPathExtension().lastPathComponent }
                } else {
                    error = "Could not read that file as text."
                }
            }
        }
    }
}
