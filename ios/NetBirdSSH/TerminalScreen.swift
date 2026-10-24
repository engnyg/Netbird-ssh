import SwiftUI
import SwiftTerm

/// SwiftTerm's iOS TerminalView already ships a keyboard accessory (Esc, Ctrl,
/// Tab, arrows, ...) which is what Termius-style SSH usage needs.
struct TerminalRepresentable: UIViewRepresentable {
    let session: TerminalSession

    func makeCoordinator() -> Coordinator { Coordinator(session: session) }

    func makeUIView(context: Context) -> SwiftTerm.TerminalView {
        let view = SwiftTerm.TerminalView(frame: .zero)
        view.terminalDelegate = context.coordinator
        view.font = UIFont.monospacedSystemFont(ofSize: 14, weight: .regular)
        view.backgroundColor = .black
        view.nativeBackgroundColor = .black
        view.nativeForegroundColor = UIColor(white: 0.9, alpha: 1)
        session.terminalView = view
        DispatchQueue.main.async { _ = view.becomeFirstResponder() }
        return view
    }

    func updateUIView(_ uiView: SwiftTerm.TerminalView, context: Context) {}

    @MainActor
    final class Coordinator: NSObject, @preconcurrency TerminalViewDelegate {
        let session: TerminalSession
        init(session: TerminalSession) { self.session = session }

        func send(source: SwiftTerm.TerminalView, data: ArraySlice<UInt8>) { session.send(data) }
        func sizeChanged(source: SwiftTerm.TerminalView, newCols: Int, newRows: Int) {
            session.resize(cols: newCols, rows: newRows)
        }
        func setTerminalTitle(source: SwiftTerm.TerminalView, title: String) { session.title = title }
        func hostCurrentDirectoryUpdate(source: SwiftTerm.TerminalView, directory: String?) {}
        func scrolled(source: SwiftTerm.TerminalView, position: Double) {}
        func requestOpenLink(source: SwiftTerm.TerminalView, link: String, params: [String: String]) {
            if let url = URL(string: link) { UIApplication.shared.open(url) }
        }
        func bell(source: SwiftTerm.TerminalView) {}
        func clipboardCopy(source: SwiftTerm.TerminalView, content: Data) {
            if let s = String(data: content, encoding: .utf8) { UIPasteboard.general.string = s }
        }
        func clipboardRead(source: SwiftTerm.TerminalView) -> Data? { nil }
        func iTermContent(source: SwiftTerm.TerminalView, content: ArraySlice<UInt8>) {}
        func rangeChanged(source: SwiftTerm.TerminalView, startY: Int, endY: Int) {}
    }
}

struct TerminalScreen: View {
    @StateObject var session: TerminalSession
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            TerminalRepresentable(session: session)
            switch session.state {
            case .connecting:
                ProgressView("Connecting to \(session.host.displayName)…")
                    .tint(.white).foregroundStyle(.white)
            case .closed(let reason):
                VStack(spacing: 12) {
                    Text(reason).multilineTextAlignment(.center).foregroundStyle(.white)
                    HStack {
                        Button("Reconnect") { Task { await session.reconnect() } }
                            .buttonStyle(.borderedProminent)
                        Button("Close") { dismiss() }.buttonStyle(.bordered)
                    }
                }
                .padding()
                .background(.black.opacity(0.85), in: RoundedRectangle(cornerRadius: 12))
                .padding()
            default:
                EmptyView()
            }
        }
        .navigationTitle(session.title.isEmpty ? session.host.displayName : session.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Disconnect", role: .destructive) { session.disconnect(); dismiss() }
            }
        }
        .task { await session.connect() }
        // The userspace tunnel stops while iOS suspends the app, so reconnect
        // when coming back to a dropped session.
        .onChange(of: scenePhase) { phase in
            if phase == .active, session.isClosed { Task { await session.reconnect() } }
        }
        .alert(item: $session.prompt) { p in
            Alert(
                title: Text(p.known.isEmpty ? "Trust this host?" : "⚠️ Host key changed"),
                message: Text(
                    (p.known.isEmpty
                        ? "The authenticity of \(p.host) can't be established.\n"
                        : "The key of \(p.host) differs from the one you trusted before. This could be a man-in-the-middle attack.\n")
                    + "\n\(p.keyType)\n\(p.fingerprint)"),
                primaryButton: .default(Text(p.known.isEmpty ? "Trust & Connect" : "Trust New Key")) { p.respond(true) },
                secondaryButton: .cancel(Text("Cancel")) { p.respond(false) })
        }
        .onDisappear { session.disconnect() }
    }
}
