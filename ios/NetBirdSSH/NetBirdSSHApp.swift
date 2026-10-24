import SwiftUI

@main
struct NetBirdSSHApp: App {
    @StateObject private var store = Store()
    @StateObject private var netbird = NetBirdManager()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .environmentObject(netbird)
                .task { if netbird.autoConnect { await netbird.connect() } }
        }
    }
}

struct RootView: View {
    var body: some View {
        TabView {
            HostsView().tabItem { Label("Hosts", systemImage: "server.rack") }
            KeysView().tabItem { Label("Keys", systemImage: "key.fill") }
            NetBirdView().tabItem { Label("NetBird", systemImage: "network") }
        }
    }
}
