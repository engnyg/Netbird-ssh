import SwiftUI

struct HostsView: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var netbird: NetBirdManager
    @State private var editing: Host?
    @State private var search = ""

    private var filtered: [Host] {
        search.isEmpty ? store.hosts
            : store.hosts.filter { $0.displayName.localizedCaseInsensitiveContains(search) || $0.address.localizedCaseInsensitiveContains(search) }
    }
    private var groups: [String] { Array(Set(filtered.map(\.group))).sorted() }

    var body: some View {
        NavigationStack {
            List {
                ForEach(groups, id: \.self) { group in
                    Section(group.isEmpty ? "Hosts" : group) {
                        ForEach(filtered.filter { $0.group == group }) { host in
                            NavigationLink {
                                TerminalScreen(session: TerminalSession(host: host, store: store, netbird: netbird))
                            } label: {
                                HostRow(host: host)
                            }
                            .swipeActions {
                                Button(role: .destructive) { store.delete(host: host) } label: { Label("Delete", systemImage: "trash") }
                                Button { editing = host } label: { Label("Edit", systemImage: "pencil") }.tint(.blue)
                            }
                        }
                    }
                }
                if store.hosts.isEmpty {
                    ContentUnavailableLabel()
                }
            }
            .searchable(text: $search)
            .navigationTitle("Hosts")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { editing = Host(username: "root") } label: { Image(systemName: "plus") }
                }
            }
            .sheet(item: $editing) { host in HostEditView(host: host) }
        }
    }
}

private struct HostRow: View {
    let host: Host
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(host.displayName).font(.headline)
                if host.viaNetbird { Image(systemName: "network").font(.caption).foregroundStyle(.orange) }
            }
            Text("\(host.username)@\(host.address):\(host.port)")
                .font(.caption.monospaced()).foregroundStyle(.secondary)
        }
    }
}

private struct ContentUnavailableLabel: View {
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "server.rack").font(.largeTitle).foregroundStyle(.secondary)
            Text("No hosts yet").font(.headline)
            Text("Tap + to add one, or pick a peer from the NetBird tab.")
                .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity).padding(.vertical, 40)
        .listRowBackground(Color.clear)
    }
}
