import Foundation
import LocalAuthentication
import Security

enum Keychain {
    private static let service = "com.engnyg.netbirdssh"

    static func set(_ data: Data, account: String, requireUserPresence: Bool = false) throws {
        delete(account: account)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
        ]
        if requireUserPresence {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &error)
            else { throw error!.takeRetainedValue() as Error }
            query[kSecAttrAccessControl as String] = access
        } else {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    /// Blocks while the system shows the Face ID prompt for protected items, so
    /// call it off the main thread.
    static func get(account: String, reason: String = "Unlock SSH key") -> Data? {
        let context = LAContext()
        context.localizedReason = reason
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func getString(account: String, reason: String = "Unlock SSH key") -> String? {
        get(account: account, reason: reason).flatMap { String(data: $0, encoding: .utf8) }
    }

    static func setString(_ value: String, account: String, requireUserPresence: Bool = false) throws {
        try set(Data(value.utf8), account: account, requireUserPresence: requireUserPresence)
    }

    static func delete(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
