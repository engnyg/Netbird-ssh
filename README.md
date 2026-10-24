# NetBird SSH（iOS）

在 iPhone / iPad 上透過 [NetBird](https://github.com/netbirdio/netbird) 網路連 SSH 的 App，功能類似 Termius。

## 功能

- **內嵌 NetBird 節點**：使用 netbird 官方 `client/embed`（用戶態 netstack），不需要 VPN 設定檔或 Network Extension，所以可以用 AltStore / Sideloadly / TrollStore 側載。
- **SSH 終端機**：SwiftTerm（xterm-256color、鍵盤附加列含 Esc/Ctrl/Tab/方向鍵）、視窗縮放、Reconnect。
- **金鑰管理**：在裝置上產生 Ed25519 / ECDSA / RSA 金鑰，或匯入 OpenSSH / PEM 私鑰（可加密）；私鑰只存在 Keychain，可要求 Face ID / 密碼才能使用；可複製 / 分享公鑰。
- **主機清單**：分組、搜尋、帳密或金鑰登入；可從 NetBird peers 清單直接新增主機。
- **主機金鑰驗證**：優先比對 NetBird 記錄的 peer SSH 主機金鑰，否則 Termius / OpenSSH 式的首次信任（TOFU），金鑰變更會警告。
- 也可不經 NetBird 直連一般 SSH 主機（每個主機可切換）。

## 架構

```
iOS App (SwiftUI + SwiftTerm)
   └── NBSSHKit.xcframework  ← go/nbsshkit，由 gomobile 產生
         ├── netbird client/embed  (userspace WireGuard netstack)
         └── golang.org/x/crypto/ssh + netbird client/ssh (PTY)
```

netbird 在 iOS 目標上原本只支援 Network Extension 的 tun fd，`patches/0001-ios-netstack-mode.patch` 讓 iOS 也能像 Android 一樣走 netstack 模式；`patches/0002-embed-sso-login.patch` 在 `client/embed` 開放帳號（SSO）登入。CI 會 clone 固定 commit 的 netbird 並套用 patch（`scripts/fetch-netbird.sh`）。

## 編譯 IPA（GitHub Actions）

推送到 `master` / `claude/**` 分支、開 PR、打 `v*` tag 或手動觸發 **Build iOS IPA**，成品在 Actions 的 artifact `NetBirdSSH-unsigned-ipa`（打 tag 時另附到 Release）。

產出的是**未簽名 IPA**，安裝時由側載工具簽名：

- AltStore / Sideloadly：選 IPA，用你的 Apple ID 簽。
- TrollStore：直接安裝。

## 使用

1. App → NetBird 分頁：填 Management URL（自架請改）、裝置名稱。
2. 登入二選一：
   - **Sign in with account**：用 NetBird 設定的身分提供者（Google / Microsoft / Okta…）帳號登入，在 App 內的瀏覽器完成；若頁面無法完成可開啟 *Use device code*。
   - 或貼上後台建立的 **Setup Key**，按 Connect。
   換伺服器時先按 *Reset registration* 再登入新伺服器。
3. Keys 分頁：產生金鑰，複製公鑰貼到伺服器 `~/.ssh/authorized_keys`。
4. Hosts 分頁：新增主機（NetBird IP 或名稱）→ 點擊連線。

## 限制

- 隧道在 App 內執行；iOS 把 App 放到背景後會暫停，回到前景時工作階段會重新連線（沒有 Network Extension 就沒有背景常駐）。
- 目前沒有 SFTP / 連接埠轉發 / 巨集（Go 端 `x/crypto/ssh` 已可擴充）。

## 本機開發

```bash
scripts/fetch-netbird.sh          # 產生 .netbird-src
cd go && go test ./...            # Go 橋接層測試
# macOS：gomobile bind -target=ios -o ../ios/Frameworks/NBSSHKit.xcframework ./nbsshkit
#        cd ios && xcodegen generate && open NetBirdSSH.xcodeproj
```
