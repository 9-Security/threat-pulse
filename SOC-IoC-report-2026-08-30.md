# 每日資安新聞 IoC 彙整報告

- 報告時間：2026-08-30 01:21 UTC
- 查核區間：2026-08-29 01:21 UTC ～ 2026-08-30 01:21 UTC
- 來源：The Hacker News、BleepingComputer、Krebs on Security、Dark Reading、SecurityWeek、The Record、Unit 42、Cisco Talos、Microsoft Security Blog、Google Cloud/Mandiant
- 符合區間文章數：5
- 明確 IoC 數：15（11 個 SHA-256、3 個網域、1 個 URL；以唯一值計數）
- 建議郵件主旨：`[SOC] 每日資安新聞 IoC 彙整報告 - 文章數 5 / IoC數 15`

> 計數原則：僅計入原文明確列在 IoC 區段中的唯一指標。檔名及合法程式被濫用時的名稱另列為調查線索，不灌入 IoC 總數。Defanged 網路指標已還原；上下文仍保留原文寫法供複核。

## 1. Microsoft Security Blog

### TerminalFix campaign deploys a reverse tunnel through multistage intrusion

- 發布時間：2026-08-29 03:43:27 UTC
- 原文：[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
- 惡意工具／家族：TerminalFix（ClickFix 變體）
- 其他原文明確偵測名稱：`Trojan:Win32/ClickFix.*`、`Trojan:Win32/TermFix.*`、`Trojan:Win32/Posilod.*`、`Trojan:Win64/DLLHijack.DAB!MTB`、`Trojan:Python/Indigo.SA`

#### 攻擊手法摘要

遭入侵網站顯示假的 Cloudflare Turnstile CAPTCHA，誘導使用者將剪貼簿中的惡意 PowerShell 指令貼入 Windows Terminal／PowerShell。指令下載 ZIP，透過合法的 `LockScreenContentServer.exe` 側載惡意 `dui70.dll`；後續以 PNG 像素隱寫傳遞並重組 payload，以 Registry Run key 和每 60 分鐘執行的排程工作維持持久性，執行 Active Directory／網域／伺服器偵察，最後使用 Python 植入程式透過 TLS WebSocket 建立反向通道及 SOCKS 類型的任意 TCP 代理。

原文特別聲明，分析鏈中**未觀察到**後續提權、停用防護、資料外洩或勒索軟體部署；因此本報告不將這些可能的後續行為記為已發生。

#### Hash IoCs

| 類型 | 值 | 原文上下文 |
|---|---|---|
| SHA-256 | `18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f` | “Initial ZIP archive (verify_pkg.zip)”；正文亦稱下載的 ZIP archive。 |
| SHA-256 | `b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a` | “Custom tunnel implant (client.py)”。 |
| SHA-256 | `ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07` | “Malicious DLL (dui70.dll)”。 |
| SHA-256 | `026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab` | “Malicious DLL (dui70.dll)”。 |
| SHA-256 | `032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22` | “Malicious DLL (dui70.dll)”。 |
| SHA-256 | `df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf` | “Malicious DLL (dui70.dll)”。 |
| SHA-256 | `eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0` | “Malicious DLL (dui70.dll)”。 |
| SHA-256 | `5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8` | “Malicious DLL (dui70.dll)”。 |
| SHA-256 | `9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24` | “Malicious DLL (dui70.dll)”。 |
| SHA-256 | `342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e` | “Malicious DLL (dui70.dll)”。 |
| SHA-256 | `ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d` | “Malicious DLL (dui70.dll)”。 |

#### 網路 IoCs（已還原 defang）

| 類型 | 還原值 | 原文值 | 原文上下文 |
|---|---|---|---|
| Domain | `gitnow.dev` | `gitnow[.]dev` | “C2 server for custom reverse tunnel implant (port 443)”；正文稱 TLS WebSocket reverse tunnel 連往該網域的 443 port。 |
| Domain | `bestsocialmedianewspapper.com` | `bestsocialmedianewspapper[.]com` | “Steganographic image hosting / payload delivery”。 |
| Domain | `offlineupdater.com` | `offlineupdater[.]com` | “Steganographic image hosting / failover”。 |
| URL | `https://linked-log.com/` | `hxxps://linked-log[.]com/` | “Compromised website”。 |

- IP 位址：原文未提供。
- MD5／SHA-1：原文未提供。

#### 可疑檔案／執行線索

| 名稱 | 上下文 |
|---|---|
| `verify_pkg.zip` | 初始下載 ZIP；原文 IoC 表將對應 SHA-256 描述為 “Initial ZIP archive”。 |
| `dui70.dll` | 攻擊者置於合法執行檔旁的惡意 DLL，藉 DLL sideloading 執行第二階段 PowerShell。 |
| `client.py` | 自訂 Python 反向通道植入程式。 |
| `1.bat` | 初始 PowerShell 解壓後靜默啟動的批次檔。 |
| `LockScreenContentServer.exe` | 合法簽章 Windows 執行檔；從非標準路徑執行並載入同目錄 `dui70.dll` 時具調查價值，本身不可單獨判定為惡意。 |
| `pythonw.exe` | 合法 Python 無視窗執行程式；原文觀察其啟動 `client.py`，本身不可單獨判定為惡意。 |

## 2. The Hacker News

### Five Critical WordPress Plugin and Theme Flaws Enable Site Takeover or RCE

- 發布時間：2026-08-29 21:55:03 +05:30（2026-08-29 16:25:03 UTC）
- 原文：[The Hacker News](https://thehackernews.com/2026/08/five-critical-wordpress-plugin-and.html)
- 惡意工具／家族：未提及。
- 攻擊手法摘要：文章列出 WPMU DEV Dashboard、Avada/Fusion Builder、TranslatePress、Pods 與 GiveWP 的五項重大漏洞，明確描述的影響包括未驗證身分繞過、管理員帳號接管、任意檔案寫入、權限提升／密碼變更、遠端程式碼或任意命令執行。文章列出的漏洞識別碼為 `CVE-2026-76581`、`CVE-2026-18431`、`CVE-2026-19632`、`CVE-2026-19598`、`CVE-2026-82222`。
- **無擷取到 IoC**：文章未提供 hash、IP、惡意網域／URL 或可疑檔名。CVE 編號不是本報告定義的 IoC，故不納入 IoC 數。

## 3. SecurityWeek

### Hasbro Data Breach Exposed Employee Personal Information

- 發布時間：2026-08-29 11:55:00 UTC
- 原文：[SecurityWeek](https://www.securityweek.com/hasbro-data-breach-exposed-employee-personal-information/)
- 惡意工具／家族：未提及。
- 攻擊手法摘要：Hasbro 表示今年稍早發現涉及其網路的資安事件，部分現任及前任員工個資可能遭存取；公司將部分系統離線並展開外部協助調查。文章明確指出尚無已知網路犯罪集團在資料外洩網站列出 Hasbro，且 Hasbro 表示未發現個資遭濫用。原文沒有交代初始入侵方法，故不推測。
- **無擷取到 IoC**：文章未提供 hash、IP、惡意網域／URL 或可疑檔名。

## 4. BleepingComputer

### Brave browser adds email aliases to help users evade tracking

- 發布時間：2026-08-29 10:19:23 EDT（2026-08-29 14:19:23 UTC）
- 原文：[BleepingComputer](https://www.bleepingcomputer.com/news/security/brave-browser-adds-email-aliases-to-help-users-evade-tracking/)
- 惡意工具／家族：未提及。
- 攻擊手法摘要：本篇不是攻擊事件。文章說明郵件地址外洩可被用於跨網站身分關聯、垃圾郵件及後續網路釣魚，並介紹 Brave Email Aliases 與 OPAQUE 驗證的防護方式；未描述具體威脅活動。
- **無擷取到 IoC**：文章未提供 hash、IP、惡意網域／URL 或可疑檔名。

## 5. BleepingComputer

### Anthropic is cutting Claude Code's current weekly limits by 17%

- 發布時間：2026-08-29 19:11:51 EDT（2026-08-29 23:11:51 UTC）
- 原文：[BleepingComputer](https://www.bleepingcomputer.com/news/artificial-intelligence/anthropic-is-cutting-claude-codes-current-weekly-limits-by-17-percent/)
- 惡意工具／家族：未提及。
- 攻擊手法摘要：不適用；本文是 Claude Code 用量上限政策變更，並非資安事件。正文尾端的攻防模擬文字屬贊助內容，未作為文章威脅情報。
- **無擷取到 IoC**：文章未提供 hash、IP、惡意網域／URL 或可疑檔名。

## 來源查核結果

| 來源 | 指定區間結果 |
|---|---|
| The Hacker News | 1 篇。 |
| BleepingComputer | 2 篇；一般網頁擷取受到 Cloudflare 驗證阻擋，改以標準 RSS reader User-Agent 取得官方 RSS 並查閱正文。 |
| Krebs on Security | 0 篇；Feed 最後更新為 2026-08-27。 |
| Dark Reading | 0 篇；官方 RSS 最新文章為 2026-08-28 20:19:22 UTC，早於起點。 |
| SecurityWeek | 1 篇。 |
| The Record | 0 篇；Feed 最新文章為 2026-08-28 16:30 UTC。 |
| Unit 42 | 0 篇；Feed 最新文章為 2026-08-28 22:00:07 UTC，早於起點 3 小時 20 分 53 秒。 |
| Cisco Talos | 0 篇；Feed 最後更新為 2026-08-27。 |
| Microsoft Security Blog | 1 篇。 |
| Google Cloud/Mandiant | 0 篇；Threat Intelligence Feed 最新文章為 2026-08-20。 |

## 人工複核注意事項

1. Defanged 指標的還原僅做字面正規化：`[.]` → `.`、`hxxps` → `https`，未對指標做存活性或歸屬推測。
2. `LockScreenContentServer.exe` 與 `pythonw.exe` 是合法程式，只有搭配原文所述路徑、參數、子程序及網路行為時才具偵測意義。
3. 本報告未把新聞頁自身、廣告、分析廠商或一般參考連結誤列為 IoC。
