## SOC News Parser

從官方 RSS/Atom 找出指定時間窗內的文章，並在 feed 只有摘要或正文品質不合格時，改抓原始 HTML 解析真正文章內容。

### 正文擷取順序

1. 接受通過品質檢查且足夠完整的 RSS `content`。
2. 套用來源專屬 CSS selector。
3. 解析 JSON-LD 的 `articleBody`。
4. 使用 Trafilatura 做通用正文抽取。
5. 最後嘗試 `article`、`main` 等語意標籤。

解析結果會記錄 `extraction_method`、字元數及 warnings。Cloudflare 驗證頁、Access Denied、過短內容不會被當成文章正文。若完整 HTML 受阻但 RSS 有通過品質檢查的部分正文，會標成 `feed:*:partial`；兩者皆不可用時才標成 `extraction_method: "failed"`、`body` 留空。JSON-LD `@graph` 最多走 64 個節點，避免環狀或過深結構拖垮擷取。沒有時區的 feed 日期會當成 UTC，並寫入來源診斷。

所有 feed 與文章請求只允許 HTTPS、來源設定中的文章網域及公開 IP；每次 redirect 都會重新驗證，並以串流方式在解壓後 12 MiB 上限立即中止，避免 feed 連結造成 SSRF 或無界下載。

目前內建 26 個來源。除原始十個來源外，高技術密度來源包括 ESET WeLiveSecurity、Securelist、SentinelLABS、Proofpoint Threat Insight、Recorded Future Insikt Group、SANS ISC、The DFIR Report、Elastic Security Labs、Check Point Research、CISA Advisories、watchTowr Labs、CERT/CC、TWCERT/CC TVN、NICS、HKCERT 與 Cyber Security News。

TWCERT/CC 等來源可能限制內容重製與公開散布；本工具預設用途是組織內部 SOC 分析。部署者仍須依自身使用方式確認授權，不應把抓取到的全文直接公開再發布。

### 安裝

需要 Python 3.12 及 [uv](https://docs.astral.sh/uv/)：

```bash
uv sync
```

### 使用

列出來源：

```bash
uv run soc-news-parser sources
```

擷取固定 UTC 結束時間之前 24 小時的文章：

```bash
uv run soc-news-parser feed microsoft-security \
  --hours 24 \
  --now 2026-08-30T01:21:00Z \
  --output microsoft.json
```

直接解析單篇難以擷取的文章：

```bash
uv run soc-news-parser article \
  "https://www.bleepingcomputer.com/news/security/brave-browser-adds-email-aliases-to-help-users-evade-tracking/" \
  --title "Brave browser adds email aliases to help users evade tracking"
```

產生可稽核 IoC evidence manifest：

```bash
uv run soc-news-parser audit \
  "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/" \
  --source microsoft-security \
  --title "TerminalFix campaign deploys a reverse tunnel through multistage intrusion" \
  --published-at 2026-08-29T03:43:27Z \
  --output terminalfix-evidence.json
```

Manifest 保存 canonical body、正文 SHA-256、擷取 warnings、parser 版本／Git revision、發布與擷取時間，以及每個候選值的原值、正規化值、行列位置、章節、上下文和理由：

- `confirmed`：原文明確 IoC 章節中的 hash／IP／domain／URL，以及正文中的 CVE ID、原文明確命名的惡意程式家族與 ATT&CK 技術。
- `candidate`：格式符合，但原文關係不足，必須人工複核；不計入 IoC 總數。
- `rejected`：出版者網域、非公開 IP，或位於 Related、Latest News、References、相關文章等編輯區塊。

`confirmed` 代表「來源明確聲稱」，不是 parser 對惡意性的獨立背書。惡意工具家族只在原文明確命名時入列；ATT&CK 技術必須同行出現 `ATT&CK` 或 `MITRE`。軟體版本號（如 `4.16.7.1`）與私有／迴環 IP 不會當成可操作 IoC。中文「妥協指標」「惡意網域」等標題與英文 IoC 章節同等效力。Markdown 雜訊（例如 `**Indicators of compromise (IoCs):-**`）會先正規化再比對，不會因為加粗或行尾符號就把整張表降成 candidate；內文句子提到 “indicators of compromise” 仍不當標題。IDN 網域的 `xn--` TLD 可抽取；不會只因為有 `[.]` 就把內文敘事升成 confirmed。
`confirmed_unique_iocs` 與報告主旨只計 hash、IP、domain、URL 與 CVE；檔名與原文指稱另行統計。`unique_counts_by_status_and_type` 仍列出各類型完整細項。

產生多來源每日報告與完整稽核 JSON：

```bash
uv run soc-news-parser report \
  --hours 24 \
  --now 2026-08-30T01:21:00Z \
  --generated-at 2026-08-30T01:30:00Z \
  --json-output daily-evidence.json \
  --markdown-output daily-report.md \
  --csv-output daily-iocs.csv
```

若有前一日的稽核 JSON，加上 `--previous-json yesterday-evidence.json`，報告會標出較昨日新增的 IoC，並統計新增／重複／今日未再出現的數量，方便值勤交接。沒有前一日檔案時不會猜測差異。

預設處理所有內建來源；可重複使用 `--source microsoft-security --source the-hacker-news` 限定來源。同一來源在時間窗內的多篇文章會各自擷取與抽 IoC，只依正規化 URL 去重（去掉 `utm_*`／點擊追蹤參數；非法 port 不會中斷整份報告），不會每站只留一篇。單一來源或文章失敗不會中止整批報告，錯誤會保存在 `source_failures` 或文章的 `extraction_method: "failed"`。同一 IoC 出現在多篇文章時，主旨總數只計一次。

郵件主旨改為值班可掃描的處置數字：待修 CVE、待封鎖網路指標、待 hunt 端點指標、相關文章數。這三個處置數字與 IoC 總數一樣採全報告唯一值；同一 CVE 被兩家媒體寫到只計一次，清單仍保留各來源列供對照。文章數只計標題或來源摘要具有明確資安主題訊號的文章；不相關文章仍保留在 JSON 的 `excluded_articles` 供稽核。IoC 總數僅計 `confirmed` 的 MD5、SHA-1、SHA-256、IPv4/IPv6、domain、URL 與 CVE，檔名與原文指稱另行統計。

Markdown 是給 SOC／威脅分析師閱讀的值班報告：開頭是今日優先處置一句話，接著是修補、封鎖、Hunt、監控、觀察清單。每個 CVE 的 CVSS 與影響只取該指標所在文句，不會把同篇最高分套到全部漏洞。事件叢集只在同一 CVE 出現於兩篇以上來源時列出。監控／觀察只在標題或來源摘要寫成外洩、釣魚活動或勒索事件時列出；產品文正文帶過 phishing／個資不會進處置清單，文章仍留在報告後半。公共遞迴 DNS（例如 `8.8.8.8`、`1.1.1.1`、`dns.google`）若出現在 IoC 章節仍記成 confirmed，但降為 hunt 複核，不列入待封鎖；不會把 AWS／CDN／GitHub 整段降級。清單只根據原文明確的 CVE、IoC 章節指標與原文影響用語產生，不把 candidate 升成 confirmed。Report ID、parser 版本、正文 hash、warnings、candidate/rejected、排除文章及來源錯誤只保留於 JSON 稽核檔。CSV 是一列一個可操作指標。JSON 會寫入 `reader_digest`（Markdown 的 SHA-256），寄送前用它核對兩份檔案仍成對，並拒絕相同輸出路徑。

### 使用 Resend 寄送報告

先在 Resend 驗證寄件網域，並以環境變數提供憑證。工作目錄的 `.env` 會在變數尚未設定時自動載入。程式不會從命令列參數接受或輸出 API key：

```bash
export RESEND_API_KEY="re_..."
export RESEND_FROM="SOC Reports <reports@your-verified-domain.example>"
export RESEND_TO="solar324yao@gmail.com"
```

先執行不會寄信的驗證：

```bash
uv run soc-news-parser send-report \
  --json-report daily-evidence.json \
  --markdown-report daily-report.md \
  --dry-run
```

確認後發送：

```bash
uv run soc-news-parser send-report \
  --json-report daily-evidence.json \
  --markdown-report daily-report.md
```

也可重複使用 `--to analyst@example.com` 指定收件人，並以 `--from` 覆寫寄件者。寄送前會確認 JSON 與 Markdown 的 Report ID 一致，並從該份 JSON 現算 `iocs.csv`（沒有可操作指標時仍附表頭）。三份檔案都會以附件寄出；郵件正文會將 Markdown 安全渲染為標準 HTML，不顯示 parser/debug 欄位。Resend `POST /emails` 請求使用由 Report ID 與收件人衍生的 `Idempotency-Key`；24 小時內重試相同 payload 不會重複寄送。

附件原始總大小限制為 28 MiB，保留 Base64 後低於 Resend 每封 40 MB 的上限。遇到網路錯誤、HTTP 429 或 5xx 最多重試三次；其他 API 拒絕會立即回報且不宣稱寄送成功。

### 每日台北時間 06:00 發送

預設時區是 `Asia/Taipei`（GMT+8），預設發送時刻是 06:00。每次會蒐集該時刻往回 24 小時的文章（例如 8/30 06:00 寄出的是 8/29 06:00 ～ 8/30 06:00），寫入 `reports/YYYY-MM-DD/`，並寄到 `RESEND_TO`。若前一日資料夾已有 JSON，會自動當昨日對照。同一班次的 `generated_at` 固定在 06:00，重試不會重複寄出。

先確認不會真的寄信：

```bash
uv run soc-news-parser deliver --dry-run
```

在會長駐的機器上用 cron（建議做法）：

```bash
./deploy/install-taipei-cron.sh
```

或手動加入 crontab，務必帶 `CRON_TZ`：

```cron
CRON_TZ=Asia/Taipei
0 6 * * * cd /path/to/soc-news-parser && /path/to/uv run soc-news-parser deliver --hours 24 --at 06:00 --timezone Asia/Taipei --output-dir /path/to/soc-news-parser/reports >> /path/to/soc-news-parser/reports/deliver.log 2>&1
```

沒有 cron 時可讓程式自己等到下一班 06:00：

```bash
uv run soc-news-parser schedule --at 06:00 --timezone Asia/Taipei
```

此命令只在程序持續執行時有效。雲端工作階段或筆電休眠後不會繼續寄信，請把 cron 裝在會一直開著的主機或 NAS 上。

### 驗證

```bash
uv run pytest
```

程式使用一般瀏覽器 User-Agent 及公開頁面，不會繞過登入、付費牆或 CAPTCHA。遇到反機器人頁時會回報失敗，應改用有授權的 API、RSS 全文或人工複核。
