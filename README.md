## SOC News Parser

從官方 RSS/Atom 找出指定時間窗內的文章，並在 feed 只有摘要或正文品質不合格時，改抓原始 HTML 解析真正文章內容。

### 正文擷取順序

1. 接受通過品質檢查且足夠完整的 RSS `content`。
2. 套用來源專屬 CSS selector。
3. 解析 JSON-LD 的 `articleBody`。
4. 使用 Trafilatura 做通用正文抽取。
5. 最後嘗試 `article`、`main` 等語意標籤。

擷取前會先剝除頁面裝飾：`script`、`nav`、`footer`、`aside`、廣告與社群分享區塊之外，另含側欄（`side-widget`、`sidebar`）、上下篇導覽與瀏覽計數器等每次載入都會變動的區域。來源可用 `exclude_selectors` 再補自己的選擇器（例如 SecurityWeek 的 `div.zox-side-widget`、HKCERT 的 `div.page-date--btm`）；選擇器寫錯不會讓整篇文章擷取失敗。解析結果會記錄 `extraction_method`、字元數及 warnings。Cloudflare 驗證頁、Access Denied、過短內容不會被當成文章正文。若完整 HTML 受阻但 RSS 有通過品質檢查的部分正文，會標成 `feed:*:partial`；兩者皆不可用時才標成 `extraction_method: "failed"`、`body` 留空。正文未取得的文章**不會**被寫成「原文未提供明確指標」——沒讀到的內容不能下任何斷言。它會列入處置清單的「人工複核」，並標明原因（例如「來源回應 HTTP 403，疑似反機器人阻擋」「頁面沒有可解析的正文結構」），報告表頭也會出現「未能取得全文：N 篇（需人工複核）」。複核項不計入待修／待封鎖／待 hunt，也不進 CSV，因為它沒有可操作的指標。JSON-LD `@graph` 最多走 64 個節點，避免環狀或過深結構拖垮擷取。沒有時區的 feed 日期會當成 UTC，並寫入來源診斷。

所有 feed 與文章請求只允許 HTTPS、來源設定中的文章網域及公開 IP；每次 redirect 都會重新驗證，並以串流方式在解壓後 12 MiB 上限立即中止，避免 feed 連結造成 SSRF 或無界下載。

目前內建 26 個來源。除原始十個來源外，高技術密度來源包括 ESET WeLiveSecurity、Securelist、SentinelLABS、Proofpoint Threat Insight、Recorded Future Insikt Group、SANS ISC、The DFIR Report、Elastic Security Labs、Check Point Research、CISA Advisories、watchTowr Labs、CERT/CC、TWCERT/CC TVN、NICS、HKCERT 與 Cyber Security News。

TWCERT/CC 等來源可能限制內容重製與公開散布；本工具預設用途是組織內部 SOC 分析。部署者仍須依自身使用方式確認授權，不應把抓取到的全文直接公開再發布。

部分來源（例如 Dark Reading）對文章頁回 HTTP 403 反機器人阻擋，且其 RSS 只有約 180 字摘要、沒有 `content:encoded`。本工具不會嘗試繞過，這些文章一律走人工複核。要取得全文請改用該來源的授權 API 或訂閱。

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

網域的最後一段必須是 IANA root zone 實際委派的 TLD，清單以 `src/soc_news_parser/data/iana_tlds.txt` 隨套件封存（含 `xn--` punycode），不在執行期連外查詢，確保同一份正文永遠得到同一份 manifest。因此 `out.tmp`、`user.enc`、`system.drawing`、`robots.txt` 這類帶點號的檔案／識別字不會被誤判成網域而混進待封鎖清單。若該行以 `File name(s)`、`payload`、`attachment` 等字樣引導，值仍會保留並改記成 `filename` 進 hunt 清單，不會整個丟掉。更新 TLD 清單：

```bash
curl -s https://data.iana.org/TLD/tlds-alpha-by-domain.txt \
  | tr 'A-Z' 'a-z' | sort > src/soc_news_parser/data/iana_tlds.txt
```

副檔名比對排在網域之前，所以 `.zip`、`.py`、`.mov` 這些同時是合法 TLD 的字尾會先判成檔名。`.onion`、`.i2p`、`.bit` 雖未在 root zone 委派，但它們指向真實的攻擊基礎設施，因此明確納入；`.local`、`.localhost`、`.invalid`、`.example` 這類文件／私網保留字仍排除。

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

Markdown 是給 SOC／威脅分析師閱讀的值班報告：開頭是今日優先處置一句話，接著是修補、封鎖、Hunt、監控、觀察清單。每個 CVE 的 CVSS 與影響只取該指標所在文句，不會把同篇最高分套到全部漏洞。事件叢集只在同一 CVE 出現於兩篇以上來源時列出。監控／觀察只在標題或來源摘要寫成外洩、釣魚活動或勒索事件時列出；產品文正文帶過 phishing／個資不會進處置清單，文章仍留在報告後半。公共遞迴 DNS（例如 `8.8.8.8`、`1.1.1.1`、`dns.google`）與靜態清單中的品牌官網／子網域（例如 `claude.ai`、`code.claude.ai`、`microsoft.com`）若出現在 IoC 章節仍記成 confirmed，但降為 hunt 複核，不列入待封鎖。不會用「主機名含品牌字」或平台後綴（`gitlab.io`、`github.io`、`squarespace.com`、`it.com`）做白名單；`claude.ai.download-app.us`、`claude-desktop.gitlab.io` 仍待封鎖。同篇文章若已有較長子網域，兩標籤且左標籤長度 ≤ 3 的父網域（例如 `it.com` 對 `downloading-api.it.com`）改為 hunt；`download-app.us` 這類長左標籤父網域仍與子網域一併封鎖。清單只根據原文明確的 CVE、IoC 章節指標與原文影響用語產生，不把 candidate 升成 confirmed。報告後半只給有明確指標、或未能取得全文的文章完整區塊；已讀到全文但沒有指標的文章集中在「其他相關文章」，一篇一行（標題連結、來源、時間、摘要摘要至 160 字），情勢掌握仍在，但不再淹沒處置清單。所有文章都保留在報告中，完整正文與候選值見 JSON。指標的「上下文」行只在原文句子確實多於指標本身時才列出；上下文等於指標值時整行省略，以指標值開頭時去掉開頭那次重複（值就在正上方）。Markdown 中的網域、IP 與 URL 一律 defang（`example[.]com`、`hxxp://`），包含處置清單、今日優先那行、以及上下文句子裡以 IANA TLD 判定為主機的字串，避免郵件用戶端把惡意主機變成可點連結；來源引用連結不受影響，仍可點擊。CSV、JSON 稽核檔與 D1／MCP 保持原值，那些是機器要用的。Report ID、parser 版本、正文 hash、warnings、candidate/rejected、排除文章及來源錯誤只保留於 JSON 稽核檔。CSV 是一列一個可操作指標。JSON 會寫入 `reader_digest`（Markdown 的 SHA-256），寄送前用它核對兩份檔案仍成對，並拒絕相同輸出路徑。

### CVE 加值：CISA KEV 與 NVD

原文常只寫 CVE 編號，不寫 CVSS，也不會說這個漏洞是否正在被攻擊。`report` 與 `deliver`
預設會把當日所有 `confirmed` CVE 拿去比對 CISA KEV 目錄與 NVD，讓「73 個待修 CVE」變成
「其中 3 個已知遭利用，今天就要修」。

加值資料是**第三方主張，不是原文說的**，所以與 evidence manifest 完全分開存放：
manifest 仍然只記錄原文明確寫了什麼，加值結果放在 JSON 的 `cve_intel`，每筆帶自己的
`sources` 與 `retrieved_at`。`candidate` 不會因為加值而升成 `confirmed`。

處置清單的變化：

- KEV 一律升為 HIGH。已確認在野利用，優先於任何文字訊號。
- CVSS 取 NVD 與原文兩者較高者判定優先級；NVD 若只有暫定低分，不會把原文標為高分的漏洞悄悄降級。
- 修補清單排序為 KEV → 優先級 → CVSS → CISA 修補期限；沒有任何分數但原文寫明 RCE 的 CVE 不會被排到已知低分項之後。KEV 項目標上 `【KEV】`。
- 理由欄寫明來源，例如 `KEV 已知遭利用，CISA 修補期限 2026-09-18；CVSS 9.8 CRITICAL（NVD）`。
  原文自己寫的分數會標成 `（原文）`，兩者不會混淆。
- 郵件主旨變成 `待修 73（KEV 3）`；報告表頭多一行「其中已知遭利用（CISA KEV）」。**該行只在 KEV 目錄確實載入成功時出現** —— 沒查到就不會寫「0 個」，因為那等於對沒檢查過的事下斷言。
- CSV 多四欄：`kev`、`kev_due_date`、`cvss_score`、`cvss_severity`。

查詢全部走與抓新聞相同的加固通道（HTTPS、主機白名單、公開 IP、redirect 重新驗證、
12 MiB 上限）。**任何加值失敗都不會中斷報告**：錯誤記在 JSON 的 `enrichment.errors`，
Markdown 會標「CVE 加值有 N 項查詢失敗」，報告照常寄出，只是 KEV／CVSS 欄位不完整。

同一時間窗重跑會得到相同的 Report ID。識別碼取自**抽取到的證據**，不是原始正文雜湊 —— 瀏覽計數器、輪播側欄這類頁面裝飾會讓同一篇未變動文章的 `body_sha256` 每次抓取都不同（實測 46 篇中有 7 篇如此），若用它當識別碼，重試就會產生新 ID、讓 Resend 的冪等鍵失效而重複寄出。加值的實質內容（KEV、CVSS）計入識別碼，查詢時戳不計入。指標若真的增減，ID 仍會改變。

結果會快取在 `--cache-dir`（預設 `.cache/enrichment`）。同一天重跑不會再發任何請求；
隔天只查沒看過的 CVE。已有分數的 CVE 快取 7 天，NVD 尚未評分的每天重查一次。

NVD 未帶 API key 時限制每 30 秒 5 次請求，73 個新 CVE 大約要 9 分鐘。申請免費 key 後
放進環境變數可提高到每 30 秒 50 次：

```bash
export NVD_API_KEY="..."
```

API key 只會送往 `services.nvd.nist.gov`；若 redirect 離開該主機，header 會被丟掉。

要完全關掉加值（離線環境、或只想要原文事實）：

```bash
uv run soc-news-parser report --no-enrich ...
uv run soc-news-parser deliver --no-enrich
```

關掉時報告會明講「CVE 加值：未啟用，CVSS 僅取自原文，未比對 CISA KEV」。

### 使用 Resend 寄送報告

先在 Resend 驗證寄件網域，並以環境變數提供憑證。工作目錄的 `.env` 會在變數尚未設定時自動載入。程式不會從命令列參數接受或輸出 API key：

```bash
export RESEND_API_KEY="re_..."
export RESEND_FROM="SOC Reports <reports@your-verified-domain.example>"
export RESEND_TO="solar324yao@gmail.com,shar.tseng@jjnet.com.tw"
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

沒有會長駐的主機時，用 GitHub Actions 跑同一支 `deliver`。工作流程在 `.github/workflows/daily-deliver.yml`：UTC 22:00（台北 06:00）排程，也可用 Actions 介面手動觸發。把倉庫推到 GitHub 的預設分支，並設定這三個 Repository secrets：

- `RESEND_API_KEY`
- `RESEND_FROM`（已驗證寄件者，例如 `IOC Reports <reports@your-verified-domain.example>`）
- `RESEND_TO`

排程只在 GitHub 預設分支生效；Cursor Cloud Agent 或尚未推到 GitHub 的遠端不會跑 Actions。GitHub 的 cron 可能延遲數分鐘到數小時，免費倉庫若 60 天沒有新 commit，排程會被停用。昨日對照靠 Actions cache 帶回 `reports/`，cache 未命中時仍會出報，只是沒有較昨日新增的統計。報告會當 artifact 保留 14 天，不會 commit 進 git。

在會長駐的機器上也可以繼續用 cron：

```bash
./deploy/install-taipei-cron.sh
```

或手動加入 crontab，務必帶 `CRON_TZ`：

```cron
CRON_TZ=Asia/Taipei
0 6 * * * cd /path/to/soc-news-parser && /path/to/uv run soc-news-parser deliver --hours 24 --at 06:00 --timezone Asia/Taipei --output-dir /path/to/soc-news-parser/reports >> /path/to/soc-news-parser/reports/deliver.log 2>&1
```

沒有 cron、也還沒接 GitHub Actions 時，可讓程式自己等到下一班 06:00：

```bash
uv run soc-news-parser schedule --at 06:00 --timezone Asia/Taipei
```

此命令只在程序持續執行時有效。雲端工作階段或筆電休眠後不會繼續寄信。

### IoCs MCP（給 Cursor 與外部 LLM／Agent）

每日 `deliver` 把確認 IoC 寫進 `reports/YYYY-MM-DD/daily-evidence.json`。MCP 只讀這些檔，**不會**自己爬網。要給外部模型用，請開 **Streamable HTTP**，不要只用 Cursor 本機 stdio。

工具相同：`list_reports`、`get_report_summary`、`search_confirmed_iocs`、`lookup_ioc`。

**1. 本機 Cursor（stdio）**

```bash
uv run soc-news-parser mcp
```

專案裡的 `.cursor/mcp.json` 會啟動這個程序。Settings → MCP 允許 `iocs` 即可。

**2. 外部 LLM／Agent（HTTP，需要 Bearer token）**

在會長駐、能讀到 `reports/` 的機器上：

```bash
export SOC_IOC_REPORTS_DIR=/path/to/soc-news-parser/reports
export SOC_IOC_MCP_TOKEN="$(openssl rand -hex 32)"
uv run soc-news-parser mcp --http --host 0.0.0.0 --port 43124
```

- `GET /health` 不需 token（探活）
- `POST /mcp` 必須帶 `Authorization: Bearer <SOC_IOC_MCP_TOKEN>`
- 沒有 token 會拒絕啟動

對外匯出時請用 HTTPS 反代（Caddy／nginx），不要把 HTTP 裸掛在公網。Cloud Agent 會收工，不適合當這台 MCP 主機。

外部 Cursor／Claude／自建 agent 的設定例：

```json
{
  "mcpServers": {
    "iocs": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${env:SOC_IOC_MCP_TOKEN}"
      }
    }
  }
}
```

報告目錄預設 `reports/`，可用 `SOC_IOC_REPORTS_DIR` 覆寫。MCP 的 `date` 參數只接受 `YYYY-MM-DD` 且必須是真實日期；解析後的路徑會再確認仍位於報告根目錄內，因此帶 `..`、斜線或指向外部的符號連結都會被拒絕，不會讀到根目錄以外的檔案。`list_reports` 也只列出符合日期格式的資料夾。

### 對外服務：Cloudflare Workers + D1

要讓外部 LLM／Agent 查詢歷史指標，本機的檔案式 MCP 有兩個先天限制：只查最新一份報告，
而且完全比對 —— log 裡的 `sub.evil.com` 對不上報告裡的 `evil.com`。`deploy/worker/`
是解法：D1 就是 SQLite，跨日期查詢、父網域比對、批次查詢都變成有索引的讀取。

沒有主機要維護。每日 Actions 把當日指標推進去，Worker 只讀。

`canonical_body` **不會**離開稽核檔 —— 那是 26 家出版商的全文。上傳的是指標值（事實）、
本專案自己的處置判斷、KEV／NVD（公共領域）、以及標題與連結（引用）。`context` 是原文
逐字句，截到 300 字元，且只發給持有 `context` scope 的 token；只有 `read` 的 token 仍
拿得到完整命中與引用連結，自行去原文閱讀。

推送與部署見 `deploy/worker/README.md`。單日匯出：

```bash
uv run soc-news-parser export-d1   --json-report reports/2026-09-05/daily-evidence.json   --output /tmp/2026-09-05.sql
```

重推同一天會先刪除當日資料再寫入，所以修正後的報告是取代而非疊加。

### 驗證

```bash
uv run pytest
```

程式使用一般瀏覽器 User-Agent 及公開頁面，不會繞過登入、付費牆或 CAPTCHA。遇到反機器人頁時會回報失敗，應改用有授權的 API、RSS 全文或人工複核。
