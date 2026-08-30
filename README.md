## SOC News Parser

從官方 RSS/Atom 找出指定時間窗內的文章，並在 feed 只有摘要或正文品質不合格時，改抓原始 HTML 解析真正文章內容。

### 正文擷取順序

1. 接受通過品質檢查且足夠完整的 RSS `content`。
2. 套用來源專屬 CSS selector。
3. 解析 JSON-LD 的 `articleBody`。
4. 使用 Trafilatura 做通用正文抽取。
5. 最後嘗試 `article`、`main` 等語意標籤。

解析結果會記錄 `extraction_method`、字元數及 warnings。Cloudflare 驗證頁、Access Denied、過短內容不會被當成文章正文。若完整 HTML 受阻但 RSS 有通過品質檢查的部分正文，會標成 `feed:*:partial`；兩者皆不可用時才標成 `extraction_method: "failed"`、`body` 留空。

所有 feed 與文章請求只允許 HTTPS、來源設定中的文章網域及公開 IP；每次 redirect 都會重新驗證，並以串流方式在解壓後 12 MiB 上限立即中止，避免 feed 連結造成 SSRF 或無界下載。

目前內建 25 個來源。除原始十個來源外，第一批高技術密度來源包括 ESET WeLiveSecurity、Securelist、SentinelLABS、Proofpoint Threat Insight、Recorded Future Insikt Group、SANS ISC、The DFIR Report、Elastic Security Labs、Check Point Research、CISA Advisories、watchTowr Labs、CERT/CC、TWCERT/CC TVN、NICS 與 HKCERT。

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

- `confirmed`：只限位於原文明確 IoC 章節的值。
- `candidate`：格式符合，但原文關係不足，必須人工複核；不計入 IoC 總數。
- `rejected`：出版者網域，或位於 Related、Latest News、References 等編輯區塊。

`confirmed` 代表「來源明確聲稱」，不是 parser 對惡意性的獨立背書。惡意工具家族及 ATT&CK 對映不做猜測，必須另外保存原文引句。
`unique_counts_by_status_and_type` 會公開各狀態及類型的唯一值計數；報告若決定不把檔名納入主旨的 IoC 總數，必須明示該計數政策，不能只呈現一個無法重算的總數。

產生多來源每日報告與完整稽核 JSON：

```bash
uv run soc-news-parser report \
  --hours 24 \
  --now 2026-08-30T01:21:00Z \
  --generated-at 2026-08-30T01:30:00Z \
  --json-output daily-evidence.json \
  --markdown-output daily-report.md
```

預設處理所有內建來源；可重複使用 `--source microsoft-security --source the-hacker-news` 限定來源。單一來源或文章失敗不會中止整批報告，錯誤會保存在 `source_failures` 或文章的 `extraction_method: "failed"`。

報告主旨的文章數只計標題或來源摘要具有明確資安主題訊號的文章；不相關文章仍保留在 JSON 的 `excluded_articles` 供稽核。IoC 總數採全報告唯一值，僅計 `confirmed` 的 MD5、SHA-1、SHA-256、IPv4/IPv6、domain 與 URL，檔名另行統計。

Markdown 是給收件者閱讀的標準報告，只呈現查核期間、相關文章、來源摘要、明確 IoC、相關檔名和必要方法說明。Report ID、parser 版本、正文 hash、warnings、candidate/rejected、排除文章及來源錯誤只保留於 JSON 稽核檔。兩份輸出在寄送前仍會驗證 Report ID 配對，並拒絕相同輸出路徑。

### 使用 Resend 寄送報告

先在 Resend 驗證寄件網域，並以環境變數提供憑證。程式不會從命令列參數接受或輸出 API key：

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

也可重複使用 `--to analyst@example.com` 指定收件人，並以 `--from` 覆寫寄件者。寄送前會確認 JSON 與 Markdown 的 Report ID 一致，兩份檔案都會以附件寄出；郵件正文會將 Markdown 安全渲染為標準 HTML，不顯示 parser/debug 欄位。Resend `POST /emails` 請求使用由 Report ID 與收件人衍生的 `Idempotency-Key`；24 小時內重試相同 payload 不會重複寄送。

附件原始總大小限制為 28 MiB，保留 Base64 後低於 Resend 每封 40 MB 的上限。遇到網路錯誤、HTTP 429 或 5xx 最多重試三次；其他 API 拒絕會立即回報且不宣稱寄送成功。

### 驗證

```bash
uv run pytest
```

程式使用一般瀏覽器 User-Agent 及公開頁面，不會繞過登入、付費牆或 CAPTCHA。遇到反機器人頁時會回報失敗，應改用有授權的 API、RSS 全文或人工複核。
