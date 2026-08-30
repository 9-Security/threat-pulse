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

目前內建原始十個來源：The Hacker News、BleepingComputer、Krebs on Security、Dark Reading、SecurityWeek、The Record、Unit 42、Cisco Talos、Microsoft Security Blog、Google Cloud/Mandiant。

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

報告主旨的 IoC 總數採全報告唯一值，僅計 `confirmed` 的 MD5、SHA-1、SHA-256、IPv4/IPv6、domain 與 URL；檔名另行統計。Markdown 只列 confirmed 指標與證據，candidate／rejected 的逐筆紀錄保留在 JSON。兩份輸出具有相同 Report ID，會拒絕相同輸出路徑並先完成暫存寫入再替換。

### 驗證

```bash
uv run pytest
```

程式使用一般瀏覽器 User-Agent 及公開頁面，不會繞過登入、付費牆或 CAPTCHA。遇到反機器人頁時會回報失敗，應改用有授權的 API、RSS 全文或人工複核。
