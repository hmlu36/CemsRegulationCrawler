# CEMS 法規網址自動監測器

此原型會由 Word 清單建立網址設定，定期比對官方網頁與附件是否更新，
並在有變更或錯誤時產生報告、下載新版檔案及發送通知。

## 判斷方式

1. 優先使用網站提供的 `ETag` 與 `Last-Modified`。
2. 一般網頁移除選單、頁尾、腳本與空白後，計算內容 SHA-256。
3. 同時比對頁面內 PDF／Word／Excel／ZIP 附件清單，發現新附件即視為變更。
4. 直接文件網址以檔案位元組 SHA-256 比對。
5. 變更後將內容、雜湊、原始網址、最終網址及伺服器時間戳存入 `archive/`。

這種設計可避免只看「頁面最後修改日期」造成漏報，也能降低導覽列或
Cookie 提示變化造成的誤報。

## 建立網址設定

```bash
python extract_urls.py "各國各地區CEMS相關法規官方網址或參考文獻.docx" \
  --output sources.json
```

產生後應人工檢查 `sources.json`：

- `priority: official`：政府或官方法規來源，建議每週監測。
- `priority: review`：需人工確認是否為官方或可信來源。
- `priority: reference`：搜尋頁、新聞、顧問或學術參考，預設不作主要法規警報。
- Google 搜尋網址會自動停用，應改成真正的官方落地頁。
- 同一法規若同時有彙整頁與 PDF，兩者都保留；彙整頁可發現新版附件，
  PDF 可驗證現行版本內容。

## 本機執行

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python monitor.py --config sources.json --root . --priority official
```

第一次執行只是建立基準，不會把所有網址誤判成更新。第二次起才會顯示
`changed`。查看 `latest_report.md`，狀態資料存於 `monitor_state.sqlite3`。

加上 `--notify` 可啟用 `.env.example` 所列的 webhook／SMTP 通知環境變數。
正式部署時應把密碼放在 GitHub Actions Secrets、NAS 排程器的秘密管理，
或雲端 Secret Manager，勿寫入程式及設定檔。

## 定期執行

### GitHub Actions

把 `run_weekly.yml` 複製為 `.github/workflows/cems-monitor.yml`，每週一台北
時間 09:00 執行。若要保存 SQLite 與下載檔案，repository 必須允許 workflow
寫入；若不希望自動 commit，可刪除 commit/push 步驟，改用 artifact 或物件儲存。

### Windows 工作排程器

動作可設為：

```text
程式：C:\path\to\.venv\Scripts\python.exe
引數：monitor.py --config sources.json --root . --priority official --notify
開始位置：C:\path\to\cems_regulation_monitor
```

建議每週一次；對經常修法的主管機關新聞／公告頁可改成每日。

## 正式化前的重要補強

- JavaScript 動態網站：為該站建立 Playwright 專用擷取器，等待指定元素後再取內容。
- Cloudflare／驗證碼：不要繞過；改用 RSS、官方 API、電子報或人工覆核。
- robots.txt 與使用條款：逐站確認，設定 0.5–2 秒延遲，不高頻抓取。
- PDF 內容比對：目前以整檔雜湊判斷。若網站會重製同內容 PDF，應另加
  `pypdf` 文字抽取與正規化，區分「檔案重打包」與「條文實質變更」。
- 法規語意摘要：變更後再交給 LLM 比對新舊文本，產生「條次、日期、適用對象、
  QA/QC、資料有效率、申報頻率、裁罰」摘要；不要讓 LLM 取代原始檔雜湊與存證。
- 稽核軌跡：保留抓取時間、HTTP 標頭、SHA-256、重新導向後網址與原始檔，
  才能回溯「何時發現何種版本」。

## 建議的維運分層

- 每週：`official`
- 每月人工檢查：`review`（確認來源是否更換或失效）
- 僅供研究：`reference`
- 連續三次錯誤：列為維護事件，不直接當作法規更新
- 新附件或內容雜湊改變：通知並下載
- 只有 HTTP 標頭改變、內容未變：不通知
