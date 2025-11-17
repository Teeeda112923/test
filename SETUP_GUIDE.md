# GitHub Actions セットアップガイド

## ステップバイステップガイド

### Step 1: NVD APIキーをGitHub Secretsに登録

1. GitHubでリポジトリを開く
2. **Settings** タブをクリック
3. 左サイドバーの **Secrets and variables** > **Actions** をクリック
4. **New repository secret** ボタンをクリック
5. 以下を入力:
   - **Name**: `NVD_API_KEY`
   - **Secret**: `209b9d6c-94c1-4f0c-878f-21716c626d99` (取得したAPIキー)
6. **Add secret** をクリック

### Step 2: その他のSecretsを登録 (オプション)

WordPress自動投稿を使う場合:

#### WORDPRESS_URL
- **Name**: `WORDPRESS_URL`
- **Secret**: `https://your-site.com` (あなたのWordPressサイトURL)

#### WORDPRESS_USERNAME
- **Name**: `WORDPRESS_USERNAME`
- **Secret**: `your-username` (WordPressのユーザー名)

#### WORDPRESS_APP_PASSWORD
- **Name**: `WORDPRESS_APP_PASSWORD`
- **Secret**: WordPressアプリパスワード

**WordPressアプリパスワードの作成方法:**
1. WordPressダッシュボードにログイン
2. **ユーザー** > **プロフィール** に移動
3. 一番下までスクロール
4. **アプリケーションパスワード** セクションを探す
5. 新しいアプリケーション名を入力（例: "GitHub Actions"）
6. **新しいアプリケーションパスワードを追加** をクリック
7. 表示されたパスワードをコピー（スペースは削除しても可）

AI要約機能を使う場合:

#### OPENAI_API_KEY
- **Name**: `OPENAI_API_KEY`
- **Secret**: `sk-...` (OpenAI APIキー)

### Step 3: JVN統合をmain.pyに追加

`src/main.py` を以下のように編集:

#### 3-1. インポート文を追加

ファイルの先頭、既存のimport文の後に追加:

```python
from jvn_feed import fetch_jvn_vulnerabilities
```

編集後:
```python
from feeds import (
    fetch_cisa_kev_ids,
    fetch_sec_gemini,
    fetch_nvd_recent,
    normalize_items,
    meets_policy,
    policy_reason,
)
from jvn_feed import fetch_jvn_vulnerabilities  # ← この行を追加
from state import load_state, save_state
from wp import create_draft_html
from enrich import enrich_cve_item
```

#### 3-2. JVN情報を取得するコードを追加

`main()` 関数内の情報収集部分（約91-96行目）を更新:

**変更前:**
```python
# 最小限の収集(Sec-Gemini中心)
cisa_ids = fetch_cisa_kev_ids()
sec_items = fetch_sec_gemini()
nvd_json = []  # fetch_nvd_recent() を使わない場合は空のままでOK

items = normalize_items(sec_items, cisa_ids, nvd_json)
```

**変更後:**
```python
# 最小限の収集(Sec-Gemini中心)
cisa_ids = fetch_cisa_kev_ids()
sec_items = fetch_sec_gemini()
jvn_items = fetch_jvn_vulnerabilities(lookback_days)  # ← この行を追加
nvd_json = []  # fetch_nvd_recent() を使わない場合は空のままでOK

items = normalize_items(sec_items, cisa_ids, nvd_json)
items.extend(jvn_items)  # ← この行を追加(JVN情報をマージ)
```

#### 3-3. デバッグ出力を更新（オプション）

97行目あたりのデバッグ出力も更新すると便利です:

**変更前:**
```python
print(f"[debug] fetched items: total={len(items)} (Sec-Gemini={len(sec_items)}, NVD={len(nvd_json)})")
```

**変更後:**
```python
print(f"[debug] fetched items: total={len(items)} (Sec-Gemini={len(sec_items)}, JVN={len(jvn_items)}, NVD={len(nvd_json)})")
```

### Step 4: 変更をGitHubにプッシュ

```bash
git add .
git commit -m "Add JVN integration and GitHub Actions workflow"
git push origin main
```

### Step 5: GitHub Actionsを有効化

1. GitHubでリポジトリを開く
2. **Actions** タブをクリック
3. "I understand my workflows, go ahead and enable them" をクリック
4. "Vulnerability Information Scanner" ワークフローが表示される

### Step 6: 手動実行でテスト

1. "Vulnerability Information Scanner" をクリック
2. 右側の **Run workflow** ボタンをクリック
3. ブランチを選択（通常は `main`）
4. オプション: 取得日数を指定（デフォルトは7日）
5. **Run workflow** をクリック

### Step 7: 実行結果を確認

1. ワークフローの実行が開始される
2. クリックして詳細を表示
3. 各ステップの進行状況を確認
4. 完了したら、ログを確認

**成功例:**
```
✓ Checkout repository
✓ Set up Python
✓ Install dependencies
✓ Run vulnerability scanner
  [debug] fetched items: total=25 (Sec-Gemini=15, JVN=10, NVD=0)
  [debug] after_seen=25, after_recency(<= 7d)=18, after_policy=5
  [posted] CVE-2024-XXXXX -> post_id=123 | 掲載対象: CVSS 9.8≥9.0
  [done] Posted 5 item(s) this run. Today total: 5/5
✓ Commit and push state changes
✓ Upload scan results
```

### Step 8: 自動実行を待つ

設定が完了すれば、毎日日本時間午前9時に自動実行されます。

## トラブルシューティング

### ❌ "NVD_API_KEY not found"

**原因:** GitHub Secretsが設定されていない

**解決策:**
1. Settings > Secrets and variables > Actions
2. `NVD_API_KEY` が登録されているか確認
3. 名前のスペルミスがないか確認

### ❌ "Module not found: jvn_feed"

**原因:** `jvn_feed.py` がリポジトリにない

**解決策:**
1. `src/jvn_feed.py` が存在するか確認
2. ファイルをコミット・プッシュしたか確認

### ❌ WordPress投稿が失敗

**原因:** WordPress設定が間違っている

**解決策:**
1. `WORDPRESS_URL` の末尾に `/` がないか確認
2. アプリパスワードを再生成
3. WordPress REST APIが有効か確認

### ❌ "No candidates under the current policy"

**原因:** 該当する脆弱性がない、またはフィルターが厳しすぎる

**解決策:**
1. 正常な動作です（重大な脆弱性がない状態）
2. `DIGEST_LOOKBACK_DAYS` を増やす（例: 14日）
3. テスト目的なら `feeds.py` の `meets_policy()` を緩和

## 次のステップ

### カスタマイズ例

#### 実行時刻を変更
`.github/workflows/vulnerability-scan.yml` を編集:

```yaml
schedule:
  # 毎日午後6時(JST) = 午前9時(UTC)
  - cron: '0 9 * * *'
```

#### 投稿上限を変更
`src/main.py` を編集:

```python
POSTS_PER_DAY_LIMIT = 10  # 5から10に変更
```

#### フィルター条件を変更
`src/feeds.py` を編集:

```python
def meets_policy(item: Dict) -> bool:
    cvss = _to_float(item.get("cvss")) or 0.0
    exploited = bool(item.get("exploit_confirmed"))
    # CVSS 7.0以上に変更
    return (cvss >= 7.0) or exploited
```

## サポート

問題が発生した場合は、GitHub Issuesで報告してください。
