# Vulnerability Information Scanner

複数のセキュリティ情報源から脆弱性情報を自動収集し、WordPressに自動投稿するシステムです。GitHub Actionsを使用して定期実行されます。

## 主な機能

- 🔍 **多様な情報源からの自動収集**
  - NVD (National Vulnerability Database)
  - JVN (Japan Vulnerability Notes)
  - CISA KEV (Known Exploited Vulnerabilities)
  - Sec-Gemini カスタムフィード

- 🤖 **GitHub Actions統合**
  - 毎日自動実行
  - 手動実行も可能
  - セキュアなシークレット管理

- 📝 **WordPress自動投稿**
  - AI要約機能(OpenAI)
  - 日本語コンテンツ生成
  - 下書きとして自動保存

- 🎯 **高度なフィルタリング**
  - CVSS 9.0以上の重大な脆弱性
  - 実悪用が確認された脆弱性
  - 重複排除機能

## セットアップ

### 1. リポジトリのクローン

```bash
git clone https://github.com/Teeeda112923/Vulnerability_information.git
cd Vulnerability_information
```

### 2. 依存関係のインストール

```bash
pip install -r requirements.txt
```

### 3. APIキーの取得

#### NVD APIキー (必須)
1. https://nvd.nist.gov/developers/request-an-api-key にアクセス
2. メールアドレスを入力
3. 確認メールのリンクをクリック
4. APIキーが即座に発行されます

**レート制限:**
- APIキーなし: 5リクエスト/30秒
- APIキーあり: 50リクエスト/30秒

#### OpenAI APIキー (オプション)
AI要約機能を使用する場合:
1. https://platform.openai.com/api-keys にアクセス
2. "Create new secret key" をクリック
3. APIキーをコピー

### 4. GitHub Secretsの設定

リポジトリの Settings > Secrets and variables > Actions で以下を設定:

| Secret名 | 説明 | 必須 |
|---------|------|------|
| `NVD_API_KEY` | NVD APIキー | ✅ 必須 |
| `WORDPRESS_URL` | WordPressサイトURL | WordPress投稿する場合 |
| `WORDPRESS_USERNAME` | WordPressユーザー名 | WordPress投稿する場合 |
| `WORDPRESS_APP_PASSWORD` | WordPressアプリパスワード | WordPress投稿する場合 |
| `OPENAI_API_KEY` | OpenAI APIキー | AI要約を使う場合 |
| `SEC_GEMINI_FEED_URL` | カスタムフィードURL | カスタマイズする場合 |

### 5. ワークフローの有効化

1. リポジトリの **Actions** タブに移動
2. ワークフローを有効化
3. 初回は手動実行で動作確認

## ローカル実行

### 環境変数の設定

```bash
cp .env.example .env
# .envファイルを編集してAPIキーを設定
```

### スクリプトの実行

```bash
cd src
python main.py
```

### JVN統合をテスト

```bash
cd src
python jvn_feed.py
```

## JVN統合の追加方法

`main.py` の先頭に以下を追加:

```python
from jvn_feed import fetch_jvn_vulnerabilities
```

`main()` 関数内の情報収集部分を更新:

```python
# 情報収集
cisa_ids = fetch_cisa_kev_ids()
sec_items = fetch_sec_gemini()
jvn_items = fetch_jvn_vulnerabilities(lookback_days)  # ← 追加
nvd_json = []

# 正規化時にJVNデータも含める
items = normalize_items(sec_items, cisa_ids, nvd_json)
# JVNアイテムをマージ
items.extend(jvn_items)
```

## 使い方

### 自動実行(推奨)

GitHub Actionsが毎日日本時間午前9時(UTC 0時)に自動実行します。

### 手動実行

1. リポジトリの **Actions** タブに移動
2. "Vulnerability Information Scanner" を選択
3. "Run workflow" をクリック
4. オプションで取得日数を指定
5. "Run workflow" を実行

### 実行結果の確認

- **WordPress**: 指定したWordPressサイトの下書きに投稿されます
- **Artifacts**: GitHub ActionsのArtifactsから `processed.json` をダウンロード可能
- **Logs**: GitHub Actionsのログで詳細を確認

## プロジェクト構造

```
Vulnerability_information/
├── .github/
│   └── workflows/
│       └── vulnerability-scan.yml  # GitHub Actionsワークフロー
├── src/
│   ├── main.py                     # メインスクリプト
│   ├── feeds.py                    # フィード取得
│   ├── jvn_feed.py                 # JVN統合 (新規)
│   ├── enrich.py                   # AI要約
│   ├── wp.py                       # WordPress投稿
│   ├── advisory.py                 # アドバイザリ処理
│   ├── state.py                    # 状態管理
│   └── summarize.py                # 要約機能
├── data/
│   └── processed.json              # 処理済みCVE記録
├── requirements.txt                # Python依存関係
├── .env.example                    # 環境変数サンプル
├── .gitignore                      # Git除外設定
└── README.md                       # このファイル
```

## カスタマイズ

### フィルタリング条件の変更

`src/feeds.py` の `meets_policy()` 関数を編集:

```python
def meets_policy(item: Dict) -> bool:
    cvss = _to_float(item.get("cvss")) or 0.0
    exploited = bool(item.get("exploit_confirmed"))
    
    # 例: CVSS 7.0以上に変更
    return (cvss >= 7.0) or exploited
```

### 実行スケジュールの変更

`.github/workflows/vulnerability-scan.yml` の cron 式を編集:

```yaml
schedule:
  # 毎日午前9時 (JST) = 午前0時 (UTC)
  - cron: '0 0 * * *'
  
  # 例: 毎日午前6時と午後6時に実行
  - cron: '0 21,9 * * *'
```

### 1日の投稿上限の変更

`src/main.py` の `POSTS_PER_DAY_LIMIT` を変更:

```python
POSTS_PER_DAY_LIMIT = 10  # デフォルトは5
```

## トラブルシューティング

### GitHub Actionsが失敗する

**症状:** ワークフローが赤くなる

**対処法:**
1. Actionsタブでログを確認
2. Secrets が正しく設定されているか確認
3. APIキーの有効性を確認

### 脆弱性が取得できない

**症状:** 候補が0件

**対処法:**
1. `DIGEST_LOOKBACK_DAYS` を増やす(例: 14日)
2. フィルタリング条件(`meets_policy`)を緩和
3. 手動で `src/feeds.py` を実行してデバッグ

### WordPress投稿が失敗する

**症状:** "failed to post" エラー

**対処法:**
1. WordPressのアプリパスワードを再生成
2. URLが正しいか確認(末尾の `/` に注意)
3. WordPress REST APIが有効か確認

## セキュリティ

- ⚠️ **APIキーをコードに直接書かないでください**
- ✅ GitHub Secretsを使用してください
- ✅ `.env` ファイルは `.gitignore` で除外されています
- ✅ 公開リポジトリの場合、機密情報を含めないでください

## ライセンス

このプロジェクトは個人/内部利用を想定しています。

## 貢献

バグ報告や機能追加のプルリクエストを歓迎します。

## サポート

問題が発生した場合は、GitHubのIssuesで報告してください。

---

**作成者:** [Teeeda112923](https://github.com/Teeeda112923)  
**最終更新:** 2024-11-17
