import os
import base64
import mimetypes
from urllib.parse import urlparse, unquote
import requests
import markdown

# ======== 環境変数 ========
def _base_url() -> str:
    url = os.environ.get("WP_BASE_URL", "").strip()
    if not url:
        raise RuntimeError("WP_BASE_URL is not set")
    return url.rstrip("/")

def _auth_tuple():
    user = os.environ.get("WP_USER", "").strip()
    app = os.environ.get("WP_APP_PASSWORD", "").strip()
    if not user or not app:
        raise RuntimeError("WP_USER / WP_APP_PASSWORD are not set")
    return (user, app)

# Application Password は Basic 認証なので Authorization ヘッダでもOK
def _auth_header() -> dict:
    user, app = _auth_tuple()
    token = base64.b64encode(f"{user}:{app}".encode("utf-8")).decode("utf-8")
    return {"Authorization": f"Basic {token}"}

# ======== メディアアップロード ========
def _guess_filename_from_url(url: str) -> str:
    path = urlparse(url).path
    name = os.path.basename(path)
    name = unquote(name) or "image.jpg"
    # WordPress が日本語ファイル名を嫌うテーマ/プラグインもあるので拡張子だけ活かす
    base, ext = os.path.splitext(name)
    ext = ext or ".jpg"
    return f"hero{ext}"

def _download_bytes(url: str) -> tuple[bytes, str]:
    r = requests.get(url, timeout=30)
    if not r.ok:
        raise RuntimeError(f"failed to GET hero image: {r.status_code} {r.text}")
    content = r.content
    ctype = r.headers.get("Content-Type") or mimetypes.guess_type(url)[0] or "application/octet-stream"
    return content, ctype

def _upload_media_return_id(hero_image_url: str) -> int | None:
    """
    外部URLの画像をダウンロード→/wp-json/wp/v2/media にアップロードして attachment ID を返す。
    失敗しても None を返す（本文内 <img> はそのまま外部URLで表示するフォールバックが効く）。
    """
    try:
        content, ctype = _download_bytes(hero_image_url)
        filename = _guess_filename_from_url(hero_image_url)

        media_url = _base_url() + "/wp-json/wp/v2/media"
        headers = _auth_header()
        # Content-Disposition はファイル名をWordPressに伝えるのに有効
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'

        files = {
            "file": (filename, content, ctype),
        }
        r = requests.post(media_url, headers=headers, files=files, timeout=60)
        if not r.ok:
            # セキュリティプラグイン等で弾かれるケースがあるのでログだけ出して続行
            print("❌ Media upload error:", r.status_code, r.text)
            return None

        j = r.json()
        media_id = j.get("id")
        if not media_id:
            print("❌ Media upload response has no 'id':", j)
            return None
        return int(media_id)
    except Exception as e:
        print("❌ Media upload exception:", repr(e))
        return None

# ======== Markdown → HTML ========
def _md_to_html(md_text: str) -> str:
    # テーブルやフェンスコードにも対応
    return markdown.markdown(
        md_text,
        extensions=["extra", "sane_lists", "tables", "fenced_code"],
        output_format="html5",
    )

# ======== 投稿作成 ========
def create_draft_html(title: str, markdown_text: str, hero_image_url: str | None = None) -> int:
    """
    - Markdown本文をHTMLに変換
    - 先頭に <figure><img ...></figure> を挿入
    - hero_image_url を実体アップロードして featured_media に設定（可能なら）
    - 下書き（draft）で投稿を作成して post_id を返す
    """
    base = _base_url()
    posts_url = base + "/wp-json/wp/v2/posts"
    auth_hdr = _auth_header()
    user, app = _auth_tuple()  # 存在チェック用

    body_html = _md_to_html(markdown_text)

    hero_block = ""
    featured_media_id = None
    if hero_image_url:
        # 本文冒頭に画像（外部URLのまま）を差し込む
        hero_block = (
            '<figure class="wp-block-image size-large">'
            f'<img src="{hero_image_url}" alt="脆弱性情報" />'
            "</figure>\n\n"
        )
        # 可能ならメディアとしてアップロードして featured に設定
        featured_media_id = _upload_media_return_id(hero_image_url)

    data = {
        "title": title,
        "status": "draft",
        "content": hero_block + body_html,
    }
    if featured_media_id:
        data["featured_media"] = featured_media_id

    # 投稿
    r = requests.post(posts_url, headers=auth_hdr, json=data, timeout=30)
    if not r.ok:
        print("❌ WordPress API error:", r.status_code, r.text)
        r.raise_for_status()

    j = r.json()
    post_id = j.get("id")
    if not post_id:
        raise RuntimeError(f"unexpected WP response: {j}")

    return int(post_id)
