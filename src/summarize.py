# src/summarize.py
from __future__ import annotations
from typing import Dict, List, Tuple
import re

# ────────────────────────────────
# 共通ユーティリティ
# ────────────────────────────────
def _safe(x) -> str:
    return "" if x is None else str(x).strip()

def _bool(x) -> bool:
    return bool(x) and str(x).lower() not in {"false", "0", "none", "null"}

def _first_nonempty(*vals: str) -> str:
    for v in vals:
        if v and str(v).strip():
            return str(v).strip()
    return ""

def _esc_braces(s: str) -> str:
    """f-string/WordPressショートコード対策：波括弧をエスケープ"""
    return (_safe(s)).replace("{", "{{").replace("}", "}}")

# ────────────────────────────────
# CVSS 表記
# ────────────────────────────────
def _cvss_label(score) -> str:
    try:
        s = float(score)
        if s >= 9.0:
            return f"{s:.1f}（緊急）"
        elif s >= 7.0:
            return f"{s:.1f}（高）"
        elif s >= 4.0:
            return f"{s:.1f}（中）"
        elif s > 0:
            return f"{s:.1f}（低）"
    except Exception:
        pass
    return "-"

# ────────────────────────────────
# 脆弱性種別の推定（cve.org説明や要約から）
# ────────────────────────────────
_HINTS = {
    "リモートコード実行": ["remote code execution", "rce", "任意のコード実行"],
    "認証回避": ["authentication bypass", "broken authentication", "認証回避"],
    "権限昇格": ["privilege escalation", "権限昇格"],
    "情報漏えい": ["information disclosure", "情報漏えい", "情報漏洩"],
    "SQLインジェクション": ["sql injection", "sqlインジェクション"],
    "XSS（クロスサイトスクリプティング）": ["cross-site scripting", "xss"],
    "ディレクトリトラバーサル": ["directory traversal", "traversal", "パストラバーサル"],
}
def _detect_vuln_type(text: str) -> str:
    t = (_safe(text)).lower()
    for label, hints in _HINTS.items():
        if any(h.lower() in t for h in hints):
            return label
    return "重大な脆弱性"

# ────────────────────────────────
# 一般的な安全対策（precise が無いときのフォールバック）
# ────────────────────────────────
def _build_mitigations(vuln_type: str) -> List[str]:
    vt = (vuln_type or "").lower()
    patch = "ベンダー提供の修正版または最新セキュリティパッチを早急に適用する"
    network = "不要な外部公開を制限し、WAF/IPS等の防御設定を見直す"
    log = "各種ログを確認し、不審な挙動（試行増加・異常応答等）を監視する"

    mitig = [patch]
    if "認証" in vt or "bypass" in vt:
        mitig += [
            "多要素認証を有効化し、不正ログインを防止する",
            "アクセス制御・セッション管理の実装を再確認する",
            log,
        ]
    elif "権限昇格" in vt or "privilege" in vt:
        mitig += [
            "最小権限の原則に基づき、不要な特権を剥奪する",
            "OS/アプリの権限設定を適切化する",
            log,
        ]
    elif "rce" in vt or "コード実行" in vt:
        mitig += [
            "外部入力値の検証・サニタイズを徹底する",
            network,
            log,
        ]
    elif "sql" in vt:
        mitig += [
            "SQLプレースホルダー等のパラメタ化クエリを使用する",
            "入力値のエスケープ処理を徹底する",
            log,
        ]
    elif "xss" in vt:
        mitig += [
            "出力時にHTMLエスケープを実施する",
            "CSP（Content Security Policy）を設定する",
            log,
        ]
    elif "ディレクトリ" in vt or "traversal" in vt:
        mitig += [
            "ユーザー入力をファイルパスに直結しない実装へ修正する",
            "サーバーのディレクトリリスティングを無効化する",
            log,
        ]
    else:
        mitig += [network, log]
    return mitig

# ────────────────────────────────
# 追加：precise mitigations の利用（ベンダ/公的機関が明示した対策のみ）
# enrich 側で item["precise_mitigations"] = ["○○へ更新", "公開インスタンス遮断", ...] をセット想定
# ────────────────────────────────
def _render_precise_mitigations(item: Dict) -> str:
    arr = item.get("precise_mitigations") or []
    if not arr:
        return ""
    lines = "".join([f"- {x}\n" for x in arr if _safe(x)])
    return lines.strip()

# ────────────────────────────────
# 参考リンクの整形（list[tuple] / list[dict] / list[str] に対応）
# ────────────────────────────────
def _render_refs(refs_any) -> Tuple[str, str]:
    """refs_md, primary_url"""
    refs_md_lines: List[str] = []
    primary = "-"
    if not refs_any:
        return "- 参考情報：-", primary

    # 正規化
    refs: List[Tuple[str, str]] = []
    if isinstance(refs_any, list):
        for r in refs_any:
            if isinstance(r, (list, tuple)) and len(r) >= 2:
                title = _safe(r[0]) or "参考情報"
                url = _safe(r[1])
                if url:
                    refs.append((title, url))
            elif isinstance(r, dict):
                title = _safe(r.get("title") or r.get("name") or "参考情報")
                url = _safe(r.get("url"))
                if url:
                    refs.append((title, url))
            elif isinstance(r, str):
                url = _safe(r)
                if url.startswith("http"):
                    refs.append(("参考情報", url))
    elif isinstance(refs_any, dict):
        title = _safe(refs_any.get("title") or refs_any.get("name") or "参考情報")
        url = _safe(refs_any.get("url"))
        if url:
            refs.append((title, url))

    for i, (t, u) in enumerate(refs):
        if i == 0:
            primary = u
        refs_md_lines.append(f"- {_esc_braces(t)}：{_esc_braces(u)}")

    return ("\n".join(refs_md_lines) or "- 参考情報：-", primary or "-"

)

# ────────────────────────────────
# タイトル生成
# （装飾の【緊急】などは付けない／機器名優先、なければベンダ名→CVE）
# ────────────────────────────────
def build_single_title(item: Dict) -> str:
    vendor = _safe(item.get("vendor"))
    product = _safe(item.get("product"))
    cve = _safe(item.get("cve"))
    summary = _safe(item.get("summary") or item.get("description"))
    vuln_type = _detect_vuln_type(summary)

    target = (vendor + " " + product).strip() or vendor or cve or "対象製品不明"
    return f"{target} の脆弱性（{vuln_type}）に関する注意喚起"

# ────────────────────────────────
# 本文生成（cve.orgで補完された item を前提）
# - precise_mitigations があれば優先して表示
# - fixed_versions があれば表直下に注記
# - WordPressブロックの波括弧はエスケープ
# - 「対象機器」空時は「不明」表示（先頭ハイフン回避）
# ────────────────────────────────
def build_item_markdown_block(item: Dict) -> str:
    cve = _safe(item.get("cve"))
    vendor = _safe(item.get("vendor"))
    product = _safe(item.get("product"))
    affected = (vendor + " " + product).strip() or vendor or "不明"

    # cve.org の Description を優先
    raw_summary = _first_nonempty(item.get("summary"), item.get("description"))
    overview_line = _safe(raw_summary)
    if "。" in overview_line:
        overview_line = overview_line.split("。")[0] + "。"

    published = _safe(item.get("published"))
    cvss_label = _cvss_label(item.get("cvss"))
    vuln_type = _detect_vuln_type(_first_nonempty(item.get("summary"), item.get("description")))

    # 既知の悪用状況
    kev = _bool(item.get("cisa_kev"))
    exploited = _bool(item.get("exploit_confirmed"))
    exploitation = (
        "現時点では、実際の攻撃による悪用は確認されていません。"
        if not (kev or exploited)
        else "この脆弱性は、実際の攻撃で悪用が確認されており、CISAのKEVカタログ等にも掲載があります。"
    )

    # precise mitigations（ベンダ／公的機関が明示）を優先。なければ一般対策3点。
    precise = _render_precise_mitigations(item)
    if precise:
        mitig_section = precise
    else:
        mitig = _build_mitigations(vuln_type)
        # 3行のみ
        m0 = mitig[0] if len(mitig) > 0 else ""
        m1 = mitig[1] if len(mitig) > 1 else ""
        m2 = mitig[2] if len(mitig) > 2 else ""
        mitig_section = "\n".join([f"- {x}" for x in [m0, m1, m2] if _safe(x)])

    # 修正版/回避策 注記
    fixeds = item.get("fixed_versions") or []
    fixed_note = ""
    if fixeds:
        bullet = "".join([f"- {x}\n" for x in fixeds if _safe(x)]).strip()
        if bullet:
            fixed_note = f"\n> **ベンダが案内する修正版/回避策**\n>\n{_esc_braces(bullet)}\n"

    # 参考情報
    refs_md, primary_ref = _render_refs(item.get("references") or item.get("official_links"))

    # 序文（装飾ヘッダは付けない）
    intro = (
        f"{affected} に関する「{vuln_type}」の脆弱性が報告されています。"
        "システムの安全性に重大な影響を与える可能性があるため、早急な対応を検討してください。"
    )

    # WordPress 情報ボックス（波括弧エスケープ済み JSON）
    # f-string で primary_ref だけ挿入し、他の { } は二重にして回避
    wp_block = (
        '<!-- wp:group {{"className":"is-style-information-box","layout":{{"type":"constrained"}}}} -->\n'
        '<div class="wp-block-group is-style-information-box"><!-- wp:paragraph -->\n'
        '<p><strong>▼ 参考情報（主要リンク）</strong></p>\n'
        '<!-- /wp:paragraph -->\n\n'
        f'<!-- wp:paragraph -->\n<p><a href="{_esc_braces(primary_ref)}">{_esc_braces(primary_ref)}</a></p>\n'
        '<!-- /wp:paragraph --></div>\n'
        '<!-- /wp:group -->'
    )

    # まとめ
    summary_section = (
        "本脆弱性は業務継続や情報保護に影響を及ぼすおそれがあります。"
        "対象環境がある場合は、最新の修正版適用や公開範囲の見直しなど、速やかな対策を実施してください。"
    )

    md = f"""{_esc_braces(intro)}

## 脆弱性の概要
{_esc_braces(overview_line)}

| 項目 | 内容 |
|------|------|
| **CVE番号** | {cve} |
| **公開日** | {published or '-'} |
| **対象機器** | {_esc_braces(affected)} |
| **脆弱性の種類** | {vuln_type} |
| **CVSSスコア** | {cvss_label} |

{wp_block}
{fixed_note}
---

## 既知の悪用状況
{_esc_braces(exploitation)}

---

## 対策
{_esc_braces(mitig_section)}

---

## まとめ
{_esc_braces(summary_section)}

---

## 参考（公式アドバイザリなど）
{_esc_braces(refs_md)}
"""
    return md.strip()
