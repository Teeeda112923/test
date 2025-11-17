# src/jvn_feed.py
"""
JVN (Japan Vulnerability Notes) API統合モジュール
"""
from __future__ import annotations

import os
from typing import Dict, List, Tuple, Any
from datetime import datetime, timedelta, timezone

import requests
from dateutil import parser as dtparser


def _safe_str(x: Any) -> str:
    return "" if x is None else str(x)


def _to_float(x: Any) -> float | None:
    try:
        return float(x)
    except Exception:
        return None


def _normalize_to_utc(iso_dt: str | None) -> str | None:
    """ISO8601/日付のみ/naiveも受け取り、UTC aware ISO8601文字列で返す"""
    if not iso_dt:
        return None
    try:
        s = iso_dt.strip()
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            s = s + "T00:00:00Z"
        dt = dtparser.isoparse(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def fetch_jvn_vulnerabilities(days: int = 7) -> List[Dict]:
    """
    JVN APIから脆弱性情報を取得
    
    Args:
        days: 取得する日数（過去N日分）
        
    Returns:
        脆弱性情報のリスト
    """
    base_url = "https://jvndb.jvn.jp/myjvn"
    params = {
        'method': 'getVulnOverviewList',
        'feed': 'hnd',
        'rangeDatePublic': str(days),
        'format': 'json'
    }
    
    try:
        r = requests.get(base_url, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
        
        items: List[Dict] = []
        vulns = []
        
        # JVNのレスポンス構造を解析
        if isinstance(data, dict):
            # item配列を探す
            vulns = (data.get('item') or 
                    data.get('items') or 
                    data.get('vulninfo') or [])
        
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
                
            # CVE IDを取得
            cve_id = ""
            # 複数の可能性のあるフィールドをチェック
            sec_ids = vuln.get('sec:identifier') or vuln.get('identifier') or []
            if isinstance(sec_ids, list):
                for sid in sec_ids:
                    if isinstance(sid, dict):
                        id_val = sid.get('$t') or sid.get('value') or ""
                        if id_val.startswith('CVE-'):
                            cve_id = id_val
                            break
            
            if not cve_id:
                # フォールバック: JVN番号を使用
                if isinstance(vuln.get('sec:identifier'), dict):
                    cve_id = vuln.get('sec:identifier', {}).get('$t', '')
                elif isinstance(vuln.get('identifier'), dict):
                    cve_id = vuln.get('identifier', {}).get('$t', '')
            
            if not cve_id:
                continue
            
            # タイトル・説明を取得
            title = ""
            if isinstance(vuln.get('title'), dict):
                title = vuln['title'].get('$t', '')
            elif isinstance(vuln.get('title'), str):
                title = vuln['title']
            
            description = ""
            if isinstance(vuln.get('description'), dict):
                description = vuln['description'].get('$t', '')
            elif isinstance(vuln.get('description'), str):
                description = vuln['description']
            
            # 公開日を取得
            published = ""
            if isinstance(vuln.get('sec:issued'), dict):
                published = vuln['sec:issued'].get('$t', '')
            elif isinstance(vuln.get('issued'), dict):
                published = vuln['issued'].get('$t', '')
            elif isinstance(vuln.get('published'), str):
                published = vuln['published']
            
            # CVSSスコアを取得
            cvss = None
            cvss_info = vuln.get('sec:cvss') or vuln.get('cvss') or {}
            if isinstance(cvss_info, dict):
                score = (cvss_info.get('sec:score') or 
                        cvss_info.get('score') or 
                        cvss_info.get('$t'))
                if score:
                    cvss = _to_float(score)
            
            # リンクを取得
            refs: List[Tuple[str, str]] = []
            link = vuln.get('link', {})
            if isinstance(link, dict):
                url = link.get('@href') or link.get('href')
                if url:
                    refs.append(("JVN詳細", url))
            
            items.append({
                "source": "jvn",
                "cve": cve_id,
                "summary": title,
                "description": description or title,
                "published": _normalize_to_utc(published),
                "cvss": cvss,
                "vendor": "",  # JVNからは取得困難
                "product": "",
                "references": refs,
                "exploit_confirmed": False,
            })
        
        print(f"[debug] JVN fetched: {len(items)} items")
        return items
        
    except Exception as e:
        print(f"[warn] failed to fetch JVN: {e}")
        return []


if __name__ == "__main__":
    # テスト実行
    import json
    items = fetch_jvn_vulnerabilities(days=7)
    print(f"Total items: {len(items)}")
    if items:
        print("Sample item:")
        print(json.dumps(items[0], ensure_ascii=False, indent=2))
