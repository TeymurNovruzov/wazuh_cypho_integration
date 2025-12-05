#!/usr/bin/env python3
import requests
import json
import os
import sqlite3
from datetime import datetime, timezone

# =============== CONFIG ===============
API_URL = "https://api.cypho.io/external/v1/issues"

API_KEY = "YOUR_TENANT_API_HERE"
LOG_FILE = "/var/ossec/logs/cypho_issues.log"

# SQLite DB to store seen issue IDs (prevents duplicates)
SEEN_DB = "/var/lib/cypho/cypho_seen.db"

TENANT = "YOUR_TENANT_NAME"
# ======================================

headers = {
    "X-Auth-Token": API_KEY,
    "Content-Type": "application/json",
}

params = {
    "tenant": TENANT,
}

payload = {
    # Add body here if your API needs it
}

# =====================================================
# SQLite duplicate-prevention
# =====================================================

def init_db():
    """Create SQLite DB and table if they don't exist."""
    os.makedirs(os.path.dirname(SEEN_DB), exist_ok=True)
    conn = sqlite3.connect(SEEN_DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS seen (
            issue_id TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()


def has_seen(issue_id):
    """Return True if this issue_id is already stored."""
    conn = sqlite3.connect(SEEN_DB)
    c = conn.cursor()
    c.execute("SELECT 1 FROM seen WHERE issue_id = ?", (issue_id,))
    row = c.fetchone()
    conn.close()
    return row is not None


def add_seen(issue_id):
    """Store a new issue_id (ignore if exists)."""
    if not issue_id:
        return
    conn = sqlite3.connect(SEEN_DB)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO seen (issue_id) VALUES (?)", (issue_id,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

# =====================================================


def fetch_issues():
    """Call Cypho API and return parsed JSON."""
    try:
        resp = requests.post(
            API_URL,
            headers=headers,
            params=params,
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] API request failed: {e}")
        return None


def normalize_issue(raw):
    """
    Map a single Cypho issue -> flat JSON event for Wazuh.
    Handles:
      - raw as dict
      - raw as JSON string
      - description as dict OR plain string
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {
                "integration": "cypho_ti",
                "tenant_name": TENANT,
                "issue_id": None,
                "ticket_id": None,
                "title": None,
                "impact": None,
                "detection_source": None,
                "url": None,
                "search_keyword": None,
                "content": raw,
                "@timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }

    if not isinstance(raw, dict):
        return {
            "integration": "cypho_ti",
            "tenant_name": TENANT,
            "raw": str(raw),
            "@timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    desc = raw.get("description", {})

    if isinstance(desc, dict):
        detection_source = desc.get("detection_source")
        url = desc.get("url")
        search_keyword = desc.get("search_keyword")
        content = desc.get("content")
    else:
        detection_source = None
        url = None
        search_keyword = None
        content = desc

    return {
        "integration": "cypho_ti",
        "tenant_name": raw.get("tenant_name") or raw.get("tenant") or TENANT,
        "issue_id": raw.get("id"),
        "ticket_id": raw.get("ticket_id"),
        "title": raw.get("title"),
        "impact": raw.get("impact"),
        "detection_source": detection_source,
        "url": url,
        "search_keyword": search_keyword,
        "content": content,
        "@timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def write_to_wazuh_log(issues):
    """Append normalized issues as JSON lines into the Wazuh log file, skipping duplicates."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    wrote = 0

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        for issue in issues:
            event = normalize_issue(issue)
            issue_id = event.get("issue_id")

            # Skip already processed issues
            if issue_id and has_seen(issue_id):
                continue

            # Write event to Wazuh JSON log
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

            # Mark ID as seen
            if issue_id:
                add_seen(issue_id)

            wrote += 1

    print(f"[INFO] Wrote {wrote} new issues (skipped duplicates)")


def main():
    # Always initialize DB first
    init_db()

    data = fetch_issues()
    if not data:
        print("[INFO] No data returned from API.")
        return

    if not isinstance(data, dict):
        print("[ERROR] Unexpected API response type:", type(data))
        return

    inner = data.get("data")

    if inner is None:
        print("[ERROR] 'data' key is missing in API response.")
        print("[ERROR] Top-level keys:", list(data.keys()))
        return

    if isinstance(inner, list):
        issues = inner
    elif isinstance(inner, dict):
        candidate_lists = [v for v in inner.values() if isinstance(v, list)]
        if candidate_lists:
            issues = candidate_lists[0]
        else:
            issues = [inner]
            print("[WARN] 'data' is a dict without list values. Treating it as a single issue.")
    else:
        print("[ERROR] Unexpected type for 'data' key:", type(inner))
        return

    if not issues:
        print("[INFO] No issues in API response.")
        return

    write_to_wazuh_log(issues)


if __name__ == "__main__":
    main()
