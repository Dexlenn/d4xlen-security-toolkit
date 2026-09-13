import os
import re
import ssl
import json
import math
import socket
import sqlite3
import hashlib
import ipaddress
import urllib.parse
import webbrowser
from datetime import datetime, timezone as dt_timezone
from collections import Counter

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
except ImportError:
    phonenumbers = None
    carrier = geocoder = timezone = None


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DB_PATH = os.path.join(BASE_DIR, "phone_reputation.db")


# ============================================================
# ANSI COLORS
# ============================================================

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"


# ============================================================
# GENERAL HELPERS
# ============================================================

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print(f"""{CYAN}{BOLD}
 ██████╗ ██╗  ██╗██╗  ██╗██╗     ███████╗███╗   ██╗
 ██╔══██╗██║  ██║╚██╗██╔╝██║     ██╔════╝████╗  ██║
 ██║  ██║███████║ ╚███╔╝ ██║     █████╗  ██╔██╗ ██║
 ██║  ██║╚════██║ ██╔██╗ ██║     ██╔══╝  ██║╚██╗██║
 ██████╔╝     ██║██╔╝ ██╗███████╗███████╗██║ ╚████║
 ╚═════╝      ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝

                     D 4 x l e n
{RESET}{BLUE}
       D4xlen Security Research Toolkit
{RESET}{DIM}
       Public Intelligence • Reputation • IOC
{RESET}
""")


def panel(title, width=74):
    line = "─" * width
    print(f"{CYAN}┌{line}┐")
    print(f"│ {BOLD}{WHITE}{title:<{width - 1}}{RESET}{CYAN}│")
    print(f"└{line}┘{RESET}")


def section(title):
    print()
    panel(title)
    print()


def safe_input(prompt):
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def print_rows(rows):
    for label, value in rows:
        print(f"  {CYAN}{label:<24}{RESET}: {value}")


def severity_color(level):
    level = str(level).upper()

    if level in ("HIGH", "VERY HIGH"):
        return f"{RED}{level}{RESET}"
    if level == "MEDIUM":
        return f"{YELLOW}{level}{RESET}"
    if level == "LOW":
        return f"{GREEN}{level}{RESET}"

    return f"{BLUE}{level}{RESET}"


def save_report(data, prefix="report"):
    os.makedirs(REPORTS_DIR, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, f"{prefix}_{stamp}.json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)

    return path


# ============================================================
# PHONE NORMALIZATION
# ============================================================

def normalize_phone_number(phone_input):
    """
    Return E.164 if possible.
    Falls back to a simple cleaned representation.
    """

    raw = phone_input.strip()

    if phonenumbers is not None:
        try:
            parsed = phonenumbers.parse(raw, None)

            if phonenumbers.is_possible_number(parsed):
                return phonenumbers.format_number(
                    parsed,
                    phonenumbers.PhoneNumberFormat.E164
                )
        except Exception:
            pass

    cleaned = re.sub(r"[^\d+]", "", raw)

    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]

    return cleaned


# ============================================================
# PHONE INTELLIGENCE
# ============================================================

def analyze_phone_number(phone_input):
    if phonenumbers is None:
        return {
            "error": "Dependency 'phonenumbers' belum terpasang."
        }

    try:
        parsed = phonenumbers.parse(phone_input, None)

        if not phonenumbers.is_possible_number(parsed):
            return {
                "error": "Nomor tidak mungkin / format tidak sesuai."
            }

        if not phonenumbers.is_valid_number(parsed):
            return {
                "error": "Nomor tidak valid."
            }

        number_type = phonenumbers.number_type(parsed)

        type_name = {
            0: "Fixed line",
            1: "Mobile",
            2: "Fixed line / Mobile",
            3: "Toll free",
            4: "Premium rate",
            5: "Shared cost",
            6: "VoIP",
            7: "Personal number",
            8: "Pager",
            9: "UAN",
            10: "Voicemail",
            99: "Unknown",
        }.get(number_type, "Unknown")

        return {
            "target": phone_input,
            "valid": True,
            "international": phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "national": phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.NATIONAL
            ),
            "e164": phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.E164
            ),
            "country_or_region": (
                geocoder.description_for_number(parsed, "en")
                or "Unknown"
            ),
            "carrier": (
                carrier.name_for_number(parsed, "en")
                or "Unknown"
            ),
            "timezone": list(
                timezone.time_zones_for_number(parsed)
            ),
            "number_type": type_name,
            "note": (
                "Carrier/location berasal dari metadata numbering plan, "
                "bukan lokasi real-time perangkat."
            ),
        }

    except phonenumbers.NumberParseException as exc:
        return {
            "error": f"Format nomor tidak dapat diproses: {exc}"
        }

    except Exception as exc:
        return {
            "error": f"Error: {exc}"
        }


def phone_menu():
    section("PHONE INTELLIGENCE")

    target = safe_input(
        f"  {BLUE}phone{RESET} {DIM}>{RESET} "
    )

    if not target:
        return

    result = analyze_phone_number(target)

    if "error" in result:
        print(
            f"\n  {RED}[!]{RESET} "
            f"{result['error']}"
        )
        return

    print_rows([
        ("Status", f"{GREEN}VALID{RESET}"),
        ("International", result["international"]),
        ("National", result["national"]),
        ("E.164", result["e164"]),
        ("Country/Region", result["country_or_region"]),
        ("Carrier", result["carrier"]),
        ("Timezone", ", ".join(result["timezone"])),
        ("Number Type", result["number_type"]),
    ])

    print(
        f"\n  {DIM}{result['note']}{RESET}"
    )

    if safe_input(
        "\n  Save JSON report? [y/N] > "
    ).lower() == "y":
        print(
            f"  Saved: {save_report(result, 'phone')}"
        )


# ============================================================
# PHONE REPUTATION DATABASE
# ============================================================

VALID_REPORT_CATEGORIES = {
    "scam",
    "spam",
    "phishing",
    "impersonation",
    "telemarketing",
    "debt_collection",
    "harassment",
    "other",
}


def init_reputation_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS phone_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                source TEXT NOT NULL DEFAULT 'local_user_report',
                confidence INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_phone_reports_number
            ON phone_reports(phone_number)
            """
        )

        conn.commit()


def add_phone_report(
    phone_number,
    category,
    description="",
    source="local_user_report",
    confidence=1,
):
    init_reputation_db()

    normalized = normalize_phone_number(phone_number)
    category = category.strip().lower()

    if category not in VALID_REPORT_CATEGORIES:
        raise ValueError(
            "Kategori report tidak valid."
        )

    confidence = max(
        1,
        min(int(confidence), 3)
    )

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO phone_reports (
                phone_number,
                category,
                description,
                source,
                confidence,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                normalized,
                category,
                description.strip(),
                source.strip() or "local_user_report",
                confidence,
                datetime.now().isoformat(timespec="seconds"),
            )
        )

        conn.commit()

    return normalized


def get_phone_reports(phone_number):
    init_reputation_db()

    normalized = normalize_phone_number(phone_number)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT
                id,
                phone_number,
                category,
                description,
                source,
                confidence,
                created_at
            FROM phone_reports
            WHERE phone_number = ?
            ORDER BY id DESC
            """,
            (normalized,)
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def summarize_phone_reports(phone_number):
    reports = get_phone_reports(phone_number)

    counts = Counter(
        report["category"]
        for report in reports
    )

    scam_like_categories = {
        "scam",
        "phishing",
        "impersonation",
    }

    scam_reports = sum(
        counts.get(category, 0)
        for category in scam_like_categories
    )

    spam_reports = (
        counts.get("spam", 0)
        + counts.get("telemarketing", 0)
    )

    high_confidence_reports = sum(
        1
        for report in reports
        if int(report.get("confidence", 1)) >= 3
    )

    return {
        "phone_number": normalize_phone_number(phone_number),
        "total_reports": len(reports),
        "scam_reports": scam_reports,
        "spam_reports": spam_reports,
        "high_confidence_reports": high_confidence_reports,
        "categories": dict(counts),
        "reports": reports,
    }


# ============================================================
# SCAM RISK SCORING
# ============================================================

def calculate_scam_score(
    scam_reports,
    spam_reports,
    total_reports,
    public_scam_mentions,
    high_confidence_reports=0,
):
    """
    Heuristic reputation score.
    This is NOT proof that a number is fraudulent.

    Maximum:
    scam reports            : 50
    spam reports            : 10
    public scam mentions    : 25
    report volume           : 10
    high-confidence reports : 5

    Total max               : 100
    """

    score = 0

    score += min(
        max(int(scam_reports), 0) * 8,
        50
    )

    score += min(
        max(int(spam_reports), 0) * 2,
        10
    )

    score += min(
        max(int(public_scam_mentions), 0) * 5,
        25
    )

    if total_reports >= 20:
        score += 10
    elif total_reports >= 10:
        score += 5

    if high_confidence_reports >= 3:
        score += 5
    elif high_confidence_reports >= 1:
        score += 2

    return min(score, 100)


def classify_risk(score):
    if score >= 75:
        return "HIGH"

    if score >= 45:
        return "MEDIUM"

    if score >= 20:
        return "LOW"

    return "UNKNOWN / INSUFFICIENT DATA"


def calculate_confidence(
    total_reports,
    public_scam_mentions,
):
    evidence_points = (
        int(total_reports)
        + int(public_scam_mentions)
    )

    if evidence_points >= 20:
        return "HIGH"

    if evidence_points >= 7:
        return "MEDIUM"

    if evidence_points >= 2:
        return "LOW"

    return "VERY LOW"


def build_phone_scam_assessment(
    phone_number,
    public_scam_mentions=0,
):
    intelligence = analyze_phone_number(phone_number)
    summary = summarize_phone_reports(phone_number)

    score = calculate_scam_score(
        scam_reports=summary["scam_reports"],
        spam_reports=summary["spam_reports"],
        total_reports=summary["total_reports"],
        public_scam_mentions=public_scam_mentions,
        high_confidence_reports=summary[
            "high_confidence_reports"
        ],
    )

    risk_level = classify_risk(score)

    confidence = calculate_confidence(
        summary["total_reports"],
        public_scam_mentions,
    )

    if risk_level == "HIGH":
        assessment = (
            "Banyak indikator reputasi negatif ditemukan. "
            "Perlakukan nomor sebagai berisiko tinggi dan verifikasi "
            "identitas melalui kanal resmi sebelum berinteraksi."
        )
    elif risk_level == "MEDIUM":
        assessment = (
            "Terdapat beberapa indikator reputasi negatif. "
            "Gunakan kehati-hatian dan lakukan verifikasi tambahan."
        )
    elif risk_level == "LOW":
        assessment = (
            "Ada sedikit indikator reputasi negatif, tetapi bukti "
            "belum cukup untuk menyimpulkan nomor adalah scam."
        )
    else:
        assessment = (
            "Belum ada cukup bukti reputasi. "
            "Status ini bukan berarti nomor terbukti aman."
        )

    return {
        "target": normalize_phone_number(phone_number),
        "phone_intelligence": intelligence,
        "reputation": {
            "total_reports": summary["total_reports"],
            "scam_reports": summary["scam_reports"],
            "spam_reports": summary["spam_reports"],
            "high_confidence_reports": summary[
                "high_confidence_reports"
            ],
            "categories": summary["categories"],
            "public_scam_mentions": int(
                public_scam_mentions
            ),
        },
        "risk_score": score,
        "risk_level": risk_level,
        "confidence": confidence,
        "assessment": assessment,
        "reports": summary["reports"],
        "methodology_note": (
            "Risk score bersifat heuristic berdasarkan laporan lokal "
            "dan jumlah public mentions yang dimasukkan pengguna. "
            "Tool ini tidak memiliki akses ke database Getcontact."
        ),
    }


# ============================================================
# PHONE SCAM MENUS
# ============================================================

def scam_check_menu():
    section("PHONE SCAM / REPUTATION CHECK")

    phone = safe_input(
        f"  {BLUE}phone{RESET} {DIM}>{RESET} "
    )

    if not phone:
        return

    raw_public_mentions = safe_input(
        "  Public scam mentions (0 jika tidak ada) > "
    )

    try:
        public_mentions = (
            int(raw_public_mentions)
            if raw_public_mentions
            else 0
        )

        if public_mentions < 0:
            public_mentions = 0

    except ValueError:
        public_mentions = 0

    result = build_phone_scam_assessment(
        phone,
        public_mentions,
    )

    phone_info = result["phone_intelligence"]

    print()

    if "error" not in phone_info:
        print_rows([
            ("Number", result["target"]),
            (
                "Country/Region",
                phone_info["country_or_region"]
            ),
            ("Carrier", phone_info["carrier"]),
            ("Number Type", phone_info["number_type"]),
        ])
    else:
        print_rows([
            ("Number", result["target"]),
            (
                "Phone metadata",
                phone_info["error"]
            ),
        ])

    print()
    print(f"  {BOLD}REPUTATION{RESET}")

    print_rows([
        (
            "Total Reports",
            result["reputation"]["total_reports"]
        ),
        (
            "Scam-like Reports",
            result["reputation"]["scam_reports"]
        ),
        (
            "Spam Reports",
            result["reputation"]["spam_reports"]
        ),
        (
            "High Confidence",
            result["reputation"][
                "high_confidence_reports"
            ]
        ),
        (
            "Public Mentions",
            result["reputation"][
                "public_scam_mentions"
            ]
        ),
    ])

    print()
    print_rows([
        (
            "Risk Score",
            f"{result['risk_score']} / 100"
        ),
        (
            "Risk Level",
            severity_color(
                result["risk_level"]
            )
        ),
        (
            "Confidence",
            result["confidence"]
        ),
    ])

    print(
        f"\n  {YELLOW}Assessment:{RESET}"
    )
    print(
        f"  {result['assessment']}"
    )

    print(
        f"\n  {DIM}{result['methodology_note']}{RESET}"
    )

    if result["reports"]:
        print(
            f"\n  {BOLD}Latest Local Reports{RESET}"
        )

        for report in result["reports"][:10]:
            desc = (
                report["description"]
                or "-"
            )

            print(
                f"   - #{report['id']} "
                f"[{report['category']}] "
                f"confidence={report['confidence']} "
                f"{desc}"
            )

    if safe_input(
        "\n  Save JSON report? [y/N] > "
    ).lower() == "y":
        print(
            f"  Saved: "
            f"{save_report(result, 'phone_scam')}"
        )


def add_scam_report_menu():
    section("ADD SUSPICIOUS PHONE REPORT")

    phone = safe_input(
        f"  {BLUE}phone{RESET} {DIM}>{RESET} "
    )

    if not phone:
        return

    print("\n  Categories:")

    categories = [
        "scam",
        "spam",
        "phishing",
        "impersonation",
        "telemarketing",
        "debt_collection",
        "harassment",
        "other",
    ]

    for index, category in enumerate(
        categories,
        start=1,
    ):
        print(
            f"   [{index}] {category}"
        )

    raw_category = safe_input(
        "\n  Category number > "
    )

    try:
        category = categories[
            int(raw_category) - 1
        ]
    except Exception:
        print(
            f"  {RED}[!]{RESET} "
            f"Invalid category."
        )
        return

    description = safe_input(
        "  Description / evidence note > "
    )

    source = safe_input(
        "  Source [local_user_report] > "
    )

    if not source:
        source = "local_user_report"

    raw_confidence = safe_input(
        "  Confidence 1-3 [1] > "
    )

    try:
        confidence = (
            int(raw_confidence)
            if raw_confidence
            else 1
        )
    except ValueError:
        confidence = 1

    normalized = add_phone_report(
        phone_number=phone,
        category=category,
        description=description,
        source=source,
        confidence=confidence,
    )

    print(
        f"\n  {GREEN}[+]{RESET} "
        f"Report saved for {normalized}"
    )


def list_phone_reports_menu():
    section("LOCAL PHONE REPORT HISTORY")

    phone = safe_input(
        f"  {BLUE}phone{RESET} {DIM}>{RESET} "
    )

    if not phone:
        return

    summary = summarize_phone_reports(phone)

    print_rows([
        (
            "Phone",
            summary["phone_number"]
        ),
        (
            "Total Reports",
            summary["total_reports"]
        ),
        (
            "Scam-like Reports",
            summary["scam_reports"]
        ),
        (
            "Spam Reports",
            summary["spam_reports"]
        ),
    ])

    if not summary["reports"]:
        print(
            f"\n  {DIM}Belum ada report lokal.{RESET}"
        )
        return

    print()

    for report in summary["reports"]:
        print(
            f"  #{report['id']} "
            f"[{report['category']}] "
            f"confidence={report['confidence']} "
            f"source={report['source']}"
        )

        if report["description"]:
            print(
                f"     {report['description']}"
            )

        print(
            f"     {report['created_at']}"
        )



# ============================================================
# USERNAME / SOCIAL PRESENCE SEARCH
# ============================================================

USERNAME_PLATFORMS = {
    "Instagram": {
        "profile": "https://www.instagram.com/{username}/",
        "domain": "instagram.com",
        "http_check": False,
    },
    "TikTok": {
        "profile": "https://www.tiktok.com/@{username}",
        "domain": "tiktok.com",
        "http_check": False,
    },
    "X / Twitter": {
        "profile": "https://x.com/{username}",
        "domain": "x.com",
        "http_check": False,
    },
    "Threads": {
        "profile": "https://www.threads.net/@{username}",
        "domain": "threads.net",
        "http_check": False,
    },
    "GitHub": {
        "profile": "https://github.com/{username}",
        "domain": "github.com",
        "http_check": True,
    },
    "Reddit": {
        "profile": "https://www.reddit.com/user/{username}/",
        "domain": "reddit.com",
        "http_check": True,
    },
    "Twitch": {
        "profile": "https://www.twitch.tv/{username}",
        "domain": "twitch.tv",
        "http_check": False,
    },
    "Pinterest": {
        "profile": "https://www.pinterest.com/{username}/",
        "domain": "pinterest.com",
        "http_check": False,
    },
    "Medium": {
        "profile": "https://medium.com/@{username}",
        "domain": "medium.com",
        "http_check": False,
    },
    "YouTube": {
        "profile": "https://www.youtube.com/@{username}",
        "domain": "youtube.com",
        "http_check": False,
    },
    "Telegram": {
        "profile": "https://t.me/{username}",
        "domain": "t.me",
        "http_check": False,
    },
    "Facebook": {
        "profile": "https://www.facebook.com/{username}",
        "domain": "facebook.com",
        "http_check": False,
    },
    "Snapchat": {
        "profile": "https://www.snapchat.com/add/{username}",
        "domain": "snapchat.com",
        "http_check": False,
    },
    "SoundCloud": {
        "profile": "https://soundcloud.com/{username}",
        "domain": "soundcloud.com",
        "http_check": False,
    },
}

USERNAME_SEARCH_ONLY = {
    "LinkedIn": {
        "query": 'site:linkedin.com/in "{username}"',
        "note": (
            "LinkedIn profile slug tidak selalu sama dengan username; "
            "hasil dianggap candidate evidence saja."
        ),
    },
    "Google / Gmail": {
        "query": '"{username}@gmail.com" OR "{username}" "Google profile"',
        "note": (
            "Alamat Gmail bukan direktori publik. Pencarian hanya mencari "
            "mention publik; tidak membuktikan akun Gmail ada atau aktif."
        ),
    },
    "WhatsApp": {
        "query": '"{username}" "WhatsApp"',
        "note": (
            "Username WhatsApp sedang diluncurkan bertahap. Verifikasi yang "
            "paling tepat adalah exact-match username di aplikasi WhatsApp; "
            "hasil web publik bukan bukti kepemilikan akun."
        ),
    },
}


def normalize_username(username):
    username = username.strip()

    while username.startswith("@"):
        username = username[1:]

    return username.strip()


def google_search_url(query):
    return (
        "https://www.google.com/search?q="
        + urllib.parse.quote_plus(query)
    )


def validate_username_input(username):
    if not username:
        return False, "Username kosong."

    if len(username) > 100:
        return False, "Username terlalu panjang."

    if any(ch.isspace() for ch in username):
        return False, "Gunakan username tanpa spasi."

    if "/" in username or "\\" in username:
        return False, "Username tidak boleh berisi slash."

    return True, None


def build_username_search_report(username):
    username = normalize_username(username)

    valid, error = validate_username_input(username)

    if not valid:
        return {"error": error}

    candidates = []

    for platform, config in USERNAME_PLATFORMS.items():
        profile_url = config["profile"].format(
            username=urllib.parse.quote(username, safe="._-")
        )

        query = (
            f'site:{config["domain"]} '
            f'"{username}"'
        )

        candidates.append({
            "platform": platform,
            "username": username,
            "candidate_profile_url": profile_url,
            "public_search_url": google_search_url(query),
            "http_check_supported": bool(
                config.get("http_check")
            ),
            "status": "NOT CHECKED",
            "note": (
                "Candidate URL only. A matching URL is not proof that "
                "the account belongs to the same real-world person."
            ),
        })

    search_only = []

    for platform, config in USERNAME_SEARCH_ONLY.items():
        query = config["query"].format(
            username=username
        )

        search_only.append({
            "platform": platform,
            "public_search_url": google_search_url(query),
            "note": config["note"],
        })

    return {
        "username": username,
        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "candidate_profiles": candidates,
        "search_only_sources": search_only,
        "methodology_note": (
            "This module searches public profile candidates and public web "
            "mentions only. Matching usernames across services do not prove "
            "that the accounts belong to the same person."
        ),
    }


def quick_check_profile_url(url):
    if requests is None:
        return {
            "status": "DEPENDENCY MISSING",
            "http_status": None,
            "reason": "requests belum terpasang.",
        }

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent":
                    "Mozilla/5.0 D4xlen-Public-OSINT/1.0"
            },
        )

        status_code = response.status_code
        body = response.text[:150000].lower()

        not_found_markers = (
            "page not found",
            "user not found",
            "profile not found",
            "this page doesn't exist",
            "this page does not exist",
            "there isn't a github pages site here",
        )

        if status_code == 404:
            status = "NOT FOUND"
            reason = "Server returned HTTP 404."

        elif status_code in (401, 403, 429):
            status = "UNKNOWN / BLOCKED"
            reason = (
                f"Platform returned HTTP {status_code}; "
                "automated validation is not reliable."
            )

        elif status_code == 200:
            if any(
                marker in body
                for marker in not_found_markers
            ):
                status = "LIKELY NOT FOUND"
                reason = (
                    "HTTP 200 returned, but page contains "
                    "a not-found indicator."
                )
            else:
                status = "POSSIBLE / UNVERIFIED"
                reason = (
                    "Public page is reachable, but this alone "
                    "does not prove account ownership or identity."
                )

        else:
            status = "UNKNOWN"
            reason = (
                f"Unexpected HTTP status {status_code}."
            )

        return {
            "status": status,
            "http_status": status_code,
            "final_url": response.url,
            "reason": reason,
        }

    except requests.RequestException as exc:
        return {
            "status": "UNKNOWN / ERROR",
            "http_status": None,
            "reason": str(exc),
        }


def run_username_quick_checks(report):
    for item in report["candidate_profiles"]:
        if not item["http_check_supported"]:
            item["status"] = "SEARCH / MANUAL VERIFY"
            continue

        check = quick_check_profile_url(
            item["candidate_profile_url"]
        )

        item["status"] = check["status"]
        item["http_status"] = check.get(
            "http_status"
        )
        item["check_reason"] = check.get(
            "reason"
        )
        item["final_url"] = check.get(
            "final_url"
        )

    return report


def print_username_report(report):
    section("USERNAME / SOCIAL PRESENCE")

    print_rows([
        ("Username", f"@{report['username']}"),
        (
            "Profile Candidates",
            len(report["candidate_profiles"])
        ),
        (
            "Search-only Sources",
            len(report["search_only_sources"])
        ),
    ])

    print(
        f"\n  {BOLD}PROFILE CANDIDATES{RESET}"
    )

    for index, item in enumerate(
        report["candidate_profiles"],
        start=1,
    ):
        print(
            f"\n  {CYAN}[{index}]{RESET} "
            f"{item['platform']}"
        )
        print(
            f"      Candidate : "
            f"{item['candidate_profile_url']}"
        )
        print(
            f"      Status    : "
            f"{item['status']}"
        )
        print(
            f"      Web Search: "
            f"{item['public_search_url']}"
        )

        if item.get("check_reason"):
            print(
                f"      Reason    : "
                f"{item['check_reason']}"
            )

    print(
        f"\n  {BOLD}SEARCH-ONLY / SPECIAL CASES{RESET}"
    )

    for item in report[
        "search_only_sources"
    ]:
        print(
            f"\n  {MAGENTA}•{RESET} "
            f"{item['platform']}"
        )
        print(
            f"      Search : "
            f"{item['public_search_url']}"
        )
        print(
            f"      Note   : "
            f"{item['note']}"
        )

    print(
        f"\n  {DIM}"
        f"{report['methodology_note']}"
        f"{RESET}"
    )


def open_all_username_searches(report):
    opened = 0

    for item in report["candidate_profiles"]:
        webbrowser.open_new_tab(
            item["public_search_url"]
        )
        opened += 1

    for item in report["search_only_sources"]:
        webbrowser.open_new_tab(
            item["public_search_url"]
        )
        opened += 1

    return opened


def username_search_menu():
    section("USERNAME / SOCIAL PRESENCE SEARCH")

    username = safe_input(
        f"  {BLUE}username{RESET} {DIM}>{RESET} "
    )

    report = build_username_search_report(
        username
    )

    if "error" in report:
        print(
            f"\n  {RED}[!]{RESET} "
            f"{report['error']}"
        )
        return

    while True:
        print_username_report(report)

        print(
            f"\n  {CYAN}[C]{RESET} "
            f"Quick-check supported public profile URLs"
        )
        print(
            f"  {CYAN}[A]{RESET} "
            f"Open all public web searches"
        )
        print(
            f"  {CYAN}[S]{RESET} "
            f"Save JSON report"
        )
        print(
            f"  {BLUE}[0]{RESET} "
            f"Back"
        )

        choice = safe_input(
            f"\n  {MAGENTA}username{RESET} "
            f"{DIM}>{RESET} "
        ).lower()

        if choice == "0":
            return

        if choice == "c":
            print(
                f"\n  {YELLOW}[*]{RESET} "
                f"Running conservative public HTTP checks..."
            )
            report = run_username_quick_checks(
                report
            )
            continue

        if choice == "a":
            opened = open_all_username_searches(
                report
            )
            print(
                f"\n  {GREEN}[+]{RESET} "
                f"Opened {opened} public searches."
            )
            continue

        if choice == "s":
            path = save_report(
                report,
                "username_presence",
            )
            print(
                f"\n  {GREEN}[+]{RESET} "
                f"Saved: {path}"
            )
            continue

        print(
            f"\n  {RED}[!]{RESET} "
            f"Invalid option."
        )


# ============================================================
# DNS / DOMAIN INTELLIGENCE
# ============================================================

def normalize_domain(value):
    value = value.strip().lower()

    if "://" in value:
        value = (
            urllib.parse.urlparse(value).hostname
            or value
        )

    value = (
        value
        .split("/")[0]
        .split(":")[0]
        .strip(".")
    )

    return value


def socket_resolve(domain):
    try:
        results = socket.getaddrinfo(
            domain,
            None,
        )

        return sorted({
            item[4][0]
            for item in results
        })

    except socket.gaierror:
        return []


def query_dns_record(
    domain,
    record_type,
):
    if dns is None:
        return []

    try:
        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5,
        )

        return [
            str(r).rstrip(".")
            for r in answers
        ]

    except Exception:
        return []


def analyze_domain(domain):
    domain = normalize_domain(domain)

    report = {
        "target": domain,
        "resolved_addresses": socket_resolve(
            domain
        ),
        "dns": {},
        "findings": [],
    }

    for record_type in (
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
    ):
        report["dns"][record_type] = (
            query_dns_record(
                domain,
                record_type,
            )
        )

    if not report["resolved_addresses"]:
        report["findings"].append({
            "severity": "MEDIUM",
            "finding": (
                "Domain tidak dapat di-resolve "
                "melalui resolver lokal."
            ),
        })

    if dns is None:
        report["findings"].append({
            "severity": "INFO",
            "finding": (
                "dnspython tidak tersedia; "
                "detail DNS terbatas."
            ),
        })

    if report["dns"].get("MX") == []:
        report["findings"].append({
            "severity": "INFO",
            "finding": (
                "Tidak ada MX record yang ditemukan."
            ),
        })

    return report


def domain_menu():
    section("DOMAIN / DNS INTELLIGENCE")

    domain = safe_input(
        f"  {BLUE}domain{RESET} {DIM}>{RESET} "
    )

    if not domain:
        return

    result = analyze_domain(domain)

    print_rows([
        ("Target", result["target"]),
        (
            "Resolved IPs",
            ", ".join(
                result["resolved_addresses"]
            ) or "None"
        ),
    ])

    print()

    for rtype, values in result["dns"].items():
        print(
            f"  {MAGENTA}{rtype:<6}{RESET}: "
            f"{', '.join(values) if values else '-'}"
        )

    if result["findings"]:
        print("\n  Findings:")

        for item in result["findings"]:
            print(
                f"   - "
                f"[{severity_color(item['severity'])}] "
                f"{item['finding']}"
            )

    if safe_input(
        "\n  Save JSON report? [y/N] > "
    ).lower() == "y":
        print(
            f"  Saved: {save_report(result, 'domain')}"
        )


# ============================================================
# IP INTELLIGENCE
# ============================================================

def analyze_ip(value):
    try:
        ip_obj = ipaddress.ip_address(
            value.strip()
        )

    except ValueError:
        return {
            "error": "Format IP tidak valid."
        }

    reverse_dns = None

    try:
        reverse_dns = socket.gethostbyaddr(
            str(ip_obj)
        )[0]

    except Exception:
        pass

    return {
        "target": str(ip_obj),
        "version": ip_obj.version,
        "is_private": ip_obj.is_private,
        "is_global": ip_obj.is_global,
        "is_loopback": ip_obj.is_loopback,
        "is_multicast": ip_obj.is_multicast,
        "is_reserved": ip_obj.is_reserved,
        "is_link_local": ip_obj.is_link_local,
        "reverse_dns": (
            reverse_dns
            or "Unknown"
        ),
        "note": (
            "This module does not geolocate "
            "or scan ports."
        ),
    }


def ip_menu():
    section("IP INTELLIGENCE")

    value = safe_input(
        f"  {BLUE}ip{RESET} {DIM}>{RESET} "
    )

    if not value:
        return

    result = analyze_ip(value)

    if "error" in result:
        print(
            f"  {RED}[!]{RESET} "
            f"{result['error']}"
        )
        return

    print_rows([
        ("IP", result["target"]),
        ("Version", result["version"]),
        ("Private", result["is_private"]),
        ("Global", result["is_global"]),
        ("Loopback", result["is_loopback"]),
        ("Multicast", result["is_multicast"]),
        ("Reserved", result["is_reserved"]),
        ("Link-local", result["is_link_local"]),
        ("Reverse DNS", result["reverse_dns"]),
    ])

    if safe_input(
        "\n  Save JSON report? [y/N] > "
    ).lower() == "y":
        print(
            f"  Saved: {save_report(result, 'ip')}"
        )


# ============================================================
# HTTP / URL SECURITY ANALYSIS
# ============================================================

SECURITY_HEADERS = {
    "strict-transport-security":
        "HSTS",
    "content-security-policy":
        "CSP",
    "x-content-type-options":
        "X-Content-Type-Options",
    "x-frame-options":
        "X-Frame-Options",
    "referrer-policy":
        "Referrer-Policy",
    "permissions-policy":
        "Permissions-Policy",
}


def ensure_url(value):
    value = value.strip()

    if not value.startswith(
        ("http://", "https://")
    ):
        value = "https://" + value

    return value


def analyze_url(url):
    if requests is None:
        return {
            "error": (
                "Dependency 'requests' "
                "belum terpasang."
            )
        }

    url = ensure_url(url)
    parsed = urllib.parse.urlparse(url)

    findings = []

    if parsed.scheme != "https":
        findings.append({
            "severity": "MEDIUM",
            "finding": (
                "URL menggunakan HTTP tanpa TLS."
            ),
        })

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent":
                    "CybersecurityAnalyzer/2.0"
            },
            stream=True,
        )

    except requests.RequestException as exc:
        return {
            "target": url,
            "error": (
                f"HTTP request gagal: {exc}"
            ),
        }

    final_url = response.url

    headers = {
        k.lower(): v
        for k, v in response.headers.items()
    }

    security_headers = {}

    for key, display_name in (
        SECURITY_HEADERS.items()
    ):
        present = key in headers

        security_headers[display_name] = {
            "present": present,
            "value": headers.get(key),
        }

        if not present:
            severity = (
                "MEDIUM"
                if key in {
                    "strict-transport-security",
                    "content-security-policy",
                }
                else "LOW"
            )

            findings.append({
                "severity": severity,
                "finding": (
                    f"Security header "
                    f"{display_name} tidak ditemukan."
                ),
            })

    report = {
        "target": url,
        "final_url": final_url,
        "status_code": response.status_code,
        "server": headers.get(
            "server",
            "Unknown",
        ),
        "content_type": headers.get(
            "content-type",
            "Unknown",
        ),
        "redirected": (
            final_url != url
        ),
        "security_headers": security_headers,
        "findings": findings,
    }

    response.close()

    return report


def url_menu():
    section(
        "URL / HTTP SECURITY ANALYSIS"
    )

    value = safe_input(
        f"  {BLUE}url{RESET} {DIM}>{RESET} "
    )

    if not value:
        return

    print(
        f"\n  {YELLOW}[*]{RESET} "
        f"Checking URL and defensive headers..."
    )

    result = analyze_url(value)

    if (
        "error" in result
        and "status_code" not in result
    ):
        print(
            f"  {RED}[!]{RESET} "
            f"{result['error']}"
        )
        return

    print_rows([
        ("Target", result["target"]),
        ("Final URL", result["final_url"]),
        ("HTTP Status", result["status_code"]),
        ("Redirected", result["redirected"]),
        ("Server", result["server"]),
        ("Content-Type", result["content_type"]),
    ])

    print("\n  Security Headers:")

    for name, data in (
        result["security_headers"].items()
    ):
        status = (
            f"{GREEN}PRESENT{RESET}"
            if data["present"]
            else f"{RED}MISSING{RESET}"
        )

        print(
            f"   - {name:<24}: {status}"
        )

    if result["findings"]:
        print("\n  Findings:")

        for item in result["findings"]:
            print(
                f"   - "
                f"[{severity_color(item['severity'])}] "
                f"{item['finding']}"
            )

    else:
        print(
            f"\n  {GREEN}[+]{RESET} "
            f"Tidak ada temuan header dasar."
        )

    if safe_input(
        "\n  Save JSON report? [y/N] > "
    ).lower() == "y":
        print(
            f"  Saved: {save_report(result, 'url')}"
        )


# ============================================================
# TLS CERTIFICATE ANALYSIS
# ============================================================

def parse_cert_time(value):
    if not value:
        return None

    try:
        return datetime.strptime(
            value,
            "%b %d %H:%M:%S %Y %Z",
        ).replace(
            tzinfo=dt_timezone.utc
        )

    except Exception:
        return None


def analyze_tls(
    host,
    port=443,
):
    host = normalize_domain(host)

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (host, port),
            timeout=8,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host,
            ) as tls_sock:

                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                tls_version = tls_sock.version()

    except Exception as exc:
        return {
            "error": (
                f"TLS connection gagal: {exc}"
            )
        }

    not_before = parse_cert_time(
        cert.get("notBefore")
    )

    not_after = parse_cert_time(
        cert.get("notAfter")
    )

    now = datetime.now(
        dt_timezone.utc
    )

    days_remaining = None
    expired = None

    if not_after:
        delta = not_after - now

        days_remaining = delta.days

        expired = (
            delta.total_seconds() < 0
        )

    subject = dict(
        x[0]
        for x in cert.get(
            "subject",
            [],
        )
    )

    issuer = dict(
        x[0]
        for x in cert.get(
            "issuer",
            [],
        )
    )

    sans = [
        value
        for key, value in cert.get(
            "subjectAltName",
            [],
        )
        if key == "DNS"
    ]

    findings = []

    if expired:
        findings.append({
            "severity": "HIGH",
            "finding": (
                "TLS certificate sudah "
                "kedaluwarsa."
            ),
        })

    elif (
        days_remaining is not None
        and days_remaining < 30
    ):
        findings.append({
            "severity": "MEDIUM",
            "finding": (
                "TLS certificate akan "
                f"kedaluwarsa dalam "
                f"{days_remaining} hari."
            ),
        })

    return {
        "host": host,
        "port": port,
        "tls_version": tls_version,
        "cipher": (
            cipher[0]
            if cipher
            else "Unknown"
        ),
        "subject_common_name": subject.get(
            "commonName",
            "Unknown",
        ),
        "issuer_common_name": issuer.get(
            "commonName",
            "Unknown",
        ),
        "serial_number": cert.get(
            "serialNumber",
            "Unknown",
        ),
        "not_before": (
            not_before.isoformat()
            if not_before
            else cert.get("notBefore")
        ),
        "not_after": (
            not_after.isoformat()
            if not_after
            else cert.get("notAfter")
        ),
        "days_remaining": days_remaining,
        "subject_alt_names": sans,
        "findings": findings,
    }


def tls_menu():
    section(
        "TLS CERTIFICATE ANALYSIS"
    )

    host = safe_input(
        f"  {BLUE}host{RESET} {DIM}>{RESET} "
    )

    if not host:
        return

    result = analyze_tls(host)

    if "error" in result:
        print(
            f"  {RED}[!]{RESET} "
            f"{result['error']}"
        )
        return

    print_rows([
        ("Host", result["host"]),
        ("TLS Version", result["tls_version"]),
        ("Cipher", result["cipher"]),
        (
            "Subject CN",
            result["subject_common_name"]
        ),
        (
            "Issuer CN",
            result["issuer_common_name"]
        ),
        ("Not Before", result["not_before"]),
        ("Not After", result["not_after"]),
        (
            "Days Remaining",
            result["days_remaining"]
        ),
    ])

    if result["findings"]:
        print("\n  Findings:")

        for item in result["findings"]:
            print(
                f"   - "
                f"[{severity_color(item['severity'])}] "
                f"{item['finding']}"
            )

    if safe_input(
        "\n  Save JSON report? [y/N] > "
    ).lower() == "y":
        print(
            f"  Saved: {save_report(result, 'tls')}"
        )


# ============================================================
# FILE HASH & ENTROPY
# ============================================================

def shannon_entropy(data):
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum(
        (
            count / length
        )
        * math.log2(
            count / length
        )
        for count in counts.values()
    )


def analyze_file(path):
    if not os.path.isfile(path):
        return {
            "error": "File tidak ditemukan."
        }

    hashers = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    total_size = 0
    entropy_sample = bytearray()
    sample_limit = 1024 * 1024

    with open(path, "rb") as f:
        while True:
            chunk = f.read(
                1024 * 1024
            )

            if not chunk:
                break

            total_size += len(chunk)

            for hasher in (
                hashers.values()
            ):
                hasher.update(chunk)

            if (
                len(entropy_sample)
                < sample_limit
            ):
                remaining = (
                    sample_limit
                    - len(entropy_sample)
                )

                entropy_sample.extend(
                    chunk[:remaining]
                )

    entropy = shannon_entropy(
        entropy_sample
    )

    findings = []

    if entropy >= 7.5:
        findings.append({
            "severity": "MEDIUM",
            "finding": (
                "Entropy sampel sangat tinggi. "
                "Hal ini dapat terjadi pada file "
                "terkompresi, terenkripsi, atau "
                "packed; bukan bukti malware."
            ),
        })

    return {
        "path": os.path.abspath(path),
        "size_bytes": total_size,
        "md5": (
            hashers["md5"].hexdigest()
        ),
        "sha1": (
            hashers["sha1"].hexdigest()
        ),
        "sha256": (
            hashers["sha256"].hexdigest()
        ),
        "entropy_sample": round(
            entropy,
            4,
        ),
        "entropy_sample_bytes": len(
            entropy_sample
        ),
        "findings": findings,
    }


def file_menu():
    section(
        "FILE HASH / ENTROPY ANALYSIS"
    )

    path = safe_input(
        f"  {BLUE}file{RESET} {DIM}>{RESET} "
    ).strip('"')

    if not path:
        return

    result = analyze_file(path)

    if "error" in result:
        print(
            f"  {RED}[!]{RESET} "
            f"{result['error']}"
        )
        return

    print_rows([
        ("Path", result["path"]),
        (
            "Size",
            f"{result['size_bytes']} bytes"
        ),
        ("MD5", result["md5"]),
        ("SHA1", result["sha1"]),
        ("SHA256", result["sha256"]),
        ("Entropy", result["entropy_sample"]),
    ])

    if result["findings"]:
        print("\n  Findings:")

        for item in result["findings"]:
            print(
                f"   - "
                f"[{severity_color(item['severity'])}] "
                f"{item['finding']}"
            )

    if safe_input(
        "\n  Save JSON report? [y/N] > "
    ).lower() == "y":
        print(
            f"  Saved: {save_report(result, 'file')}"
        )


# ============================================================
# IOC AUTO DETECTION
# ============================================================

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

PHONE_RE = re.compile(
    r"^\+?[0-9][0-9\s().-]{6,}$"
)


def detect_ioc(value):
    value = value.strip()

    if not value:
        return "unknown"

    try:
        ipaddress.ip_address(value)
        return "ip"

    except ValueError:
        pass

    parsed = urllib.parse.urlparse(
        value
    )

    if (
        parsed.scheme in (
            "http",
            "https",
        )
        and parsed.netloc
    ):
        return "url"

    if DOMAIN_RE.match(
        value.lower()
    ):
        return "domain"

    if PHONE_RE.match(value):
        return "phone"

    if os.path.isfile(
        value.strip('"')
    ):
        return "file"

    if re.fullmatch(
        r"[a-fA-F0-9]{32}",
        value,
    ):
        return "md5"

    if re.fullmatch(
        r"[a-fA-F0-9]{40}",
        value,
    ):
        return "sha1"

    if re.fullmatch(
        r"[a-fA-F0-9]{64}",
        value,
    ):
        return "sha256"

    return "unknown"


def ioc_menu():
    section("IOC AUTO ANALYZER")

    value = safe_input(
        f"  {BLUE}ioc{RESET} {DIM}>{RESET} "
    )

    if not value:
        return

    detected = detect_ioc(value)

    print(
        f"\n  Detected type: "
        f"{BOLD}{detected.upper()}{RESET}"
    )

    if detected == "ip":
        result = analyze_ip(value)

    elif detected == "url":
        result = analyze_url(value)

    elif detected == "domain":
        result = analyze_domain(value)

    elif detected == "phone":
        result = (
            build_phone_scam_assessment(
                value,
                0,
            )
        )

    elif detected == "file":
        result = analyze_file(
            value.strip('"')
        )

    elif detected in (
        "md5",
        "sha1",
        "sha256",
    ):
        result = {
            "indicator": value,
            "type": detected,
            "note": (
                "Hash dikenali secara sintaksis. "
                "Tool offline ini tidak menentukan "
                "apakah hash malicious tanpa "
                "threat-intelligence source."
            ),
        }

    else:
        result = {
            "indicator": value,
            "type": "unknown",
            "note": (
                "Format IOC belum dikenali."
            ),
        }

    print()

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )

    if safe_input(
        "\n  Save JSON report? [y/N] > "
    ).lower() == "y":
        print(
            f"  Saved: {save_report(result, 'ioc')}"
        )


# ============================================================
# DEPENDENCY STATUS
# ============================================================

def dependency_status():
    section("DEPENDENCY STATUS")

    print_rows([
        (
            "requests",
            "OK"
            if requests
            else "MISSING"
        ),
        (
            "dnspython",
            "OK"
            if dns
            else "MISSING"
        ),
        (
            "phonenumbers",
            "OK"
            if phonenumbers
            else "MISSING"
        ),
        (
            "sqlite3",
            "OK (built-in)"
        ),
        (
            "Database",
            DB_PATH
        ),
    ])


# ============================================================
# MAIN MENU
# ============================================================

def main_menu():
    init_reputation_db()

    while True:
        section(
            "D4xlen CYBERSECURITY MODULES"
        )

        print(
            f"  {CYAN}[1]{RESET} "
            f"Phone Intelligence"
        )

        print(
            f"  {CYAN}[2]{RESET} "
            f"Phone Scam / Reputation Check"
        )

        print(
            f"  {CYAN}[3]{RESET} "
            f"Add Suspicious Phone Report"
        )

        print(
            f"  {CYAN}[4]{RESET} "
            f"Local Phone Report History"
        )

        print(
            f"  {CYAN}[5]{RESET} "
            f"Username / Social Presence Search"
        )

        print(
            f"  {CYAN}[6]{RESET} "
            f"Domain / DNS Intelligence"
        )

        print(
            f"  {CYAN}[7]{RESET} "
            f"IP Intelligence"
        )

        print(
            f"  {CYAN}[8]{RESET} "
            f"URL / HTTP Security Headers"
        )

        print(
            f"  {CYAN}[9]{RESET} "
            f"TLS Certificate Analysis"
        )

        print(
            f"  {CYAN}[10]{RESET} "
            f"File Hash / Entropy Analysis"
        )

        print(
            f"  {CYAN}[11]{RESET} "
            f"IOC Auto Analyzer"
        )

        print(
            f"  {CYAN}[12]{RESET} "
            f"Dependency Status"
        )

        print(
            f"  {BLUE}[0]{RESET} "
            f"Exit"
        )

        choice = safe_input(
            f"\n  {MAGENTA}module{RESET} "
            f"{DIM}>{RESET} "
        )

        if choice == "1":
            phone_menu()

        elif choice == "2":
            scam_check_menu()

        elif choice == "3":
            add_scam_report_menu()

        elif choice == "4":
            list_phone_reports_menu()

        elif choice == "5":
            username_search_menu()

        elif choice == "6":
            domain_menu()

        elif choice == "7":
            ip_menu()

        elif choice == "8":
            url_menu()

        elif choice == "9":
            tls_menu()

        elif choice == "10":
            file_menu()

        elif choice == "11":
            ioc_menu()

        elif choice == "12":
            dependency_status()

        elif choice == "0":
            print(
                f"\n  {GREEN}[+]{RESET} "
                f"Session closed.\n"
            )
            break

        else:
            print(
                f"\n  {RED}[!]{RESET} "
                f"Invalid module."
            )

        safe_input(
            "\n  Press Enter to continue..."
        )


def main():
    clear_screen()
    banner()
    main_menu()


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print(
            f"\n\n  {YELLOW}[*]{RESET} "
            f"Interrupted by user."
        )

    except Exception as exc:
        print(
            f"\n  {RED}[!]{RESET} "
            f"Fatal error: {exc}"
        )
