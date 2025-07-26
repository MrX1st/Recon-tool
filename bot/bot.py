import os
import re
import logging
import asyncio
import sqlite3
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

# ────────────────────────────────────────────────────────────────────────────────
#  Internal modules
# ────────────────────────────────────────────────────────────────────────────────
from scanner.ip_discovery import multi_source_search, store_assets
from scanner.subdomain_enum import enumerate_subdomains, store_subdomains
from scanner.geolocation import GeolocationService, store_geolocation_data
from scanner.company_info import gather_company_information
from scanner.vulnerability_scanner import scan_for_vulnerabilities, store_vulnerability_data

# ────────────────────────────────────────────────────────────────────────────────
#  Configuration & globals
# ────────────────────────────────────────────────────────────────────────────────
load_dotenv()
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory session storage (reserved for future use)
user_sessions: dict[int, dict] = {}

SUPPORTED_DOMAINS = [
    "goldapple.ru",
    "goldapple.kz",
    "goldapple.by",
    "goldapple.qa",
    "goldapple.ae",
]

DOMAIN_REGEX = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "assets.db")

# ────────────────────────────────────────────────────────────────────────────────
#  Menu entry points
# ────────────────────────────────────────────────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ *Perimeter Security Audit Tool*\n\n"
        "Welcome! This tool helps you discover and analyze your organisation's "
        "external attack surface.\n\n"
        "Please select an option below:",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard(),
    )

def main_menu_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton("🔍 Asset Discovery", callback_data="asset_discovery")],
        [InlineKeyboardButton("🌐 Subdomain Enumeration", callback_data="subdomain_enum")],
        [InlineKeyboardButton("📊 View Results", callback_data="view_results")],
        [InlineKeyboardButton("⚙️ Advanced Options", callback_data="advanced_options")],
        [InlineKeyboardButton("📖 Help", callback_data="help")],
    ]
    return InlineKeyboardMarkup(keyboard)

# ────────────────────────────────────────────────────────────────────────────────
#  Callback router
# ────────────────────────────────────────────────────────────────────────────────
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    # ── Main navigation ────────────────────────────────────────────────────────
    if data == "asset_discovery":
        await asset_discovery_menu(query)
    elif data == "subdomain_enum":
        await subdomain_enumeration_menu(query)
    elif data == "view_results":
        await view_results_menu(query)
    elif data == "advanced_options":
        await advanced_options_menu(query)
    elif data == "help":
        await show_help(query, context)
    elif data == "back_to_main":
        await query.edit_message_text(
            "🛡️ *Perimeter Security Audit Tool*\n\n"
            "Welcome back to the main menu. Select an option:",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )

    # ── Asset discovery actions ───────────────────────────────────────────────
    elif data == "scan_all_assets":
        await start_asset_scan_all(query)
    elif data.startswith("scan_assets_"):
        domain = data.removeprefix("scan_assets_")
        await start_asset_scan(query, domain)
    elif data.startswith("vuln_scan_assets_"):
        domain = data.removeprefix("vuln_scan_assets_")
        await start_vulnerability_scan_assets(query, domain)
    elif data.startswith("detailed_assets_"):
        domain = data.removeprefix("detailed_assets_")
        await show_detailed_assets(query, domain)

    # ── Subdomain enumeration actions ─────────────────────────────────────────
    elif data == "scan_all_subdomains":
        await start_subdomain_scan_all(query)
    elif data.startswith("scan_subdomains_"):
        domain = data.removeprefix("scan_subdomains_")
        await start_subdomain_scan(query, domain)
    elif data.startswith("vuln_scan_subdomains_"):
        domain = data.removeprefix("vuln_scan_subdomains_")
        await start_vulnerability_scan_subdomains(query, domain)
    elif data.startswith("detailed_subdomains_"):
        domain = data.removeprefix("detailed_subdomains_")
        await show_detailed_subdomains(query, domain)
    elif data.startswith("subdomain_level_"):
        await handle_subdomain_level_selection(query, data)

    # ── Results navigation ────────────────────────────────────────────────────
    elif data == "view_assets_data":
        await show_assets_data(query)
    elif data == "view_subdomains_data":
        await show_subdomains_data(query)
    elif data == "view_vulnerabilities_data":
        await show_vulnerabilities_data(query)

    # ── Advanced options placeholders ─────────────────────────────────────────
    elif data == "adv_option_1":
        await query.edit_message_text(
            "⚙️ You selected *Advanced Option 1* (feature coming soon).",
            parse_mode="Markdown",
        )
    elif data == "adv_option_2":
        await query.edit_message_text(
            "⚙️ You selected *Advanced Option 2* (feature coming soon).",
            parse_mode="Markdown",
        )

    else:
        await query.edit_message_text("❌ Unknown action. Please try again.")

# ────────────────────────────────────────────────────────────────────────────────
#  Asset-discovery flow
# ────────────────────────────────────────────────────────────────────────────────
async def asset_discovery_menu(query):
    keyboard = [
        [InlineKeyboardButton(f"🏢 Scan {d}", callback_data=f"scan_assets_{d}")]
        for d in SUPPORTED_DOMAINS
    ]
    keyboard.append([InlineKeyboardButton("🔍 Scan All Domains", callback_data="scan_all_assets")])
    keyboard.append([InlineKeyboardButton("← Back", callback_data="back_to_main")])
    await query.edit_message_text(
        "🔍 *Asset Discovery*\n\n"
        "Select which domain to scan for IP addresses & open ports.",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )

async def start_asset_scan(query, domain: str):
    await query.edit_message_text(
        f"🔄 Starting asset discovery for *{domain}*...\nPlease wait…",
        parse_mode="Markdown",
    )
    try:
        assets = multi_source_search(domain)
        store_assets(assets)

        if not assets:
            await query.edit_message_text(
                f"✅ Asset discovery finished for *{domain}*.\n\n❌ No assets found.",
                parse_mode="Markdown",
            )
            return

        total_assets = len(assets)
        total_ports = sum(len(a.get("ports", [])) for a in assets)

        geo_service = GeolocationService()
        geo_data = geo_service.bulk_geolocate([a["ip"] for a in assets])
        if geo_data:
            store_geolocation_data(geo_data)

        # Build summary text
        summary = (
            f"✅ *Asset Discovery Results for {domain}*\n\n"
            f"📊 **Summary:**\n"
            f"• IP addresses found: {total_assets}\n"
            f"• Open ports found: {total_ports}\n\n"
        )

        # Geo top 3
        if geo_data:
            countries: dict[str, int] = {}
            for g in geo_data:
                countries[g.get("country", "Unknown")] = countries.get(g.get("country", "Unknown"), 0) + 1
            top3 = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:3]
            summary += "🌍 **Top Locations:**\n"
            for country, count in top3:
                summary += f"• {country}: {count} IPs\n"
            summary += "\n"

        summary += "🔍 **Sample Assets:**\n"
        for a in assets[:5]:
            ports = ", ".join(map(str, a.get("ports", [])))
            summary += f"• {a['ip']}  [ports: {ports}]\n"
        if total_assets > 5:
            summary += f"…and {total_assets - 5} more."

        # Action buttons
        keyboard = [
            [InlineKeyboardButton("🔒 Scan for Vulnerabilities", callback_data=f"vuln_scan_assets_{domain}")],
            [InlineKeyboardButton("📊 View Detailed Results", callback_data=f"detailed_assets_{domain}")],
            [InlineKeyboardButton("← Back to Menu", callback_data="back_to_main")],
        ]
        await query.edit_message_text(
            summary, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard)
        )

    except Exception as e:
        logger.error("Asset discovery error: %s", e)
        await query.edit_message_text(
            f"❌ Error during asset discovery for {domain}: {e}",
            parse_mode="Markdown",
        )

async def start_asset_scan_all(query):
    await query.edit_message_text(
        "🔄 Starting asset discovery for *all supported domains*…", parse_mode="Markdown"
    )
    all_assets = []
    try:
        for domain in SUPPORTED_DOMAINS:
            assets = multi_source_search(domain)
            store_assets(assets)
            all_assets.extend(assets)

        if not all_assets:
            await query.edit_message_text(
                "✅ Asset discovery finished. ❌ No assets found.",
                parse_mode="Markdown",
            )
            return
        await query.edit_message_text(
            f"✅ Asset discovery finished.\nTotal assets found: {len(all_assets)}",
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.error("Global asset discovery error: %s", e)
        await query.edit_message_text(
            f"❌ Error during global asset discovery: {e}", parse_mode="Markdown"
        )

# ────────────────────────────────────────────────────────────────────────────────
#  Subdomain-enumeration flow
# ────────────────────────────────────────────────────────────────────────────────
async def subdomain_enumeration_menu(query):
    keyboard = [
        [InlineKeyboardButton(f"🏢 {d}", callback_data=f"scan_subdomains_{d}")]
        for d in SUPPORTED_DOMAINS
    ]
    keyboard.append([InlineKeyboardButton("🔍 Scan All Domains", callback_data="scan_all_subdomains")])
    keyboard.append([InlineKeyboardButton("← Back", callback_data="back_to_main")])
    await query.edit_message_text(
        "🌐 *Subdomain Enumeration*\n\nSelect a domain to enumerate subdomains.",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )

async def start_subdomain_scan(query, domain: str):
    await query.edit_message_text(
        f"🔄 Starting subdomain enumeration for *{domain}*…", parse_mode="Markdown"
    )
    try:
        subdomains = enumerate_subdomains(domain)
        store_subdomains(subdomains, domain)

        if not subdomains:
            await query.edit_message_text(
                f"✅ Enumeration finished for *{domain}*.\n❌ No subdomains found.",
                parse_mode="Markdown",
            )
            return

        await process_subdomain_results(query, subdomains, domain)

    except Exception as e:
        logger.exception("Subdomain enumeration error")
        await query.edit_message_text(
            f"❌ Error during subdomain enumeration for {domain}: {e}",
            parse_mode="Markdown",
        )

async def start_subdomain_scan_all(query):
    await query.edit_message_text(
        "🔄 Starting subdomain enumeration for *all supported domains*…",
        parse_mode="Markdown",
    )
    all_subs = []
    try:
        for d in SUPPORTED_DOMAINS:
            subs = enumerate_subdomains(d)
            store_subdomains(subs, d)
            all_subs.extend(subs)
        await query.edit_message_text(
            f"✅ Enumeration finished for all domains.\nTotal subdomains found: {len(all_subs)}",
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.error("Global subdomain enumeration error: %s", e)
        await query.edit_message_text(
            f"❌ Error during global subdomain enumeration: {e}",
            parse_mode="Markdown",
        )

# ── Result presentation helpers ────────────────────────────────────────────────
async def process_subdomain_results(query, subdomains: list[dict], domain: str):
    """Show a summary of subdomain enumeration and provide action buttons."""
    total = len(subdomains)
    resolved = [s for s in subdomains if s.get("resolved")]
    resolved_count = len(resolved)
    unresolved_count = total - resolved_count

    text = (
        f"✅ *Subdomain Enumeration Results for {domain}*\n\n"
        f"📊 **Summary:**\n"
        f"• Total subdomains: {total}\n"
        f"• Resolved: {resolved_count}\n"
        f"• Unresolved: {unresolved_count}\n\n"
    )

    if resolved:
        text += "🌐 **Sample Resolved Subdomains:**\n"
        for s in resolved[:10]:
            ip = s.get("ip") or "N/A"
            text += f"• {s['subdomain']} → {ip}\n"
        if resolved_count > 10:
            text += f"…and {resolved_count - 10} more.\n"

    keyboard = [
        [InlineKeyboardButton("🔒 Scan for Vulnerabilities", callback_data=f"vuln_scan_subdomains_{domain}")],
        [InlineKeyboardButton("📊 View Detailed Results", callback_data=f"detailed_subdomains_{domain}")],
        [InlineKeyboardButton("← Back to Menu", callback_data="back_to_main")],
    ]
    await query.edit_message_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

# ────────────────────────────────────────────────────────────────────────────────
#  Vulnerability-scan flows
# ────────────────────────────────────────────────────────────────────────────────
async def start_vulnerability_scan_subdomains(query, domain: str):
    await query.edit_message_text(
        f"🔄 Scanning *resolved* subdomains of {domain} for vulnerabilities…",
        parse_mode="Markdown",
    )

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip FROM subdomains WHERE parent_domain=? AND ip IS NOT NULL", (domain,))
    ips = [row[0] for row in c.fetchall()]
    conn.close()

    if not ips:
        await query.edit_message_text(
            f"❌ No resolved subdomains for {domain} to scan.",
            parse_mode="Markdown",
        )
        return

    try:
        all_results = []
        for ip in ips[:10]:  # limit to avoid Telegram timeouts
            results = scan_for_vulnerabilities(ip, [80, 443])
            all_results.extend(results)
        if all_results:
            store_vulnerability_data(all_results)
            total_vulns = sum(len(r["vulnerabilities"]) for r in all_results)
            await query.edit_message_text(
                f"✅ Vulnerability scan finished.\nDiscovered *{total_vulns}* potential findings.",
                parse_mode="Markdown",
            )
        else:
            await query.edit_message_text(
                "✅ Vulnerability scan finished. No issues detected.",
                parse_mode="Markdown",
            )
    except Exception as e:
        logger.error("Subdomain vulnerability scan error: %s", e)
        await query.edit_message_text(
            f"❌ Error during vulnerability scan: {e}",
            parse_mode="Markdown",
        )

async def start_vulnerability_scan_assets(query, domain: str):
    await query.edit_message_text(
        f"🔄 Scanning discovered assets of {domain} for vulnerabilities…",
        parse_mode="Markdown",
    )

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip FROM assets WHERE domain=?", (domain,))
    ips = [row[0] for row in c.fetchall()]
    conn.close()

    if not ips:
        await query.edit_message_text(
            f"❌ No assets for {domain} to scan.",
            parse_mode="Markdown",
        )
        return

    try:
        all_results = []
        for ip in ips[:10]:
            results = scan_for_vulnerabilities(ip, [80, 443])
            all_results.extend(results)
        if all_results:
            store_vulnerability_data(all_results)
            total_vulns = sum(len(r["vulnerabilities"]) for r in all_results)
            await query.edit_message_text(
                f"✅ Vulnerability scan finished.\nDiscovered *{total_vulns}* potential findings.",
                parse_mode="Markdown",
            )
        else:
            await query.edit_message_text(
                "✅ Vulnerability scan finished. No issues detected.",
                parse_mode="Markdown",
            )
    except Exception as e:
        logger.error("Asset vulnerability scan error: %s", e)
        await query.edit_message_text(
            f"❌ Error during vulnerability scan: {e}",
            parse_mode="Markdown",
        )

# ────────────────────────────────────────────────────────────────────────────────
#  Detailed results screens
# ────────────────────────────────────────────────────────────────────────────────
async def show_detailed_subdomains(query, domain: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT domain, ip, resolved FROM subdomains WHERE parent_domain=? ORDER BY domain LIMIT 100",
        (domain,),
    )
    rows = c.fetchall()
    conn.close()

    if not rows:
        await query.edit_message_text(
            f"No subdomain data for {domain}.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="view_results")]]),
        )
        return

    text = f"*Detailed Subdomains for {domain}* (max 100 rows):\n\n"
    for sub, ip, res in rows:
        status = "✅" if res else "❌"
        ip_txt = f" ({ip})" if ip else ""
        text += f"{status} {sub}{ip_txt}\n"

    await query.edit_message_text(
        text,
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="view_results")]]),
    )

async def show_detailed_assets(query, domain: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT ip FROM assets WHERE domain=? ORDER BY ip LIMIT 100",
        (domain,),
    )
    rows = c.fetchall()
    conn.close()

    if not rows:
        await query.edit_message_text(
            f"No asset data for {domain}.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="view_results")]]),
        )
        return

    text = f"*Detailed Assets for {domain}* (max 100 rows):\n\n"
    for row in rows:
        text += f"• {row[0]}\n"

    await query.edit_message_text(
        text,
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="view_results")]]),
    )

# ────────────────────────────────────────────────────────────────────────────────
#  Results overview screens
# ────────────────────────────────────────────────────────────────────────────────
async def view_results_menu(query):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM assets")
    assets_cnt = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM subdomains")
    subs_cnt = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM vulnerabilities")
    vulns_cnt = c.fetchone()[0] or 0
    conn.close()

    if not any([assets_cnt, subs_cnt, vulns_cnt]):
        await query.edit_message_text(
            "📊 *View Results*\n\nNo data available. Run a scan first.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="back_to_main")]]),
        )
        return

    text = "📊 *View Results*\n\nSelect a dataset to view:\n"
    keyboard = []
    if assets_cnt:
        keyboard.append([InlineKeyboardButton(f"• Assets ({assets_cnt})", callback_data="view_assets_data")])
    if subs_cnt:
        keyboard.append([InlineKeyboardButton(f"• Subdomains ({subs_cnt})", callback_data="view_subdomains_data")])
    if vulns_cnt:
        keyboard.append([InlineKeyboardButton(f"• Vulnerabilities ({vulns_cnt})", callback_data="view_vulnerabilities_data")])
    keyboard.append([InlineKeyboardButton("← Back", callback_data="back_to_main")])

    await query.edit_message_text(
        text,
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )

async def show_assets_data(query):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip FROM assets ORDER BY ip LIMIT 50")
    rows = c.fetchall()
    conn.close()

    if not rows:
        await query.edit_message_text(
            "No asset records.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="view_results")]]),
        )
        return

    text = "*Assets Found (first 50)*:\n" + "\n".join(f"• {r[0]}" for r in rows)
    await query.edit_message_text(
        text,
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="view_results")]]),
    )

async def show_subdomains_data(query):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT domain, resolved, ip FROM subdomains ORDER BY domain LIMIT 50")
    rows = c.fetchall()
    conn.close()

    if not rows:
        await query.edit_message_text(
            "No subdomains data found.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data='view_results')]])
        )
        return

    text = "*Subdomains Found (showing up to 50)*:\n"
    for domain, resolved, ip in rows:
        status = "✅" if resolved else "❌"
        ip_part = f" ({ip})" if ip else ""
        text += f"{status} {domain}{ip_part}\n"

    keyboard = [[InlineKeyboardButton("← Back", callback_data='view_results')]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(text, parse_mode='Markdown', reply_markup=reply_markup)


DB_PATH = './data/assets.db'  # Use your actual DB path

def escape_markdown_v2(text: str) -> str:
    if not text:
        return ""
    # First, escape backslash itself:
    text = text.replace('\\', '\\\\')
    special_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(special_chars)}])', r'\\\1', text)

async def show_vulnerabilities_data(query):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT ip, port, cve_id, severity, description FROM vulnerabilities ORDER BY severity DESC LIMIT 50"
    )
    rows = c.fetchall()
    conn.close()

    if not rows:
        await query.edit_message_text(
            "No vulnerability data stored.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="view_results")]]),
        )
        return

    text_lines = ["*Vulnerabilities (top 50)*:\n"]
    for ip, port, cve, sev, desc in rows:
        ip_esc = escape_markdown_v2(ip or "")
        port_esc = escape_markdown_v2(str(port) if port is not None else "")
        cve_esc = escape_markdown_v2(cve or "")
        sev_esc = escape_markdown_v2(sev or "")
        desc_esc = escape_markdown_v2(desc or "")

        # Build one formatted line per vulnerability
        text_lines.append(
            f"• {ip_esc}:{port_esc} | {cve_esc} | Severity: {sev_esc}\n  {desc_esc}\n"
        )

    final_text = "\n".join(text_lines)

    keyboard = [[InlineKeyboardButton("← Back", callback_data="view_results")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(final_text, parse_mode='MarkdownV2', reply_markup=reply_markup)


# ────────────────────────────────────────────────────────────────────────────────
#  Advanced options placeholder
# ────────────────────────────────────────────────────────────────────────────────
async def advanced_options_menu(query):
    keyboard = [
        [InlineKeyboardButton("Option 1 (Placeholder)", callback_data="adv_option_1")],
        [InlineKeyboardButton("Option 2 (Placeholder)", callback_data="adv_option_2")],
        [InlineKeyboardButton("← Back", callback_data="back_to_main")],
    ]
    await query.edit_message_text(
        "⚙️ *Advanced Options*\n\nSelect an option (placeholders):",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )

# ────────────────────────────────────────────────────────────────────────────────
#  Help
# ────────────────────────────────────────────────────────────────────────────────
async def show_help(query, context):
    help_text = (
        "🛡️ *Perimeter Security Audit Tool Help*\n\n"
        "**What this tool does:**\n"
        "• Discovers IP addresses and open ports for your domains\n"
        "• Enumerates subdomains with level filtering\n"
        "• Provides geolocation data for discovered assets\n"
        "• Gathers company information from WHOIS and certificates\n"
        "• Performs basic vulnerability assessment\n\n"
        "**Features:**\n"
        "• **Asset Discovery**: Uses passive reconnaissance to find IPs and ports\n"
        "• **Subdomain Enumeration**: Finds subdomains from certificate transparency logs\n"
        "• **Level Filtering**: Choose specific subdomain levels (1st, 2nd, 3rd, 4th)\n"
        "• **Geolocation**: Maps discovered IPs to geographic locations\n"
        "• **Company Info**: Extracts organization details from WHOIS data\n"
        "• **Vulnerability Scanning**: Basic vulnerability assessment using CVE databases\n\n"
        "**Supported Domains:**\n"
        + "\n".join(f"• {domain}" for domain in SUPPORTED_DOMAINS)
        + "\n\n"
        "**Note:** This tool uses only passive reconnaissance techniques and free APIs to ensure legal compliance and avoid detection."
    )

    keyboard = [[InlineKeyboardButton("← Back to Menu", callback_data="back_to_main")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(
        help_text,
        parse_mode="Markdown",
        reply_markup=reply_markup,
    )

# ────────────────────────────────────────────────────────────────────────────────
#  Misc handlers
# ────────────────────────────────────────────────────────────────────────────────
async def handle_subdomain_level_selection(query, data: str):
    # Placeholder for future granular level scans (1st / 2nd / …)
    await query.edit_message_text("Feature not implemented yet.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="back_to_main")]]))

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Single-message fallback: treat plain domain names as ad-hoc asset scan."""
    text = (update.message.text or "").strip().lower()
    if DOMAIN_REGEX.match(text):
        await update.message.reply_text(f"🔄 Scanning domain {text}…")
        loop = asyncio.get_running_loop()
        assets = await loop.run_in_executor(None, multi_source_search, text)
        store_assets(assets)
        await update.message.reply_text(f"✅ Scan finished. Assets discovered: {len(assets)}")
        return

    await update.message.reply_text(
        "Unknown command. Use /start to open the menu.",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Menu", callback_data="back_to_main")]]),
    )

# ────────────────────────────────────────────────────────────────────────────────
#  Main entry
# ────────────────────────────────────────────────────────────────────────────────
def main():
    application = (
        ApplicationBuilder()
        .token(TOKEN)
        .build()
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

    logger.info("Perimeter Security Audit Bot started.")
    application.run_polling()

if __name__ == "__main__":
    main()
