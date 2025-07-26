import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "assets.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Assets table
    c.execute('''
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Ports table with version and banner
    c.execute('''
    CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER,
        port INTEGER,
        protocol TEXT,
        service TEXT,
        version TEXT,
        banner TEXT,
        FOREIGN KEY(asset_id) REFERENCES assets(id)
    )
    ''')

    # Subdomains with ip and parent_domain - updated schema without 'subdomain' column
    c.execute('''
    CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        parent_domain TEXT,
        ip TEXT,
        resolved BOOLEAN,
        last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Geolocation table
    c.execute('''
    CREATE TABLE IF NOT EXISTS geolocation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        country TEXT,
        country_code TEXT,
        region TEXT,
        city TEXT,
        latitude REAL,
        longitude REAL,
        isp TEXT,
        organization TEXT,
        timezone TEXT,
        as_number TEXT,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Company info table
    c.execute('''
    CREATE TABLE IF NOT EXISTS company_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        registrar TEXT,
        creation_date TEXT,
        expiration_date TEXT,
        organization TEXT,
        country TEXT,
        cert_organization TEXT,
        cert_issuer TEXT,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Vulnerabilities table
    c.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        port INTEGER,
        cve_id TEXT,
        description TEXT,
        cvss_score REAL,
        severity TEXT,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Scan history table
    c.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT,
        domain TEXT,
        parameters TEXT,
        results_count INTEGER,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()
