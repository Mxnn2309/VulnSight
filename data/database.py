import sqlite3

def init_db():
    conn = sqlite3.connect('vulnsight.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            cve_id TEXT,
            cvss_score REAL,
            epss_score REAL,
            asset_criticality INTEGER,
            discovery_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")