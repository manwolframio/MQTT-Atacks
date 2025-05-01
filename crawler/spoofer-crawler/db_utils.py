import sqlite3

DB_PATH = "mqtt_spoofer.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS captured_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_mac TEXT, dst_mac TEXT,
            src_ip TEXT, dst_ip TEXT,
            src_port INTEGER, dst_port INTEGER,
            topic TEXT, payload TEXT,
            raw BLOB
        )
    """)
    conn.commit()
    return conn

