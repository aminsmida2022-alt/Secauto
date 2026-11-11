import sqlite3, os, json

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secauto.db')

def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _conn() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id       TEXT UNIQUE NOT NULL,
            targets      TEXT NOT NULL,
            tools        TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'running',
            started_at   TEXT NOT NULL,
            finished_at  TEXT,
            total_findings INTEGER DEFAULT 0,
            total_tp     INTEGER DEFAULT 0,
            lang         TEXT DEFAULT 'fr'
        )''')
        c.commit()

def save_scan(run_id, targets, tools, started_at, lang='fr'):
    with _conn() as c:
        c.execute(
            'INSERT OR REPLACE INTO scans (run_id,targets,tools,status,started_at,lang) VALUES (?,?,?,?,?,?)',
            (run_id, json.dumps(targets), json.dumps(tools), 'running', started_at, lang)
        )
        c.commit()

def update_scan(run_id, status, finished_at, total_findings=0, total_tp=0):
    with _conn() as c:
        c.execute(
            'UPDATE scans SET status=?,finished_at=?,total_findings=?,total_tp=? WHERE run_id=?',
            (status, finished_at, total_findings, total_tp, run_id)
        )
        c.commit()

def get_scan(run_id):
    with _conn() as c:
        row = c.execute('SELECT * FROM scans WHERE run_id=?', (run_id,)).fetchone()
        return dict(row) if row else None

def get_all_scans():
    with _conn() as c:
        return [dict(r) for r in c.execute('SELECT * FROM scans ORDER BY started_at DESC').fetchall()]
