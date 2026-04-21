import sqlite3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common.crypto_utils import generate_keys

DB_PATH       = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'voting.db')
STUDENTS_TXT  = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'students.txt')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS server_keys (
            id    INTEGER PRIMARY KEY CHECK(id = 1),
            pub_e INTEGER NOT NULL,
            pub_n INTEGER NOT NULL,
            priv_d INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS students (
            matricule TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            group_num INTEGER NOT NULL,
            section   INTEGER DEFAULT 1,
            pub_e     INTEGER,
            pub_n     INTEGER,
            priv_d    INTEGER
        );

        CREATE TABLE IF NOT EXISTS candidates (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL,
            group_num INTEGER NOT NULL,
            UNIQUE(name, group_num)
        );

        CREATE TABLE IF NOT EXISTS elections (
            group_num INTEGER PRIMARY KEY,
            status    TEXT DEFAULT 'closed' CHECK(status IN ('open','closed')),
            close_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS votes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            voter_matricule TEXT NOT NULL REFERENCES students(matricule),
            candidate_id    INTEGER NOT NULL REFERENCES candidates(id),
            group_num       INTEGER NOT NULL,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(voter_matricule)
        );
    ''')
    for g in [1, 2, 3]:
        c.execute('INSERT OR IGNORE INTO elections (group_num, status) VALUES (?, ?)', (g, 'closed'))
    conn.commit()
    conn.close()


def setup_server_keys():
    """Generate and store RSA keys for the server (runs once)."""
    conn = get_db()
    row = conn.execute('SELECT * FROM server_keys WHERE id=1').fetchone()
    if row:
        conn.close()
        return dict(row)
    pub, priv = generate_keys()
    conn.execute(
        'INSERT INTO server_keys (id, pub_e, pub_n, priv_d) VALUES (1, ?, ?, ?)',
        (pub[0], pub[1], priv[0])
    )
    conn.commit()
    conn.close()
    print(f'[KEYGEN] Server keys generated: pub=({pub[0]}, {pub[1]})')
    return {'pub_e': pub[0], 'pub_n': pub[1], 'priv_d': priv[0]}


def get_server_keys():
    conn = get_db()
    row = conn.execute('SELECT * FROM server_keys WHERE id=1').fetchone()
    conn.close()
    return dict(row) if row else None


def import_students():
    """Parse students.txt and insert into DB."""
    conn = get_db()
    count = 0
    with open(STUDENTS_TXT, encoding='utf-8') as f:
        lines = f.readlines()
    for line in lines[1:]:
        parts = line.strip().split('\t')
        if len(parts) < 8:
            continue
        matricule = parts[0].strip()
        full_name = parts[1].strip()
        username  = parts[3].strip()
        group_num = parts[5].strip()
        section   = parts[6].strip()
        password  = parts[7].strip()
        if not matricule or not username:
            continue
        conn.execute(
            'INSERT OR IGNORE INTO students '
            '(matricule, full_name, username, password, group_num, section) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (matricule, full_name, username, password,
             int(group_num) if group_num else 1,
             int(section)   if section   else 1)
        )
        count += 1
    conn.commit()
    conn.close()
    return count


def generate_student_keys():
    """Generate RSA key pairs for all students who don't have keys yet."""
    conn = get_db()
    rows = conn.execute(
        'SELECT matricule FROM students WHERE pub_e IS NULL'
    ).fetchall()
    for row in rows:
        pub, priv = generate_keys()
        conn.execute(
            'UPDATE students SET pub_e=?, pub_n=?, priv_d=? WHERE matricule=?',
            (pub[0], pub[1], priv[0], row['matricule'])
        )
    conn.commit()
    conn.close()
    print(f'[KEYGEN] Generated RSA keys for {len(rows)} students')


# ── Auth & vote helpers ────────────────────────────────────────────────────────

def authenticate(username, password):
    conn = get_db()
    row = conn.execute(
        'SELECT * FROM students WHERE username=? AND password=?',
        (username, password)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_candidates(group_num):
    conn = get_db()
    rows = conn.execute(
        'SELECT id, name FROM candidates WHERE group_num=? ORDER BY name',
        (group_num,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def check_and_close_elections():
    """Auto-close any elections whose close_at deadline has passed."""
    conn = get_db()
    conn.execute("""
        UPDATE elections
        SET status = 'closed', close_at = NULL
        WHERE status = 'open'
          AND close_at IS NOT NULL
          AND close_at <= datetime('now', 'localtime')
    """)
    conn.commit()
    conn.close()


def election_status(group_num):
    conn = get_db()
    row = conn.execute(
        'SELECT status FROM elections WHERE group_num=?', (group_num,)
    ).fetchone()
    conn.close()
    return row['status'] if row else 'closed'


def election_info(group_num):
    """Return full election row including close_at."""
    conn = get_db()
    row = conn.execute(
        'SELECT status, close_at FROM elections WHERE group_num=?', (group_num,)
    ).fetchone()
    conn.close()
    return dict(row) if row else {'status': 'closed', 'close_at': None}


def has_voted(matricule):
    conn = get_db()
    row = conn.execute(
        'SELECT 1 FROM votes WHERE voter_matricule=?', (matricule,)
    ).fetchone()
    conn.close()
    return row is not None


def record_vote(voter_matricule, candidate_id, group_num):
    conn = get_db()
    conn.execute(
        'INSERT INTO votes (voter_matricule, candidate_id, group_num) VALUES (?,?,?)',
        (voter_matricule, candidate_id, group_num)
    )
    conn.commit()
    conn.close()


def get_results(group_num):
    conn = get_db()
    rows = conn.execute('''
        SELECT c.name, COUNT(v.id) AS cnt
        FROM candidates c
        LEFT JOIN votes v ON v.candidate_id = c.id
        WHERE c.group_num = ?
        GROUP BY c.id
        ORDER BY cnt DESC
    ''', (group_num,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
