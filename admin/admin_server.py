#!/usr/bin/env python3
import sys
import os
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, redirect, url_for, session, flash
from db import (get_db, init_db, import_students, generate_student_keys,
                setup_server_keys, get_server_keys,
                get_candidates, get_results,
                authenticate, election_status, election_info,
                check_and_close_elections, has_voted, record_vote)

app = Flask(__name__, template_folder='templates')
app.secret_key = 'change-this-secret-key'

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def student_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('student'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


# ── Unified login ──────────────────────────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('admin'):
        return redirect(url_for('dashboard'))
    if session.get('student'):
        return redirect(url_for('vote'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('dashboard'))

        student = authenticate(username, password)
        if student:
            session['student'] = {
                'matricule': student['matricule'],
                'full_name': student['full_name'],
                'group':     student['group_num'],
                'username':  student['username'],
                # Private key delivered to browser for client-side signing
                'priv_d':    student['priv_d'],
                'priv_n':    student['pub_n'],
            }
            return redirect(url_for('vote'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── Student voting ─────────────────────────────────────────────────────────────

@app.route('/vote')
@student_required
def vote():
    s     = session['student']
    group = s['group']

    if has_voted(s['matricule']):
        return redirect(url_for('thankyou'))

    if election_status(group) != 'open':
        return render_template('wait.html', full_name=s['full_name'], group=group)

    candidates = get_candidates(group)
    if not candidates:
        return render_template('wait.html', full_name=s['full_name'], group=group,
                               message='No candidates have been added yet.')

    server_keys = get_server_keys()

    return render_template('vote.html',
        full_name    = s['full_name'],
        group        = group,
        candidates   = candidates,
        server_e     = server_keys['pub_e'],
        server_n     = server_keys['pub_n'],
        student_d    = s['priv_d'],
        student_n    = s['priv_n'],
    )


@app.route('/submit-vote', methods=['POST'])
@student_required
def submit_vote():
    s     = session['student']
    group = s['group']

    if has_voted(s['matricule']):
        return redirect(url_for('thankyou'))

    if election_status(group) != 'open':
        flash('The election is not open.', 'danger')
        return redirect(url_for('vote'))

    try:
        candidate_id = int(request.form['candidate_id'])
        vote_cipher  = int(request.form['vote_cipher'])
        signature    = int(request.form['signature'])
    except (KeyError, ValueError):
        flash('Please select a candidate.', 'danger')
        return redirect(url_for('vote'))

    # ── Step 1: verify RSA signature with student's public key ───────────────
    #   Recompute: h = SHA-256(vote_cipher) % student_n
    #   Check:     signature ^ student_e  mod student_n  == h
    conn = get_db()
    student_row = conn.execute(
        'SELECT pub_e, pub_n FROM students WHERE matricule=?',
        (s['matricule'],)
    ).fetchone()
    conn.close()

    student_n = student_row['pub_n']
    student_e = student_row['pub_e']
    h = int(hashlib.sha256(str(vote_cipher).encode()).hexdigest(), 16) % student_n

    if pow(signature, student_e, student_n) != h:
        flash('Signature verification failed — vote rejected.', 'danger')
        return redirect(url_for('vote'))

    # ── Step 2: decrypt vote with server's private key ────────────────────────
    #   M = vote_cipher ^ server_d  mod server_n
    server_keys = get_server_keys()
    server_n    = server_keys['pub_n']
    server_d    = server_keys['priv_d']
    M = pow(vote_cipher, server_d, server_n)

    # ── Step 3: integrity check — decrypted value must match selected ID ──────
    try:
        decrypted_str = M.to_bytes((M.bit_length() + 7) // 8, 'big').decode()
        decrypted_id  = int(decrypted_str)
    except Exception:
        flash('Vote decryption failed.', 'danger')
        return redirect(url_for('vote'))

    if decrypted_id != candidate_id:
        flash('Vote integrity check failed — encrypted candidate does not match selection.', 'danger')
        return redirect(url_for('vote'))

    # ── Step 4: confirm candidate belongs to student's group ─────────────────
    conn = get_db()
    row = conn.execute(
        'SELECT id FROM candidates WHERE id=? AND group_num=?',
        (candidate_id, group)
    ).fetchone()
    conn.close()

    if not row:
        flash('Invalid candidate.', 'danger')
        return redirect(url_for('vote'))

    record_vote(s['matricule'], candidate_id, group)
    session.pop('student', None)
    return redirect(url_for('thankyou'))


@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')


# ── Admin dashboard ────────────────────────────────────────────────────────────

@app.route('/admin/')
@admin_required
def dashboard():
    check_and_close_elections()
    groups = []
    conn = get_db()
    for g in [1, 2, 3]:
        status = conn.execute(
            'SELECT status FROM elections WHERE group_num=?', (g,)
        ).fetchone()['status']
        total = conn.execute(
            'SELECT COUNT(*) FROM students WHERE group_num=?', (g,)
        ).fetchone()[0]
        voted = conn.execute(
            'SELECT COUNT(*) FROM votes WHERE group_num=?', (g,)
        ).fetchone()[0]
        cands = conn.execute(
            'SELECT COUNT(*) FROM candidates WHERE group_num=?', (g,)
        ).fetchone()[0]
        groups.append({'num': g, 'status': status,
                       'total': total, 'voted': voted, 'candidates': cands})
    conn.close()
    return render_template('dashboard.html', groups=groups)


@app.route('/admin/group/<int:g>')
@admin_required
def group_detail(g):
    check_and_close_elections()
    conn = get_db()
    candidates = conn.execute(
        'SELECT id, name FROM candidates WHERE group_num=? ORDER BY name', (g,)
    ).fetchall()
    info        = election_info(g)
    results     = get_results(g)
    total_votes = sum(r['cnt'] for r in results)
    candidate_names = {c['name'] for c in candidates}
    students = conn.execute(
        'SELECT full_name FROM students WHERE group_num=? ORDER BY full_name', (g,)
    ).fetchall()
    conn.close()
    eligible = [s['full_name'] for s in students if s['full_name'] not in candidate_names]
    return render_template('group.html', g=g, candidates=candidates,
                           status=info['status'], close_at=info['close_at'],
                           results=results, total_votes=total_votes,
                           eligible_students=eligible)


@app.route('/admin/group/<int:g>/add_candidate', methods=['POST'])
@admin_required
def add_candidate(g):
    name = request.form.get('name', '').strip()
    if not name:
        flash('Candidate name cannot be empty', 'danger')
        return redirect(url_for('group_detail', g=g))
    conn = get_db()
    try:
        conn.execute('INSERT INTO candidates (name, group_num) VALUES (?, ?)', (name, g))
        conn.commit()
        flash(f'Candidate "{name}" added to Group {g}', 'success')
    except Exception:
        flash(f'"{name}" is already a candidate in Group {g}', 'warning')
    conn.close()
    return redirect(url_for('group_detail', g=g))


@app.route('/admin/group/<int:g>/remove_candidate/<int:cid>', methods=['POST'])
@admin_required
def remove_candidate(g, cid):
    conn = get_db()
    votes = conn.execute(
        'SELECT COUNT(*) FROM votes WHERE candidate_id=?', (cid,)
    ).fetchone()[0]
    if votes > 0:
        flash('Cannot remove a candidate who already received votes', 'danger')
    else:
        conn.execute('DELETE FROM candidates WHERE id=? AND group_num=?', (cid, g))
        conn.commit()
        flash('Candidate removed', 'success')
    conn.close()
    return redirect(url_for('group_detail', g=g))


@app.route('/admin/group/<int:g>/toggle_election', methods=['POST'])
@admin_required
def toggle_election(g):
    conn    = get_db()
    current = conn.execute(
        'SELECT status FROM elections WHERE group_num=?', (g,)
    ).fetchone()['status']

    if current == 'open':
        # Close immediately
        conn.execute(
            'UPDATE elections SET status=?, close_at=NULL WHERE group_num=?',
            ('closed', g)
        )
        conn.commit()
        conn.close()
        flash(f'Election for Group {g} has been closed.', 'success')
        return redirect(url_for('group_detail', g=g))

    # Opening — validate candidates + close_at
    cands = conn.execute(
        'SELECT COUNT(*) FROM candidates WHERE group_num=?', (g,)
    ).fetchone()[0]
    if cands == 0:
        flash('Add at least one candidate before opening the election.', 'danger')
        conn.close()
        return redirect(url_for('group_detail', g=g))

    close_at = request.form.get('close_at', '').strip()
    if not close_at:
        flash('Please set a closing date and time.', 'danger')
        conn.close()
        return redirect(url_for('group_detail', g=g))

    # datetime-local gives "YYYY-MM-DDTHH:MM" — normalise to SQLite format
    close_at_sql = close_at.replace('T', ' ')

    conn.execute(
        'UPDATE elections SET status=?, close_at=? WHERE group_num=?',
        ('open', close_at_sql, g)
    )
    conn.commit()
    conn.close()
    flash(f'Election for Group {g} is now open. Closes at {close_at_sql}.', 'success')
    return redirect(url_for('group_detail', g=g))


if __name__ == '__main__':
    init_db()
    setup_server_keys()
    conn = get_db()
    count = conn.execute('SELECT COUNT(*) FROM students').fetchone()[0]
    conn.close()
    if count == 0:
        n = import_students()
        print(f'[INIT] Imported {n} students')
    generate_student_keys()
    app.run(port=5000, debug=True)
