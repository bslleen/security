#!/usr/bin/env python3
"""
Voting server — TCP socket, JSON packets.

Packet format (client → server):

  Action 1 — get candidates after login:
    {"action": "candidates", "username": "...", "password": "..."}
  Response: JSON with status, group, full_name, candidates list,
            and the student's RSA private key (d, n) for signing.

  Action 2 — submit vote:
    {
      "action":      "vote",
      "username":    "...",
      "vote_cipher": <int>,   # C = candidate_id ^ server_e  mod server_n
      "signature":   <int>    # S = hash(C) % student_n  ^ student_d  mod student_n
    }
  Response: "Vote accepted" or "Vote rejected: <reason>"

Security properties demonstrated:
  Confidentiality  — vote encrypted with server's public RSA key
  Authenticity     — vote signed with student's private RSA key
  Integrity        — SHA-256 hash prevents tampering
  Non-repudiation  — only the student holds their private key
  Unicité          — server rejects duplicate voter IDs
"""

import sys
import os
import socket
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.crypto_utils import decrypt_vote, verify_signature
from db import (init_db, import_students, generate_student_keys, setup_server_keys,
                get_server_keys, authenticate, get_candidates,
                election_status, has_voted, record_vote, get_db)

HOST = '127.0.0.1'
PORT = 12345


def handle_candidates(data):
    student = authenticate(data.get('username', ''), data.get('password', ''))
    if not student:
        return json.dumps({'status': 'error', 'message': 'Invalid credentials'})

    group = student['group_num']

    if election_status(group) != 'open':
        return json.dumps({'status': 'error',
                           'message': f'Election for Group {group} is not open yet'})

    if has_voted(student['matricule']):
        return json.dumps({'status': 'error', 'message': 'You have already voted'})

    candidates = get_candidates(group)
    if not candidates:
        return json.dumps({'status': 'error', 'message': 'No candidates registered yet'})

    server_keys = get_server_keys()

    # Deliver the student's private key so they can sign their vote
    return json.dumps({
        'status':    'ok',
        'group':     group,
        'full_name': student['full_name'],
        'candidates': candidates,
        'server_pub_e': server_keys['pub_e'],
        'server_pub_n': server_keys['pub_n'],
        'student_priv_d': student['priv_d'],
        'student_priv_n': student['pub_n'],   # same n for both keys
    })


def handle_vote(data):
    student = authenticate(data.get('username', ''), data.get('password', ''))
    if not student:
        return 'Vote rejected: invalid credentials'

    group = student['group_num']

    if election_status(group) != 'open':
        return f'Vote rejected: election for Group {group} is not open'

    if has_voted(student['matricule']):
        return 'Vote rejected: already voted'

    try:
        vote_cipher = int(data['vote_cipher'])
        signature   = int(data['signature'])
    except (KeyError, ValueError):
        return 'Vote rejected: malformed packet'

    # ── Step 1: verify signature with student's public key ──────────────────
    student_pub = (student['pub_e'], student['pub_n'])
    if not verify_signature(vote_cipher, signature, student_pub):
        return 'Vote rejected: invalid RSA signature'

    # ── Step 2: decrypt vote with server's private key ──────────────────────
    server_keys = get_server_keys()
    server_priv = (server_keys['priv_d'], server_keys['pub_n'])
    try:
        candidate_id_str = decrypt_vote(vote_cipher, server_priv)
        candidate_id = int(candidate_id_str)
    except Exception:
        return 'Vote rejected: decryption failed'

    # ── Step 3: confirm candidate belongs to student's group ────────────────
    conn = get_db()
    row = conn.execute(
        'SELECT id FROM candidates WHERE id=? AND group_num=?',
        (candidate_id, group)
    ).fetchone()
    conn.close()

    if not row:
        return 'Vote rejected: invalid candidate'

    record_vote(student['matricule'], candidate_id, group)
    print(f'[COUNTED] {student["full_name"]} → candidate {candidate_id}')
    return 'Vote accepted'


def handle_request(raw):
    try:
        data   = json.loads(raw)
        action = data.get('action', '')
        if action == 'candidates':
            return handle_candidates(data)
        elif action == 'vote':
            return handle_vote(data)
        else:
            return 'Vote rejected: unknown action'
    except Exception as e:
        print(f'[ERROR] {e}')
        return 'Vote rejected: server error'


def start_server():
    init_db()
    setup_server_keys()

    conn = get_db()
    count = conn.execute('SELECT COUNT(*) FROM students').fetchone()[0]
    conn.close()
    if count == 0:
        imported = import_students()
        print(f'[INIT] Imported {imported} students')
    generate_student_keys()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f'[STARTED] Voting server on {HOST}:{PORT}')

    while True:
        conn, addr = server.accept()
        print(f'[CONNECTION] {addr}')
        try:
            raw      = conn.recv(4096).decode('utf-8')
            response = handle_request(raw)
            conn.send(response.encode('utf-8'))
        except Exception as e:
            print(f'[ERROR] {e}')
            conn.send('Vote rejected: server error'.encode('utf-8'))
        conn.close()


if __name__ == '__main__':
    start_server()
