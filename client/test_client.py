#!/usr/bin/env python3
"""
Voter client — demonstrates the full cryptographic protocol:

  1. Authenticate → receive server public key + own private key
  2. Encrypt vote:   C = candidate_id ^ server_e  mod server_n
  3. Sign vote:      S = hash(C) % student_n  ^ student_d  mod student_n
  4. Send envelope:  {username, vote_cipher: C, signature: S}
"""

import socket
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.crypto_utils import encrypt_vote, sign_data

HOST = '127.0.0.1'
PORT = 12345


def send_request(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(json.dumps(data).encode('utf-8'))
            return s.recv(4096).decode('utf-8')
    except Exception as e:
        print(f'[ERROR] {e}')
        return None


def main():
    print('=== SecureVote Client ===\n')

    username = input('Username : ').strip()
    password = input('Password : ').strip()

    # ── Step 1: authenticate and receive keys + candidates ──────────────────
    resp = send_request({'action': 'candidates',
                         'username': username, 'password': password})
    if resp is None:
        print('Could not reach server.')
        return

    try:
        data = json.loads(resp)
    except json.JSONDecodeError:
        print(f'Server: {resp}')
        return

    if data.get('status') != 'ok':
        print(f'Error: {data.get("message")}')
        return

    group      = data['group']
    full_name  = data['full_name']
    candidates = data['candidates']

    # Keys delivered by server
    server_pub    = (data['server_pub_e'],    data['server_pub_n'])
    student_priv  = (data['student_priv_d'],  data['student_priv_n'])

    print(f'\nWelcome, {full_name} (Group {group})')
    print('\nCandidates:')
    for i, c in enumerate(candidates, 1):
        print(f'  {i}. {c["name"]}')

    # ── Step 2: select candidate ─────────────────────────────────────────────
    while True:
        try:
            choice = int(input('\nEnter candidate number: ').strip())
            if 1 <= choice <= len(candidates):
                break
            print(f'Enter a number between 1 and {len(candidates)}')
        except ValueError:
            print('Invalid input')

    selected = candidates[choice - 1]

    # ── Step 3: encrypt candidate ID with server's public key ────────────────
    #   C = candidate_id ^ e  mod n
    vote_cipher = encrypt_vote(str(selected['id']), server_pub)

    # ── Step 4: sign hash of ciphertext with student's private key ───────────
    #   S = hash(C) % n  ^ d  mod n
    signature = sign_data(vote_cipher, student_priv)

    print('\n[CRYPTO] Encrypting and signing ballot...')
    print(f'         C (cipher)    = {vote_cipher}')
    print(f'         S (signature) = {signature}')

    # ── Step 5: send the digital envelope ────────────────────────────────────
    resp = send_request({
        'action':      'vote',
        'username':    username,
        'password':    password,
        'vote_cipher': vote_cipher,
        'signature':   signature,
    })

    print(f'\nServer response: {resp}')


if __name__ == '__main__':
    main()
