#!/usr/bin/env python3

import sys
import os

# Ensure project root is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import socket
import json

from common.crypto_utils import verify_signature, decrypt_vote

HOST = '127.0.0.1'
PORT = 12345

SERVER_PRIVATE_KEY = (2353, 3245)

FILES = {
    'students': 'server/students.json',
    'voted': 'server/voted_ids.json',
    'results': 'server/results.json'
}

VALID_VOTES = {"Candidat_A", "Candidat_B", "Candidat_C"}


def load_data(file_key):
    path = os.path.join(os.getcwd(), FILES[file_key])
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        if file_key == 'results':
            data = {candidate: 0 for candidate in VALID_VOTES}
        elif file_key == 'voted':
            data = []
        else:
            data = {}
        save_data(file_key, data)
        return data


def save_data(file_key, data):
    path = os.path.join(os.getcwd(), FILES[file_key])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def process_vote(json_data):
    try:
        student_id = json_data["student_id"]
        ciphertext = int(json_data["vote"])
        signature = int(json_data["signature"])

        print(f"[RECEIVED] Vote from {student_id}")

        students = load_data('students')
        if student_id not in students:
            print("[ERROR] Unknown student")
            return "Vote rejected"

        public_key = tuple(students[student_id]["public_key"])

        if not verify_signature(ciphertext, signature, public_key):
            print("[ERROR] Invalid signature")
            return "Vote rejected"

        print("[OK] Signature verified")

        voted_ids = load_data('voted')
        if student_id in voted_ids:
            print("[ERROR] Already voted")
            return "Vote rejected"

        vote = decrypt_vote(ciphertext, SERVER_PRIVATE_KEY)
        print(f"[DECRYPTED] Vote = {vote}")

        if vote not in VALID_VOTES:
            print("[ERROR] Invalid candidate")
            return "Vote rejected"

        results = load_data('results')
        results[vote] += 1
        save_data('results', results)

        voted_ids.append(student_id)
        save_data('voted', voted_ids)

        print(f"[COUNTED] {vote} → {results}")
        return "Vote accepted"

    except KeyError as e:
        print(f"[ERROR] Missing field: {e}")
        return "Vote rejected"

    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        return "Vote rejected"


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen()

    print(f"[STARTED] Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        print(f"[NEW CONNECTION] {addr}")

        try:
            data = conn.recv(4096).decode('utf-8')

            if not data:
                conn.close()
                continue

            try:
                vote_json = json.loads(data)
                response = process_vote(vote_json)
            except json.JSONDecodeError:
                print("[ERROR] Invalid JSON format")
                response = "Vote rejected"

            conn.send(response.encode('utf-8'))

        except Exception as e:
            print(f"[ERROR] Connection issue: {e}")

        finally:
            conn.close()
            print("[CLOSED] Connection\n")


if __name__ == "__main__":
    start_server()