#!/usr/bin/env python3

import socket
import json
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.crypto_utils import encrypt_vote, sign_data

HOST = '127.0.0.1'
PORT = 12345

SERVER_PUBLIC_KEY = (17, 3245)
VOTER_PRIVATE_KEY = (2353, 3245)


def send_request(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(json.dumps(data).encode('utf-8'))
            return s.recv(4096).decode('utf-8')
    except Exception as e:
        print(f"[ERROR] {e}")
        return None


def create_vote(student_id, candidate):
    ciphertext = encrypt_vote(candidate, SERVER_PUBLIC_KEY)
    signature = sign_data(ciphertext, VOTER_PRIVATE_KEY)

    return {
        "student_id": student_id,
        "vote": ciphertext,
        "signature": signature
    }


def main():
    print("Client ready\n")

    while True:
        student_id = input("ID: ").strip()
        vote = input("Vote (Candidat_A/B/C): ").strip()

        packet = create_vote(student_id, vote)
        response = send_request(packet)

        print(response, "\n")


if __name__ == "__main__":
    main()
