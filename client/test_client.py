#!/usr/bin/env python3
import socket
import json
import os
import sys

# Ensure project root is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

HOST = '127.0.0.1'
PORT = 12345

from common.crypto_utils import encrypt_vote, sign_data

SERVER_PUBLIC_KEY = (17, 3245)
VOTER_PRIVATE_KEY = (2353, 3245)

def send_request(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(json.dumps(data).encode('utf-8'))
            response = s.recv(4096).decode('utf-8')
            return response
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return None

def create_vote_packet(student_id, candidate):
    ciphertext = encrypt_vote(candidate, SERVER_PUBLIC_KEY)
    signature = sign_data(ciphertext, VOTER_PRIVATE_KEY)

    return {
        "student_id": student_id,
        "vote": ciphertext,
        "signature": signature
    }

def option1_manual_vote():
    student_id = input("Enter student_id: ").strip()
    candidate = input("Enter candidate (Candidat_A/B/C): ").strip()

    packet = create_vote_packet(student_id, candidate)
    response = send_request(packet)

    if response:
        print(f"[SERVER] {response}")

def option2_simulate():
    print("Simulating votes...\n")

    tests = [
        ("Ali123", "Candidat_A"),
        ("Ali456", "Candidat_B"),
        ("Ali789", "Candidat_A"),
        ("Ali123", "Candidat_C"),
        ("FakeID", "Candidat_A")
    ]

    for i, (student_id, candidate) in enumerate(tests, 1):
        print(f"Test {i}: {student_id} -> {candidate}")

        packet = create_vote_packet(student_id, candidate)
        response = send_request(packet)

        print(f"Result: {response}\n")

def main():
    print("Secure E-Voting Client\n")

    while True:
        print("1. Send vote")
        print("2. Simulate election")
        print("0. Exit")

        choice = input("Choice: ").strip()

        if choice == '1':
            option1_manual_vote()
        elif choice == '2':
            option2_simulate()
        elif choice == '0':
            break
        else:
            print("Invalid choice\n")

if __name__ == "__main__":
    main()