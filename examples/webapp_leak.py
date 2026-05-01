"""
webapp_leak.py — example Python program with PII leaks detected by taint-lite.

Run:
    python3 src/main.py examples/webapp_leak.py

Expected: 3 leaks reported (lines 22, 27, 34)
"""

import logging
import requests

# Simulated stubs — in a real app these would fetch from a database or session
def get_email(uid): ...
def get_name(uid): ...
def get_ssn(uid): ...


def process_user(user_id):
    email = get_email(user_id)
    name = get_name(user_id)
    ssn = get_ssn(user_id)

    # LEAK 1: raw PII written directly to the application log
    logging.info(f"Processing request for {email}")

    # LEAK 2: name sent to a third-party analytics service
    send_analytics({"user": name, "action": "login"})

    # Safe: anonymised display name never reaches a sink
    display = name[0] + "***"
    print("Welcome,", display)

    # LEAK 3: SSN included in an outbound API call
    payload = {"id": user_id, "ssn": ssn}
    send_to_api("https://internal.example.com/verify", data=payload)
