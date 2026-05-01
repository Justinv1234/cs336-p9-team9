"""
webapp_clean.py — example Python program with NO PII leaks.

Run:
    python3 src/main.py examples/webapp_clean.py

Expected: "No PII leaks detected."
"""

import logging

def get_email(uid): ...
def get_name(uid): ...


def anonymize_email(email):
    local, domain = email.split("@")
    return local[0] + "***@" + domain


def process_user(user_id):
    email = get_email(user_id)
    name = get_name(user_id)

    # Safe: only non-PII data goes to the log
    logging.info("Processing user request id=%s", user_id)

    # Safe: email is anonymised before any external call
    safe_email = anonymize_email(email)
    send_analytics({"email_domain": safe_email.split("@")[1]})

    # Safe: literal greeting, no PII in the payload
    send_to_api("https://internal.example.com/greet", data={"message": "hello"})
