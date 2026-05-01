"""
custom_policy_demo.py — demonstrates custom policy sources and sinks.

Uses healthcare-specific sources (fetch_credit_card, get_passport_number)
and sinks (kafka_publish, s3_upload) defined in custom_policy.json.

Run WITHOUT custom policy (no leaks detected — unknown sources/sinks):
    python3 src/main.py examples/custom_policy_demo.py

Run WITH custom policy (2 leaks reported):
    python3 src/main.py examples/custom_policy_demo.py --policy examples/custom_policy.json
"""


def process_patient(patient_id):
    card = fetch_credit_card(patient_id)
    passport = get_passport_number(patient_id)

    # This sink is only known when custom_policy.json is loaded
    kafka_publish("payments-topic", {"card": card})

    # Also only a sink with the custom policy
    s3_upload("patient-docs/", {"passport": passport})

    # Safe: no PII in this call
    kafka_publish("audit-topic", {"event": "patient_login", "id": patient_id})
