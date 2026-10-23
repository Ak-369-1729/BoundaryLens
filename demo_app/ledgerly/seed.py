"""Deterministic, fictional seed data for the Ledgerly demo application.

Every person, vendor and amount here is invented. Markers (BLM-...) are unique
strings placed in private fields so that an access-control test can prove which
record was returned, instead of guessing from a status code.
"""

import os

USERS = {
    "alice": {
        "username": "alice",
        "display_name": "Alice Moreau (fictional)",
        "role": "user",
        "password": os.environ.get("LEDGERLY_ALICE_PASSWORD", "alice-local-demo"),
    },
    "bob": {
        "username": "bob",
        "display_name": "Bob Tanaka (fictional)",
        "role": "user",
        "password": os.environ.get("LEDGERLY_BOB_PASSWORD", "bob-local-demo"),
    },
    "admin": {
        "username": "admin",
        "display_name": "Dana Admin (fictional)",
        "role": "admin",
        "password": os.environ.get("LEDGERLY_ADMIN_PASSWORD", "admin-local-demo"),
    },
}

INVOICES = [
    {
        "id": "inv_a7Kq2LmZ9x",
        "number": "EXP-2026-0141",
        "owner": "alice",
        "vendor": "Northwind Office Supply",
        "category": "office",
        "amount": "412.50",
        "currency": "EUR",
        "status": "approved",
        "issued_on": "2026-03-04",
        "notes": "Ergonomic chair and monitor arm for home office.",
        "confidential_ref": "BLM-ALICE-INV-7F3A",
    },
    {
        "id": "inv_a3Vt8RpQ1c",
        "number": "EXP-2026-0178",
        "owner": "alice",
        "vendor": "Harbor Rail Travel",
        "category": "travel",
        "amount": "1280.00",
        "currency": "EUR",
        "status": "submitted",
        "issued_on": "2026-04-19",
        "notes": "Client workshop travel, two return tickets.",
        "confidential_ref": "BLM-ALICE-INV-2C8D",
    },
    {
        "id": "inv_b5Nc4WyH6e",
        "number": "EXP-2026-0152",
        "owner": "bob",
        "vendor": "Cobalt Coworking",
        "category": "workspace",
        "amount": "650.00",
        "currency": "USD",
        "status": "approved",
        "issued_on": "2026-03-21",
        "notes": "Monthly hot-desk membership, March.",
        "confidential_ref": "BLM-BOB-INV-5E19",
    },
    {
        "id": "inv_b9Xs1DfJ3u",
        "number": "EXP-2026-0190",
        "owner": "bob",
        "vendor": "Lumen Cloud Hosting",
        "category": "software",
        "amount": "89.99",
        "currency": "USD",
        "status": "rejected",
        "issued_on": "2026-05-02",
        "notes": "Personal project hosting; not reimbursable.",
        "confidential_ref": "BLM-BOB-INV-9A04",
    },
]

ATTACHMENTS = {
    "inv_a7Kq2LmZ9x": [{"filename": "receipt-northwind-0141.pdf", "size_bytes": 48211, "private_marker": "BLM-ALICE-ATT-7F3A"}],
    "inv_a3Vt8RpQ1c": [{"filename": "rail-tickets-0178.pdf", "size_bytes": 91022, "private_marker": "BLM-ALICE-ATT-2C8D"}],
    "inv_b5Nc4WyH6e": [{"filename": "cobalt-march-0152.pdf", "size_bytes": 30554, "private_marker": "BLM-BOB-ATT-5E19"}],
    "inv_b9Xs1DfJ3u": [{"filename": "lumen-may-0190.pdf", "size_bytes": 12870, "private_marker": "BLM-BOB-ATT-9A04"}],
}

ADMIN_MARKER = "BLM-ADMIN-SUMMARY-91C2"
