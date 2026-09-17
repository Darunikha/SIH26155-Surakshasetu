"""One-off dev script: resets the Cisco 'security-admin-session-timeout 900'
unknown pattern back to pending_review after a demo recording run already
confirmed it, and removes the mapping/example rows that confirmation
created, so a re-recording of the /training beat has something to act on
again. Not part of the app -- delete after use."""
import asyncio

from app.db import Collections, connect


async def main():
    db = connect()
    vendor = "Cisco"
    raw_line = "security-admin-session-timeout 900"

    result = await db[Collections.UNKNOWN_PATTERNS].update_many(
        {"vendor": vendor, "raw_line": raw_line},
        {"$set": {"status": "pending_review", "ai_suggestion": None}, "$unset": {"confirmed_mapping_id": ""}},
    )
    print(f"Reset {result.modified_count} unknown_patterns document(s) to pending_review")

    deleted_examples = await db[Collections.TRAINING_EXAMPLES].delete_many({"vendor": vendor, "raw_line": raw_line})
    print(f"Deleted {deleted_examples.deleted_count} training_examples document(s)")

    deleted_mappings = await db[Collections.TRAINING_MAPPINGS].delete_many({"vendor": vendor, "raw_line": raw_line})
    print(f"Deleted {deleted_mappings.deleted_count} training_mappings document(s)")


asyncio.run(main())
