"""
Pillar 4: Compliance — Audit Trail
Every access to sensitive data is logged with: who, what, when, from where.
In production: logs ship to AWS CloudTrail and Elasticsearch for tamper-evident storage.
"""
import json
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict

@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    user_id: str
    action: str           # READ, WRITE, DELETE, DECRYPT
    resource: str         # what was accessed (record_id, table, etc.)
    data_tier: str        # the classification tier of the accessed data
    source_ip: str
    outcome: str          # SUCCESS or DENIED
    previous_hash: str    # hash of previous event (tamper detection)
    event_hash: str = ""  # this event's hash (set after creation)

    def compute_hash(self) -> str:
        """
        Hash chaining: each event's hash includes the previous event's hash.
        This creates a chain where tampering with any event invalidates all subsequent ones.
        This is the same principle used in blockchain.
        """
        data = json.dumps({k: v for k, v in asdict(self).items() if k != "event_hash"},
                          sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

class AuditLogger:
    """
    Append-only audit log with hash chaining for tamper detection.
    In production: write to AWS CloudTrail or an append-only Elasticsearch index.
    """

    def __init__(self, log_path: str = "pillar4_compliance/audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(exist_ok=True)
        self._last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        """Get the hash of the most recent event (genesis hash if no events yet)."""
        if not self.log_path.exists():
            return "0" * 64  # genesis hash
        lines = self.log_path.read_text().strip().splitlines()
        if not lines:
            return "0" * 64
        last_event = json.loads(lines[-1])
        return last_event.get("event_hash", "0" * 64)

    def log(self, user_id: str, action: str, resource: str,
            data_tier: str, source_ip: str, outcome: str) -> AuditEvent:
        """Log an access event. Returns the event for confirmation."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            action=action,
            resource=resource,
            data_tier=data_tier,
            source_ip=source_ip,
            outcome=outcome,
            previous_hash=self._last_hash,
        )
        event.event_hash = event.compute_hash()
        self._last_hash = event.event_hash

        # Append to log (never overwrite — this is immutable)
        with open(self.log_path, "a") as fh:
            fh.write(json.dumps(asdict(event)) + "\n")

        return event

    def verify_integrity(self) -> bool:
        """
        Verify the chain has not been tampered with.
        Any modification to any past event breaks the chain.
        Run this daily as a compliance check.
        """
        if not self.log_path.exists():
            return True

        lines = self.log_path.read_text().strip().splitlines()
        if not lines:
            return True

        previous_hash = "0" * 64
        for i, line in enumerate(lines):
            event = json.loads(line)
            stored_hash = event.pop("event_hash")

            # Re-compute what the hash should be
            event_copy = AuditEvent(**event, event_hash="")
            event_copy.previous_hash = previous_hash
            expected_hash = event_copy.compute_hash()

            if stored_hash != expected_hash:
                print(f"[AUDIT] INTEGRITY VIOLATION at event {i+1}: hash mismatch")
                return False

            previous_hash = stored_hash

        print(f"[AUDIT] Integrity verified: {len(lines)} events in chain")
        return True

    def generate_compliance_report(self, output_path: str = "compliance_report.json"):
        """Generate a report showing access patterns for auditor review."""
        if not self.log_path.exists():
            return {}

        events = [json.loads(line) for line in self.log_path.read_text().strip().splitlines()]
        report = {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "total_events": len(events),
            "by_action": {},
            "by_data_tier": {},
            "denied_access_attempts": [],
            "chain_integrity": self.verify_integrity(),
        }

        for event in events:
            action = event["action"]
            tier = event["data_tier"]
            report["by_action"][action] = report["by_action"].get(action, 0) + 1
            report["by_data_tier"][tier] = report["by_data_tier"].get(tier, 0) + 1
            if event["outcome"] == "DENIED":
                report["denied_access_attempts"].append({
                    "user": event["user_id"],
                    "resource": event["resource"],
                    "timestamp": event["timestamp"],
                })

        with open(output_path, "w") as fh:
            json.dump(report, fh, indent=2)

        print(f"Compliance report written to {output_path}")
        return report


def demonstrate_compliance():
    logger = AuditLogger()
    print("=== PILLAR 4: COMPLIANCE & AUDIT TRAIL ===\n")

    # Simulate a day of access events
    events = [
        ("alice", "READ",    "record-001", "confidential",    "10.0.0.1", "SUCCESS"),
        ("alice", "DECRYPT", "record-001", "confidential",    "10.0.0.1", "SUCCESS"),
        ("bob",   "READ",    "record-002", "keys_to_kingdom", "10.0.0.2", "SUCCESS"),
        ("eve",   "READ",    "record-002", "keys_to_kingdom", "192.168.1.50", "DENIED"),
        ("alice", "WRITE",   "record-003", "internal",        "10.0.0.1", "SUCCESS"),
        ("bob",   "DELETE",  "record-001", "confidential",    "10.0.0.2", "SUCCESS"),
    ]

    for user, action, resource, tier, ip, outcome in events:
        event = logger.log(user, action, resource, tier, ip, outcome)
        status = "ALLOWED" if outcome == "SUCCESS" else "BLOCKED"
        print(f"[{status}] {user} {action} {resource} ({tier}) from {ip}")

    print("\nVerifying audit trail integrity...")
    logger.verify_integrity()

    print("\nGenerating compliance report...")
    report = logger.generate_compliance_report()
    print(f"Total events: {report['total_events']}")
    print(f"Denied attempts: {len(report['denied_access_attempts'])}")


if __name__ == "__main__":
    demonstrate_compliance()