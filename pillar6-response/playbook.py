"""
Pillar 6: Response — Dynamic Threat Playbook
Automated response to security alerts.

When Prometheus fires an alert (via webhook), this playbook:
1. Assesses severity
2. Revokes access if warranted
3. Logs the response for audit purposes
4. Sends notification (simulated)

In production: integrate with PagerDuty, Slack, and AWS STS (revoke IAM sessions).
"""
import json
import time
import logging
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("pillar6-response/response_log.txt")
    ]
)
logger = logging.getLogger("playbook")

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Alert:
    alert_name: str
    user_id: str
    details: dict
    severity: Severity
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

class AccessRevocationService:
    """
    Manages revoked users.
    In production: write to Redis/Postgres and invalidate JWT sessions via
    a token blacklist. For AWS IAM: aws iam delete-access-key.
    """
    REVOCATION_DB = Path("pillar6-response/revoked_users.json")

    def __init__(self):
        self.REVOCATION_DB.parent.mkdir(exist_ok=True)
        self._revoked = self._load()

    def _load(self) -> dict:
        if self.REVOCATION_DB.exists():
            return json.loads(self.REVOCATION_DB.read_text())
        return {}

    def _save(self):
        self.REVOCATION_DB.write_text(json.dumps(self._revoked, indent=2))

    def revoke(self, user_id: str, reason: str, revoked_by: str = "playbook"):
        self._revoked[user_id] = {
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "revoked_by": revoked_by,
        }
        self._save()
        logger.critical(f"[REVOKE] Access revoked for user: {user_id} | Reason: {reason}")

    def is_revoked(self, user_id: str) -> bool:
        return user_id in self._revoked

    def reinstate(self, user_id: str, approved_by: str):
        if user_id in self._revoked:
            del self._revoked[user_id]
            self._save()
            logger.info(f"[REINSTATE] Access restored for {user_id} by {approved_by}")

class IncidentLogger:
    """Records every incident and its resolution for post-mortem analysis."""

    INCIDENT_LOG = Path("pillar6-response/incidents.jsonl")

    def __init__(self):
        self.INCIDENT_LOG.parent.mkdir(exist_ok=True)

    def record(self, alert: Alert, action_taken: str, outcome: str):
        incident = {
            "incident_id": f"INC-{int(time.time())}",
            "alert_name": alert.alert_name,
            "user_id": alert.user_id,
            "severity": alert.severity.value,
            "alert_timestamp": alert.timestamp,
            "response_timestamp": datetime.now(timezone.utc).isoformat(),
            "action_taken": action_taken,
            "outcome": outcome,
            "details": alert.details,
        }
        with open(self.INCIDENT_LOG, "a") as fh:
            fh.write(json.dumps(incident) + "\n")
        logger.info(f"[INCIDENT LOG] {incident['incident_id']}: {action_taken}")
        return incident["incident_id"]

class ThreatPlaybook:
    """
    The decision engine. Receives alerts and executes the appropriate response.

    Alert -> assess severity -> choose action -> execute -> log
    """

    def __init__(self):
        self.revocation = AccessRevocationService()
        self.incident_log = IncidentLogger()

    def assess_severity(self, alert: Alert) -> Severity:
        """
        Severity assessment heuristics.
        In production: ML model trained on historical incidents.
        """
        if alert.alert_name == "AnomalousRequestRate":
            rate = alert.details.get("request_count", 0)
            if rate > 1000:
                return Severity.CRITICAL
            elif rate > 200:
                return Severity.HIGH
            return Severity.MEDIUM

        if alert.alert_name == "AccessDenied":
            denials = alert.details.get("denial_count", 0)
            if denials > 10:
                return Severity.HIGH
            return Severity.MEDIUM

        if alert.alert_name == "HighErrorRate":
            return Severity.HIGH

        return Severity.LOW

    def execute(self, alert: Alert):
        """Main playbook entry point."""
        severity = self.assess_severity(alert)
        alert.severity = severity

        logger.warning(
            f"\n{'='*60}\n"
            f"ALERT: {alert.alert_name}\n"
            f"User:  {alert.user_id}\n"
            f"Severity: {severity.value.upper()}\n"
            f"Details: {alert.details}\n"
            f"{'='*60}"
        )

        # Decision node
        if severity == Severity.CRITICAL:
            action = self._critical_response(alert)
        elif severity == Severity.HIGH:
            action = self._high_response(alert)
        elif severity == Severity.MEDIUM:
            action = self._medium_response(alert)
        else:
            action = self._low_response(alert)

        incident_id = self.incident_log.record(alert, action, "executed")
        logger.info(f"Incident {incident_id} logged. Response complete.\n")
        return incident_id

    def _critical_response(self, alert: Alert) -> str:
        """Immediate access revocation + notify security team."""
        self.revocation.revoke(
            alert.user_id,
            reason=f"Critical alert: {alert.alert_name}",
            revoked_by="playbook-auto"
        )
        self._notify_security_team(alert, "CRITICAL — access revoked automatically")
        return "access_revoked"

    def _high_response(self, alert: Alert) -> str:
        """Rate limit + page on-call engineer."""
        self._notify_security_team(alert, "HIGH — manual review required within 15 minutes")
        return "paged_oncall"

    def _medium_response(self, alert: Alert) -> str:
        """Log and flag for next-business-day review."""
        logger.warning(f"[MEDIUM] Flagged for review: {alert.user_id}")
        return "flagged_for_review"

    def _low_response(self, alert: Alert) -> str:
        logger.info(f"[LOW] Alert logged: {alert.alert_name}")
        return "logged"

    def _notify_security_team(self, alert: Alert, message: str):
        """
        In production: POST to Slack webhook, PagerDuty, or email.
        Simulated here with a log entry.
        """
        logger.critical(
            f"[NOTIFY] Security Team Alert\n"
            f"  Message:  {message}\n"
            f"  Alert:    {alert.alert_name}\n"
            f"  User:     {alert.user_id}\n"
            f"  Time:     {alert.timestamp}\n"
            f"  Details:  {alert.details}"
        )

def run_rca(incident_log_path: str = "pillar6-response/incidents.jsonl"):
    """
    Root Cause Analysis Pipeline.
    After an incident is contained, RCA determines what governance control failed.
    """
    log = Path(incident_log_path)
    if not log.exists():
        print("No incidents to analyse.")
        return

    incidents = [json.loads(line) for line in log.read_text().strip().splitlines()]
    print(f"\n=== ROOT CAUSE ANALYSIS: {len(incidents)} incidents ===\n")

    for inc in incidents:
        print(f"Incident: {inc['incident_id']}")
        print(f"  Alert:    {inc['alert_name']}")
        print(f"  Severity: {inc['severity']}")
        print(f"  User:     {inc['user_id']}")
        print(f"  Action:   {inc['action_taken']}")

        # RCA questions (in production: filled in by the incident responder)
        rca = {
            "root_cause": "Unknown — investigation required",
            "contributing_factors": [],
            "governance_gaps": [],
            "recommended_controls": [],
        }

        if inc["alert_name"] == "AnomalousRequestRate":
            rca["root_cause"] = "Abnormal API access pattern"
            rca["contributing_factors"] = ["No rate limiting in governance policy", "No MFA for this tier"]
            rca["governance_gaps"] = ["Pillar 1: rate limits not defined for this data tier"]
            rca["recommended_controls"] = [
                "Add rate limits to DataPolicy schema",
                "Require MFA for any tier with >50 req/min baseline",
                "Implement progressive delays after anomaly threshold"
            ]

        print(f"  RCA: {rca['root_cause']}")
        print(f"  Fix: {', '.join(rca['recommended_controls'])}\n")

        # The virtuous cycle: RCA output updates Pillar 1
        print("  >>> This finding should update classification.py Pillar 1 controls <<<\n")


if __name__ == "__main__":
    playbook = ThreatPlaybook()

    print("=== PILLAR 6: RESPONSE & RCA ===\n")
    print("Simulating security alert pipeline...\n")

    # Simulate incoming alerts
    test_alerts = [
        Alert("AnomalousRequestRate", "eve", {"request_count": 1500}, Severity.LOW),
        Alert("AccessDenied", "mallory", {"denial_count": 15, "target": "keys_to_kingdom"}, Severity.LOW),
        Alert("HighErrorRate", "system", {"error_rate": 0.45}, Severity.LOW),
    ]

    for alert in test_alerts:
        playbook.execute(alert)
        time.sleep(0.5)

    print("\nRunning Root Cause Analysis...")
    run_rca()