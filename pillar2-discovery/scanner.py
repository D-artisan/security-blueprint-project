"""
Pillar 2: Data Discovery Scanner
Scans structured and unstructured data sources for sensitive content.
In production this is AWS Macie (S3) or a commercial DLP tool.
This open-source version shows you exactly how they work under the hood.
"""
import re
import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime

# Add parent to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from api.classification import classify_by_content, DataTier

@dataclass
class Finding:
    source: str           # where the data was found
    location: str         # table/column/file/path
    sample: str           # redacted sample for review
    tier: DataTier
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self):
        return {
            "source": self.source,
            "location": self.location,
            "sample": self.sample[:50] + "..." if len(self.sample) > 50 else self.sample,
            "tier": self.tier.value,
            "timestamp": self.timestamp,
        }

class DatabaseScanner:
    """Scans PostgreSQL tables for sensitive data patterns."""

    def __init__(self, host=None, user=None, password=None, dbname=None):
        host = host or os.environ.get("POSTGRES_HOST", "localhost")
        user = user or os.environ.get("POSTGRES_USER", "scanner")
        password = password or os.environ.get("POSTGRES_PASSWORD", "")
        dbname = dbname or os.environ.get("POSTGRES_DB", "appdb")
        try:
            import psycopg2
            self.conn = psycopg2.connect(host=host, user=user, password=password, dbname=dbname)
        except ImportError:
            print("Install psycopg2: pip install psycopg2-binary")
            self.conn = None

    def scan(self) -> list[Finding]:
        if not self.conn:
            return []

        findings = []
        cursor = self.conn.cursor()

        # Get all tables
        cursor.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public'
        """)
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            # Get column names
            cursor.execute(f"""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = '{table}'
            """)
            columns = [row[0] for row in cursor.fetchall()]

            # Sample each column
            for column in columns:
                cursor.execute(f"SELECT {column} FROM {table} LIMIT 100")
                rows = cursor.fetchall()
                for row in rows:
                    value = str(row[0]) if row[0] else ""
                    tier = classify_by_content(value)
                    if tier in (DataTier.CONFIDENTIAL, DataTier.KEYS_TO_KINGDOM):
                        findings.append(Finding(
                            source="postgresql",
                            location=f"{table}.{column}",
                            sample=value,
                            tier=tier,
                        ))

        cursor.close()
        return findings

class FileSystemScanner:
    """Scans a directory tree for sensitive data in files."""

    SCANNABLE_EXTENSIONS = {".txt", ".csv", ".json", ".log", ".env", ".yaml", ".yml", ".md"}

    def scan(self, directory: str) -> list[Finding]:
        findings = []
        for path in Path(directory).rglob("*"):
            if path.is_file() and path.suffix in self.SCANNABLE_EXTENSIONS:
                try:
                    content = path.read_text(errors="ignore")
                    for line_num, line in enumerate(content.splitlines(), 1):
                        tier = classify_by_content(line)
                        if tier in (DataTier.CONFIDENTIAL, DataTier.KEYS_TO_KINGDOM):
                            findings.append(Finding(
                                source="filesystem",
                                location=f"{path}:{line_num}",
                                sample=line.strip(),
                                tier=tier,
                            ))
                except PermissionError:
                    pass
        return findings

def run_discovery(output_path: str = "discovery_report.json"):
    """Run all scanners and produce a unified findings report."""
    print("Starting data discovery scan...")
    all_findings = []

    # Database scan
    print("  Scanning PostgreSQL...")
    db_scanner = DatabaseScanner()
    db_findings = db_scanner.scan()
    all_findings.extend(db_findings)
    print(f"  Found {len(db_findings)} sensitive database fields")

    # Filesystem scan of current directory
    print("  Scanning filesystem...")
    fs_scanner = FileSystemScanner()
    fs_findings = fs_scanner.scan(".")
    all_findings.extend(fs_findings)
    print(f"  Found {len(fs_findings)} sensitive files/lines")

    # Write report
    report = {
        "scan_timestamp": datetime.utcnow().isoformat(),
        "total_findings": len(all_findings),
        "by_tier": {
            "confidential": sum(1 for f in all_findings if f.tier == DataTier.CONFIDENTIAL),
            "keys_to_kingdom": sum(1 for f in all_findings if f.tier == DataTier.KEYS_TO_KINGDOM),
        },
        "findings": [f.to_dict() for f in all_findings]
    }

    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)

    print(f"\nDiscovery complete. Report written to {output_path}")
    print(f"Total findings: {len(all_findings)}")
    print(f"  Confidential: {report['by_tier']['confidential']}")
    print(f"  Keys to Kingdom: {report['by_tier']['keys_to_kingdom']}")
    return report

if __name__ == "__main__":
    pip_check = os.system("pip show psycopg2-binary > /dev/null 2>&1")
    if pip_check != 0:
        os.system("pip install psycopg2-binary -q")
    run_discovery()