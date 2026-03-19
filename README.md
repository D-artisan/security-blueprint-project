# The $9.44M Security Blueprint
### A Hands-On Project Guide to the 6 Pillars of Data Security

> The average US data breach costs $9.44 million. 83% of organisations suffer more than one.
> This guide turns you from someone who understands that number theoretically into someone
> who can build the architecture that prevents it.

**What you will build:** A secure, production-grade application layer demonstrating all 6 pillars of data security using exclusively free and open-source tools, deployed on AWS and Cloudflare free tiers.

**Who this is for:** Anyone who can write basic Python and run terminal commands. Security experience is not required.

**Environment:** Windows 11 with WSL2 (Ubuntu) or native Linux/Mac. All commands run in a bash terminal.

**Cost:** $0

---

## How to Use This Guide

Each pillar has three sections:

- **The Concept** explains what it is and why it matters in plain language
- **The Real World** shows how it actually works in production environments
- **The Build** gives you step-by-step hands-on implementation

Complete them in order. Each pillar builds on the last.

---

## Setup: Your Environment

Before touching any pillar, get your environment ready.

```bash
# WSL2 (run in PowerShell as Admin first, then restart)
wsl --install && wsl --set-default-version 2

# Inside your Ubuntu WSL terminal:
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv docker.io docker-compose git curl unzip

# Allow Docker without sudo
sudo usermod -aG docker $USER && newgrp docker

# Node.js (needed for Wrangler/Cloudflare CLI)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
npm install -g wrangler

# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip awscliv2.zip && sudo ./aws/install

# Verify everything
python3 --version && docker --version && node --version && wrangler --version && aws --version
```

### Free accounts you need

| Service | What it gives you | Sign up |
|---|---|---|
| AWS | S3 (5GB), RDS (750hrs/mo), CloudTrail, IAM | aws.amazon.com/free |
| Cloudflare | Workers (100k req/day), D1 (5GB), free TLS | dash.cloudflare.com |
| GitHub | Code hosting, Actions CI/CD | github.com |

### Project structure

```bash
mkdir security-blueprint && cd security-blueprint

mkdir -p api tests infra/docker observability/{prometheus,grafana,elk} \
         pillar2-discovery pillar4_compliance pillar6-response

python3 -m venv env && source env/bin/activate
git init
```

---

## Pillar 1: Governance — Set the Policy

### The Concept

Governance is the rulebook. Before you write a single line of security code, you need to answer: **what data do we have, and how sensitive is it?**

Without governance, developers make up their own rules. One person encrypts everything. Another encrypts nothing. A third stores API keys in plain text in the database. Governance eliminates that inconsistency.

The real-world tool for governance is a **data classification matrix** — a simple table that maps data types to required security controls. Every decision in pillars 2 through 6 flows from this matrix.

### The Real World

In regulated industries (banking, insurance, healthcare), governance frameworks are legally mandated. GDPR requires you to classify personal data. HIPAA requires you to classify health records. PCI-DSS requires you to classify cardholder data. The frameworks differ, but they all start from the same question: **what are we protecting, and how badly would it hurt if someone got it?**

A typical four-tier classification:

| Tier | Label | Examples | Controls Required |
|---|---|---|---|
| 0 | Unclassified | Public website content, lunch menus | None |
| 1 | Internal Use | Employee directories, internal wikis | Basic IAM roles |
| 2 | Confidential | Customer emails, business plans | Encryption + access logging |
| 3 | Keys to the Kingdom | Passwords, API keys, financial records | Zero Trust + KMS + isolation |

Once classified, a **policy** defines what must happen to each tier. This is not a feelings-based decision. If data is Tier 3, it gets KMS encryption, period. Policy enforces consistency at scale.

### The Build

Create your governance schema as code. This makes the policy executable and auditable.

**Create `api/classification.py`:**

```python
"""
Pillar 1: Governance Schema
The policy rulebook. Every security decision references this file.
"""
from enum import Enum
from dataclasses import dataclass

class DataTier(str, Enum):
    UNCLASSIFIED = "unclassified"       # Tier 0: public
    INTERNAL = "internal"               # Tier 1: employees only
    CONFIDENTIAL = "confidential"       # Tier 2: encrypted + logged
    KEYS_TO_KINGDOM = "keys_to_kingdom" # Tier 3: zero trust + KMS

@dataclass
class DataPolicy:
    tier: DataTier
    encrypt_at_rest: bool
    encrypt_in_transit: bool     # always True for Tier 2+
    audit_every_access: bool
    retention_days: int
    requires_mfa: bool
    isolation_required: bool     # separate storage from other data

POLICY_MATRIX = {
    DataTier.UNCLASSIFIED: DataPolicy(
        tier=DataTier.UNCLASSIFIED,
        encrypt_at_rest=False,
        encrypt_in_transit=False,
        audit_every_access=False,
        retention_days=365,
        requires_mfa=False,
        isolation_required=False,
    ),
    DataTier.INTERNAL: DataPolicy(
        tier=DataTier.INTERNAL,
        encrypt_at_rest=False,
        encrypt_in_transit=True,
        audit_every_access=False,
        retention_days=180,
        requires_mfa=False,
        isolation_required=False,
    ),
    DataTier.CONFIDENTIAL: DataPolicy(
        tier=DataTier.CONFIDENTIAL,
        encrypt_at_rest=True,
        encrypt_in_transit=True,
        audit_every_access=True,
        retention_days=90,
        requires_mfa=False,
        isolation_required=False,
    ),
    DataTier.KEYS_TO_KINGDOM: DataPolicy(
        tier=DataTier.KEYS_TO_KINGDOM,
        encrypt_at_rest=True,
        encrypt_in_transit=True,
        audit_every_access=True,
        retention_days=30,
        requires_mfa=True,
        isolation_required=True,
    ),
}

def get_policy(tier: DataTier) -> DataPolicy:
    """Single source of truth for all security decisions."""
    return POLICY_MATRIX[tier]

def classify_by_content(data: str) -> DataTier:
    """
    Simple pattern-based auto-classification.
    In production, this is a ML model or a dedicated DLP scanner.
    """
    import re
    # UK National Insurance numbers
    if re.search(r'\b[A-Z]{2}\d{6}[A-D]\b', data):
        return DataTier.KEYS_TO_KINGDOM
    # Credit card numbers (basic Luhn pattern)
    if re.search(r'\b(?:\d[ -]?){13,16}\b', data):
        return DataTier.KEYS_TO_KINGDOM
    # API keys or secrets (heuristic: long alphanumeric strings)
    if re.search(r'\b[A-Za-z0-9_\-]{32,}\b', data):
        return DataTier.CONFIDENTIAL
    # Email addresses
    if re.search(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b', data):
        return DataTier.CONFIDENTIAL
    return DataTier.INTERNAL
```

**Test your governance schema:**

```bash
cd security-blueprint
source env/bin/activate
pip install fastapi uvicorn python-jose cryptography boto3 prometheus-client pydantic

python3 -c "
from api.classification import classify_by_content, get_policy

test_data = [
    ('Hello world', 'should be internal'),
    ('user@example.com', 'should be confidential'),
    ('NI number: AB123456C', 'should be keys_to_kingdom'),
]

for data, description in test_data:
    tier = classify_by_content(data)
    policy = get_policy(tier)
    print(f'{description}: tier={tier.value}, encrypt={policy.encrypt_at_rest}')
"
```

**What you should see:**
```
should be internal: tier=internal, encrypt=False
should be confidential: tier=confidential, encrypt=True
should be keys_to_kingdom: tier=keys_to_kingdom, encrypt=True
```

**What this teaches you:** The governance matrix is the brain. Every downstream security system (encryption, access control, audit logging) consults this single source of truth. When a regulator asks "how do you handle personal data?", you point them at this file.

---

## Pillar 2: Discovery — Locate the Data

### The Concept

You cannot protect data you do not know exists. Discovery is the process of finding sensitive data hiding across your environment — in databases, S3 buckets, log files, email attachments, and anywhere else it might have drifted.

The surprising truth is that **preconceived data maps are almost always wrong**. Development teams copy production data into test environments. Support teams paste customer emails into Slack. A developer stores an API key in a comment. Discovery is how you find what actually exists, not what you think exists.

### The Real World

Discovery operates across two categories:

**Structured data** (databases, APIs): You know the schema. You can query column names, scan for PII patterns, and classify rows. Tools like AWS Macie do this automatically for S3. For databases, a custom scanner queries each column and runs pattern matching.

**Unstructured data** (S3 buckets, emails, files): You do not know the schema. A file called `backup_jan.csv` could be a spreadsheet of customer financial records or a list of vegetable prices. Discovery tools scan the content, not the filename.

**Data Loss Prevention (DLP)** is the motion-tracking version of discovery. Instead of scanning what is stored, DLP monitors what is moving — flagging when confidential data appears in an outbound email or is copied to a USB drive.

The key insight is that discovery is not a one-time exercise. Data is created constantly. Discovery must run continuously.

### The Build

Build a local data scanner that finds sensitive data across a simulated environment.

**Start local infrastructure:**

First, create a `.env` file in your project root to keep credentials out of source code:

```bash
cp .env.example .env
# Edit .env with your values (defaults work for local development)
```

Your `.env` file should look like:
```env
# PostgreSQL
POSTGRES_USER=scanner
POSTGRES_PASSWORD=scanpass
POSTGRES_DB=appdb

# Grafana
GF_SECURITY_ADMIN_PASSWORD=admin
```

> **Important:** `.env` is gitignored and never committed. Only `.env.example` (with placeholder values) is tracked in version control.

Create `infra/docker/docker-compose.yml`:

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:16
    env_file:
      - ../../.env
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
```

```bash
docker-compose -f infra/docker/docker-compose.yml up -d
```

**Seed the database with realistic data including hidden sensitive content:**

```bash
# Install Postgres client
sudo apt install -y postgresql-client

# Seed with mixed-sensitivity data
psql -h localhost -U scanner -d appdb -c "
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT,
    email TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO users (username, email, notes) VALUES
('alice', 'alice@example.com', 'Standard account'),
('bob', 'bob@corp.com', 'NI: AB123456C - HR record'),
('charlie', 'charlie@test.com', 'Card: 4111-1111-1111-1111 on file'),
('diana', 'diana@co.uk', 'Internal wiki access only');
" -W
# password: value of POSTGRES_PASSWORD from your .env file
```

**Create `pillar2-discovery/scanner.py`:**

```python
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
```

```bash
pip install psycopg2-binary
python3 pillar2-discovery/scanner.py
cat discovery_report.json
```

**What this teaches you:** Discovery is not glamorous, but it is where security starts. The scanner shows you exactly what AWS Macie and commercial DLP tools do internally — pattern matching at scale. The discovery report becomes the input to Pillar 3: now you know what needs protecting.

---

## Pillar 3: Protection — Shield the Assets

### The Concept

Protection means making data unreadable without authorisation, even if an attacker gets direct access to the storage layer. It has two dimensions:

**Data at rest** (stored in databases, files, S3 buckets): Encrypted on disk. If someone steals the hard drive or the database dump, they see ciphertext — scrambled bytes with no value without the key.

**Data in transit** (moving across a network): Encrypted in the pipe. If someone intercepts the traffic between your app and your database, or between your users and your server, they see ciphertext.

These are not the same problem and require different solutions.

### The Real World: Data in Transit

Every HTTPS connection uses TLS (Transport Layer Security). TLS is the padlock in your browser's address bar. Cloudflare handles TLS termination — it sits between your users and your origin server, decrypting traffic at the edge and re-encrypting it before sending it on.

The threat model this addresses: **man-in-the-middle attacks**. Without TLS, a malicious actor on the same wifi network as your user can read every byte they send. With TLS, they see encrypted noise.

In production: Cloudflare Proxy (free tier) automatically handles TLS for any domain you point at it. You never need to manage certificates.

### The Real World: Data at Rest

Two approaches:

**Envelope encryption with KMS** (Key Management Service): AWS KMS generates and manages cryptographic keys. Your application asks KMS to encrypt data and receives ciphertext. To decrypt, it asks KMS again. Your application never holds the key itself. This is the gold standard for Keys to the Kingdom data.

**Application-level encryption**: Your application generates and manages its own keys, typically using AES-256-GCM. Simpler than KMS, appropriate for Confidential data, but requires careful key management.

**Key rotation**: Encrypting once is not enough. Keys must be rotated on a schedule (annually at minimum, monthly for sensitive data). Key rotation means re-encrypting all data with a new key and retiring the old one. This limits the blast radius if a key is ever compromised.

### The Build

**Part A: Data in Transit — Cloudflare TLS**

```bash
# Log in to Cloudflare
wrangler login

# Create a Worker that enforces HTTPS and adds security headers
mkdir -p worker/src
```

Create `worker/wrangler.toml`:

```toml
name = "security-blueprint"
main = "src/index.js"
compatibility_date = "2024-01-01"

[vars]
ENVIRONMENT = "production"
```

Create `worker/src/index.js`:

```javascript
/**
 * Pillar 3: Data in Transit Protection
 * Cloudflare Worker as the edge security layer.
 * All traffic passes through this before reaching the origin.
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Enforce HTTPS - redirect any HTTP request
    if (url.protocol === "http:") {
      return Response.redirect(`https://${url.host}${url.pathname}`, 301);
    }

    // 2. Security headers (OWASP recommended)
    const securityHeaders = {
      // Prevent clickjacking
      "X-Frame-Options": "DENY",
      // Prevent MIME sniffing
      "X-Content-Type-Options": "nosniff",
      // Force HTTPS for 1 year (HSTS)
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      // Control what data is sent in Referer header
      "Referrer-Policy": "strict-origin-when-cross-origin",
      // Disable browser features not needed
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      // Content Security Policy
      "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    };

    // 3. Rate limiting by IP (basic — production uses Cloudflare Rate Limiting rules)
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    const rateLimitKey = `rate:${clientIP}:${Math.floor(Date.now() / 60000)}`; // per minute window

    // 4. Block requests from known bad IPs/bots
    const botScore = request.cf?.botManagement?.score;
    if (botScore !== undefined && botScore < 30) {
      return new Response("Access denied", {
        status: 403,
        headers: securityHeaders,
      });
    }

    // 5. Pass request to origin with security headers
    const response = new Response(
      JSON.stringify({
        status: "protected",
        edge_colo: request.cf?.colo,
        tls_version: request.cf?.tlsVersion,
        client_ip: clientIP,
        message: "Traffic encrypted at the Cloudflare edge. Origin server never exposed directly.",
      }),
      {
        headers: {
          "Content-Type": "application/json",
          ...securityHeaders,
        },
      }
    );

    return response;
  }
};
```

```bash
cd worker
wrangler deploy

# Test the TLS enforcement
curl -I https://security-blueprint.YOUR-SUBDOMAIN.workers.dev
# Look for: Strict-Transport-Security in the response headers
```

**Part B: Data at Rest — AES-256-GCM Encryption with Key Rotation**

Create `api/protection.py`:

```python
"""
Pillar 3: Data at Rest Protection
AES-256-GCM encryption with key lifecycle management.

AES-256-GCM explained:
- AES: Advanced Encryption Standard (the algorithm)
- 256: Key length in bits (longer = stronger; 256-bit has 2^256 possible keys)
- GCM: Galois/Counter Mode — provides both encryption AND authentication
       (you cannot tamper with the ciphertext without detection)

Why GCM over CBC: GCM detects tampering. CBC does not.
"""
import os
import json
import base64
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class KeyVault:
    """
    Manages encryption key lifecycle.
    In production: AWS KMS or HashiCorp Vault handles this.
    This file-based vault demonstrates the same concepts locally.
    """

    def __init__(self, vault_path: str = ".keyvault"):
        self.vault_path = Path(vault_path)
        self.vault_path.mkdir(exist_ok=True)
        self.keys_file = self.vault_path / "keys.json"
        self._keys = self._load_keys()

    def _load_keys(self) -> dict:
        if self.keys_file.exists():
            return json.loads(self.keys_file.read_text())
        return {}

    def _save_keys(self):
        self.keys_file.write_text(json.dumps(self._keys, indent=2))

    def generate_key(self, key_id: str) -> str:
        """Generate a new 256-bit AES key and store it in the vault."""
        raw_key = AESGCM.generate_key(bit_length=256)
        self._keys[key_id] = {
            "key": base64.b64encode(raw_key).decode(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "active",
            "algorithm": "AES-256-GCM",
        }
        self._save_keys()
        print(f"[KeyVault] Generated key: {key_id}")
        return key_id

    def get_active_key(self) -> tuple[str, bytes]:
        """Get the current active encryption key."""
        active = {k: v for k, v in self._keys.items() if v["status"] == "active"}
        if not active:
            key_id = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
            self.generate_key(key_id)
            active = {key_id: self._keys[key_id]}

        key_id = max(active.keys(), key=lambda k: active[k]["created_at"])
        raw = base64.b64decode(self._keys[key_id]["key"])
        return key_id, raw

    def get_key_by_id(self, key_id: str) -> bytes:
        """Get a specific key by ID (needed for decryption of old records)."""
        if key_id not in self._keys:
            raise KeyError(f"Key {key_id} not found in vault")
        return base64.b64decode(self._keys[key_id]["key"])

    def rotate_keys(self):
        """
        Key rotation: generate a new active key, retire the old one.
        After rotation, you must re-encrypt all data using re_encrypt_record().
        """
        # Retire all currently active keys
        for key_id in self._keys:
            if self._keys[key_id]["status"] == "active":
                self._keys[key_id]["status"] = "retired"
                self._keys[key_id]["retired_at"] = datetime.now(timezone.utc).isoformat()
                print(f"[KeyVault] Retired key: {key_id}")

        # Generate new active key
        new_id = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        self.generate_key(new_id)
        self._save_keys()
        print(f"[KeyVault] Rotation complete. New active key: {new_id}")
        return new_id

    def list_keys(self):
        """Show all keys and their status. Useful for auditing."""
        for key_id, meta in self._keys.items():
            print(f"  {key_id}: {meta['status']} (created {meta['created_at'][:10]})")


class EncryptionService:
    """
    Application-level encryption service.
    Wrap this around any data store operation that handles Confidential+ data.
    """

    def __init__(self):
        self.vault = KeyVault()

    def encrypt(self, plaintext: str) -> dict:
        """
        Encrypt plaintext. Returns a dict containing:
        - ciphertext: the encrypted bytes (base64-encoded for storage)
        - key_id: which key was used (needed for decryption)
        - nonce: the random nonce used (safe to store alongside ciphertext)

        The nonce is not a secret. It just ensures that encrypting the same
        plaintext twice produces different ciphertext (preventing pattern analysis).
        """
        key_id, key_bytes = self.vault.get_active_key()
        aesgcm = AESGCM(key_bytes)

        # 12-byte random nonce — never reuse a nonce with the same key
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "key_id": key_id,
            "algorithm": "AES-256-GCM",
            "encrypted_at": datetime.now(timezone.utc).isoformat(),
        }

    def decrypt(self, encrypted_record: dict) -> str:
        """
        Decrypt a record. Uses the key_id to retrieve the correct key,
        even if it has been rotated. Old records are always decryptable
        as long as the key is in the vault (retired, not deleted).
        """
        key_bytes = self.vault.get_key_by_id(encrypted_record["key_id"])
        aesgcm = AESGCM(key_bytes)
        nonce = base64.b64decode(encrypted_record["nonce"])
        ciphertext = base64.b64decode(encrypted_record["ciphertext"])
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

    def re_encrypt_record(self, encrypted_record: dict) -> dict:
        """
        Key rotation step 2: re-encrypt an existing record with the new active key.
        Decrypt with the old key, encrypt with the new key.
        This is called for every record in the database after a rotation.
        """
        plaintext = self.decrypt(encrypted_record)
        return self.encrypt(plaintext)


def demonstrate_protection():
    """Walk through the full protection lifecycle."""
    service = EncryptionService()

    print("=== PILLAR 3: DATA AT REST PROTECTION ===\n")

    # 1. Encrypt sensitive data
    sensitive = "NI Number: AB123456C - financial record"
    print(f"Original:  {sensitive}")

    record = service.encrypt(sensitive)
    print(f"Encrypted: {record['ciphertext'][:50]}... (truncated)")
    print(f"Key used:  {record['key_id']}")
    print(f"Algorithm: {record['algorithm']}\n")

    # 2. Decrypt
    recovered = service.decrypt(record)
    print(f"Decrypted: {recovered}")
    assert recovered == sensitive, "Decryption failed!"
    print("Decryption verified.\n")

    # 3. Key rotation
    print("Performing key rotation...")
    service.vault.rotate_keys()
    print("\nKeys in vault after rotation:")
    service.vault.list_keys()

    # 4. Re-encrypt with new key (simulates what you do for all DB records)
    print("\nRe-encrypting record with new key...")
    new_record = service.re_encrypt_record(record)
    print(f"New key used: {new_record['key_id']}")
    recovered_after_rotation = service.decrypt(new_record)
    assert recovered_after_rotation == sensitive
    print("Data successfully re-encrypted and verified.\n")

    print("Key insight: The ciphertext is different after rotation,")
    print("but the plaintext is identical. Old keys can be retired safely.")

if __name__ == "__main__":
    demonstrate_protection()
```

```bash
python3 api/protection.py
```

**What you should see:**
```
Original:  NI Number: AB123456C - financial record
Encrypted: abcXYZ123... (truncated)
Key used:  key-20250316
Algorithm: AES-256-GCM

Decrypted: NI Number: AB123456C - financial record
Decryption verified.

Performing key rotation...
[KeyVault] Retired key: key-20250316
[KeyVault] Generated key: key-20250316-143022
...
```

**What this teaches you:** The separation between the ciphertext and the key is the fundamental principle of encryption. The ciphertext can sit in a public S3 bucket and it does not matter — without the key it is worthless. Key rotation limits the damage window: if a key leaks, all data encrypted with it is at risk. Rotating means the window is bounded.

---

## Pillar 4: Compliance — Prove the Controls

### The Concept

Compliance is not about following rules for their own sake. It is about being able to **prove** that your controls work. Auditors, regulators, and legal teams do not take your word for it. They want evidence.

The evidence comes from two sources:

1. **Audit trails**: Immutable logs showing who accessed what, when, and from where
2. **Automated retention policies**: Proof that you destroy data when it reaches its legal expiry date

The compliance lifecycle follows four stages:
1. **Creation** — data enters the system
2. **Active use** — every access is logged
3. **Mandatory retention** — stored securely for the legally required period
4. **Automated destruction** — deleted automatically at expiry

Holding data past its legal retention is not just wasteful. It is a financial liability. Every day you store data you are not legally required to keep is another day it can be breached.

### The Real World

AWS CloudTrail records every API call made to your AWS account. In a regulated environment, CloudTrail logs are the audit trail that proves to GDPR regulators or HIPAA auditors that access controls are working. CloudTrail logs are themselves stored in a locked S3 bucket that is immutable — even administrators cannot delete them.

AWS S3 lifecycle rules automate the destruction phase. You define: "delete all objects in this prefix after 30 days." S3 executes this automatically, and you can prove it with the lifecycle configuration document.

### The Build

**Part A: Audit Trail — Every Access Logged**

Create `pillar4_compliance/audit_trail.py`:

```python
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
```

**Part B: Automated Destruction — S3 Lifecycle Rules**

```bash
# Create an S3 bucket for compliance data
BUCKET="security-blueprint-compliance-$(date +%s)"
aws s3api create-bucket \
  --bucket $BUCKET \
  --region eu-west-2 \
  --create-bucket-configuration LocationConstraint=eu-west-2
echo "Bucket created: $BUCKET"

# Lock down public access
aws s3api put-public-access-block \
  --bucket $BUCKET \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable versioning (every change is retained — can prove what existed when)
aws s3api put-bucket-versioning \
  --bucket $BUCKET \
  --versioning-configuration Status=Enabled

# Apply tiered retention lifecycle rules:
# Tier 2 (Confidential): 90 days
# Tier 3 (Keys to Kingdom): 30 days
# Audit logs: 7 years (regulatory requirement in many jurisdictions)
aws s3api put-bucket-lifecycle-configuration \
  --bucket $BUCKET \
  --lifecycle-configuration '{
    "Rules": [
      {
        "ID": "confidential-90-days",
        "Status": "Enabled",
        "Filter": {"Prefix": "confidential/"},
        "Expiration": {"Days": 90},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 90}
      },
      {
        "ID": "keys-to-kingdom-30-days",
        "Status": "Enabled",
        "Filter": {"Prefix": "keys_to_kingdom/"},
        "Expiration": {"Days": 30},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
      },
      {
        "ID": "audit-logs-7-years",
        "Status": "Enabled",
        "Filter": {"Prefix": "audit/"},
        "Expiration": {"Days": 2555}
      }
    ]
  }'

# Verify the lifecycle rules are in place (this is your compliance evidence)
aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET

echo "Bucket: $BUCKET"
echo "Save this name for the teardown section."
```

```bash
python3 pillar4_compliance/audit_trail.py
```

**What this teaches you:** Compliance is evidence-based. The audit log hash chain means that even you cannot go back and change a log entry without being detected — it is technically enforced honesty. The S3 lifecycle rule is your proof to a GDPR auditor that you do not hold data longer than required.

---

## Pillar 5: Detection — Eyes on the Glass

### The Concept

Detection is the security system that watches your running system for threats. It operates on the premise that some attacks will get past your perimeter — the question is how quickly you find out.

The core technique is **User Behaviour Analytics (UBA)**: establish a baseline of normal activity, then alert on deviations. A user who normally downloads 1,000 files a day suddenly downloading 1,000,000 is an anomaly trigger. It might be a legitimate batch process. It might be data exfiltration. Either way, you need to know.

Detection generates **alerts**, which flow to a central console (SIEM — Security Information and Event Management) for triage.

### The Real World

**Prometheus** scrapes metrics from your application every 15 seconds. Request volume, latency, error rate, active users — all become time-series data.

**Grafana** visualises those metrics and evaluates alert rules. When request volume from a single user crosses your anomaly threshold, Grafana fires an alert to a webhook.

**Elasticsearch and Kibana** handle logs — the narrative of what happened. Metrics tell you something is wrong. Logs tell you exactly what happened and in what order.

Together, these three form the open-source equivalent of a commercial SIEM platform.

### The Build

> **What You'll Build:**
> - **Prometheus**: Collects metrics (numbers) from your API every 15 seconds
> - **Grafana**: Beautiful dashboards showing request rates, errors, and anomalies in real-time
> - **Elasticsearch + Kibana**: Stores and searches detailed logs (the full story of what happened)
> 
> **Time Required:** 30-45 minutes
> 
> **What You'll Learn:**
> - How to visualize security metrics in Grafana
> - How to write PromQL queries to analyze request patterns
> - How to detect anomalous behavior (like rate limit breaches)
> - How to correlate metrics (Grafana) with logs (Kibana)

---

**Pre-flight Checklist:**

Before starting, ensure you have:
```bash
# 1. Docker and Docker Compose installed
docker --version  # Should show Docker version 20.x or higher
docker-compose --version  # Should show version 1.29.x or higher

# 2. Required Python packages from previous pillars
pip list | grep -E "cryptography|fastapi|uvicorn|prometheus-client"

# 3. The project structure from Pillars 1-4
ls -la api/  # Should show: main.py, classification.py, protection.py
ls -la pillar4_compliance/  # Should show: audit_trail.py

# 4. At least 4GB free RAM (check with: free -h)
# 5. Ports 3000, 5601, 8000, 9090, 9200 are not in use
netstat -tuln | grep -E '3000|5601|8000|9090|9200'
# Should return nothing (ports are free)
```

If any checks fail, resolve them before proceeding.

---

**Start the observability stack:**

Create `observability/docker-compose.yml`:

```yaml
version: "3.9"

services:
  prometheus:
    image: prom/prometheus:v2.51.0
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=7d"

  grafana:
    image: grafana/grafana:10.4.0
    env_file:
      - ../.env
    environment:
      GF_USERS_ALLOW_SIGN_UP: "false"
    ports:
      - "3000:3000"
    volumes:
      - grafana-storage:/var/lib/grafana
    depends_on:
      - prometheus

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    ports:
      - "9200:9200"
    ulimits:
      memlock:
        soft: -1
        hard: -1

  kibana:
    image: docker.elastic.co/kibana/kibana:8.13.0
    environment:
      ELASTICSEARCH_HOSTS: http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  grafana-storage:
```

Create `observability/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets: []  # configure Alertmanager URL here for production

scrape_configs:
  - job_name: "security-blueprint-api"
    static_configs:
      - targets: ["host.docker.internal:8000"]  # Use this for Docker Desktop
      # For Linux/WSL2, replace with your machine IP (get it with: hostname -I | awk '{print $1}')
      # Example: - targets: ["192.168.1.100:8000"]
    metrics_path: /metrics
```

Create `observability/prometheus/alert_rules.yml`:

```yaml
groups:
  - name: security_alerts
    rules:
      # Alert if any user exceeds 50 requests per minute
      - alert: AnomalousRequestRate
        expr: rate(vault_api_requests_total[1m]) * 60 > 50
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Anomalous request rate detected"
          description: "User is making more than 50 requests/minute"

      # Alert if error rate exceeds 10%
      - alert: HighErrorRate
        expr: |
          rate(vault_api_requests_total{status=~"4..|5.."}[5m]) /
          rate(vault_api_requests_total[5m]) > 0.10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High error rate"
          description: "More than 10% of requests are failing"

      # Alert on any access denial
      - alert: AccessDenied
        expr: increase(vault_api_anomaly_alerts_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Access denied events detected"
```

```bash
cd observability
docker-compose up -d

# Wait 30 seconds for services to start
sleep 30

# Verify all services are running
curl -s http://localhost:9090/-/healthy   # Prometheus should return "Healthy"
curl -s http://localhost:3000/api/health  # Grafana should return {"database":"ok"}
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool  # Elasticsearch

# If any service fails, check logs:
# docker-compose logs prometheus
# docker-compose logs grafana
```

**Build the FastAPI application with instrumented metrics:**

Create `api/main.py`:

```python
"""
The application under observation.
Every endpoint records metrics that feed into Prometheus/Grafana detection.
"""
import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.classification import DataTier, get_policy, classify_by_content
from api.protection import EncryptionService
from pillar4_compliance.audit_trail import AuditLogger

# === METRICS (Pillar 5: Detection) ===
REQUEST_COUNT = Counter(
    "vault_api_requests_total",
    "Total API requests",
    ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram(
    "vault_api_request_duration_seconds",
    "Request latency by endpoint",
    ["endpoint"]
)
ANOMALY_ALERTS = Counter(
    "vault_api_anomaly_alerts_total",
    "Anomaly alerts fired",
    ["user_id", "reason"]
)
ACTIVE_USERS = Gauge(
    "vault_api_active_users",
    "Active users in last 5 minutes"
)
ENCRYPTION_OPS = Counter(
    "vault_api_encryption_operations_total",
    "Number of encryption/decryption operations",
    ["operation", "tier"]
)

# === SERVICES ===
encryption = EncryptionService()
audit = AuditLogger()
DATA_STORE = {}  # In production: PostgreSQL

# === ANOMALY DETECTION STATE ===
import redis as redis_lib
try:
    r = redis_lib.Redis(host="localhost", port=6379, decode_responses=True)
    r.ping()
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False
    print("[WARNING] Redis not available. Anomaly detection using in-memory fallback.")
    _request_counts = {}

def check_anomaly(user_id: str) -> bool:
    """Returns True if the user's request rate is anomalous."""
    import datetime
    window = datetime.datetime.utcnow().strftime("%Y%m%d%H%M")
    key = f"requests:{user_id}:{window}"

    if REDIS_AVAILABLE:
        count = r.incr(key)
        r.expire(key, 120)
    else:
        _request_counts[key] = _request_counts.get(key, 0) + 1
        count = _request_counts[key]

    THRESHOLD = 50
    if count > THRESHOLD:
        ANOMALY_ALERTS.labels(user_id=user_id, reason="rate_exceeded").inc()
        audit.log(user_id, "ANOMALY", f"rate:{count}/min", "internal", "0.0.0.0", "DENIED")
        return True
    return False

# === APP ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Security Blueprint API starting...")
    yield
    print("Security Blueprint API shutting down.")

app = FastAPI(title="Security Blueprint API", lifespan=lifespan)

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    REQUEST_LATENCY.labels(endpoint=request.url.path).observe(duration)
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=str(response.status_code)
    ).inc()
    return response

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/health")
def health():
    return {"status": "ok", "redis": REDIS_AVAILABLE}

class StoreRequest(BaseModel):
    user_id: str
    data: str
    tier: DataTier = None  # if None, auto-classify

@app.post("/data")
def store_data(req: StoreRequest, request: Request):
    # Auto-classify if not specified
    tier = req.tier or classify_by_content(req.data)
    policy = get_policy(tier)

    # Anomaly detection
    if check_anomaly(req.user_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded — anomaly detected")

    # Apply policy
    if policy.encrypt_at_rest:
        encrypted = encryption.encrypt(req.data)
        stored_value = encrypted
        ENCRYPTION_OPS.labels(operation="encrypt", tier=tier.value).inc()
    else:
        stored_value = req.data

    record_id = str(uuid.uuid4())
    DATA_STORE[record_id] = {"value": stored_value, "tier": tier, "owner": req.user_id}

    # Audit log
    audit.log(req.user_id, "WRITE", record_id, tier.value,
              request.client.host, "SUCCESS")

    return {"record_id": record_id, "tier": tier.value, "encrypted": policy.encrypt_at_rest}

@app.get("/data/{record_id}")
def retrieve_data(record_id: str, user_id: str, request: Request):
    record = DATA_STORE.get(record_id)
    if not record:
        audit.log(user_id, "READ", record_id, "unknown", request.client.host, "DENIED")
        raise HTTPException(status_code=404, detail="Not found")

    if record["owner"] != user_id:
        audit.log(user_id, "READ", record_id, record["tier"].value, request.client.host, "DENIED")
        ANOMALY_ALERTS.labels(user_id=user_id, reason="unauthorized_access").inc()
        raise HTTPException(status_code=403, detail="Access denied")

    policy = get_policy(record["tier"])
    if policy.encrypt_at_rest:
        value = encryption.decrypt(record["value"])
        ENCRYPTION_OPS.labels(operation="decrypt", tier=record["tier"].value).inc()
    else:
        value = record["value"]

    audit.log(user_id, "READ", record_id, record["tier"].value, request.client.host, "SUCCESS")
    return {"data": value, "tier": record["tier"].value}
```

```bash
# Start the API (in a new terminal)
cd security-blueprint
pip install redis fastapi uvicorn prometheus-client
uvicorn api.main:app --reload --port 8000 --host 0.0.0.0

# In another terminal, verify the API is up and exposing metrics
curl http://localhost:8000/health
# Should return: {"status":"ok","redis":false}

curl -s http://localhost:8000/metrics | grep vault_api
# Should show metrics like: vault_api_requests_total, vault_api_encryption_operations_total

# Generate some test data to populate metrics
curl -X POST http://localhost:8000/data \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "data": "NI: AB123456C", "tier": "keys_to_kingdom"}'

curl -X POST http://localhost:8000/data \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "data": "internal memo"}'

# Make a few more requests to generate meaningful metrics
for i in {1..10}; do
  curl -s -X POST http://localhost:8000/data \
    -H "Content-Type: application/json" \
    -d '{"user_id": "bob", "data": "test data '$i'"}' > /dev/null
  echo "Request $i sent"
done
```

**Set up Grafana dashboards:**

**Step 1: Access Grafana**
1. Open http://localhost:3000 in your browser
2. Login with:
   - **Username:** `admin`
   - **Password:** `admin`
3. You may be prompted to change the password - you can skip this step

**Step 2: Add Prometheus Data Source**
1. Click the **☰** (hamburger menu icon) in the top-left
2. Go to **Connections** → **Data sources**
3. Click **Add new data source**
4. Select **Prometheus** from the list
5. Configure the connection:
   - **Name:** Leave as `Prometheus` (default)
   - **URL:** `http://prometheus:9090`
6. Scroll down and click **Save & test**
7. You should see: ✅ **"Successfully queried the Prometheus API"**

**Troubleshooting: If "Save & test" fails**
- Check Prometheus is running: `curl http://localhost:9090/-/healthy`
- If using Linux/WSL2, the URL might need to be your host IP
- Get your IP: `hostname -I | awk '{print $1}'`

**Step 3: Verify Prometheus is Scraping Your API**
1. Open http://localhost:9090/targets in your browser
2. Find the job "security-blueprint-api"
3. Status should be **UP** (green)
4. If it shows **DOWN** (red):
   - Your API isn't reachable from the Prometheus container
   - Edit `observability/prometheus/prometheus.yml`
   - Change `targets: ["host.docker.internal:8000"]` to `targets: ["YOUR_IP:8000"]`
   - Run: `cd observability && docker-compose restart prometheus`

**Step 4: Create Your First Dashboard**
1. In Grafana, click **☰** → **Dashboards**
2. Click **New** → **New Dashboard**
3. Click **+ Add visualization**
4. Select **Prometheus** as the data source
5. You'll see a query editor - click the **Code** button (top-right of query box) to switch to code mode

Now create these panels:

**Panel 1: Request Rate**
1. **Query (paste this in the Code editor):**
   ```promql
   rate(vault_api_requests_total[1m])
   ```
2. **In the query editor, find the "Legend" field** (below your query) and enter:
   ```
   {{method}} {{endpoint}}
   ```
3. **Panel options (right sidebar):**
   - **Title:** `Request Rate (per second)`
   - **Visualization:** Time series (default)
4. Scroll down to **Legend** section (right sidebar):
   - **Legend mode:** Table
   - **Legend values:** Check "Last"
5. Click **Apply** (top-right)

**Panel 2: Error Rate %**
1. Click **Add** → **Visualization** (to add another panel)
2. **Query:**
   ```promql
   sum(rate(vault_api_requests_total{status=~"4..|5.."}[5m])) / 
   sum(rate(vault_api_requests_total[5m])) * 100
   ```
3. **Panel options:**
   - **Title:** `Error Rate %`
   - **Visualization:** Click the visualization picker and select **Gauge**
4. In the right sidebar:
   - **Unit:** Select "Percent (0-100)"
   - **Min:** `0`
   - **Max:** `100`
5. **Thresholds:**
   - Base (0): Green
   - Click **+ Add threshold**: `5` → Yellow
   - Click **+ Add threshold**: `10` → Red
6. Click **Apply**

**Panel 3: Anomaly Alerts**
1. Click **Add** → **Visualization**
2. **Query:**
   ```promql
   increase(vault_api_anomaly_alerts_total[5m])
   ```
3. **In the query editor Legend field**, enter: `{{user_id}} - {{reason}}`
4. **Panel options:**
   - **Title:** `Anomaly Alerts (last 5 min)`
   - **Visualization:** Time series
5. Click **Apply**

**Panel 4: Encryption Operations**
1. Click **Add** → **Visualization**
2. **Query:**
   ```promql
   rate(vault_api_encryption_operations_total[1m])
   ```
3. **In the query editor Legend field**, enter: `{{operation}} - {{tier}}`
4. **Panel options:**
   - **Title:** `Encryption Ops/sec`
   - **Visualization:** Time series
5. Click **Apply**

**Step 5: Save Your Dashboard**
1. Click the **💾 Save** icon (disk icon, top-right corner)
2. **Dashboard name:** `Security Blueprint Dashboard`
3. Click **Save**

**Important Notes:**
- If you see "No data" in any panel, check that your API is running and generating requests
- The Error Rate panel will only show data after you make some requests that include errors
- Filter out favicon noise by adding `{endpoint!="/favicon.ico"}` to queries if needed

**Step 6: Test Your Dashboard with Real Traffic**

**Use the automated traffic generator:**

First, create `generate-traffic.sh` in your project root:
```bash
#!/bin/bash

# Traffic generator for Security Blueprint API
# Generates mix of successful requests and errors to test Grafana dashboard

API_URL="http://localhost:8000"
INTERVAL=2  # seconds between requests

echo "🚀 Starting traffic generator for $API_URL"
echo "📊 This will generate a mix of successful and error responses"
echo "Press Ctrl+C to stop"
echo ""

# Counter for tracking
success_count=0
error_count=0

while true; do
    # Generate 3 successful requests
    echo "✅ Sending successful requests..."
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/" 
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/health"
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/"
    success_count=$((success_count + 3))
    
    sleep $INTERVAL
    
    # Generate 1-2 errors (404s from non-existent endpoints)
    echo "❌ Sending error requests..."
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/nonexistent"
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/invalid/path"
    error_count=$((error_count + 2))
    
    sleep $INTERVAL
    
    # Generate another successful request
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/"
    success_count=$((success_count + 1))
    
    # Display summary
    echo "📈 Total - Success: $success_count | Errors: $error_count | Error Rate: $((error_count * 100 / (success_count + error_count)))%"
    echo "---"
    
    sleep $INTERVAL
done
```

Make it executable and run it:
```bash
chmod +x generate-traffic.sh
./generate-traffic.sh
```

This script continuously generates:
- ✅ Successful requests (200 status)
- ❌ Error requests (404 status)
- ~33% error rate for realistic dashboard testing
- Live statistics in your terminal

Press **Ctrl+C** to stop the script.

**Alternatively, trigger an anomaly alert manually (rate limit breach):**
```bash
# Send 80 requests rapidly to trigger the 50 req/min threshold
echo "Triggering anomaly detection..."
for i in $(seq 1 80); do
  curl -s -X POST http://localhost:8000/data \
    -H "Content-Type: application/json" \
    -d '{"user_id": "eve", "data": "flood test"}' > /dev/null
done
echo "Anomaly triggered! Check your Grafana dashboard."
```

**What to look for in Grafana:**
1. **Request Rate panel:** Should show steady traffic with `generate-traffic.sh` running, or a spike with the manual flood test
2. **Anomaly Alerts panel:** Should increment from 0 after the 80-request flood test
3. **Error Rate panel:** Will show ~33% with `generate-traffic.sh`, or higher with the flood test (429 rate limit errors)
4. **Encryption Ops panel:** Shows encrypt/decrypt operations per second

**Refresh your dashboard:**
- Click the **🔄 Refresh** icon (top-right)
- Or set auto-refresh: Click the dropdown next to refresh → Select "5s" or "10s" for continuous monitoring
- **Important:** Auto-refresh is essential when using `generate-traffic.sh` for real-time updates

**Adjust time range:**
- Click the **time picker** (top-right, shows "Last 6 hours")
- Select **Last 5 minutes** or **Last 15 minutes** to see recent data

---

### Troubleshooting Common Grafana Issues

**Problem: All panels show "No data"**

**Solution:**
```bash
# 1. Check if your API is running
curl http://localhost:8000/health
# Should return: {"status":"ok",...}

# 2. Check if metrics are being exposed
curl -s http://localhost:8000/metrics | grep vault_api
# Should show multiple vault_api metrics

# 3. Check if Prometheus is scraping successfully
# Open http://localhost:9090/targets in your browser
# Look for "security-blueprint-api" - should be UP (green)

# 4. If it shows DOWN, fix the networking:
# Get your machine's IP
hostname -I | awk '{print $1}'
# Example output: 192.168.1.100

# Edit observability/prometheus/prometheus.yml
# Change the targets line to use your IP:
# - targets: ["192.168.1.100:8000"]

# Restart Prometheus
cd observability
docker-compose restart prometheus

# 5. Generate test traffic with the automated script
cd ..
./generate-traffic.sh
# Press Ctrl+C to stop when you see data in your dashboard
```

**Problem: Error Rate gauge shows two needles (duplicate data)**

**Solution:** One gauge is for `/data` endpoint, the other for `/favicon.ico` (browser requests). Filter it out:
```promql
sum(rate(vault_api_requests_total{endpoint!="/favicon.ico",status=~"4..|5.."}[5m])) / 
sum(rate(vault_api_requests_total{endpoint!="/favicon.ico"}[5m])) * 100
```

**Problem: Can't delete a panel**

**Solution:**
1. Hover over the panel title
2. Click the **three dots (⋮)** 
3. Select **Remove**
4. **Important:** Click **💾 Save** (top-right) or changes won't persist!

**Problem: Query works in Prometheus UI but not in Grafana**

**Solution:**
1. Go to Grafana → **Connections** → **Data sources** → **Prometheus**
2. Click **Save & test**
3. Look for the green success message
4. If it fails, check the URL is correct: `http://prometheus:9090`

**Problem: Dashboard disappeared after refresh**

**Solution:** You forgot to save it! Always click **💾 Save** after making changes.

---

**View logs in Kibana:**

1. First, ship your audit events to Elasticsearch:
```bash
python3 pillar4_compliance/audit_trail.py

python3 -c "
import json, urllib.request
from pathlib import Path

log = Path('pillar4_compliance/audit.jsonl')
for line in log.read_text().strip().splitlines():
    event = json.loads(line)
    req = urllib.request.Request(
        'http://localhost:9200/vault-api-logs-000001/_doc',
        data=json.dumps(event).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    urllib.request.urlopen(req)
    print(f'Shipped: {event[\"action\"]} by {event[\"user_id\"]}')
"
```

2. Confirm Elasticsearch received them:
```bash
curl -s http://localhost:9200/vault-api-logs-000001/_count | python3 -m json.tool
# Should show: "count": 6
```

3. Open http://localhost:5601 > Stack Management > **Data Views** (Kibana 8.x renamed "Index Patterns" to "Data Views")
4. Click **Create data view**
   - **Name:** `vault-api-logs-*`
   - **Index pattern:** `vault-api-logs-*` (this is a separate field — do not leave it as `example-*`)
   - **Timestamp field:** `timestamp`
   - Click **Save data view to Kibana**
5. Hamburger menu > **Discover** > select `vault-api-logs-*` > filter by `outcome: DENIED` to see all blocked access attempts

---

### Quick Reference: Useful PromQL Queries

Copy these queries into Grafana to explore your metrics:

**Request Metrics:**
```promql
# Requests per second
rate(vault_api_requests_total[1m])

# Requests per minute (more intuitive)
rate(vault_api_requests_total[1m]) * 60

# Total requests in the last hour
sum(increase(vault_api_requests_total[1h]))

# Requests by user
sum by (user_id) (rate(vault_api_requests_total[1m]))

# Requests by endpoint
sum by (endpoint) (rate(vault_api_requests_total[1m]))

# Requests by status code
sum by (status) (rate(vault_api_requests_total[1m]))
```

**Error Analysis:**
```promql
# Error rate as percentage
sum(rate(vault_api_requests_total{status=~"4..|5.."}[5m])) / 
sum(rate(vault_api_requests_total[5m])) * 100

# Only server errors (5xx)
sum(rate(vault_api_requests_total{status=~"5.."}[5m])) / 
sum(rate(vault_api_requests_total[5m])) * 100

# Count of errors in last 15 minutes
sum(increase(vault_api_requests_total{status=~"4..|5.."}[15m]))

# Errors by endpoint
sum by (endpoint) (rate(vault_api_requests_total{status=~"4..|5.."}[5m]))
```

**Security Metrics:**
```promql
# Anomaly alerts
increase(vault_api_anomaly_alerts_total[5m])

# Anomaly alerts by user
sum by (user_id) (increase(vault_api_anomaly_alerts_total[5m]))

# Encryption operations per second
rate(vault_api_encryption_operations_total[1m])

# Encryption operations by tier
sum by (tier) (rate(vault_api_encryption_operations_total[1m]))

# Decrypt operations only
rate(vault_api_encryption_operations_total{operation="decrypt"}[1m])
```

**Performance Metrics:**
```promql
# Average request latency (seconds)
avg(rate(vault_api_request_duration_seconds_sum[5m]) / rate(vault_api_request_duration_seconds_count[5m]))

# 95th percentile latency
histogram_quantile(0.95, rate(vault_api_request_duration_seconds_bucket[5m]))

# Slowest endpoint (by avg latency)
avg by (endpoint) (rate(vault_api_request_duration_seconds_sum[5m]) / rate(vault_api_request_duration_seconds_count[5m]))
```

**Filtering Tips:**
```promql
# Exclude favicon requests from all queries
{endpoint!="/favicon.ico"}

# Only successful requests
{status="200"}

# Only errors
{status=~"4..|5.."}

# Specific user
{user_id="alice"}

# Multiple users
{user_id=~"alice|bob"}
```

**Using these queries:**
1. In Grafana, create a new panel or edit an existing one
2. Click **Code** mode in the query editor
3. Paste any query from above
4. Adjust the time range `[1m]`, `[5m]`, `[1h]` as needed
5. Click **Apply** to see results

---

### Practice Exercises

**Exercise 1: Create a "Security Overview" Dashboard**

Build a single-screen dashboard that shows:
1. Total requests in last 24 hours (Stat panel)
2. Current error rate (Gauge panel)
3. Request rate trend (Time series panel)
4. Top 5 users by request count (Bar chart)

**Exercise 2: Investigate an Incident**

1. Generate an anomaly: Use the rapid flood script from Step 6 (80 requests in quick succession)
2. In Grafana: Note the exact time the spike occurred
3. In Kibana: Search for logs from that time period
4. Filter by `user_id: "eve"` and `outcome: "DENIED"`
5. Count how many requests were blocked
6. Optional: Keep `generate-traffic.sh` running in the background for continuous data flow

**Exercise 3: Custom Alert**

Create an alert that fires when any user makes more than 100 requests in 5 minutes:
```promql
sum by (user_id) (rate(vault_api_requests_total[5m]) * 300) > 100
```

**Exercise 4: Filter Out Noise**

Some metrics include `/favicon.ico` and `/metrics` endpoints. Create a clean dashboard that excludes these:
```promql
rate(vault_api_requests_total{endpoint!~"/favicon.ico|/metrics"}[1m])
```

---

**What this teaches you:** Detection is the difference between discovering a breach in real time (minutes of damage) versus discovering it months later (millions of dollars of damage). The Prometheus alert rules are your tripwires. Grafana is the screen that lights up when one is triggered. Kibana is the forensic layer — once the alert fires, you come here to read the full story of what happened.

---

## Pillar 6: Response — Act and Adapt

### The Concept

Response is what you do when detection fires an alert. It has two phases:

**Immediate response**: Stop the bleeding. Revoke access, isolate the affected system, preserve evidence. Speed is everything — every minute a breach continues, more data is exfiltrated.

**Root Cause Analysis (RCA)**: After containment, determine why it happened. Was it a known vulnerability? A misconfiguration? A zero-day? The answer determines how you fix the governance rules (Pillar 1) to prevent recurrence.

This is why the 6 pillars are described as a **virtuous cycle**, not a linear process. The response to yesterday's breach defines the governance of tomorrow's architecture.

### The Real World: The RCA Pipeline

Every mature security team runs the same five-step process after an incident:

| Step | Name | What happens |
|---|---|---|
| 1 | Alert | Prometheus fires. On-call engineer is paged. |
| 2 | Triage | Assess severity. Is this exfiltration or a noisy test? Contain the breach. |
| 3 | Mitigate | Execute the runbook: revoke access, restore from backup if needed. |
| 4 | Investigate (RCA) | Determine root cause. Was it a known issue or novel attack? |
| 5 | Update | Rewrite the playbook. Update governance rules. Fix the control that failed. |

**The 3-2-1 Backup Rule** governs step 3:
- **3** copies of the data
- **2** different storage media (e.g., local disk + S3)
- **1** stored offsite (cross-region S3 or air-gapped)

**Velero** is the Kubernetes-native tool that implements this for cluster workloads: it snapshots both Kubernetes resources (YAML manifests) and persistent volumes, shipping encrypted backups to S3.

### The Build

**Part A: Automated Threat Response**

Create `pillar6-response/playbook.py`:

```python
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
```

```bash
python3 pillar6-response/playbook.py
```

**Part B: Kubernetes Disaster Recovery with Velero (Conceptual Runbook)**

Velero is the industry-standard Kubernetes backup tool. The commands below show exactly what the DR runbook looks like, using a local kind cluster.

```bash
# Install kind (Kubernetes in Docker)
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

# Create a local cluster
kind create cluster --name security-blueprint

```bash
# Install Velero CLI
wget https://github.com/vmware-tanzu/velero/releases/download/v1.13.0/velero-v1.13.0-linux-amd64.tar.gz
tar -xvf velero-v1.13.0-linux-amd64.tar.gz
sudo mv velero-v1.13.0-linux-amd64/velero /usr/local/bin/

# Install Velero in the cluster
# Replace YOUR-COMPLIANCE-BUCKET with your actual bucket name
# Replace eu-west-2 with your actual bucket region (check: aws s3api get-bucket-location --bucket YOUR-BUCKET)
velero install \
  --provider aws \
  --plugins velero/velero-plugin-for-aws:v1.9.0 \
  --bucket YOUR-COMPLIANCE-BUCKET \
  --backup-location-config region=eu-west-2 \
  --use-volume-snapshots=false \
  --secret-file ~/.aws/credentials

# Wait for Velero to be ready and backup location to show Available
kubectl rollout status deployment/velero -n velero
sleep 60
velero backup-location get
# PHASE must show Available before continuing — if Unavailable, check:
# kubectl logs deployment/velero -n velero | grep -i error | tail -20

# DR Runbook — Step 1: Schedule daily backups at 2am
velero schedule create daily-backup \
  --schedule="0 2 * * *" \
  --ttl 720h  # 30-day retention

# DR Runbook — Step 2: Create workload and take an emergency backup
kubectl create namespace production
kubectl create deployment vault-api --image=nginx --namespace=production
kubectl get pods -n production  # should show nginx pod

velero backup create emergency-save-v2 --include-namespaces production
velero backup get  # wait until STATUS shows: Completed

# DR Runbook — Step 3: Simulate disaster
kubectl delete namespace production
kubectl get namespace production  # should return: Error from server (NotFound)

# DR Runbook — Step 4: Restore from backup
velero restore create --from-backup emergency-save-v2 --include-namespaces production

# Check restore status
velero restore get
velero restore describe emergency-save-v2  # wait until Phase: Completed

# DR Runbook — Step 5: Validate recovery
kubectl get pods -n production          # pods should be running
kubectl get svc -n production           # services should have endpoints
kubectl rollout status deployment/vault-api -n production

echo "Recovery validated. RTO met."

# Teardown the kind cluster
kind delete cluster --name security-blueprint
```

**What this teaches you:** The response pillar is where you prove that all the other pillars work under pressure. The Velero runbook is not something you read when disaster strikes — it is something you practice monthly in a dry run, measuring actual RTO against your SLA. "Backup is easy. Restore is where you prove it works."

---

## Putting It All Together: The Virtuous Cycle in Action

Run the entire pipeline:

```bash
# Terminal 1: Start infrastructure
docker-compose -f infra/docker/docker-compose.yml up -d
cd observability && docker-compose up -d

# Terminal 2: Start the API
source env/bin/activate
uvicorn api.main:app --reload --port 8000 --host 0.0.0.0

# Terminal 3: Run discovery
python3 pillar2-discovery/scanner.py

# Terminal 4: Simulate an attack — flood the API as user 'eve'
for i in $(seq 1 60); do
  curl -s -X POST http://localhost:8000/data \
    -H "Content-Type: application/json" \
    -d '{"user_id": "eve", "data": "test"}' > /dev/null
done

# Watch Prometheus alert fire: http://localhost:9090/alerts
# Watch Grafana anomaly panel spike: http://localhost:3000
# Watch the playbook respond:
python3 pillar6-response/playbook.py

# Generate the compliance report
python3 pillar4_compliance/audit_trail.py
```

---

## TEARDOWN: Remove All Cloud Resources

Run this after every practice session.

### Step 1: Stop local Docker stacks

```bash
cd observability
docker-compose down -v

cd ../infra/docker
docker-compose down -v

# Remove all unused images and volumes
docker system prune -af --volumes
```

### Step 2: Delete the Cloudflare Worker

```bash
cd security-blueprint/worker
wrangler delete security-blueprint
# Confirm when prompted
```

Verify: Cloudflare dashboard > Workers & Pages > no `security-blueprint` entry.

### Step 3: Delete the AWS S3 bucket

```bash
# Replace with your actual bucket name (saved from Pillar 4)
BUCKET="security-blueprint-compliance-TIMESTAMP"

# Step 3a: Delete all object versions (S3 versioning keeps them otherwise)
aws s3api delete-objects \
  --bucket $BUCKET \
  --delete "$(aws s3api list-object-versions \
    --bucket $BUCKET \
    --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' \
    --output json 2>/dev/null)" 2>/dev/null || true

# Step 3b: Delete all delete markers
aws s3api delete-objects \
  --bucket $BUCKET \
  --delete "$(aws s3api list-object-versions \
    --bucket $BUCKET \
    --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' \
    --output json 2>/dev/null)" 2>/dev/null || true

# Step 3c: Final recursive delete and bucket removal
aws s3 rm s3://$BUCKET --recursive
aws s3api delete-bucket --bucket $BUCKET --region eu-west-2

# Verify
aws s3 ls | grep security-blueprint
# Should return nothing
```

### Step 4: Verify AWS billing is clean

```bash
# Check for any remaining S3 buckets you created
aws s3 ls

# Check for any IAM users created during this project
aws iam list-users --query 'Users[*].UserName'

# Check for any IAM policies you created
aws iam list-policies --scope Local --query 'Policies[*].PolicyName'
```

Then log into the AWS Console:
1. Billing > Bills — confirm $0.00 charges
2. Set a budget alert: Billing > Budgets > Create Budget > $1 monthly threshold

### Step 5: Clean local files

```bash
cd security-blueprint
rm -rf .keyvault pillar6-response/revoked_users.json \
       pillar4_compliance/audit.jsonl pillar6-response/incidents.jsonl \
       discovery_report.json compliance_report.json \
       env __pycache__ .wrangler
```

---

## What You Have Built and Learned

| Pillar | What you built | What you can now explain |
|---|---|---|
| Governance | Data classification matrix + policy engine | Why policy must precede implementation |
| Discovery | Database and filesystem scanner | How DLP tools find hidden sensitive data |
| Protection | AES-256-GCM encryption + key rotation | The difference between data at rest vs in transit |
| Compliance | Hash-chained audit log + S3 lifecycle rules | How to prove controls to an auditor |
| Detection | Prometheus + Grafana + ELK + anomaly detection | How SIEM tools work and what they alert on |
| Response | Dynamic playbook + Velero DR runbook + RCA | How to contain a breach and prevent recurrence |

### Interview-Ready Answers

**"How do you approach data security?"**
Security is a virtuous cycle. I start with governance — classifying data by sensitivity tier, which drives every downstream decision. Discovery runs continuously to find what actually exists versus what we think exists. Protection applies encryption at rest for Confidential+ data using AES-256-GCM with key rotation, and TLS in transit via Cloudflare. Compliance generates tamper-evident audit trails with hash chaining and automated S3 lifecycle deletion. Detection watches for anomalies using Prometheus and Grafana, shipping logs to Elasticsearch for SIEM-style triage. And response triggers automated playbooks that revoke access within milliseconds and generate RCA reports that feed back into governance. Each incident makes the next architecture stronger.

**"What is the difference between encryption at rest and in transit?"**
At rest means the data is stored encrypted on disk or in a database. Even if someone steals the storage medium, they see ciphertext. I implement this with AES-256-GCM at the application layer. In transit means data is encrypted as it travels across a network, preventing man-in-the-middle interception. This is TLS — the same protocol as HTTPS. At Cloudflare's edge, every request is TLS-terminated before it touches the origin server, so the origin IP is never exposed directly.

**"Walk me through how you would perform Root Cause Analysis after a breach."**
Five steps: Alert fires in Prometheus, on-call is paged via PagerDuty. Triage assesses severity — is this exfiltration or a noisy test? If confirmed, contain by revoking access via the playbook. Mitigate by restoring from the most recent Velero backup to meet RTO targets, validating with kubectl checks on pod health and service endpoints. Investigate to determine root cause — first-of-a-kind vulnerability, known issue, or misconfiguration? Then update: rewrite the playbook, update the governance classification matrix, close the control gap. The RCA output feeds directly back into Pillar 1.

---

*Stack: Python · FastAPI · Cloudflare Workers · AWS S3 · PostgreSQL · Redis · Prometheus · Grafana · Elasticsearch · Kibana · Velero · Docker · AES-256-GCM · JWT*
