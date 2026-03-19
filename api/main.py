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