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