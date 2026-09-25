#!/usr/bin/env python3
"""
Sijill Verifier CLI - Standalone implementation independent of sijill/ package
Verifies the integrity of the hash-chained record store.
"""

import argparse
import json
import sqlite3
import sys
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def canonicalise_and_hash(record):
    """
    Canonicalise a record dict and compute its SHA-256 hash.
    
    1. Take the record as a JSON object of every field except record_hash and signature
    2. Serialise with keys sorted, separators , and : with no whitespace, non-ASCII preserved, encoded UTF-8
    3. record_hash = lowercase hex SHA-256 of those bytes
    
    Important: seq is serialised as an integer; every other field as a string.
    """
    # Create a copy without record_hash and signature
    obj = {k: v for k, v in record.items() if k not in ('record_hash', 'signature')}
    
    # Serialise with keys sorted, separators , and : with no whitespace
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    
    # Compute SHA-256 hash
    hash_bytes = sha256(serialized).digest()
    return hash_bytes.hex()


def verify_signature(record_hash_hex, signature_hex, public_key):
    """
    Verify Ed25519 signature against the public key.
    
    signature = Ed25519 signature of the 32 raw bytes of record_hash (decode the hex first), hex-encoded
    """
    try:
        # Decode hex strings to bytes
        record_hash_bytes = bytes.fromhex(record_hash_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        
        # Verify signature
        public_key.verify(signature_bytes, record_hash_bytes)
        return True
    except Exception:
        return False


def load_public_key(pubkey_path):
    """Load Ed25519 public key from file."""
    with open(pubkey_path, 'rb') as f:
        key_data = f.read()
    
    # Try PEM format first
    try:
        return serialization.load_pem_public_key(key_data)
    except ValueError:
        # Try raw hex format
        try:
            key_bytes = bytes.fromhex(key_data.decode().strip())
            return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
        except:
            raise ValueError(f"Could not load public key from {pubkey_path}")


def verify_records(db_path, pubkey_path):
    """
    Walk every record in seq order and verify the chain.
    
    Checks in order:
    1. seq is exactly previous + 1 → else FAIL seq=N gap
    2. recomputed hash equals stored record_hash → else FAIL seq=N content altered
    3. prev_hash equals previous record's record_hash → else FAIL seq=N chain broken
    4. signature verifies against the public key → else FAIL seq=N signature invalid
    
    Stops at first failure.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all records in seq order
    cursor.execute("SELECT * FROM records ORDER BY seq ASC")
    rows = cursor.fetchall()
    
    # Get column names
    cursor.execute("PRAGMA table_info(records)")
    columns = [col[1] for col in cursor.fetchall()]
    
    # Load public key
    public_key = load_public_key(pubkey_path)
    
    prev_seq = 0
    prev_record_hash = None
    record_count = 0
    first_ts = None
    last_ts = None
    
    for row in rows:
        record = dict(zip(columns, row))
        seq = record['seq']
        record_count += 1
        
        if first_ts is None:
            first_ts = record['ts']
        last_ts = record['ts']
        
        # Check 1: seq is exactly previous + 1
        if seq != prev_seq + 1:
            print(f"FAIL seq={seq} gap")
            return False
        
        # Check 2: recomputed hash equals stored record_hash
        recomputed_hash = canonicalise_and_hash(record)
        if recomputed_hash != record['record_hash']:
            print(f"FAIL seq={seq} content altered")
            return False
        
        # Check 3: prev_hash equals previous record's record_hash
        if prev_record_hash is not None:
            if record['prev_hash'] != prev_record_hash:
                print(f"FAIL seq={seq} chain broken")
                return False
        else:
            # First record should have 64 zeros as prev_hash
            if record['prev_hash'] != '0' * 64:
                print(f"FAIL seq={seq} chain broken (first record prev_hash not 64 zeros)")
                return False
        
        # Check 4: signature verifies against the public key
        if not verify_signature(record['record_hash'], record['signature'], public_key):
            print(f"FAIL seq={seq} signature invalid")
            return False
        
        prev_seq = seq
        prev_record_hash = record['record_hash']
    
    conn.close()
    
    # All checks passed
    print(f"PASS records={record_count} first={first_ts} last={last_ts}")
    return True


def main():
    parser = argparse.ArgumentParser(description='Verify Sijill record chain integrity')
    parser.add_argument('--db', required=True, help='Path to SQLite database')
    parser.add_argument('--pubkey', required=True, help='Path to Ed25519 public key file')
    
    args = parser.parse_args()
    
    success = verify_records(args.db, args.pubkey)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
