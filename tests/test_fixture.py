#!/usr/bin/env python3
"""
Fixture generator for creating a valid 50-record chain with test keypair.
This is used for acceptance testing of the verifier.
"""

import json
import sqlite3
import sys
from hashlib import sha256
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_keypair():
    """Generate Ed25519 keypair and save to files."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Save private key
    with open('test_private.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key in PEM format
    with open('test_public.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    # Also save public key in hex format for easier use
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    with open('test_public.hex', 'w') as f:
        f.write(pub_bytes.hex())
    
    return private_key, public_key


def canonicalise_and_hash(record):
    """
    Canonicalise a record dict and compute its SHA-256 hash.
    """
    obj = {k: v for k, v in record.items() if k not in ('record_hash', 'signature')}
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    hash_bytes = sha256(serialized).digest()
    return hash_bytes.hex()


def sign_record(record_hash_hex, private_key):
    """
    Sign the record hash with Ed25519 private key.
    """
    record_hash_bytes = bytes.fromhex(record_hash_hex)
    signature_bytes = private_key.sign(record_hash_bytes)
    return signature_bytes.hex()


def create_database():
    """Create SQLite database with records table."""
    conn = sqlite3.connect('test_fixture.db')
    cursor = conn.cursor()
    
    # Drop table if exists to start fresh
    cursor.execute('DROP TABLE IF EXISTS records')
    
    cursor.execute('''
        CREATE TABLE records (
            seq INTEGER PRIMARY KEY,
            type TEXT,
            ts TEXT,
            model_id TEXT,
            model_digest TEXT,
            node_id TEXT,
            node_region TEXT,
            policy_id TEXT,
            policy_hash TEXT,
            approval_ref TEXT,
            mode TEXT,
            decision TEXT,
            rule_hits TEXT,
            input_hash TEXT,
            output_hash TEXT,
            prev_hash TEXT,
            record_hash TEXT,
            signature TEXT
        )
    ''')
    
    conn.commit()
    return conn


def generate_record(seq, prev_hash, private_key, timestamp):
    """Generate a single valid record."""
    record = {
        'seq': seq,
        'type': 'inference',
        'ts': timestamp,
        'model_id': 'llama-3.2-3b-instruct',
        'model_digest': 'sha256:abc123def4567890123456789012345678901234567890123456789012345678',
        'node_id': 'auh-node-01',
        'node_region': 'AE-AZ',
        'policy_id': 'gov-assistant',
        'policy_hash': 'a' * 64,
        'approval_ref': 'APR-0147',
        'mode': 'record',
        'decision': 'allow',
        'rule_hits': '[]',
        'input_hash': 'b' * 64,
        'output_hash': 'c' * 64,
        'prev_hash': prev_hash
    }
    
    # Compute record hash
    record_hash = canonicalise_and_hash(record)
    record['record_hash'] = record_hash
    
    # Sign the record
    signature = sign_record(record_hash, private_key)
    record['signature'] = signature
    
    return record


def generate_fixture(num_records=50):
    """Generate a fixture database with valid record chain."""
    print(f"Generating {num_records} record fixture...")
    
    # Generate keypair
    private_key, public_key = generate_keypair()
    print("Generated Ed25519 keypair")
    
    # Create database
    conn = create_database()
    cursor = conn.cursor()
    
    prev_hash = '0' * 64
    base_time = datetime(2026, 9, 25, 10, 0, 0, tzinfo=timezone.utc)
    
    for seq in range(1, num_records + 1):
        # Generate timestamp for each record (1 second apart)
        timestamp = (base_time.replace(second=seq % 60, minute=(base_time.minute + seq // 60) % 60,
                                     hour=(base_time.hour + seq // 3600) % 24)).isoformat()
        
        record = generate_record(seq, prev_hash, private_key, timestamp)
        
        # Insert into database
        cursor.execute('''
            INSERT INTO records VALUES (
                :seq, :type, :ts, :model_id, :model_digest, :node_id, :node_region,
                :policy_id, :policy_hash, :approval_ref, :mode, :decision, :rule_hits,
                :input_hash, :output_hash, :prev_hash, :record_hash, :signature
            )
        ''', record)
        
        prev_hash = record['record_hash']
        
        if seq % 10 == 0:
            print(f"Generated {seq} records...")
    
    conn.commit()
    conn.close()
    
    print(f"Fixture generation complete: {num_records} records in test_fixture.db")
    print("Keys saved as test_private.pem and test_public.pem")
    print("Public key also saved as test_public.hex")


if __name__ == '__main__':
    num_records = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    generate_fixture(num_records)
