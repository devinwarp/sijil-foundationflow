#!/usr/bin/env python3
"""
Acceptance tests for Sijill verifier.
Tests 1-4 as specified in the Build Spec.
"""

import subprocess
import sqlite3
import sys
import os


def run_verifier(db_path, pubkey_path):
    """Run the verifier and return the result."""
    result = subprocess.run(
        ['python', 'verifier/sijill_verify.py', '--db', db_path, '--pubkey', pubkey_path],
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def test_1_valid_chain():
    """Test 1: Seed 50 calls. Verifier passes."""
    print("\n=== Test 1: Valid 50-record chain ===")
    
    # Generate fixture
    print("Generating fixture...")
    subprocess.run(['python', 'tests/test_fixture.py', '50'], check=True)
    
    # Run verifier
    returncode, stdout, stderr = run_verifier('test_fixture.db', 'test_public.hex')
    
    if returncode == 0 and 'PASS' in stdout:
        print("✓ Test 1 PASSED: Verifier passes on valid chain")
        print(f"  Output: {stdout.strip()}")
        return True
    else:
        print("✗ Test 1 FAILED: Verifier should pass on valid chain")
        print(f"  Return code: {returncode}")
        print(f"  Stdout: {stdout}")
        print(f"  Stderr: {stderr}")
        return False


def test_2_content_altered():
    """Test 2: Change output_hash of record 17 with sqlite3. Verifier fails at 17, content altered."""
    print("\n=== Test 2: Content altered (output_hash changed) ===")
    
    # Generate fresh fixture
    print("Generating fresh fixture...")
    subprocess.run(['python', 'tests/test_fixture.py', '50'], check=True)
    
    # Modify record 17's output_hash
    conn = sqlite3.connect('test_fixture.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE records SET output_hash = 'd' * 64 WHERE seq = 17")
    conn.commit()
    conn.close()
    
    # Run verifier
    returncode, stdout, stderr = run_verifier('test_fixture.db', 'test_public.hex')
    
    if returncode == 1 and 'content altered' in stdout and 'seq=17' in stdout:
        print("✓ Test 2 PASSED: Verifier detects content alteration at seq 17")
        print(f"  Output: {stdout.strip()}")
        return True
    else:
        print("✗ Test 2 FAILED: Verifier should detect content alteration at seq 17")
        print(f"  Return code: {returncode}")
        print(f"  Stdout: {stdout}")
        print(f"  Stderr: {stderr}")
        return False


def test_3_signature_invalid():
    """Test 3: Change record 17's content and recompute its hash without the private key. Verifier fails at 17, signature invalid."""
    print("\n=== Test 3: Signature invalid (content changed, hash recomputed without key) ===")
    
    # Generate fresh fixture
    print("Generating fresh fixture...")
    subprocess.run(['python', 'tests/test_fixture.py', '50'], check=True)
    
    # Modify record 17's content and recompute hash without private key
    # This simulates an attacker who understands the hashing but doesn't have the private key
    import json
    from hashlib import sha256
    
    conn = sqlite3.connect('test_fixture.db')
    cursor = conn.cursor()
    
    # Get record 17
    columns = [col[1] for col in cursor.execute("PRAGMA table_info(records)").fetchall()]
    cursor.execute("SELECT * FROM records WHERE seq = 17")
    row = cursor.fetchone()
    record = dict(zip(columns, row))
    
    # Change the model_id (content alteration)
    record['model_id'] = 'fake-model'
    
    # Recompute hash using the canonicalisation algorithm
    obj = {k: v for k, v in record.items() if k not in ('record_hash', 'signature')}
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    new_hash = sha256(serialized).digest().hex()
    
    # Update with new hash but keep old signature (which won't match)
    cursor.execute("UPDATE records SET model_id = ?, record_hash = ? WHERE seq = 17",
                  (record['model_id'], new_hash))
    
    conn.commit()
    conn.close()
    
    # Run verifier
    returncode, stdout, stderr = run_verifier('test_fixture.db', 'test_public.hex')
    
    if returncode == 1 and 'signature invalid' in stdout and 'seq=17' in stdout:
        print("✓ Test 3 PASSED: Verifier detects invalid signature at seq 17")
        print(f"  Output: {stdout.strip()}")
        return True
    else:
        print("✗ Test 3 FAILED: Verifier should detect invalid signature at seq 17")
        print(f"  Return code: {returncode}")
        print(f"  Stdout: {stdout}")
        print(f"  Stderr: {stderr}")
        return False


def test_4_gap():
    """Test 4: Delete record 17. Verifier fails at 18, gap."""
    print("\n=== Test 4: Gap (record 17 deleted) ===")
    
    # Generate fresh fixture
    print("Generating fresh fixture...")
    subprocess.run(['python', 'tests/test_fixture.py', '50'], check=True)
    
    # Delete record 17
    conn = sqlite3.connect('test_fixture.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM records WHERE seq = 17")
    conn.commit()
    conn.close()
    
    # Run verifier
    returncode, stdout, stderr = run_verifier('test_fixture.db', 'test_public.hex')
    
    if returncode == 1 and 'gap' in stdout and 'seq=18' in stdout:
        print("✓ Test 4 PASSED: Verifier detects gap at seq 18")
        print(f"  Output: {stdout.strip()}")
        return True
    else:
        print("✗ Test 4 FAILED: Verifier should detect gap at seq 18")
        print(f"  Return code: {returncode}")
        print(f"  Stdout: {stdout}")
        print(f"  Stderr: {stderr}")
        return False


def cleanup():
    """Clean up test files."""
    files_to_remove = [
        'test_fixture.db',
        'test_private.pem',
        'test_public.pem',
        'test_public.hex'
    ]
    for f in files_to_remove:
        if os.path.exists(f):
            os.remove(f)


def main():
    """Run all acceptance tests."""
    print("=" * 60)
    print("Sijill Verifier Acceptance Tests (Tests 1-4)")
    print("=" * 60)
    
    results = []
    
    try:
        results.append(("Test 1: Valid chain", test_1_valid_chain()))
        results.append(("Test 2: Content altered", test_2_content_altered()))
        results.append(("Test 3: Signature invalid", test_3_signature_invalid()))
        results.append(("Test 4: Gap detection", test_4_gap()))
    finally:
        cleanup()
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    all_passed = True
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("=" * 60)
    
    if all_passed:
        print("All acceptance tests PASSED!")
        return 0
    else:
        print("Some acceptance tests FAILED!")
        return 1


if __name__ == '__main__':
    sys.exit(main())
