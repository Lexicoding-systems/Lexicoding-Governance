"""Tests for cryptographic functions."""

import pytest
from core.crypto import (
    generate_keypair,
    serialize_public_key,
    serialize_private_key,
    deserialize_public_key,
    deserialize_private_key,
    sign_message,
    verify_signature,
    hash_data,
    hash_block,
    derive_key,
    derive_node_id,
    generate_nonce,
    constant_time_compare,
)


class TestKeypairGeneration:
    """Test Ed25519 keypair generation."""
    
    def test_generate_keypair(self):
        """Test that keypair generation produces valid keys."""
        private_key, public_key = generate_keypair()
        
        # Serialize keys
        private_bytes = serialize_private_key(private_key)
        public_bytes = serialize_public_key(public_key)
        
        # Check sizes
        assert len(private_bytes) == 32, "Private key should be 32 bytes"
        assert len(public_bytes) == 32, "Public key should be 32 bytes"
    
    def test_keypair_uniqueness(self):
        """Test that each keypair is unique."""
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        
        pub1_bytes = serialize_public_key(pub1)
        pub2_bytes = serialize_public_key(pub2)
        
        assert pub1_bytes != pub2_bytes, "Each keypair should be unique"
    
    def test_key_serialization_roundtrip(self):
        """Test that keys can be serialized and deserialized."""
        private_key, public_key = generate_keypair()
        
        # Serialize
        private_bytes = serialize_private_key(private_key)
        public_bytes = serialize_public_key(public_key)
        
        # Deserialize
        restored_private = deserialize_private_key(private_bytes)
        restored_public = deserialize_public_key(public_bytes)
        
        # Check they work the same
        assert serialize_private_key(restored_private) == private_bytes
        assert serialize_public_key(restored_public) == public_bytes


class TestDigitalSignatures:
    """Test Ed25519 digital signatures."""
    
    def test_sign_and_verify(self, keypair):
        """Test signing and verifying a message."""
        private_key, public_key = keypair
        
        message = {"type": "test", "data": "example"}
        
        # Sign message
        signature = sign_message(message, private_key)
        
        # Verify signature
        assert len(signature) == 64, "Signature should be 64 bytes"
        assert verify_signature(message, signature, public_key)
    
    def test_invalid_signature_rejected(self, keypair):
        """Test that invalid signatures are rejected."""
        private_key, public_key = keypair
        
        message = {"type": "test"}
        signature = sign_message(message, private_key)
        
        # Modify message
        tampered_message = {"type": "test", "extra": "field"}
        
        # Verify should fail
        assert not verify_signature(tampered_message, signature, public_key)
    
    def test_wrong_key_rejected(self):
        """Test that signature from wrong key is rejected."""
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()
        
        message = {"type": "test"}
        signature = sign_message(message, priv1)
        
        # Verify with different public key should fail
        assert not verify_signature(message, signature, pub2)


class TestHashFunctions:
    """Test SHA256 hash functions."""
    
    def test_hash_data(self):
        """Test that hash_data produces correct output."""
        data = b"test data"
        hash_result = hash_data(data)
        
        assert len(hash_result) == 32, "SHA256 should produce 32 bytes"
    
    def test_hash_deterministic(self):
        """Test that hashing is deterministic."""
        data = b"test data"
        hash1 = hash_data(data)
        hash2 = hash_data(data)
        
        assert hash1 == hash2, "Hash should be deterministic"
    
    def test_hash_block(self):
        """Test hash_block function."""
        previous_hash = bytes(32)  # All zeros
        data = {"test": "data"}
        timestamp = 1234567890
        
        block_hash = hash_block(previous_hash, data, timestamp)
        
        assert len(block_hash) == 32, "Block hash should be 32 bytes"
    
    def test_hash_block_different_for_different_data(self):
        """Test that different data produces different hashes."""
        previous_hash = bytes(32)
        timestamp = 1234567890
        
        hash1 = hash_block(previous_hash, {"data": "1"}, timestamp)
        hash2 = hash_block(previous_hash, {"data": "2"}, timestamp)
        
        assert hash1 != hash2, "Different data should produce different hashes"


class TestKeyDerivation:
    """Test HKDF key derivation."""
    
    def test_derive_key(self):
        """Test key derivation."""
        master_key = b"master_key_material_for_testing_purposes"
        info = b"purpose_specific_info"
        
        derived = derive_key(master_key, info, length=32)
        
        assert len(derived) == 32, "Derived key should have requested length"
    
    def test_derived_keys_different_for_different_info(self):
        """Test that different info produces different keys."""
        master_key = b"master_key_material"
        
        key1 = derive_key(master_key, b"purpose1")
        key2 = derive_key(master_key, b"purpose2")
        
        assert key1 != key2, "Different info should produce different keys"
    
    def test_derive_key_deterministic(self):
        """Test that key derivation is deterministic."""
        master_key = b"master_key_material"
        info = b"purpose"
        
        key1 = derive_key(master_key, info)
        key2 = derive_key(master_key, info)
        
        assert key1 == key2, "Key derivation should be deterministic"


class TestNodeIdentity:
    """Test node ID derivation."""
    
    def test_derive_node_id(self, keypair):
        """Test node ID derivation from public key."""
        _, public_key = keypair
        public_bytes = serialize_public_key(public_key)
        
        node_id = derive_node_id(public_bytes)
        
        assert node_id.startswith("node_"), "Node ID should start with 'node_'"
        assert len(node_id) == 21, "Node ID should be 'node_' + 16 hex chars"
    
    def test_node_id_deterministic(self, keypair):
        """Test that node ID is deterministic."""
        _, public_key = keypair
        public_bytes = serialize_public_key(public_key)
        
        node_id1 = derive_node_id(public_bytes)
        node_id2 = derive_node_id(public_bytes)
        
        assert node_id1 == node_id2, "Node ID should be deterministic"


class TestNonceGeneration:
    """Test secure nonce generation."""
    
    def test_generate_nonce(self):
        """Test nonce generation."""
        nonce = generate_nonce()
        
        assert len(nonce) == 16, "Nonce should be 16 bytes"
    
    def test_nonces_unique(self):
        """Test that nonces are unique."""
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        
        assert nonce1 != nonce2, "Nonces should be unique"


class TestConstantTimeComparison:
    """Test constant-time comparison."""
    
    def test_constant_time_compare_equal(self):
        """Test comparison of equal byte strings."""
        data = b"test data"
        
        assert constant_time_compare(data, data)
    
    def test_constant_time_compare_not_equal(self):
        """Test comparison of different byte strings."""
        data1 = b"test data 1"
        data2 = b"test data 2"
        
        assert not constant_time_compare(data1, data2)
