"""Tests for hash chain implementation."""

import pytest
from audit.hash_chain import HashChain, Block


class TestHashChain:
    """Test hash chain functionality."""
    
    def test_chain_initialization(self):
        """Test that chain is initialized with genesis block."""
        chain = HashChain()
        
        assert chain.get_chain_length() == 1, "Chain should start with genesis block"
        
        genesis = chain.get_block(0)
        assert genesis is not None
        assert genesis.block_number == 0
        assert genesis.data["type"] == "genesis"
    
    def test_add_block(self):
        """Test adding blocks to the chain."""
        chain = HashChain()
        
        data1 = {"audit_id": "audit_1", "decision": "approved"}
        block1 = chain.add_block(data1)
        
        assert block1.block_number == 1
        assert block1.data == data1
        assert chain.get_chain_length() == 2
    
    def test_block_linking(self):
        """Test that blocks are properly linked."""
        chain = HashChain()
        
        block1 = chain.add_block({"data": "1"})
        block2 = chain.add_block({"data": "2"})
        
        # Block 2's previous_hash should match block 1's hash
        assert block2.previous_hash == block1.block_hash
    
    def test_verify_block(self):
        """Test verifying individual blocks."""
        chain = HashChain()
        
        chain.add_block({"data": "test"})
        
        # Verify both genesis and new block
        assert chain.verify_block(0), "Genesis block should verify"
        assert chain.verify_block(1), "New block should verify"
    
    def test_verify_chain(self):
        """Test verifying entire chain."""
        chain = HashChain()
        
        # Add multiple blocks
        for i in range(5):
            chain.add_block({"data": f"block_{i}"})
        
        assert chain.verify_chain(), "Chain should be valid"
    
    def test_tampered_block_detected(self):
        """Test that tampering with a block is detected."""
        chain = HashChain()
        
        block1 = chain.add_block({"data": "original"})
        chain.add_block({"data": "block2"})
        
        # Tamper with block 1's data
        block1.data["data"] = "tampered"
        
        # Verification should fail
        assert not chain.verify_chain(), "Tampering should be detected"
    
    def test_get_latest_block(self):
        """Test getting the latest block."""
        chain = HashChain()
        
        block1 = chain.add_block({"data": "1"})
        block2 = chain.add_block({"data": "2"})
        
        latest = chain.get_latest_block()
        assert latest.block_number == block2.block_number
        assert latest.data == block2.data
    
    def test_get_nonexistent_block(self):
        """Test getting a block that doesn't exist."""
        chain = HashChain()
        
        block = chain.get_block(999)
        assert block is None
    
    def test_merkle_root(self):
        """Test Merkle root calculation."""
        chain = HashChain()
        
        # Add some blocks
        for i in range(4):
            chain.add_block({"data": f"block_{i}"})
        
        merkle_root = chain.get_merkle_root()
        
        assert len(merkle_root) == 32, "Merkle root should be 32 bytes"
    
    def test_export_chain(self):
        """Test exporting chain as dictionaries."""
        chain = HashChain()
        
        chain.add_block({"data": "test1"})
        chain.add_block({"data": "test2"})
        
        exported = chain.export_chain()
        
        assert len(exported) == 3, "Should have 3 blocks (genesis + 2)"
        assert all("block_number" in block for block in exported)
        assert all("block_hash" in block for block in exported)
    
    def test_verification_proof(self):
        """Test generating verification proof for a block."""
        chain = HashChain()
        
        block1 = chain.add_block({"data": "test"})
        
        proof = chain.get_verification_proof(1)
        
        assert proof is not None
        assert proof["block_number"] == 1
        assert proof["chain_valid"] == True
        assert proof["block_valid"] == True


class TestBlock:
    """Test Block data structure."""
    
    def test_block_creation(self):
        """Test creating a block."""
        block = Block(
            block_number=1,
            timestamp=1234567890,
            data={"test": "data"},
            previous_hash=bytes(32),
            block_hash=bytes(32)
        )
        
        assert block.block_number == 1
        assert block.data == {"test": "data"}
    
    def test_block_validation_invalid_hash_size(self):
        """Test that invalid hash sizes are rejected."""
        with pytest.raises(ValueError):
            Block(
                block_number=1,
                timestamp=1234567890,
                data={},
                previous_hash=b"too_short",  # Not 32 bytes
                block_hash=bytes(32)
            )
