"""Immutable hash chain implementation for audit trails.

This module implements a tamper-evident hash chain where each block contains
the hash of the previous block, creating an immutable audit trail.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import time

from ..core.crypto import hash_block, hash_data


@dataclass
class Block:
    """A block in the hash chain.
    
    Each block contains:
    - Block number (sequential)
    - Timestamp
    - Data (audit record)
    - Hash of previous block
    - Hash of this block
    
    Attributes:
        block_number: Sequential block number (0 for genesis)
        timestamp: Unix timestamp when block was created
        data: Block data (typically an audit record)
        previous_hash: SHA256 hash of previous block (32 bytes)
        block_hash: SHA256 hash of this block (32 bytes)
    """
    
    block_number: int
    timestamp: int
    data: Dict[str, Any]
    previous_hash: bytes
    block_hash: bytes
    
    def __post_init__(self):
        """Validate block structure."""
        if len(self.previous_hash) != 32:
            raise ValueError("Previous hash must be 32 bytes")
        if len(self.block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")


class HashChain:
    """Immutable hash chain for audit trail.
    
    The hash chain creates a tamper-evident data structure where:
    - Each block contains a hash of the previous block
    - Any modification to a block invalidates all subsequent blocks
    - The chain can be verified to detect tampering
    
    Example:
        >>> chain = HashChain()
        >>> 
        >>> # Add audit records
        >>> block1 = chain.add_block({"decision": "approved"})
        >>> block2 = chain.add_block({"decision": "rejected"})
        >>> 
        >>> # Verify chain integrity
        >>> assert chain.verify_chain()
        >>> 
        >>> # Query blocks
        >>> block = chain.get_block(1)
    """
    
    def __init__(self):
        """Initialize a new hash chain with genesis block."""
        self.blocks: List[Block] = []
        self._create_genesis_block()
    
    def _create_genesis_block(self):
        """Create the genesis (first) block in the chain."""
        genesis_data = {
            "type": "genesis",
            "message": "VARX Protocol Audit Trail Genesis Block"
        }
        
        # Genesis block has no previous block (all zeros)
        previous_hash = bytes(32)
        
        # Calculate genesis block hash
        timestamp = int(time.time())
        block_hash = hash_block(previous_hash, genesis_data, timestamp)
        
        genesis_block = Block(
            block_number=0,
            timestamp=timestamp,
            data=genesis_data,
            previous_hash=previous_hash,
            block_hash=block_hash
        )
        
        self.blocks.append(genesis_block)
        print(f"Hash chain initialized with genesis block")
    
    def add_block(self, data: Dict[str, Any]) -> Block:
        """Add a new block to the chain.
        
        Args:
            data: Block data (typically an audit record)
            
        Returns:
            The newly created block
            
        Example:
            >>> chain = HashChain()
            >>> audit_record = {
            ...     "audit_id": "audit_123",
            ...     "decision": "approved"
            ... }
            >>> block = chain.add_block(audit_record)
            >>> print(f"Block {block.block_number} added")
        """
        # Get previous block
        previous_block = self.blocks[-1]
        
        # Create new block
        block_number = len(self.blocks)
        timestamp = int(time.time())
        previous_hash = previous_block.block_hash
        
        # Calculate block hash
        block_hash = hash_block(previous_hash, data, timestamp)
        
        new_block = Block(
            block_number=block_number,
            timestamp=timestamp,
            data=data,
            previous_hash=previous_hash,
            block_hash=block_hash
        )
        
        self.blocks.append(new_block)
        
        return new_block
    
    def get_block(self, block_number: int) -> Optional[Block]:
        """Retrieve a block by number.
        
        Args:
            block_number: Block number to retrieve
            
        Returns:
            Block if found, None otherwise
        """
        if 0 <= block_number < len(self.blocks):
            return self.blocks[block_number]
        return None
    
    def get_latest_block(self) -> Block:
        """Get the most recent block in the chain.
        
        Returns:
            The latest block
        """
        return self.blocks[-1]
    
    def verify_block(self, block_number: int) -> bool:
        """Verify the integrity of a specific block.
        
        This checks that the block's hash is correctly computed from its
        contents and previous block hash.
        
        Args:
            block_number: Block number to verify
            
        Returns:
            True if block is valid, False otherwise
        """
        if block_number >= len(self.blocks):
            return False
        
        block = self.blocks[block_number]
        
        # Recompute block hash
        computed_hash = hash_block(
            block.previous_hash,
            block.data,
            block.timestamp
        )
        
        # Compare with stored hash
        return computed_hash == block.block_hash
    
    def verify_chain(self) -> bool:
        """Verify the integrity of the entire chain.
        
        This checks:
        - Each block's hash is correctly computed
        - Each block's previous_hash matches the previous block's hash
        - Block numbers are sequential
        
        Returns:
            True if chain is valid, False if any block is invalid
        """
        if not self.blocks:
            return False
        
        # Verify genesis block
        if not self.verify_block(0):
            return False
        
        # Verify each subsequent block
        for i in range(1, len(self.blocks)):
            block = self.blocks[i]
            previous_block = self.blocks[i - 1]
            
            # Check block number is sequential
            if block.block_number != i:
                return False
            
            # Check previous hash matches
            if block.previous_hash != previous_block.block_hash:
                return False
            
            # Verify block hash
            if not self.verify_block(i):
                return False
        
        return True
    
    def get_chain_length(self) -> int:
        """Get the number of blocks in the chain.
        
        Returns:
            Number of blocks (including genesis)
        """
        return len(self.blocks)
    
    def get_merkle_root(self, block_numbers: Optional[List[int]] = None) -> bytes:
        """Calculate Merkle root for a set of blocks.
        
        This creates a Merkle tree from block hashes and returns the root.
        Useful for efficient verification of multiple blocks.
        
        Args:
            block_numbers: List of block numbers to include (None = all blocks)
            
        Returns:
            32-byte Merkle root hash
        """
        if block_numbers is None:
            block_numbers = list(range(len(self.blocks)))
        
        # Get hashes for specified blocks
        hashes = [
            self.blocks[i].block_hash
            for i in block_numbers
            if i < len(self.blocks)
        ]
        
        if not hashes:
            return bytes(32)
        
        return self._compute_merkle_root(hashes)
    
    def _compute_merkle_root(self, hashes: List[bytes]) -> bytes:
        """Compute Merkle root from a list of hashes.
        
        Args:
            hashes: List of 32-byte hashes
            
        Returns:
            Merkle root hash
        """
        if len(hashes) == 1:
            return hashes[0]
        
        # Pair up hashes and hash the pairs
        next_level = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                # Hash the pair
                combined = hash_data(hashes[i] + hashes[i + 1])
            else:
                # Odd one out, promote to next level
                combined = hashes[i]
            next_level.append(combined)
        
        # Recursively compute root
        return self._compute_merkle_root(next_level)
    
    def export_chain(self) -> List[Dict[str, Any]]:
        """Export the chain as a list of dictionaries.
        
        Useful for serialization and storage.
        
        Returns:
            List of block dictionaries
        """
        return [
            {
                "block_number": block.block_number,
                "timestamp": block.timestamp,
                "data": block.data,
                "previous_hash": block.previous_hash.hex(),
                "block_hash": block.block_hash.hex()
            }
            for block in self.blocks
        ]
    
    def get_verification_proof(
        self,
        block_number: int
    ) -> Optional[Dict[str, Any]]:
        """Generate a cryptographic proof for a block's validity.
        
        Args:
            block_number: Block to generate proof for
            
        Returns:
            Verification proof dictionary or None if block not found
        """
        if block_number >= len(self.blocks):
            return None
        
        block = self.blocks[block_number]
        
        # Generate Merkle path (simplified)
        merkle_root = self.get_merkle_root()
        
        return {
            "block_number": block_number,
            "block_hash": block.block_hash.hex(),
            "previous_hash": block.previous_hash.hex(),
            "merkle_root": merkle_root.hex(),
            "chain_valid": self.verify_chain(),
            "block_valid": self.verify_block(block_number)
        }
