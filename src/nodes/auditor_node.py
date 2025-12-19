"""AuditorNode implementation for the VARX Protocol.

The AuditorNode maintains an immutable, tamper-evident audit trail of all
governance decisions using a cryptographic hash chain.
"""

from typing import Optional, Any, List
from dataclasses import dataclass

from .base_node import BaseNode, NodeConfig
from ..core.protocol import Message, MessageType, NodeType
from ..audit.hash_chain import HashChain, Block


class AuditorNode(BaseNode):
    """AuditorNode implementation for audit trail management.
    
    The AuditorNode is responsible for:
    - Receiving audit records from VARXNode
    - Verifying cryptographic signatures on records
    - Adding records to tamper-evident hash chain
    - Providing query interface for audit history
    - Generating compliance reports
    
    Example:
        >>> config = NodeConfig(node_type=NodeType.AUDITOR)
        >>> auditor_node = AuditorNode(config)
        >>> 
        >>> # Process audit record from VARXNode
        >>> response = auditor_node.handle_message(audit_message)
    """
    
    def __init__(self, config: NodeConfig):
        """Initialize the AuditorNode.
        
        Args:
            config: Node configuration (must have node_type=NodeType.AUDITOR)
        """
        if config.node_type != NodeType.AUDITOR:
            raise ValueError("AuditorNode requires node_type=NodeType.AUDITOR")
        
        super().__init__(config)
        
        # Initialize hash chain for audit trail
        self.hash_chain = HashChain()
        
        # Statistics
        self.records_processed = 0
        self.verifications_performed = 0
    
    def handle_message(self, message: Message) -> Optional[Message]:
        """Handle incoming messages (audit records and queries).
        
        Args:
            message: Incoming message
            
        Returns:
            Acknowledgment message for audit records, response for queries
        """
        # Verify message authenticity
        if not self.verify_message(message):
            print(f"AuditorNode {self.node_id}: Invalid message received")
            return None
        
        # Handle audit record
        if message.message_type == MessageType.AUDIT_RECORD:
            return self._handle_audit_record(message)
        
        # Handle audit query
        if message.message_type == MessageType.AUDIT_QUERY:
            return self._handle_audit_query(message)
        
        print(f"AuditorNode {self.node_id}: Unknown message type {message.message_type}")
        return None
    
    def _handle_audit_record(self, message: Message) -> Message:
        """Process an audit record and add to hash chain.
        
        Args:
            message: Audit record message
            
        Returns:
            Audit acknowledgment message
        """
        payload = message.payload
        audit_id = payload.get("audit_id")
        
        print(f"AuditorNode {self.node_id}: Processing audit record {audit_id}")
        
        # Add record to hash chain
        block = self.hash_chain.add_block(payload)
        
        # Update statistics
        self.records_processed += 1
        
        # Create acknowledgment payload
        ack_payload = {
            "audit_id": audit_id,
            "block_number": block.block_number,
            "block_hash": block.block_hash.hex(),
            "previous_hash": block.previous_hash.hex(),
            "merkle_root": block.block_hash.hex(),  # Simplified
            "verification_proof": {
                "hash_chain_valid": self.hash_chain.verify_chain(),
                "signatures_valid": True,
                "merkle_path": []
            }
        }
        
        # Create and sign acknowledgment message
        ack_message = self.create_message(
            MessageType.AUDIT_ACKNOWLEDGMENT,
            ack_payload
        )
        
        print(f"AuditorNode {self.node_id}: Added audit record to block {block.block_number}")
        
        return ack_message
    
    def _handle_audit_query(self, message: Message) -> Message:
        """Process an audit query and return matching records.
        
        Args:
            message: Audit query message
            
        Returns:
            Audit query response message
        """
        payload = message.payload
        query_id = payload.get("query_id")
        filters = payload.get("filters", {})
        
        print(f"AuditorNode {self.node_id}: Processing query {query_id}")
        
        # Query the hash chain
        records = self._query_records(filters)
        
        # Update statistics
        self.verifications_performed += 1
        
        # Create response payload
        response_payload = {
            "query_id": query_id,
            "total_records": len(records),
            "records": records,
            "pagination": {
                "current_page": 1,
                "total_pages": 1,
                "per_page": 100
            },
            "verification": {
                "hash_chain_valid": self.hash_chain.verify_chain(),
                "start_block_hash": self.hash_chain.blocks[0].block_hash.hex() if self.hash_chain.blocks else "",
                "end_block_hash": self.hash_chain.blocks[-1].block_hash.hex() if self.hash_chain.blocks else ""
            }
        }
        
        # Create and sign response message
        response_message = self.create_message(
            MessageType.AUDIT_QUERY_RESPONSE,
            response_payload
        )
        
        print(f"AuditorNode {self.node_id}: Query returned {len(records)} records")
        
        return response_message
    
    def _query_records(self, filters: dict[str, Any]) -> List[dict[str, Any]]:
        """Query audit records based on filters.
        
        Args:
            filters: Query filters (timestamps, node IDs, etc.)
            
        Returns:
            List of matching audit records
        """
        results = []
        
        start_timestamp = filters.get("start_timestamp")
        end_timestamp = filters.get("end_timestamp")
        model_node_id = filters.get("model_node_id")
        decision_type = filters.get("decision_type")
        
        for block in self.hash_chain.blocks:
            # Skip genesis block
            if block.block_number == 0:
                continue
            
            # Apply timestamp filter
            if start_timestamp and block.timestamp < start_timestamp:
                continue
            if end_timestamp and block.timestamp > end_timestamp:
                continue
            
            # Apply node ID filter
            if model_node_id:
                if block.data.get("model_node_id") != model_node_id:
                    continue
            
            # Apply decision type filter
            if decision_type:
                decision_summary = block.data.get("decision_summary", {})
                if decision_summary.get("decision") != decision_type:
                    continue
            
            # Add matching record
            results.append({
                "block_number": block.block_number,
                "audit_id": block.data.get("audit_id"),
                "timestamp": block.timestamp,
                "decision": block.data.get("decision_summary", {}).get("decision"),
                "summary": f"Decision for request {block.data.get('request_id')}"
            })
        
        return results
    
    def verify_block(self, block_number: int) -> dict[str, Any]:
        """Verify the integrity of a specific block.
        
        Args:
            block_number: Block number to verify
            
        Returns:
            Verification result with proof
        """
        if block_number >= len(self.hash_chain.blocks):
            return {
                "valid": False,
                "error": "Block not found"
            }
        
        block = self.hash_chain.blocks[block_number]
        
        # Verify block hash
        is_valid = self.hash_chain.verify_block(block_number)
        
        return {
            "valid": is_valid,
            "block_number": block_number,
            "block_hash": block.block_hash.hex(),
            "previous_hash": block.previous_hash.hex(),
            "timestamp": block.timestamp
        }
    
    def verify_chain_integrity(self) -> dict[str, Any]:
        """Verify the integrity of the entire hash chain.
        
        Returns:
            Verification result for the complete chain
        """
        is_valid = self.hash_chain.verify_chain()
        
        return {
            "chain_valid": is_valid,
            "total_blocks": len(self.hash_chain.blocks),
            "genesis_hash": self.hash_chain.blocks[0].block_hash.hex() if self.hash_chain.blocks else "",
            "latest_hash": self.hash_chain.blocks[-1].block_hash.hex() if self.hash_chain.blocks else ""
        }
    
    def get_status(self) -> dict[str, Any]:
        """Get current AuditorNode status.
        
        Returns:
            Status dictionary including chain statistics
        """
        base_status = super().get_status()
        base_status.update({
            "records_processed": self.records_processed,
            "verifications_performed": self.verifications_performed,
            "chain_length": len(self.hash_chain.blocks),
            "chain_valid": self.hash_chain.verify_chain()
        })
        return base_status
