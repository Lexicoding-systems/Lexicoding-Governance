"""Base node implementation for the VARX Protocol.

This module provides the abstract base class that all VARX nodes inherit from,
implementing common functionality for message handling, cryptographic operations,
and network communication.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Any
import time

from cryptography.hazmat.primitives.asymmetric import ed25519

from ..core.protocol import Message, MessageType, NodeIdentity, NodeType
from ..core.crypto import (
    generate_keypair,
    serialize_public_key,
    sign_message,
    verify_signature,
    derive_node_id,
    generate_nonce,
)
from ..utils.nonce import NonceValidator


@dataclass
class NodeConfig:
    """Configuration for a VARX node.
    
    Attributes:
        node_type: Type of node (Model, VARX, or Auditor)
        private_key: Optional pre-existing private key (generated if None)
        nonce_validity_window: Time window in seconds for nonce validity (default: 300)
        message_timeout: Maximum age for accepted messages in seconds (default: 300)
    """
    
    node_type: NodeType
    private_key: Optional[ed25519.Ed25519PrivateKey] = None
    nonce_validity_window: int = 300
    message_timeout: int = 300


class BaseNode(ABC):
    """Abstract base class for all VARX Protocol nodes.
    
    This class provides common functionality for:
    - Node identity management
    - Cryptographic signing and verification
    - Message creation and validation
    - Nonce-based replay protection
    
    Attributes:
        config: Node configuration
        private_key: Ed25519 private key for signing
        public_key: Ed25519 public key for identification
        node_id: Unique node identifier derived from public key
        identity: NodeIdentity object for message sending
        nonce_validator: Validator for replay protection
    """
    
    def __init__(self, config: NodeConfig):
        """Initialize the base node.
        
        Args:
            config: Node configuration
        """
        self.config = config
        
        # Generate or use provided keypair
        if config.private_key:
            self.private_key = config.private_key
        else:
            self.private_key, _ = generate_keypair()
        
        self.public_key = self.private_key.public_key()
        
        # Derive node ID from public key
        public_key_bytes = serialize_public_key(self.public_key)
        self.node_id = derive_node_id(public_key_bytes)
        
        # Create node identity
        self.identity = NodeIdentity(
            node_id=self.node_id,
            node_type=config.node_type,
            public_key=public_key_bytes
        )
        
        # Initialize nonce validator for replay protection
        self.nonce_validator = NonceValidator(
            validity_window=config.nonce_validity_window
        )
        
        print(f"{self.config.node_type.value} initialized: {self.node_id}")
    
    def create_message(
        self,
        message_type: MessageType,
        payload: dict[str, Any]
    ) -> Message:
        """Create a new signed message.
        
        Args:
            message_type: Type of message to create
            payload: Message payload
            
        Returns:
            Signed Message object
            
        Example:
            >>> node = ModelNode(NodeConfig(NodeType.MODEL))
            >>> message = node.create_message(
            ...     MessageType.GOVERNANCE_REQUEST,
            ...     {"request_id": "req_123"}
            ... )
        """
        # Generate unique message ID and nonce
        nonce = generate_nonce()
        message_id = f"msg_{nonce[:8].hex()}"
        
        # Create message
        message = Message(
            message_type=message_type,
            message_id=message_id,
            sender=self.identity,
            timestamp=int(time.time()),
            nonce=nonce,
            payload=payload
        )
        
        # Sign the message
        message.signature = self._sign_message(message)
        
        return message
    
    def _sign_message(self, message: Message) -> bytes:
        """Sign a message with the node's private key.
        
        Args:
            message: Message to sign
            
        Returns:
            Ed25519 signature (64 bytes)
        """
        # Create signing data (exclude signature field)
        sign_data = {
            "protocol_version": message.protocol_version,
            "message_type": message.message_type.value,
            "message_id": message.message_id,
            "sender": {
                "node_id": message.sender.node_id,
                "node_type": message.sender.node_type.value,
                "public_key": message.sender.public_key.hex()
            },
            "timestamp": message.timestamp,
            "nonce": message.nonce.hex(),
            "payload": message.payload
        }
        
        return sign_message(sign_data, self.private_key)
    
    def verify_message(self, message: Message) -> bool:
        """Verify a message's cryptographic signature and freshness.
        
        Args:
            message: Message to verify
            
        Returns:
            True if message is valid and fresh, False otherwise
        """
        # Check timestamp is within acceptable window
        current_time = int(time.time())
        time_diff = abs(current_time - message.timestamp)
        if time_diff > self.config.message_timeout:
            print(f"Message rejected: timestamp outside validity window ({time_diff}s)")
            return False
        
        # Validate nonce for replay protection
        if not self.nonce_validator.validate(message.nonce, message.timestamp):
            print(f"Message rejected: invalid or replayed nonce")
            return False
        
        # Verify signature
        from ..core.crypto import deserialize_public_key
        
        try:
            sender_public_key = deserialize_public_key(message.sender.public_key)
            
            # Create verification data (exclude signature)
            verify_data = {
                "protocol_version": message.protocol_version,
                "message_type": message.message_type.value,
                "message_id": message.message_id,
                "sender": {
                    "node_id": message.sender.node_id,
                    "node_type": message.sender.node_type.value,
                    "public_key": message.sender.public_key.hex()
                },
                "timestamp": message.timestamp,
                "nonce": message.nonce.hex(),
                "payload": message.payload
            }
            
            if not verify_signature(verify_data, message.signature, sender_public_key):
                print(f"Message rejected: invalid signature")
                return False
            
            return True
            
        except Exception as e:
            print(f"Message verification error: {e}")
            return False
    
    @abstractmethod
    def handle_message(self, message: Message) -> Optional[Message]:
        """Handle an incoming message.
        
        This method must be implemented by subclasses to define node-specific
        message handling logic.
        
        Args:
            message: Incoming message
            
        Returns:
            Optional response message
        """
        pass
    
    def get_status(self) -> dict[str, Any]:
        """Get current node status.
        
        Returns:
            Status dictionary with node information
        """
        return {
            "node_id": self.node_id,
            "node_type": self.config.node_type.value,
            "status": "operational"
        }
