"""VARX Protocol message definitions.

This module defines the core message types and data structures used in the
VARX Protocol for governance, decision-making, and audit trail management.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import time


class MessageType(Enum):
    """Types of messages in the VARX Protocol."""
    
    GOVERNANCE_REQUEST = "governance_request"
    GOVERNANCE_DECISION = "governance_decision"
    AUDIT_RECORD = "audit_record"
    AUDIT_ACKNOWLEDGMENT = "audit_acknowledgment"
    AUDIT_QUERY = "audit_query"
    AUDIT_QUERY_RESPONSE = "audit_query_response"
    NODE_REGISTRATION = "node_registration"
    HEARTBEAT = "heartbeat"


class NodeType(Enum):
    """Types of nodes in the VARX Protocol."""
    
    MODEL = "ModelNode"
    VARX = "VARXNode"
    AUDITOR = "AuditorNode"


class DecisionType(Enum):
    """Possible governance decision outcomes."""
    
    APPROVED = "approved"
    APPROVED_WITH_CONDITIONS = "approved_with_conditions"
    REJECTED = "rejected"
    PENDING_HUMAN_REVIEW = "pending_human_review"


class RiskLevel(Enum):
    """Risk levels for governance requests."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NodeIdentity:
    """Identity information for a VARX node.
    
    Attributes:
        node_id: Unique identifier for the node
        node_type: Type of node (Model, VARX, or Auditor)
        public_key: Ed25519 public key (32 bytes)
    """
    
    node_id: str
    node_type: NodeType
    public_key: bytes
    
    def __post_init__(self):
        """Validate node identity."""
        if len(self.public_key) != 32:
            raise ValueError("Public key must be exactly 32 bytes")


@dataclass
class Message:
    """Base message structure for VARX Protocol.
    
    All messages in the protocol inherit from this base structure and include
    cryptographic authentication via Ed25519 signatures.
    
    Attributes:
        protocol_version: VARX protocol version (semver)
        message_type: Type of message being sent
        message_id: Unique identifier for this message
        sender: Identity of the sending node
        timestamp: Unix timestamp when message was created
        nonce: Random nonce for replay protection (16 bytes)
        payload: Message-specific payload data
        signature: Ed25519 signature (64 bytes, set after signing)
    """
    
    protocol_version: str = "1.0.0"
    message_type: MessageType = MessageType.GOVERNANCE_REQUEST
    message_id: str = ""
    sender: Optional[NodeIdentity] = None
    timestamp: int = field(default_factory=lambda: int(time.time()))
    nonce: bytes = b""
    payload: dict[str, Any] = field(default_factory=dict)
    signature: Optional[bytes] = None
    
    def __post_init__(self):
        """Validate message structure."""
        if self.nonce and len(self.nonce) != 16:
            raise ValueError("Nonce must be exactly 16 bytes")
        if self.signature and len(self.signature) != 64:
            raise ValueError("Signature must be exactly 64 bytes")


@dataclass
class ReasoningStep:
    """A single step in an AI reasoning pathway.
    
    Attributes:
        step: Step number in the reasoning sequence
        reasoning: Description of the reasoning at this step
        confidence: Confidence level (0.0 to 1.0)
    """
    
    step: int
    reasoning: str
    confidence: float
    
    def __post_init__(self):
        """Validate reasoning step."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")


@dataclass
class ReasoningPathway:
    """Complete reasoning pathway for a governance request.
    
    Attributes:
        steps: List of reasoning steps
        conclusion: Final conclusion of the reasoning
    """
    
    steps: list[ReasoningStep]
    conclusion: str


@dataclass
class Action:
    """An action requiring governance approval.
    
    Attributes:
        action_type: Type of action (e.g., "data_access", "model_output")
        description: Human-readable description
        parameters: Action-specific parameters
    """
    
    action_type: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class GovernanceRequest:
    """Request for governance decision on an AI action.
    
    This message is sent by a ModelNode to a VARXNode requesting approval
    for a specific action.
    
    Attributes:
        request_id: Unique identifier for this request
        action: The action requiring approval
        reasoning_pathway: AI's reasoning for the action
        risk_level: Assessed risk level
        requested_rule_bundles: List of rule bundles to apply
    """
    
    request_id: str
    action: Action
    reasoning_pathway: ReasoningPathway
    risk_level: RiskLevel
    requested_rule_bundles: list[str] = field(default_factory=list)


@dataclass
class RuleResult:
    """Result of evaluating a single rule.
    
    Attributes:
        rule_bundle: Name of the rule bundle
        rule_id: Identifier of the rule
        result: Whether the rule passed or failed
        details: Optional details about the evaluation
    """
    
    rule_bundle: str
    rule_id: str
    result: str  # "passed", "failed", "skipped"
    details: Optional[str] = None


@dataclass
class DecisionReasoning:
    """Reasoning for a governance decision.
    
    Attributes:
        summary: Brief summary of the decision
        details: Detailed explanation as list of points
        applied_rules: Results of all rules that were evaluated
    """
    
    summary: str
    details: list[str]
    applied_rules: list[RuleResult]


@dataclass
class GovernanceDecision:
    """Response to a governance request.
    
    This message is sent by a VARXNode back to a ModelNode with the
    governance decision.
    
    Attributes:
        request_id: ID of the original request
        decision: The governance decision
        confidence: Confidence in the decision (0.0 to 1.0)
        reasoning: Explanation for the decision
        conditions: List of conditions if decision is conditional
        expires_at: Unix timestamp when decision expires
        decision_metadata: Additional metadata about the decision
    """
    
    request_id: str
    decision: DecisionType
    confidence: float
    reasoning: DecisionReasoning
    conditions: list[str] = field(default_factory=list)
    expires_at: Optional[int] = None
    decision_metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate decision."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")


@dataclass
class AuditRecord:
    """Record of a governance decision for the audit trail.
    
    This message is sent by a VARXNode to an AuditorNode to record a
    governance decision in the immutable audit trail.
    
    Attributes:
        audit_id: Unique identifier for this audit record
        request_id: ID of the governance request
        decision_id: ID of the governance decision
        model_node_id: ID of the model node that made the request
        varx_node_id: ID of the VARX node that made the decision
        decision_summary: Summary of the decision
        full_request: Complete governance request
        full_decision: Complete governance decision
        compliance_tags: Regulatory compliance tags
    """
    
    audit_id: str
    request_id: str
    decision_id: str
    model_node_id: str
    varx_node_id: str
    decision_summary: dict[str, Any]
    full_request: Optional[dict[str, Any]] = None
    full_decision: Optional[dict[str, Any]] = None
    compliance_tags: list[str] = field(default_factory=list)


@dataclass
class AuditAcknowledgment:
    """Acknowledgment that an audit record was added to the hash chain.
    
    Attributes:
        audit_id: ID of the audit record
        block_number: Block number in the hash chain
        block_hash: Hash of the block
        previous_hash: Hash of the previous block
        merkle_root: Merkle root of the block
    """
    
    audit_id: str
    block_number: int
    block_hash: bytes
    previous_hash: bytes
    merkle_root: bytes
    
    def __post_init__(self):
        """Validate acknowledgment."""
        if len(self.block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")
        if len(self.previous_hash) != 32:
            raise ValueError("Previous hash must be 32 bytes")
        if len(self.merkle_root) != 32:
            raise ValueError("Merkle root must be 32 bytes")


def create_message(
    message_type: MessageType,
    sender: NodeIdentity,
    payload: dict[str, Any],
    nonce: bytes,
    message_id: str,
) -> Message:
    """Create a new VARX protocol message.
    
    Args:
        message_type: Type of message to create
        sender: Identity of the sending node
        payload: Message payload
        nonce: Random nonce for replay protection
        message_id: Unique message identifier
        
    Returns:
        A new Message instance ready to be signed
    """
    return Message(
        message_type=message_type,
        sender=sender,
        payload=payload,
        nonce=nonce,
        message_id=message_id,
    )
