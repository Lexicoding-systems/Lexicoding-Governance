"""ModelNode implementation for the VARX Protocol.

The ModelNode represents an AI system being governed. It sends governance
requests to the VARXNode for approval before executing actions.
"""

from typing import Optional, Any
from dataclasses import dataclass

from .base_node import BaseNode, NodeConfig
from ..core.protocol import (
    Message,
    MessageType,
    NodeType,
    GovernanceRequest,
    Action,
    ReasoningPathway,
    ReasoningStep,
    RiskLevel,
    GovernanceDecision,
    DecisionType,
)


@dataclass
class PendingRequest:
    """Tracks a pending governance request.
    
    Attributes:
        request_id: Unique identifier for the request
        message: The sent message
        response: Response received (None if pending)
    """
    
    request_id: str
    message: Message
    response: Optional[Message] = None


class ModelNode(BaseNode):
    """ModelNode implementation for AI systems requiring governance.
    
    The ModelNode is responsible for:
    - Creating governance requests for AI actions
    - Signing requests with Ed25519
    - Receiving and processing governance decisions
    - Tracking pending requests
    
    Example:
        >>> config = NodeConfig(node_type=NodeType.MODEL)
        >>> model_node = ModelNode(config)
        >>> 
        >>> # Create an action requiring approval
        >>> action = Action(
        ...     action_type="data_access",
        ...     description="Access customer database",
        ...     parameters={"database": "customers"}
        ... )
        >>> 
        >>> # Create reasoning pathway
        >>> reasoning = ReasoningPathway(
        ...     steps=[
        ...         ReasoningStep(1, "User requested recommendations", 0.95)
        ...     ],
        ...     conclusion="Data access necessary"
        ... )
        >>> 
        >>> # Request governance decision
        >>> request_msg = model_node.request_governance(
        ...     action=action,
        ...     reasoning=reasoning,
        ...     risk_level=RiskLevel.MEDIUM
        ... )
    """
    
    def __init__(self, config: NodeConfig):
        """Initialize the ModelNode.
        
        Args:
            config: Node configuration (must have node_type=NodeType.MODEL)
        """
        if config.node_type != NodeType.MODEL:
            raise ValueError("ModelNode requires node_type=NodeType.MODEL")
        
        super().__init__(config)
        
        # Track pending requests
        self.pending_requests: dict[str, PendingRequest] = {}
    
    def request_governance(
        self,
        action: Action,
        reasoning: ReasoningPathway,
        risk_level: RiskLevel,
        rule_bundles: Optional[list[str]] = None
    ) -> Message:
        """Request a governance decision for an action.
        
        Args:
            action: The action requiring approval
            reasoning: AI's reasoning for the action
            risk_level: Assessed risk level
            rule_bundles: Optional list of specific rule bundles to apply
            
        Returns:
            Signed governance request message
            
        Example:
            >>> action = Action("data_access", "Access user data")
            >>> reasoning = ReasoningPathway(
            ...     steps=[ReasoningStep(1, "User requested data", 0.9)],
            ...     conclusion="Access justified"
            ... )
            >>> message = model_node.request_governance(
            ...     action, reasoning, RiskLevel.LOW
            ... )
        """
        # Generate unique request ID
        import secrets
        request_id = f"req_{secrets.token_hex(8)}"
        
        # Create governance request payload
        request_payload = {
            "request_id": request_id,
            "action": {
                "action_type": action.action_type,
                "description": action.description,
                "parameters": action.parameters
            },
            "reasoning_pathway": {
                "steps": [
                    {
                        "step": step.step,
                        "reasoning": step.reasoning,
                        "confidence": step.confidence
                    }
                    for step in reasoning.steps
                ],
                "conclusion": reasoning.conclusion
            },
            "risk_level": risk_level.value,
            "requested_rule_bundles": rule_bundles or ["default"]
        }
        
        # Create and sign message
        message = self.create_message(
            MessageType.GOVERNANCE_REQUEST,
            request_payload
        )
        
        # Track pending request
        self.pending_requests[request_id] = PendingRequest(
            request_id=request_id,
            message=message
        )
        
        print(f"ModelNode {self.node_id}: Created governance request {request_id}")
        
        return message
    
    def handle_message(self, message: Message) -> Optional[Message]:
        """Handle incoming messages (typically governance decisions).
        
        Args:
            message: Incoming message
            
        Returns:
            Optional response message (typically None for decisions)
        """
        # Verify message authenticity
        if not self.verify_message(message):
            print(f"ModelNode {self.node_id}: Invalid message received")
            return None
        
        # Handle governance decision
        if message.message_type == MessageType.GOVERNANCE_DECISION:
            return self._handle_governance_decision(message)
        
        print(f"ModelNode {self.node_id}: Unknown message type {message.message_type}")
        return None
    
    def _handle_governance_decision(self, message: Message) -> Optional[Message]:
        """Process a governance decision from VARXNode.
        
        Args:
            message: Governance decision message
            
        Returns:
            None (decisions don't require response)
        """
        payload = message.payload
        request_id = payload.get("request_id")
        
        if request_id not in self.pending_requests:
            print(f"ModelNode {self.node_id}: Received decision for unknown request {request_id}")
            return None
        
        # Update pending request with response
        self.pending_requests[request_id].response = message
        
        decision = payload.get("decision")
        confidence = payload.get("confidence", 0.0)
        
        print(f"ModelNode {self.node_id}: Received decision for {request_id}: "
              f"{decision} (confidence: {confidence:.2f})")
        
        # In a real implementation, this would trigger the action if approved
        if decision == DecisionType.APPROVED.value:
            print(f"  → Action approved, proceeding with execution")
        elif decision == DecisionType.APPROVED_WITH_CONDITIONS.value:
            conditions = payload.get("conditions", [])
            print(f"  → Action approved with {len(conditions)} conditions")
        elif decision == DecisionType.REJECTED.value:
            reasoning = payload.get("reasoning", {})
            print(f"  → Action rejected: {reasoning.get('summary', 'No reason given')}")
        elif decision == DecisionType.PENDING_HUMAN_REVIEW.value:
            print(f"  → Action pending human review")
        
        return None
    
    def get_request_status(self, request_id: str) -> Optional[dict[str, Any]]:
        """Get the status of a governance request.
        
        Args:
            request_id: Request identifier
            
        Returns:
            Status dictionary or None if request not found
        """
        if request_id not in self.pending_requests:
            return None
        
        pending = self.pending_requests[request_id]
        
        status = {
            "request_id": request_id,
            "status": "pending" if pending.response is None else "completed"
        }
        
        if pending.response:
            status["decision"] = pending.response.payload.get("decision")
            status["confidence"] = pending.response.payload.get("confidence")
        
        return status
    
    def get_status(self) -> dict[str, Any]:
        """Get current ModelNode status.
        
        Returns:
            Status dictionary including request statistics
        """
        base_status = super().get_status()
        base_status.update({
            "pending_requests": len([
                r for r in self.pending_requests.values()
                if r.response is None
            ]),
            "completed_requests": len([
                r for r in self.pending_requests.values()
                if r.response is not None
            ]),
            "total_requests": len(self.pending_requests)
        })
        return base_status
