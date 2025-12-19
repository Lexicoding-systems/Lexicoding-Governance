"""VARXNode implementation for the VARX Protocol.

The VARXNode is the core governance decision engine that evaluates AI
reasoning against configurable rule bundles using the π_varx semantic engine.
"""

from typing import Optional, Any
from dataclasses import dataclass

from .base_node import BaseNode, NodeConfig
from ..core.protocol import (
    Message,
    MessageType,
    NodeType,
    DecisionType,
    RiskLevel,
)
from ..engine.pi_varx import PiVarxEngine
from ..engine.sat_solver import SATSolver


@dataclass
class RuleBundle:
    """A bundle of governance rules.
    
    Attributes:
        name: Name of the rule bundle
        version: Version identifier
        rules: List of rules in the bundle
    """
    
    name: str
    version: str
    rules: list[dict[str, Any]]


class VARXNode(BaseNode):
    """VARXNode implementation for governance decision-making.
    
    The VARXNode is responsible for:
    - Receiving and validating governance requests
    - Analyzing reasoning pathways with π_varx engine
    - Evaluating requests against rule bundles
    - Generating signed governance decisions
    - Forwarding audit records to AuditorNode
    
    Example:
        >>> config = NodeConfig(node_type=NodeType.VARX)
        >>> varx_node = VARXNode(config)
        >>> 
        >>> # Process governance request from ModelNode
        >>> response = varx_node.handle_message(request_message)
    """
    
    def __init__(self, config: NodeConfig):
        """Initialize the VARXNode.
        
        Args:
            config: Node configuration (must have node_type=NodeType.VARX)
        """
        if config.node_type != NodeType.VARX:
            raise ValueError("VARXNode requires node_type=NodeType.VARX")
        
        super().__init__(config)
        
        # Initialize π_varx semantic engine
        self.pi_varx_engine = PiVarxEngine()
        
        # Initialize SAT solver for rule validation
        self.sat_solver = SATSolver()
        
        # Load default rule bundles
        self.rule_bundles: dict[str, RuleBundle] = {}
        self._load_default_rule_bundles()
        
        # Statistics
        self.requests_processed = 0
        self.decisions_made = {
            "approved": 0,
            "approved_with_conditions": 0,
            "rejected": 0,
            "pending_human_review": 0
        }
    
    def _load_default_rule_bundles(self):
        """Load default rule bundles."""
        # Default rule bundle
        self.rule_bundles["default"] = RuleBundle(
            name="default",
            version="1.0",
            rules=[
                {
                    "id": "basic_safety",
                    "type": "constraint",
                    "condition": "risk_level != critical"
                }
            ]
        )
        
        # GDPR compliance rules
        self.rule_bundles["gdpr_compliance"] = RuleBundle(
            name="gdpr_compliance",
            version="1.0",
            rules=[
                {
                    "id": "data_minimization",
                    "type": "constraint",
                    "condition": "data_scope == minimal"
                },
                {
                    "id": "purpose_limitation",
                    "type": "constraint",
                    "condition": "purpose_declared == true"
                }
            ]
        )
    
    def handle_message(self, message: Message) -> Optional[Message]:
        """Handle incoming messages (typically governance requests).
        
        Args:
            message: Incoming message
            
        Returns:
            Governance decision message if request, None otherwise
        """
        # Verify message authenticity
        if not self.verify_message(message):
            print(f"VARXNode {self.node_id}: Invalid message received")
            return None
        
        # Handle governance request
        if message.message_type == MessageType.GOVERNANCE_REQUEST:
            return self._handle_governance_request(message)
        
        print(f"VARXNode {self.node_id}: Unknown message type {message.message_type}")
        return None
    
    def _handle_governance_request(self, message: Message) -> Message:
        """Process a governance request and generate a decision.
        
        Args:
            message: Governance request message
            
        Returns:
            Governance decision message
        """
        import time
        start_time = time.time()
        
        payload = message.payload
        request_id = payload.get("request_id")
        
        print(f"VARXNode {self.node_id}: Processing request {request_id}")
        
        # Extract request details
        action = payload.get("action", {})
        reasoning_pathway = payload.get("reasoning_pathway", {})
        risk_level = payload.get("risk_level", "medium")
        requested_bundles = payload.get("requested_rule_bundles", ["default"])
        
        # Evaluate reasoning with π_varx engine
        reasoning_analysis = self.pi_varx_engine.analyze(reasoning_pathway)
        
        # Evaluate against rule bundles
        rule_results = []
        for bundle_name in requested_bundles:
            if bundle_name in self.rule_bundles:
                bundle = self.rule_bundles[bundle_name]
                for rule in bundle.rules:
                    result = self.sat_solver.evaluate_rule(rule, action, reasoning_analysis)
                    rule_results.append({
                        "rule_bundle": bundle_name,
                        "rule_id": rule["id"],
                        "result": "passed" if result else "failed"
                    })
        
        # Make decision based on analysis and rules
        decision = self._make_decision(
            risk_level,
            reasoning_analysis,
            rule_results
        )
        
        # Calculate processing time
        processing_time = int((time.time() - start_time) * 1000)
        
        # Create decision payload
        decision_payload = {
            "request_id": request_id,
            "decision": decision["decision"].value,
            "confidence": decision["confidence"],
            "reasoning": {
                "summary": decision["summary"],
                "details": decision["details"],
                "applied_rules": rule_results
            },
            "conditions": decision.get("conditions", []),
            "expires_at": int(time.time()) + 3600,  # 1 hour validity
            "decision_metadata": {
                "varx_node_id": self.node_id,
                "evaluation_time_ms": processing_time,
                "pi_varx_version": "1.0.0"
            }
        }
        
        # Create and sign decision message
        decision_message = self.create_message(
            MessageType.GOVERNANCE_DECISION,
            decision_payload
        )
        
        # Update statistics
        self.requests_processed += 1
        self.decisions_made[decision["decision"].value] += 1
        
        print(f"VARXNode {self.node_id}: Decision for {request_id}: "
              f"{decision['decision'].value} ({processing_time}ms)")
        
        # TODO: Forward to AuditorNode for audit trail
        
        return decision_message
    
    def _make_decision(
        self,
        risk_level: str,
        reasoning_analysis: dict[str, Any],
        rule_results: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Make a governance decision based on analysis.
        
        Args:
            risk_level: Assessed risk level
            reasoning_analysis: Results from π_varx analysis
            rule_results: Results from rule evaluation
            
        Returns:
            Decision dictionary with decision, confidence, and reasoning
        """
        # Check if any rules failed
        failed_rules = [r for r in rule_results if r["result"] == "failed"]
        
        # Check reasoning quality
        reasoning_score = reasoning_analysis.get("confidence", 0.5)
        
        # Decision logic
        if failed_rules:
            return {
                "decision": DecisionType.REJECTED,
                "confidence": 0.95,
                "summary": f"Governance rules failed: {len(failed_rules)} rule(s)",
                "details": [
                    f"Rule {r['rule_id']} from {r['rule_bundle']} failed"
                    for r in failed_rules
                ]
            }
        
        if risk_level == RiskLevel.CRITICAL.value:
            return {
                "decision": DecisionType.PENDING_HUMAN_REVIEW,
                "confidence": 0.90,
                "summary": "Critical risk level requires human review",
                "details": ["Risk level: CRITICAL", "Human oversight required"]
            }
        
        if risk_level == RiskLevel.HIGH.value and reasoning_score < 0.8:
            return {
                "decision": DecisionType.PENDING_HUMAN_REVIEW,
                "confidence": 0.85,
                "summary": "High risk with uncertain reasoning requires review",
                "details": [
                    f"Risk level: HIGH",
                    f"Reasoning confidence: {reasoning_score:.2f}"
                ]
            }
        
        if reasoning_score < 0.6:
            return {
                "decision": DecisionType.REJECTED,
                "confidence": 0.80,
                "summary": "Insufficient reasoning confidence",
                "details": [
                    f"Reasoning confidence too low: {reasoning_score:.2f}",
                    "Minimum required: 0.60"
                ]
            }
        
        # Approve with conditions for medium/high risk
        if risk_level in [RiskLevel.MEDIUM.value, RiskLevel.HIGH.value]:
            return {
                "decision": DecisionType.APPROVED_WITH_CONDITIONS,
                "confidence": reasoning_score,
                "summary": "Approved with monitoring conditions",
                "details": [
                    "All governance rules passed",
                    f"Reasoning analysis confidence: {reasoning_score:.2f}"
                ],
                "conditions": [
                    "Action must be logged",
                    "Human notification required",
                    f"Monitoring required for {risk_level} risk"
                ]
            }
        
        # Approve for low risk
        return {
            "decision": DecisionType.APPROVED,
            "confidence": reasoning_score,
            "summary": "Action approved",
            "details": [
                "All governance rules passed",
                f"Risk level: {risk_level}",
                f"Reasoning confidence: {reasoning_score:.2f}"
            ]
        }
    
    def get_status(self) -> dict[str, Any]:
        """Get current VARXNode status.
        
        Returns:
            Status dictionary including decision statistics
        """
        base_status = super().get_status()
        base_status.update({
            "requests_processed": self.requests_processed,
            "decisions": self.decisions_made,
            "rule_bundles_loaded": len(self.rule_bundles),
            "pi_varx_version": "1.0.0"
        })
        return base_status
