# VARX Protocol API Specification

## Overview

This document defines the message formats and API specifications for the VARX Protocol. All communication between nodes uses cryptographically signed messages following these specifications.

## Protocol Version

**Current Version**: `1.0.0`

**Version Negotiation**: Nodes must verify protocol version compatibility before exchanging messages.

## Message Format

### Base Message Structure

All VARX Protocol messages follow this base structure:

```json
{
  "protocol_version": "1.0.0",
  "message_type": "governance_request",
  "message_id": "msg_a1b2c3d4",
  "sender": {
    "node_id": "node_abc123",
    "node_type": "ModelNode",
    "public_key": "302a300506032b657003210012345..."
  },
  "timestamp": 1703012345,
  "nonce": "a1b2c3d4e5f6g7h8",
  "payload": { },
  "signature": "base64_encoded_ed25519_signature"
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol_version` | string | Yes | VARX protocol version (semver) |
| `message_type` | string | Yes | Type of message (see Message Types) |
| `message_id` | string | Yes | Unique message identifier |
| `sender` | object | Yes | Sender identification |
| `timestamp` | integer | Yes | Unix timestamp (seconds) |
| `nonce` | string | Yes | Hex-encoded 16-byte nonce |
| `payload` | object | Yes | Message-specific payload |
| `signature` | string | Yes | Base64-encoded Ed25519 signature |

## Message Types

### 1. Governance Request

**Sent by**: ModelNode → VARXNode

**Purpose**: Request governance decision for an AI action

```json
{
  "message_type": "governance_request",
  "payload": {
    "request_id": "req_xyz789",
    "action": {
      "type": "data_access",
      "description": "Access customer database for recommendation generation",
      "parameters": {
        "database": "customers",
        "query": "SELECT * FROM customers WHERE region = 'EU'",
        "purpose": "personalized_recommendations"
      }
    },
    "reasoning_pathway": {
      "steps": [
        {
          "step": 1,
          "reasoning": "User requested personalized product recommendations",
          "confidence": 0.95
        },
        {
          "step": 2,
          "reasoning": "Recommendations require customer purchase history",
          "confidence": 0.90
        },
        {
          "step": 3,
          "reasoning": "Query filters for EU customers only to comply with GDPR",
          "confidence": 0.98
        }
      ],
      "conclusion": "Data access is necessary and proportionate"
    },
    "risk_level": "medium",
    "requested_rule_bundles": ["gdpr_compliance", "data_minimization"]
  }
}
```

### 2. Governance Decision

**Sent by**: VARXNode → ModelNode

**Purpose**: Return governance decision for requested action

```json
{
  "message_type": "governance_decision",
  "payload": {
    "request_id": "req_xyz789",
    "decision": "approved",
    "confidence": 0.92,
    "reasoning": {
      "summary": "Data access approved with conditions",
      "details": [
        "Purpose aligns with user consent",
        "Query properly scoped to necessary data",
        "GDPR data minimization satisfied",
        "Retention policy must be applied"
      ],
      "applied_rules": [
        {
          "rule_bundle": "gdpr_compliance",
          "rule_id": "data_minimization",
          "result": "passed"
        },
        {
          "rule_bundle": "gdpr_compliance",
          "rule_id": "purpose_limitation",
          "result": "passed"
        }
      ]
    },
    "conditions": [
      "Data must be deleted after 30 days",
      "User must be notified of data access",
      "Log all access events"
    ],
    "expires_at": 1703013945,
    "decision_metadata": {
      "varx_node_id": "node_varx001",
      "evaluation_time_ms": 145,
      "pi_varx_version": "1.0.0"
    }
  }
}
```

**Decision Values**:
- `approved`: Action is permitted
- `approved_with_conditions`: Action permitted with restrictions
- `rejected`: Action is not permitted
- `pending_human_review`: Requires human oversight

### 3. Audit Record

**Sent by**: VARXNode → AuditorNode

**Purpose**: Record governance decision in immutable audit trail

```json
{
  "message_type": "audit_record",
  "payload": {
    "audit_id": "audit_456",
    "request_id": "req_xyz789",
    "decision_id": "dec_abc123",
    "model_node": {
      "node_id": "node_abc123",
      "signature": "base64_model_signature"
    },
    "varx_node": {
      "node_id": "node_varx001",
      "signature": "base64_varx_signature"
    },
    "decision_summary": {
      "decision": "approved_with_conditions",
      "risk_level": "medium",
      "human_reviewed": false,
      "conditions_count": 3
    },
    "full_request": { },
    "full_decision": { },
    "compliance_tags": ["GDPR", "EU_AI_ACT"]
  }
}
```

### 4. Audit Acknowledgment

**Sent by**: AuditorNode → VARXNode

**Purpose**: Confirm audit record was added to hash chain

```json
{
  "message_type": "audit_acknowledgment",
  "payload": {
    "audit_id": "audit_456",
    "block_number": 12345,
    "block_hash": "a3f8e9b2c1d4...",
    "previous_hash": "b7c9d1e3f5a2...",
    "merkle_root": "c8d1e2f4a6b3...",
    "verification_proof": {
      "hash_chain_valid": true,
      "signatures_valid": true,
      "merkle_path": ["hash1", "hash2", "hash3"]
    }
  }
}
```

### 5. Audit Query

**Sent by**: Any Node → AuditorNode

**Purpose**: Query audit trail for records

```json
{
  "message_type": "audit_query",
  "payload": {
    "query_id": "query_789",
    "filters": {
      "start_timestamp": 1703000000,
      "end_timestamp": 1703012345,
      "model_node_id": "node_abc123",
      "decision_type": "approved",
      "risk_level": "high",
      "compliance_tags": ["GDPR"]
    },
    "pagination": {
      "page": 1,
      "per_page": 100
    },
    "include_verification": true
  }
}
```

### 6. Audit Query Response

**Sent by**: AuditorNode → Querying Node

**Purpose**: Return audit records matching query

```json
{
  "message_type": "audit_query_response",
  "payload": {
    "query_id": "query_789",
    "total_records": 42,
    "records": [
      {
        "block_number": 12340,
        "audit_id": "audit_450",
        "timestamp": 1703010000,
        "decision": "approved",
        "summary": "Data access approved for model_abc123"
      }
    ],
    "pagination": {
      "current_page": 1,
      "total_pages": 1,
      "per_page": 100
    },
    "verification": {
      "hash_chain_valid": true,
      "start_block_hash": "a1b2c3...",
      "end_block_hash": "d4e5f6..."
    }
  }
}
```

### 7. Node Registration

**Sent by**: Any Node → Network

**Purpose**: Register a node in the VARX network

```json
{
  "message_type": "node_registration",
  "payload": {
    "node_id": "node_new001",
    "node_type": "ModelNode",
    "public_key": "302a300506032b657003210012345...",
    "capabilities": [
      "governance_requests",
      "decision_processing"
    ],
    "metadata": {
      "version": "1.0.0",
      "operator": "Organization Name",
      "description": "Production model node"
    }
  }
}
```

### 8. Heartbeat

**Sent by**: All Nodes (periodic)

**Purpose**: Indicate node is alive and operational

```json
{
  "message_type": "heartbeat",
  "payload": {
    "node_id": "node_abc123",
    "status": "operational",
    "metrics": {
      "uptime_seconds": 86400,
      "requests_processed": 1234,
      "average_response_time_ms": 150,
      "error_rate": 0.001
    },
    "last_block_number": 12345
  }
}
```

## API Endpoints

### RESTful API

All nodes expose a RESTful API for message exchange:

#### POST /v1/messages

**Purpose**: Send a message to a node

**Request**:
```http
POST /v1/messages HTTP/1.1
Host: varxnode.example.com
Content-Type: application/json

{
  "protocol_version": "1.0.0",
  "message_type": "governance_request",
  ...
}
```

**Response**:
```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "status": "accepted",
  "message_id": "msg_a1b2c3d4",
  "estimated_processing_time_ms": 200
}
```

**Status Codes**:
- `202 Accepted`: Message accepted for processing
- `400 Bad Request`: Invalid message format
- `401 Unauthorized`: Invalid signature
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Processing error

#### GET /v1/messages/{message_id}

**Purpose**: Check message processing status

**Response**:
```json
{
  "message_id": "msg_a1b2c3d4",
  "status": "completed",
  "response": { }
}
```

#### GET /v1/audit/records

**Purpose**: Query audit records (AuditorNode only)

**Query Parameters**:
- `start_time`: Unix timestamp
- `end_time`: Unix timestamp
- `node_id`: Filter by node ID
- `page`: Page number
- `per_page`: Records per page

**Response**:
```json
{
  "total": 42,
  "records": [ ],
  "page": 1,
  "per_page": 100
}
```

#### GET /v1/audit/verify/{block_number}

**Purpose**: Verify hash chain integrity

**Response**:
```json
{
  "block_number": 12345,
  "block_hash": "a3f8e9b2c1d4...",
  "previous_hash": "b7c9d1e3f5a2...",
  "chain_valid": true,
  "verification_path": [ ]
}
```

#### GET /v1/health

**Purpose**: Health check endpoint

**Response**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "node_type": "VARXNode",
  "uptime_seconds": 86400
}
```

### WebSocket API

For real-time communication, nodes support WebSocket connections:

#### Connection

```javascript
const ws = new WebSocket('wss://varxnode.example.com/v1/stream');

ws.onopen = () => {
  // Send authentication message
  ws.send(JSON.stringify({
    message_type: 'auth',
    payload: { token: 'auth_token' }
  }));
};

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  // Handle incoming message
};
```

#### Streaming Audit Records

```javascript
// Subscribe to audit records
ws.send(JSON.stringify({
  message_type: 'subscribe',
  payload: {
    stream: 'audit_records',
    filters: { risk_level: 'high' }
  }
}));

// Receive real-time updates
ws.onmessage = (event) => {
  const auditRecord = JSON.parse(event.data);
  console.log('New audit record:', auditRecord);
};
```

## Cryptographic Specifications

### Signature Generation

All messages must be signed before transmission:

```python
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519

def sign_message(message: dict, private_key: ed25519.Ed25519PrivateKey) -> str:
    """
    Sign a VARX protocol message.
    
    Args:
        message: Message dictionary (without signature field)
        private_key: Ed25519 private key
        
    Returns:
        Base64-encoded signature
    """
    # Serialize message deterministically
    canonical = json.dumps(message, sort_keys=True).encode('utf-8')
    
    # Sign with Ed25519
    signature = private_key.sign(canonical)
    
    # Return base64-encoded signature
    import base64
    return base64.b64encode(signature).decode('ascii')
```

### Signature Verification

Recipients must verify signatures on all messages:

```python
def verify_message(
    message: dict,
    signature: str,
    public_key: ed25519.Ed25519PublicKey
) -> bool:
    """
    Verify a VARX protocol message signature.
    
    Args:
        message: Message dictionary (without signature field)
        signature: Base64-encoded signature
        public_key: Ed25519 public key
        
    Returns:
        True if signature is valid
    """
    import base64
    from cryptography.exceptions import InvalidSignature
    
    # Remove signature field for verification
    message_copy = message.copy()
    message_copy.pop('signature', None)
    
    # Serialize message
    canonical = json.dumps(message_copy, sort_keys=True).encode('utf-8')
    
    # Decode signature
    sig_bytes = base64.b64decode(signature)
    
    # Verify signature
    try:
        public_key.verify(sig_bytes, canonical)
        return True
    except InvalidSignature:
        return False
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "INVALID_SIGNATURE",
    "message": "Message signature verification failed",
    "details": {
      "message_id": "msg_a1b2c3d4",
      "sender": "node_abc123"
    },
    "timestamp": 1703012345
  }
}
```

### Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_SIGNATURE` | Signature verification failed | 401 |
| `INVALID_NONCE` | Nonce already used or invalid | 400 |
| `EXPIRED_MESSAGE` | Message timestamp outside validity window | 400 |
| `UNKNOWN_NODE` | Sender node not registered | 404 |
| `MALFORMED_MESSAGE` | Message structure invalid | 400 |
| `RATE_LIMIT_EXCEEDED` | Too many requests | 429 |
| `INTERNAL_ERROR` | Internal processing error | 500 |
| `RULE_BUNDLE_NOT_FOUND` | Requested rule bundle doesn't exist | 404 |
| `EVALUATION_TIMEOUT` | Decision evaluation timed out | 504 |

## Rate Limiting

All API endpoints implement rate limiting:

**Limits**:
- Governance Requests: 100 requests per minute per node
- Audit Queries: 50 requests per minute per node
- Health Checks: 1000 requests per minute per node

**Headers**:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1703012400
```

## Versioning

The VARX Protocol uses semantic versioning (major.minor.patch):

- **Major**: Breaking changes to message format or API
- **Minor**: Backward-compatible feature additions
- **Patch**: Backward-compatible bug fixes

**Version Compatibility**:
- Nodes must support their declared version and one prior major version
- Version negotiation occurs during node registration
- Unsupported versions return error code `UNSUPPORTED_VERSION`

## Security Considerations

1. **TLS Required**: All HTTP/WebSocket connections must use TLS 1.3+
2. **Certificate Validation**: Nodes must validate TLS certificates
3. **Replay Protection**: Nonces must be validated to prevent replay attacks
4. **Timestamp Validation**: Messages outside ±5 minute window rejected
5. **Signature Verification**: All signatures must be verified before processing
6. **Rate Limiting**: Implement rate limits to prevent DoS attacks

## Example Implementation

### Python Client Example

```python
import requests
import json
from cryptography.hazmat.primitives.asymmetric import ed25519

class VARXClient:
    """Example VARX Protocol client."""
    
    def __init__(self, node_url: str, private_key: ed25519.Ed25519PrivateKey):
        self.node_url = node_url
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    def send_governance_request(self, action: dict, reasoning: dict) -> dict:
        """Send a governance request."""
        message = {
            "protocol_version": "1.0.0",
            "message_type": "governance_request",
            "message_id": self._generate_message_id(),
            "sender": {
                "node_id": self._get_node_id(),
                "node_type": "ModelNode",
                "public_key": self._serialize_public_key()
            },
            "timestamp": int(time.time()),
            "nonce": self._generate_nonce(),
            "payload": {
                "request_id": self._generate_request_id(),
                "action": action,
                "reasoning_pathway": reasoning,
                "risk_level": "medium",
                "requested_rule_bundles": ["gdpr_compliance"]
            }
        }
        
        # Sign message
        message['signature'] = sign_message(message, self.private_key)
        
        # Send to VARXNode
        response = requests.post(
            f"{self.node_url}/v1/messages",
            json=message,
            headers={"Content-Type": "application/json"}
        )
        
        return response.json()
```

## References

- [Architecture Documentation](./architecture.md)
- [Cryptography Documentation](./cryptography.md)
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) - JSON Format
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) - Ed25519
