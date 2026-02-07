"""
MFQP Reference Implementation (Python) - Production Hardened

Metalogue Federated Query Protocol v1.0

This module provides a PRODUCTION-GRADE reference implementation for MFQP
message creation, signing, and verification with comprehensive validation,
error handling, and security controls.

Features:
- Input validation with size limits
- Timestamp validation (anti-replay protection)
- Comprehensive error handling
- Thread-safe operations
- Full type hints

Requirements:
    pip install cryptography pydantic

Usage:
    from metalogue.protocol.mfqp import GhostQuery, sign_message, verify_signature
    
    # Create and sign a Ghost Query
    query = GhostQuery.create(
        source_company="acme-corp",
        target_company="globex-inc",
        intent="What is the inventory status?",
        intent_class="inventory.status",
    )
    signature = sign_message(query, private_key)
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, ClassVar, Dict, FrozenSet, List, Optional, Pattern, Tuple
from uuid import UUID, uuid4


# =============================================================================
# CONSTANTS
# =============================================================================

MFQP_VERSION = "1.0"
MESSAGE_VERSION_BYTE = b"\x01"

# Security limits
MAX_INTENT_LENGTH = 2000
MAX_COMPANY_SLUG_LENGTH = 128
MAX_INTENT_CLASS_LENGTH = 256
MAX_RESULTS_COUNT = 1000
MAX_REDACTED_FIELDS = 100
MAX_PAYLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
MAX_TIMESTAMP_DRIFT_SECONDS = 300  # 5 minutes

# Validation patterns
COMPANY_SLUG_PATTERN: Pattern = re.compile(r"^[a-z0-9][a-z0-9\-]{0,126}[a-z0-9]$|^[a-z0-9]$")
INTENT_CLASS_PATTERN: Pattern = re.compile(r"^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*$")
UUID_PATTERN: Pattern = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE
)


# =============================================================================
# CRYPTOGRAPHIC IMPORTS
# =============================================================================

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


# =============================================================================
# EXCEPTIONS
# =============================================================================

class MFQPError(Exception):
    """Base exception for MFQP errors."""
    
    def __init__(self, message: str, error_code: str = "X001"):
        super().__init__(message)
        self.error_code = error_code
        self.message = message


class ValidationError(MFQPError):
    """Raised when message validation fails."""
    
    def __init__(self, message: str, field: str = None):
        super().__init__(message, "V001")
        self.field = field


class SignatureError(MFQPError):
    """Raised when signature creation or verification fails."""
    
    def __init__(self, message: str):
        super().__init__(message, "E001")


class CryptoUnavailableError(MFQPError):
    """Raised when cryptography library is not installed."""
    
    def __init__(self):
        super().__init__(
            "cryptography library required: pip install cryptography",
            "X002"
        )


class ReplayError(MFQPError):
    """Raised when a replay attack is detected."""
    
    def __init__(self, message: str):
        super().__init__(message, "E007")


class MessageSizeError(MFQPError):
    """Raised when message exceeds size limits."""
    
    def __init__(self, message: str, limit: int, actual: int):
        super().__init__(message, "E008")
        self.limit = limit
        self.actual = actual


# =============================================================================
# ENUMS
# =============================================================================

class AuthLevel(str, Enum):
    """Authentication level of a federation partner."""
    PENDING = "pending"
    VERIFIED = "verified"
    TRUSTED = "trusted"
    
    @classmethod
    def values(cls) -> FrozenSet[str]:
        return frozenset(v.value for v in cls)


class ResponseStatus(str, Enum):
    """Status of a query response."""
    SUCCESS = "success"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    
    @classmethod
    def values(cls) -> FrozenSet[str]:
        return frozenset(v.value for v in cls)


# =============================================================================
# REPLAY PROTECTION
# =============================================================================

class ReplayProtector:
    """
    Thread-safe replay protection using a sliding window of seen query IDs.
    
    In production, this should be backed by Redis or similar distributed cache.
    """
    
    def __init__(self, window_seconds: int = 600, max_entries: int = 100000, cleanup_interval_seconds: int = 60):
        self._seen: Dict[str, datetime] = {}
        self._lock = threading.Lock()
        self._window = timedelta(seconds=window_seconds)
        self._max_entries = max_entries
        self._cleanup_interval = cleanup_interval_seconds
        self._last_cleanup: float = 0.0
    
    def check_and_record(self, query_id: str) -> bool:
        """
        Check if query_id has been seen. If not, record it.
        
        Returns:
            True if this is a new query_id, False if replay detected.
        """
        import time as _time
        now = datetime.now(timezone.utc)
        
        with self._lock:
            # Periodic time-based cleanup (even under low traffic)
            current_time = _time.time()
            if current_time - self._last_cleanup > self._cleanup_interval:
                self._last_cleanup = current_time
                cutoff = now - self._window
                self._seen = {
                    k: v for k, v in self._seen.items()
                    if v > cutoff
                }
            
            # Also prune if exceeding max entries
            if len(self._seen) > self._max_entries:
                cutoff = now - self._window
                self._seen = {
                    k: v for k, v in self._seen.items() 
                    if v > cutoff
                }
            
            if query_id in self._seen:
                return False
            
            self._seen[query_id] = now
            return True


# Global replay protector (replace with distributed solution in production)
_replay_protector = ReplayProtector()


# =============================================================================
# VALIDATION HELPERS
# =============================================================================

def validate_uuid(value: str, field_name: str) -> str:
    """Validate a UUID v4 string."""
    if not value:
        raise ValidationError(f"{field_name} is required", field_name)
    
    if not UUID_PATTERN.match(value):
        raise ValidationError(f"{field_name} must be a valid UUID v4", field_name)
    
    return value


def validate_company_slug(value: str, field_name: str) -> str:
    """Validate a company slug."""
    if not value:
        raise ValidationError(f"{field_name} is required", field_name)
    
    if len(value) > MAX_COMPANY_SLUG_LENGTH:
        raise ValidationError(
            f"{field_name} exceeds max length of {MAX_COMPANY_SLUG_LENGTH}",
            field_name
        )
    
    if not COMPANY_SLUG_PATTERN.match(value):
        raise ValidationError(
            f"{field_name} must be lowercase alphanumeric with hyphens",
            field_name
        )
    
    return value


def validate_intent(value: str, field_name: str = "intent") -> str:
    """Validate intent string."""
    if not value:
        raise ValidationError(f"{field_name} is required", field_name)
    
    if len(value) > MAX_INTENT_LENGTH:
        raise ValidationError(
            f"{field_name} exceeds max length of {MAX_INTENT_LENGTH}",
            field_name
        )
    
    # Check for control characters (except newlines)
    if any(ord(c) < 32 and c not in '\n\r\t' for c in value):
        raise ValidationError(
            f"{field_name} contains invalid control characters",
            field_name
        )
    
    return value


def validate_intent_class(value: str, field_name: str = "intent_class") -> str:
    """Validate intent class string."""
    if not value:
        raise ValidationError(f"{field_name} is required", field_name)
    
    if len(value) > MAX_INTENT_CLASS_LENGTH:
        raise ValidationError(
            f"{field_name} exceeds max length of {MAX_INTENT_CLASS_LENGTH}",
            field_name
        )
    
    if not INTENT_CLASS_PATTERN.match(value):
        raise ValidationError(
            f"{field_name} must match pattern: category.subcategory",
            field_name
        )
    
    return value


def validate_timestamp(
    value: datetime,
    field_name: str = "timestamp",
    max_drift_seconds: int = MAX_TIMESTAMP_DRIFT_SECONDS,
) -> datetime:
    """Validate timestamp is within acceptable drift."""
    if value.tzinfo is None:
        raise ValidationError(f"{field_name} must be timezone-aware", field_name)
    
    now = datetime.now(timezone.utc)
    drift = abs((now - value).total_seconds())
    
    if drift > max_drift_seconds:
        raise ValidationError(
            f"{field_name} is {drift:.0f}s from current time (max: {max_drift_seconds}s)",
            field_name
        )
    
    return value


def validate_freshness_seconds(value: int, field_name: str = "freshness_required_seconds") -> int:
    """Validate freshness requirement."""
    if value < 0:
        raise ValidationError(f"{field_name} must be non-negative", field_name)
    
    if value > 86400 * 7:  # 7 days max
        raise ValidationError(f"{field_name} cannot exceed 7 days", field_name)
    
    return value


# =============================================================================
# BASE MESSAGE
# =============================================================================

@dataclass
class MFQPMessage:
    """
    Base class for MFQP messages with validation and serialization.
    """
    
    def validate(self) -> None:
        """Validate all fields. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement validate()")
    
    def to_canonical_bytes(self) -> bytes:
        """Convert message to canonical bytes for signing."""
        raise NotImplementedError("Subclasses must implement to_canonical_bytes()")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for JSON serialization."""
        raise NotImplementedError("Subclasses must implement to_dict()")
    
    def to_json(self, indent: int = None) -> str:
        """Serialize message to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":") if indent is None else None, indent=indent)
    
    def compute_hash(self) -> str:
        """Compute SHA-256 hash of canonical bytes."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()


# =============================================================================
# GHOST QUERY
# =============================================================================

@dataclass
class GhostQuery(MFQPMessage):
    """
    MFQP Ghost Query - Intent-only federated query.
    
    Attributes:
        query_id: Globally unique query identifier (UUID v4)
        source_company: Organization slug of the requester
        target_company: Organization slug of the responder
        intent: Natural language description of query intent
        intent_class: Classified intent category (e.g., "inventory.status")
        auth_level: Authentication level of the requester
        freshness_required_seconds: Maximum age of response data
        timestamp: Query creation timestamp (UTC)
    """
    query_id: str
    source_company: str
    target_company: str
    intent: str
    intent_class: str
    auth_level: AuthLevel
    timestamp: datetime
    freshness_required_seconds: int = 300
    
    # Class-level validation settings
    ENABLE_REPLAY_PROTECTION: ClassVar[bool] = True
    
    def __post_init__(self):
        """Validate on construction."""
        self.validate()
    
    def validate(self) -> None:
        """Validate all fields."""
        validate_uuid(self.query_id, "query_id")
        validate_company_slug(self.source_company, "source_company")
        validate_company_slug(self.target_company, "target_company")
        validate_intent(self.intent, "intent")
        validate_intent_class(self.intent_class, "intent_class")
        validate_freshness_seconds(self.freshness_required_seconds)
        validate_timestamp(self.timestamp)
        
        if not isinstance(self.auth_level, AuthLevel):
            if self.auth_level not in AuthLevel.values():
                raise ValidationError(
                    f"auth_level must be one of: {', '.join(AuthLevel.values())}",
                    "auth_level"
                )
            self.auth_level = AuthLevel(self.auth_level)
        
        # Source and target must differ
        if self.source_company == self.target_company:
            raise ValidationError(
                "source_company and target_company must be different",
                "source_company"
            )
    
    def check_replay(self) -> None:
        """Check for replay attack. Raises ReplayError if detected."""
        if self.ENABLE_REPLAY_PROTECTION:
            if not _replay_protector.check_and_record(self.query_id):
                raise ReplayError(f"Duplicate query_id detected: {self.query_id}")
    
    @staticmethod
    def create(
        source_company: str,
        target_company: str,
        intent: str,
        intent_class: str,
        auth_level: AuthLevel = AuthLevel.VERIFIED,
        freshness_required_seconds: int = 300,
    ) -> GhostQuery:
        """Create a new Ghost Query with generated ID and timestamp."""
        return GhostQuery(
            query_id=str(uuid4()),
            source_company=source_company,
            target_company=target_company,
            intent=intent,
            intent_class=intent_class,
            auth_level=auth_level,
            freshness_required_seconds=freshness_required_seconds,
            timestamp=datetime.now(timezone.utc),
        )
    
    def to_canonical_bytes(self) -> bytes:
        """Convert Ghost Query to canonical bytes for signing."""
        parts = [MESSAGE_VERSION_BYTE]
        
        parts.append(_length_prefix_string(MFQP_VERSION))
        parts.append(UUID(self.query_id).bytes)
        parts.append(_length_prefix_string(self.source_company))
        parts.append(_length_prefix_string(self.target_company))
        parts.append(_length_prefix_string(self.intent))
        parts.append(_length_prefix_string(self.intent_class))
        parts.append(_length_prefix_string(self.auth_level.value))
        parts.append(struct.pack(">I", self.freshness_required_seconds))
        
        timestamp_us = int(self.timestamp.timestamp() * 1_000_000)
        parts.append(struct.pack(">Q", timestamp_us))
        
        return b"".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Ghost Query to dictionary."""
        return {
            "mfqp_version": MFQP_VERSION,
            "message_type": "ghost_query",
            "query_id": self.query_id,
            "source_company": self.source_company,
            "target_company": self.target_company,
            "intent": self.intent,
            "intent_class": self.intent_class,
            "auth_level": self.auth_level.value,
            "freshness_required_seconds": self.freshness_required_seconds,
            "timestamp": self.timestamp.isoformat(),
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any], skip_replay_check: bool = False) -> GhostQuery:
        """
        Deserialize from dictionary with full validation.
        
        Args:
            data: Dictionary containing Ghost Query fields
            skip_replay_check: If True, skip replay protection (for testing)
        """
        # Validate protocol version
        version = data.get("mfqp_version", MFQP_VERSION)
        if not version.startswith("1."):
            raise ValidationError(
                f"Unsupported MFQP version: {version} (supported: 1.x)",
                "mfqp_version"
            )
        
        timestamp_str = data.get("timestamp", "")
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        
        query = GhostQuery(
            query_id=data["query_id"],
            source_company=data["source_company"],
            target_company=data["target_company"],
            intent=data["intent"],
            intent_class=data["intent_class"],
            auth_level=AuthLevel(data["auth_level"]),
            freshness_required_seconds=data.get("freshness_required_seconds", 300),
            timestamp=datetime.fromisoformat(timestamp_str),
        )
        
        if not skip_replay_check:
            query.check_replay()
        
        return query


# =============================================================================
# ATTESTATION
# =============================================================================

@dataclass
class Attestation:
    """Cryptographic attestation of a response."""
    attestation_id: str
    response_hash: str
    signer_key_id: str
    policy_snapshot: Dict[str, Any]
    signature: bytes = field(default_factory=bytes)
    
    def __post_init__(self):
        """Validate on construction."""
        validate_uuid(self.attestation_id, "attestation_id")
        
        if not self.response_hash or len(self.response_hash) != 64:
            raise ValidationError("response_hash must be 64 hex characters", "response_hash")
        
        if not self.signer_key_id or len(self.signer_key_id) != 64:
            raise ValidationError("signer_key_id must be 64 hex characters", "signer_key_id")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "response_hash": self.response_hash,
            "signer_key_id": self.signer_key_id,
            "policy_snapshot": self.policy_snapshot,
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> Attestation:
        sig = data.get("signature", "")
        signature_bytes = base64.b64decode(sig) if sig else b""
        
        return Attestation(
            attestation_id=data["attestation_id"],
            response_hash=data["response_hash"],
            signer_key_id=data["signer_key_id"],
            policy_snapshot=data["policy_snapshot"],
            signature=signature_bytes,
        )


# =============================================================================
# QUERY RESPONSE
# =============================================================================

@dataclass
class QueryResponse(MFQPMessage):
    """MFQP Query Response - Attested answer to a Ghost Query."""
    query_id: str
    status: ResponseStatus
    payload: Optional[Dict[str, Any]]
    redactions: List[str]
    results_count: int
    freshness_timestamp: datetime
    attestation: Attestation
    timestamp: datetime
    
    def __post_init__(self):
        """Validate on construction."""
        self.validate()
    
    def validate(self) -> None:
        """Validate all fields."""
        validate_uuid(self.query_id, "query_id")
        
        if not isinstance(self.status, ResponseStatus):
            if self.status not in ResponseStatus.values():
                raise ValidationError(
                    f"status must be one of: {', '.join(ResponseStatus.values())}",
                    "status"
                )
            self.status = ResponseStatus(self.status)
        
        if self.results_count < 0:
            raise ValidationError("results_count must be non-negative", "results_count")
        
        if self.results_count > MAX_RESULTS_COUNT:
            raise ValidationError(
                f"results_count exceeds max of {MAX_RESULTS_COUNT}",
                "results_count"
            )
        
        if len(self.redactions) > MAX_REDACTED_FIELDS:
            raise ValidationError(
                f"redactions exceeds max of {MAX_REDACTED_FIELDS} fields",
                "redactions"
            )
        
        # Validate payload size
        if self.payload is not None:
            payload_json = json.dumps(self.payload)
            if len(payload_json) > MAX_PAYLOAD_SIZE_BYTES:
                raise MessageSizeError(
                    "payload exceeds maximum size",
                    MAX_PAYLOAD_SIZE_BYTES,
                    len(payload_json)
                )
    
    @staticmethod
    def create(
        query_id: str,
        status: ResponseStatus,
        payload: Optional[Dict[str, Any]],
        redactions: List[str],
        results_count: int,
        attestation: Attestation,
    ) -> QueryResponse:
        """Create a new Query Response."""
        now = datetime.now(timezone.utc)
        return QueryResponse(
            query_id=query_id,
            status=status,
            payload=payload,
            redactions=redactions,
            results_count=results_count,
            freshness_timestamp=now,
            attestation=attestation,
            timestamp=now,
        )
    
    def to_canonical_bytes(self) -> bytes:
        """Convert response to canonical bytes for attestation verification."""
        parts = [MESSAGE_VERSION_BYTE]
        
        response_hash_bytes = bytes.fromhex(self.attestation.response_hash)
        parts.append(response_hash_bytes)
        
        timestamp_us = int(self.freshness_timestamp.timestamp() * 1_000_000)
        parts.append(struct.pack(">Q", timestamp_us))
        
        policy_json = json.dumps(self.attestation.policy_snapshot, sort_keys=True)
        policy_hash = hashlib.sha256(policy_json.encode()).digest()
        parts.append(policy_hash)
        
        return b"".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "mfqp_version": MFQP_VERSION,
            "message_type": "query_response",
            "query_id": self.query_id,
            "status": self.status.value,
            "payload": self.payload,
            "redactions": self.redactions,
            "results_count": self.results_count,
            "freshness_timestamp": self.freshness_timestamp.isoformat(),
            "attestation": self.attestation.to_dict(),
            "timestamp": self.timestamp.isoformat(),
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> QueryResponse:
        def parse_ts(s: str) -> datetime:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return datetime.fromisoformat(s)
        
        return QueryResponse(
            query_id=data["query_id"],
            status=ResponseStatus(data["status"]),
            payload=data.get("payload"),
            redactions=data.get("redactions", []),
            results_count=data.get("results_count", 0),
            freshness_timestamp=parse_ts(data["freshness_timestamp"]),
            attestation=Attestation.from_dict(data["attestation"]),
            timestamp=parse_ts(data["timestamp"]),
        )


# =============================================================================
# CRYPTOGRAPHIC FUNCTIONS
# =============================================================================

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new Ed25519 keypair.
    
    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    if not CRYPTO_AVAILABLE:
        raise CryptoUnavailableError()
    
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    
    return private_bytes, public_bytes


def compute_key_fingerprint(public_key_bytes: bytes) -> str:
    """Compute the SHA-256 fingerprint of a public key."""
    if len(public_key_bytes) != 32:
        raise ValidationError("public key must be 32 bytes", "public_key")
    return hashlib.sha256(public_key_bytes).hexdigest()


def sign_message(message: MFQPMessage, private_key: bytes) -> bytes:
    """
    Sign an MFQP message with Ed25519.
    
    Args:
        message: The MFQP message to sign
        private_key: Raw Ed25519 private key bytes (32 bytes)
    
    Returns:
        64-byte Ed25519 signature
    """
    if not CRYPTO_AVAILABLE:
        raise CryptoUnavailableError()
    
    if len(private_key) != 32:
        raise ValidationError("private key must be 32 bytes", "private_key")
    
    try:
        key = Ed25519PrivateKey.from_private_bytes(private_key)
        canonical_bytes = message.to_canonical_bytes()
        return key.sign(canonical_bytes)
    except Exception as e:
        raise SignatureError(f"Failed to sign message: {e}") from e


def verify_signature(
    message: MFQPMessage,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """
    Verify an Ed25519 signature on an MFQP message.
    
    Args:
        message: The MFQP message that was signed
        signature: The 64-byte Ed25519 signature
        public_key: Raw Ed25519 public key bytes (32 bytes)
    
    Returns:
        True if signature is valid, False otherwise
    """
    if not CRYPTO_AVAILABLE:
        raise CryptoUnavailableError()
    
    if len(public_key) != 32:
        return False
    
    if len(signature) != 64:
        return False
    
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        canonical_bytes = message.to_canonical_bytes()
        key.verify(signature, canonical_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def compute_response_hash(payload: Dict[str, Any]) -> str:
    """Compute SHA-256 hash of a response payload."""
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload_json.encode()).hexdigest()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _length_prefix_string(s: str) -> bytes:
    """Encode a string with a 2-byte big-endian length prefix."""
    encoded = s.encode("utf-8")
    length = len(encoded)
    if length > 65535:
        raise MessageSizeError(
            f"String too long for length prefix: {length} bytes",
            65535,
            length
        )
    return struct.pack(">H", length) + encoded


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Classes
    "MFQPMessage",
    "GhostQuery",
    "QueryResponse",
    "Attestation",
    "ReplayProtector",
    # Enums
    "AuthLevel",
    "ResponseStatus",
    # Functions
    "generate_keypair",
    "compute_key_fingerprint",
    "sign_message",
    "verify_signature",
    "compute_response_hash",
    # Validation
    "validate_uuid",
    "validate_company_slug",
    "validate_intent",
    "validate_intent_class",
    "validate_timestamp",
    # Constants
    "MFQP_VERSION",
    "MAX_INTENT_LENGTH",
    "MAX_PAYLOAD_SIZE_BYTES",
    # Exceptions
    "MFQPError",
    "ValidationError",
    "SignatureError",
    "CryptoUnavailableError",
    "ReplayError",
    "MessageSizeError",
]
