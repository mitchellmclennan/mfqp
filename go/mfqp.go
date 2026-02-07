// Package protocol provides the MFQP (Metalogue Federated Query Protocol) v1.0
// reference implementation for Go.
//
// MFQP enables privacy-preserving, cryptographically attested queries between
// AI systems operated by different organizations through "Ghost Queries" —
// intent-only transmissions that reveal purpose without exposing raw data.
//
// Example usage:
//
//	query, err := protocol.NewGhostQuery(protocol.GhostQueryParams{
//	    SourceCompany: "acme-corp",
//	    TargetCompany: "globex-inc",
//	    Intent:        "What is the inventory status?",
//	    IntentClass:   "inventory.status",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	signature, err := protocol.SignMessage(query, privateKey)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	valid := protocol.VerifySignature(query, signature, publicKey)
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// CONSTANTS
// =============================================================================

// MFQPVersion is the protocol version.
const MFQPVersion = "1.0"

// MessageVersionByte is the version marker in canonical byte encoding.
const MessageVersionByte = 0x01

// Security limits
const (
	MaxIntentLength          = 2000
	MaxCompanySlugLength     = 128
	MaxIntentClassLength     = 256
	MaxResultsCount          = 1000
	MaxRedactedFields        = 100
	MaxPayloadSizeBytes      = 10 * 1024 * 1024 // 10MB
	MaxTimestampDriftSeconds = 300              // 5 minutes
)

// Validation patterns
var (
	companySlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,126}[a-z0-9]$|^[a-z0-9]$`)
	intentClassPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*$`)
)

// =============================================================================
// ERRORS
// =============================================================================

// MFQPError is the base error type for MFQP operations.
type MFQPError struct {
	Code    string
	Message string
	Field   string
}

func (e *MFQPError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("[%s] %s (field: %s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Common errors
var (
	ErrCryptoUnavailable = &MFQPError{Code: "X002", Message: "cryptography unavailable"}
	ErrInvalidSignature  = &MFQPError{Code: "E001", Message: "invalid signature"}
	ErrReplayDetected    = &MFQPError{Code: "E007", Message: "replay attack detected"}
)

// NewValidationError creates a validation error.
func NewValidationError(message, field string) *MFQPError {
	return &MFQPError{Code: "V001", Message: message, Field: field}
}

// NewMessageSizeError creates a message size error.
func NewMessageSizeError(message string, limit, actual int) *MFQPError {
	return &MFQPError{
		Code:    "E008",
		Message: fmt.Sprintf("%s (limit: %d, actual: %d)", message, limit, actual),
	}
}

// =============================================================================
// ENUMS
// =============================================================================

// AuthLevel represents the authentication level of a federation partner.
type AuthLevel string

const (
	AuthLevelPending  AuthLevel = "pending"
	AuthLevelVerified AuthLevel = "verified"
	AuthLevelTrusted  AuthLevel = "trusted"
)

// IsValid returns true if the auth level is valid.
func (a AuthLevel) IsValid() bool {
	switch a {
	case AuthLevelPending, AuthLevelVerified, AuthLevelTrusted:
		return true
	}
	return false
}

// ResponseStatus represents the status of a query response.
type ResponseStatus string

const (
	ResponseStatusSuccess     ResponseStatus = "success"
	ResponseStatusDenied      ResponseStatus = "denied"
	ResponseStatusTimeout     ResponseStatus = "timeout"
	ResponseStatusError       ResponseStatus = "error"
	ResponseStatusRateLimited ResponseStatus = "rate_limited"
)

// IsValid returns true if the response status is valid.
func (r ResponseStatus) IsValid() bool {
	switch r {
	case ResponseStatusSuccess, ResponseStatusDenied, ResponseStatusTimeout,
		ResponseStatusError, ResponseStatusRateLimited:
		return true
	}
	return false
}

// =============================================================================
// REPLAY PROTECTION
// =============================================================================

// ReplayProtector provides thread-safe replay attack protection.
type ReplayProtector struct {
	mu          sync.RWMutex
	seen        map[string]time.Time
	window      time.Duration
	maxEntries  int
	lastCleanup time.Time
}

// NewReplayProtector creates a new replay protector.
func NewReplayProtector(windowSeconds, maxEntries int) *ReplayProtector {
	return &ReplayProtector{
		seen:        make(map[string]time.Time),
		window:      time.Duration(windowSeconds) * time.Second,
		maxEntries:  maxEntries,
		lastCleanup: time.Now(),
	}
}

// CheckAndRecord checks if queryID has been seen. Returns true if new, false if replay.
func (rp *ReplayProtector) CheckAndRecord(queryID string) bool {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	now := time.Now()

	// Periodic cleanup
	if len(rp.seen) > rp.maxEntries || now.Sub(rp.lastCleanup) > time.Minute {
		cutoff := now.Add(-rp.window)
		for k, v := range rp.seen {
			if v.Before(cutoff) {
				delete(rp.seen, k)
			}
		}
		rp.lastCleanup = now
	}

	if _, exists := rp.seen[queryID]; exists {
		return false
	}

	rp.seen[queryID] = now
	return true
}

// Global replay protector
var globalReplayProtector = NewReplayProtector(600, 100000)

// =============================================================================
// GHOST QUERY
// =============================================================================

// GhostQuery represents an intent-only federated query.
type GhostQuery struct {
	QueryID                  string    `json:"query_id"`
	SourceCompany            string    `json:"source_company"`
	TargetCompany            string    `json:"target_company"`
	Intent                   string    `json:"intent"`
	IntentClass              string    `json:"intent_class"`
	AuthLevel                AuthLevel `json:"auth_level"`
	FreshnessRequiredSeconds int       `json:"freshness_required_seconds"`
	Timestamp                time.Time `json:"timestamp"`
}

// GhostQueryParams are the parameters for creating a new GhostQuery.
type GhostQueryParams struct {
	SourceCompany            string
	TargetCompany            string
	Intent                   string
	IntentClass              string
	AuthLevel                AuthLevel // Optional, defaults to AuthLevelVerified
	FreshnessRequiredSeconds int       // Optional, defaults to 300
}

// NewGhostQuery creates a new Ghost Query with generated ID and timestamp.
func NewGhostQuery(params GhostQueryParams) (*GhostQuery, error) {
	if params.AuthLevel == "" {
		params.AuthLevel = AuthLevelVerified
	}
	if params.FreshnessRequiredSeconds == 0 {
		params.FreshnessRequiredSeconds = 300
	}

	q := &GhostQuery{
		QueryID:                  uuid.New().String(),
		SourceCompany:            params.SourceCompany,
		TargetCompany:            params.TargetCompany,
		Intent:                   params.Intent,
		IntentClass:              params.IntentClass,
		AuthLevel:                params.AuthLevel,
		FreshnessRequiredSeconds: params.FreshnessRequiredSeconds,
		Timestamp:                time.Now().UTC(),
	}

	if err := q.Validate(); err != nil {
		return nil, err
	}

	return q, nil
}

// Validate validates all fields of the GhostQuery.
func (q *GhostQuery) Validate() error {
	// Validate query_id
	if _, err := uuid.Parse(q.QueryID); err != nil {
		return NewValidationError("invalid UUID format", "query_id")
	}

	// Validate source_company
	if q.SourceCompany == "" {
		return NewValidationError("source_company is required", "source_company")
	}
	if len(q.SourceCompany) > MaxCompanySlugLength {
		return NewValidationError(
			fmt.Sprintf("exceeds max length of %d", MaxCompanySlugLength),
			"source_company",
		)
	}
	if !companySlugPattern.MatchString(q.SourceCompany) {
		return NewValidationError("must be lowercase alphanumeric with hyphens", "source_company")
	}

	// Validate target_company
	if q.TargetCompany == "" {
		return NewValidationError("target_company is required", "target_company")
	}
	if len(q.TargetCompany) > MaxCompanySlugLength {
		return NewValidationError(
			fmt.Sprintf("exceeds max length of %d", MaxCompanySlugLength),
			"target_company",
		)
	}
	if !companySlugPattern.MatchString(q.TargetCompany) {
		return NewValidationError("must be lowercase alphanumeric with hyphens", "target_company")
	}

	// Source and target must differ
	if q.SourceCompany == q.TargetCompany {
		return NewValidationError("source and target must be different", "source_company")
	}

	// Validate intent
	if q.Intent == "" {
		return NewValidationError("intent is required", "intent")
	}
	if len(q.Intent) > MaxIntentLength {
		return NewValidationError(
			fmt.Sprintf("exceeds max length of %d", MaxIntentLength),
			"intent",
		)
	}

	// Validate intent_class
	if q.IntentClass == "" {
		return NewValidationError("intent_class is required", "intent_class")
	}
	if len(q.IntentClass) > MaxIntentClassLength {
		return NewValidationError(
			fmt.Sprintf("exceeds max length of %d", MaxIntentClassLength),
			"intent_class",
		)
	}
	if !intentClassPattern.MatchString(q.IntentClass) {
		return NewValidationError("must match pattern: category.subcategory", "intent_class")
	}

	// Validate auth_level
	if !q.AuthLevel.IsValid() {
		return NewValidationError("must be pending, verified, or trusted", "auth_level")
	}

	// Validate freshness
	if q.FreshnessRequiredSeconds < 0 {
		return NewValidationError("must be non-negative", "freshness_required_seconds")
	}
	if q.FreshnessRequiredSeconds > 86400*7 {
		return NewValidationError("cannot exceed 7 days", "freshness_required_seconds")
	}

	// Validate timestamp drift
	drift := time.Since(q.Timestamp).Abs()
	if drift.Seconds() > MaxTimestampDriftSeconds {
		return NewValidationError(
			fmt.Sprintf("%.0fs from current time (max: %ds)", drift.Seconds(), MaxTimestampDriftSeconds),
			"timestamp",
		)
	}

	return nil
}

// CheckReplay checks for replay attack. Returns error if detected.
func (q *GhostQuery) CheckReplay() error {
	if !globalReplayProtector.CheckAndRecord(q.QueryID) {
		return ErrReplayDetected
	}
	return nil
}

// ToCanonicalBytes converts the GhostQuery to canonical bytes for signing.
func (q *GhostQuery) ToCanonicalBytes() ([]byte, error) {
	var buf []byte

	// Version byte
	buf = append(buf, MessageVersionByte)

	// MFQP version (length-prefixed)
	versionBytes, err := lengthPrefixString(MFQPVersion)
	if err != nil {
		return nil, err
	}
	buf = append(buf, versionBytes...)

	// Query ID as UUID bytes
	queryUUID, err := uuid.Parse(q.QueryID)
	if err != nil {
		return nil, err
	}
	buf = append(buf, queryUUID[:]...)

	// String fields (length-prefixed)
	fields := []string{q.SourceCompany, q.TargetCompany, q.Intent, q.IntentClass, string(q.AuthLevel)}
	for _, field := range fields {
		fieldBytes, err := lengthPrefixString(field)
		if err != nil {
			return nil, err
		}
		buf = append(buf, fieldBytes...)
	}

	// Freshness (big-endian uint32)
	freshnessBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(freshnessBytes, uint32(q.FreshnessRequiredSeconds))
	buf = append(buf, freshnessBytes...)

	// Timestamp as microseconds since epoch (big-endian uint64)
	timestampUs := uint64(q.Timestamp.UnixMicro())
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, timestampUs)
	buf = append(buf, timestampBytes...)

	return buf, nil
}

// ToDict converts the GhostQuery to a map for JSON serialization.
func (q *GhostQuery) ToDict() map[string]interface{} {
	return map[string]interface{}{
		"mfqp_version":               MFQPVersion,
		"message_type":               "ghost_query",
		"query_id":                   q.QueryID,
		"source_company":             q.SourceCompany,
		"target_company":             q.TargetCompany,
		"intent":                     q.Intent,
		"intent_class":               q.IntentClass,
		"auth_level":                 string(q.AuthLevel),
		"freshness_required_seconds": q.FreshnessRequiredSeconds,
		"timestamp":                  q.Timestamp.Format(time.RFC3339Nano),
	}
}

// ToJSON serializes the GhostQuery to JSON.
func (q *GhostQuery) ToJSON() ([]byte, error) {
	return json.Marshal(q.ToDict())
}

// ParseGhostQuery parses a GhostQuery from a map.
func ParseGhostQuery(data map[string]interface{}, skipReplayCheck bool) (*GhostQuery, error) {
	// Validate protocol version
	if v, ok := data["mfqp_version"].(string); ok {
		if len(v) > 0 && v[0] != '1' {
			return nil, NewValidationError(
				fmt.Sprintf("unsupported MFQP version: %s (supported: 1.x)", v),
				"mfqp_version",
			)
		}
	}

	q := &GhostQuery{}

	if v, ok := data["query_id"].(string); ok {
		q.QueryID = v
	}
	if v, ok := data["source_company"].(string); ok {
		q.SourceCompany = v
	}
	if v, ok := data["target_company"].(string); ok {
		q.TargetCompany = v
	}
	if v, ok := data["intent"].(string); ok {
		q.Intent = v
	}
	if v, ok := data["intent_class"].(string); ok {
		q.IntentClass = v
	}
	if v, ok := data["auth_level"].(string); ok {
		q.AuthLevel = AuthLevel(v)
	}
	if v, ok := data["freshness_required_seconds"].(float64); ok {
		q.FreshnessRequiredSeconds = int(v)
	}
	if v, ok := data["timestamp"].(string); ok {
		var parseErr error
		q.Timestamp, parseErr = time.Parse(time.RFC3339Nano, v)
		if parseErr != nil {
			q.Timestamp, parseErr = time.Parse(time.RFC3339, v)
			if parseErr != nil {
				// Try with Z suffix replaced
				normalized := strings.TrimSuffix(v, "Z") + "+00:00"
				q.Timestamp, parseErr = time.Parse(time.RFC3339, normalized)
				if parseErr != nil {
					return nil, NewValidationError(
						fmt.Sprintf("invalid timestamp format: %s", v),
						"timestamp",
					)
				}
			}
		}
	}

	if err := q.Validate(); err != nil {
		return nil, err
	}

	if !skipReplayCheck {
		if err := q.CheckReplay(); err != nil {
			return nil, err
		}
	}

	return q, nil
}

// ParseQueryResponse parses a QueryResponse from a map.
func ParseQueryResponse(data map[string]interface{}) (*QueryResponse, error) {
	// Validate protocol version
	if v, ok := data["mfqp_version"].(string); ok {
		if len(v) > 0 && v[0] != '1' {
			return nil, NewValidationError(
				fmt.Sprintf("unsupported MFQP version: %s (supported: 1.x)", v),
				"mfqp_version",
			)
		}
	}

	r := &QueryResponse{}

	if v, ok := data["query_id"].(string); ok {
		r.QueryID = v
	}
	if v, ok := data["status"].(string); ok {
		r.Status = ResponseStatus(v)
	}
	if v, ok := data["payload"].(map[string]interface{}); ok {
		r.Payload = v
	}
	if v, ok := data["redactions"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				r.Redactions = append(r.Redactions, s)
			}
		}
	}
	if v, ok := data["results_count"].(float64); ok {
		r.ResultsCount = int(v)
	}
	if v, ok := data["freshness_timestamp"].(string); ok {
		var parseErr error
		r.FreshnessTimestamp, parseErr = time.Parse(time.RFC3339Nano, v)
		if parseErr != nil {
			r.FreshnessTimestamp, _ = time.Parse(time.RFC3339, v)
		}
	}
	if v, ok := data["timestamp"].(string); ok {
		var parseErr error
		r.Timestamp, parseErr = time.Parse(time.RFC3339Nano, v)
		if parseErr != nil {
			r.Timestamp, _ = time.Parse(time.RFC3339, v)
		}
	}

	// Parse attestation
	if attData, ok := data["attestation"].(map[string]interface{}); ok {
		att := &Attestation{}
		if v, ok := attData["attestation_id"].(string); ok {
			att.AttestationID = v
		}
		if v, ok := attData["response_hash"].(string); ok {
			att.ResponseHash = v
		}
		if v, ok := attData["signer_key_id"].(string); ok {
			att.SignerKeyID = v
		}
		if v, ok := attData["policy_snapshot"].(map[string]interface{}); ok {
			att.PolicySnapshot = v
		}
		if v, ok := attData["signature"].(string); ok {
			att.Signature, _ = base64.StdEncoding.DecodeString(v)
		}
		r.Attestation = att
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	return r, nil
}

// =============================================================================
// ATTESTATION
// =============================================================================

// Attestation represents the cryptographic attestation of a response.
type Attestation struct {
	AttestationID  string                 `json:"attestation_id"`
	ResponseHash   string                 `json:"response_hash"`
	SignerKeyID    string                 `json:"signer_key_id"`
	PolicySnapshot map[string]interface{} `json:"policy_snapshot"`
	Signature      []byte                 `json:"signature"`
}

// Validate validates the attestation.
func (a *Attestation) Validate() error {
	if _, err := uuid.Parse(a.AttestationID); err != nil {
		return NewValidationError("invalid UUID format", "attestation_id")
	}
	if len(a.ResponseHash) != 64 {
		return NewValidationError("must be 64 hex characters", "response_hash")
	}
	if len(a.SignerKeyID) != 64 {
		return NewValidationError("must be 64 hex characters", "signer_key_id")
	}
	return nil
}

// ToDict converts the Attestation to a map.
func (a *Attestation) ToDict() map[string]interface{} {
	return map[string]interface{}{
		"attestation_id":  a.AttestationID,
		"response_hash":   a.ResponseHash,
		"signer_key_id":   a.SignerKeyID,
		"policy_snapshot": a.PolicySnapshot,
		"signature":       base64.StdEncoding.EncodeToString(a.Signature),
	}
}

// =============================================================================
// QUERY RESPONSE
// =============================================================================

// QueryResponse represents an attested answer to a Ghost Query.
type QueryResponse struct {
	QueryID            string                 `json:"query_id"`
	Status             ResponseStatus         `json:"status"`
	Payload            map[string]interface{} `json:"payload,omitempty"`
	Redactions         []string               `json:"redactions"`
	ResultsCount       int                    `json:"results_count"`
	FreshnessTimestamp time.Time              `json:"freshness_timestamp"`
	Attestation        *Attestation           `json:"attestation"`
	Timestamp          time.Time              `json:"timestamp"`
}

// Validate validates all fields of the QueryResponse.
func (r *QueryResponse) Validate() error {
	if _, err := uuid.Parse(r.QueryID); err != nil {
		return NewValidationError("invalid UUID format", "query_id")
	}
	if !r.Status.IsValid() {
		return NewValidationError("invalid status", "status")
	}
	if r.ResultsCount < 0 {
		return NewValidationError("must be non-negative", "results_count")
	}
	if r.ResultsCount > MaxResultsCount {
		return NewValidationError(
			fmt.Sprintf("exceeds max of %d", MaxResultsCount),
			"results_count",
		)
	}
	if len(r.Redactions) > MaxRedactedFields {
		return NewValidationError(
			fmt.Sprintf("exceeds max of %d fields", MaxRedactedFields),
			"redactions",
		)
	}
	if r.Attestation != nil {
		if err := r.Attestation.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ToCanonicalBytes converts the QueryResponse to canonical bytes for verification.
func (r *QueryResponse) ToCanonicalBytes() ([]byte, error) {
	var buf []byte

	// Version byte
	buf = append(buf, MessageVersionByte)

	// Response hash (32 bytes)
	responseHashBytes, err := hex.DecodeString(r.Attestation.ResponseHash)
	if err != nil {
		return nil, err
	}
	buf = append(buf, responseHashBytes...)

	// Timestamp as microseconds
	timestampUs := uint64(r.FreshnessTimestamp.UnixMicro())
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, timestampUs)
	buf = append(buf, timestampBytes...)

	// Policy snapshot hash
	policyJSON, err := json.Marshal(r.Attestation.PolicySnapshot)
	if err != nil {
		return nil, err
	}
	policyHash := sha256.Sum256(policyJSON)
	buf = append(buf, policyHash[:]...)

	return buf, nil
}

// ToDict converts the QueryResponse to a map.
func (r *QueryResponse) ToDict() map[string]interface{} {
	return map[string]interface{}{
		"mfqp_version":        MFQPVersion,
		"message_type":        "query_response",
		"query_id":            r.QueryID,
		"status":              string(r.Status),
		"payload":             r.Payload,
		"redactions":          r.Redactions,
		"results_count":       r.ResultsCount,
		"freshness_timestamp": r.FreshnessTimestamp.Format(time.RFC3339Nano),
		"attestation":         r.Attestation.ToDict(),
		"timestamp":           r.Timestamp.Format(time.RFC3339Nano),
	}
}

// =============================================================================
// CRYPTOGRAPHIC FUNCTIONS
// =============================================================================

// GenerateKeypair generates a new Ed25519 keypair.
// Returns (privateKey, publicKey, error).
func GenerateKeypair() ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey[:32], publicKey, nil
}

// ComputeKeyFingerprint computes the SHA-256 fingerprint of a public key.
func ComputeKeyFingerprint(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString(hash[:])
}

// Message is an interface for signable MFQP messages.
type Message interface {
	ToCanonicalBytes() ([]byte, error)
}

// SignMessage signs an MFQP message with Ed25519.
func SignMessage(message Message, privateKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, NewValidationError("private key must be 32 bytes", "private_key")
	}

	canonicalBytes, err := message.ToCanonicalBytes()
	if err != nil {
		return nil, err
	}

	// Expand private key to full 64 bytes for ed25519 package
	fullPrivateKey := ed25519.NewKeyFromSeed(privateKey)
	signature := ed25519.Sign(fullPrivateKey, canonicalBytes)

	return signature, nil
}

// VerifySignature verifies an Ed25519 signature on an MFQP message.
func VerifySignature(message Message, signature, publicKey []byte) bool {
	if len(publicKey) != 32 {
		return false
	}
	if len(signature) != 64 {
		return false
	}

	canonicalBytes, err := message.ToCanonicalBytes()
	if err != nil {
		return false
	}

	return ed25519.Verify(publicKey, canonicalBytes, signature)
}

// ComputeResponseHash computes SHA-256 hash of a response payload.
func ComputeResponseHash(payload map[string]interface{}) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(payloadJSON)
	return hex.EncodeToString(hash[:]), nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func lengthPrefixString(s string) ([]byte, error) {
	encoded := []byte(s)
	length := len(encoded)
	if length > 65535 {
		return nil, NewMessageSizeError(
			fmt.Sprintf("string too long for length prefix: %d bytes", length),
			65535,
			length,
		)
	}
	result := make([]byte, 2+length)
	binary.BigEndian.PutUint16(result[:2], uint16(length))
	copy(result[2:], encoded)
	return result, nil
}
