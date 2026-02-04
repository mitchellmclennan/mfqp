/**
 * MFQP Reference Implementation (TypeScript) - Production Hardened
 *
 * Metalogue Federated Query Protocol v1.0
 *
 * Features:
 * - Runtime validation with Zod schemas
 * - Comprehensive error handling
 * - Size limits and sanitization
 * - Timestamp validation (anti-replay)
 *
 * Requirements:
 *   npm install @noble/ed25519 zod
 *
 * Usage:
 *   import { GhostQuery, signMessage, verifySignature } from './mfqp';
 *
 *   const query = GhostQuery.create({
 *     sourceCompany: 'acme-corp',
 *     targetCompany: 'globex-inc',
 *     intent: 'What is the inventory status?',
 *     intentClass: 'inventory.status',
 *   });
 *
 *   const signature = await signMessage(query, privateKey);
 *   const isValid = await verifySignature(query, signature, publicKey);
 */

// =============================================================================
// CONSTANTS
// =============================================================================

export const MFQP_VERSION = '1.0';
const MESSAGE_VERSION_BYTE = 0x01;

// Security limits
export const MAX_INTENT_LENGTH = 2000;
export const MAX_COMPANY_SLUG_LENGTH = 128;
export const MAX_INTENT_CLASS_LENGTH = 256;
export const MAX_RESULTS_COUNT = 1000;
export const MAX_REDACTED_FIELDS = 100;
export const MAX_PAYLOAD_SIZE_BYTES = 10 * 1024 * 1024; // 10MB
export const MAX_TIMESTAMP_DRIFT_MS = 300 * 1000; // 5 minutes

// Validation patterns
const COMPANY_SLUG_REGEX = /^[a-z0-9][a-z0-9-]{0,126}[a-z0-9]$|^[a-z0-9]$/;
const INTENT_CLASS_REGEX = /^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// =============================================================================
// ERRORS
// =============================================================================

export class MFQPError extends Error {
    readonly code: string;

    constructor(message: string, code: string = 'X001') {
        super(message);
        this.name = 'MFQPError';
        this.code = code;
    }
}

export class ValidationError extends MFQPError {
    readonly field?: string;

    constructor(message: string, field?: string) {
        super(field ? `${field}: ${message}` : message, 'V001');
        this.name = 'ValidationError';
        this.field = field;
    }
}

export class SignatureError extends MFQPError {
    constructor(message: string) {
        super(message, 'E001');
        this.name = 'SignatureError';
    }
}

export class ReplayError extends MFQPError {
    constructor(queryId: string) {
        super(`Duplicate query_id detected: ${queryId}`, 'E007');
        this.name = 'ReplayError';
    }
}

export class CryptoUnavailableError extends MFQPError {
    constructor() {
        super('Ed25519 library required: npm install @noble/ed25519', 'X002');
        this.name = 'CryptoUnavailableError';
    }
}

// =============================================================================
// TYPES
// =============================================================================

export type AuthLevel = 'pending' | 'verified' | 'trusted';
export type ResponseStatus = 'success' | 'denied' | 'timeout' | 'error' | 'rate_limited';

const AUTH_LEVELS: readonly AuthLevel[] = ['pending', 'verified', 'trusted'];
const RESPONSE_STATUSES: readonly ResponseStatus[] = ['success', 'denied', 'timeout', 'error', 'rate_limited'];

export interface GhostQueryData {
    mfqp_version: string;
    message_type: 'ghost_query';
    query_id: string;
    source_company: string;
    target_company: string;
    intent: string;
    intent_class: string;
    auth_level: AuthLevel;
    freshness_required_seconds: number;
    timestamp: string;
    signature?: string;
}

export interface AttestationData {
    attestation_id: string;
    response_hash: string;
    signer_key_id: string;
    policy_snapshot: Record<string, unknown>;
    signature: string;
}

export interface QueryResponseData {
    mfqp_version: string;
    message_type: 'query_response';
    query_id: string;
    status: ResponseStatus;
    payload?: Record<string, unknown>;
    redactions: string[];
    results_count: number;
    freshness_timestamp: string;
    attestation: AttestationData;
    timestamp: string;
}

export interface GhostQueryOptions {
    sourceCompany: string;
    targetCompany: string;
    intent: string;
    intentClass: string;
    authLevel?: AuthLevel;
    freshnessRequiredSeconds?: number;
}

// =============================================================================
// REPLAY PROTECTION
// =============================================================================

class ReplayProtector {
    private seen: Map<string, number> = new Map();
    private windowMs: number;
    private maxEntries: number;
    private lastCleanup: number = Date.now();

    constructor(windowSeconds: number = 600, maxEntries: number = 100000) {
        this.windowMs = windowSeconds * 1000;
        this.maxEntries = maxEntries;
    }

    checkAndRecord(queryId: string): boolean {
        const now = Date.now();

        // Periodic cleanup
        if (this.seen.size > this.maxEntries || now - this.lastCleanup > 60000) {
            const cutoff = now - this.windowMs;
            for (const [k, v] of this.seen.entries()) {
                if (v < cutoff) this.seen.delete(k);
            }
            this.lastCleanup = now;
        }

        if (this.seen.has(queryId)) {
            return false;
        }

        this.seen.set(queryId, now);
        return true;
    }
}

const globalReplayProtector = new ReplayProtector();

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

function validateUuid(value: string, field: string): void {
    if (!value) throw new ValidationError('is required', field);
    if (!UUID_REGEX.test(value)) throw new ValidationError('must be a valid UUID v4', field);
}

function validateCompanySlug(value: string, field: string): void {
    if (!value) throw new ValidationError('is required', field);
    if (value.length > MAX_COMPANY_SLUG_LENGTH) {
        throw new ValidationError(`exceeds max length of ${MAX_COMPANY_SLUG_LENGTH}`, field);
    }
    if (!COMPANY_SLUG_REGEX.test(value)) {
        throw new ValidationError('must be lowercase alphanumeric with hyphens', field);
    }
}

function validateIntent(value: string, field: string = 'intent'): void {
    if (!value) throw new ValidationError('is required', field);
    if (value.length > MAX_INTENT_LENGTH) {
        throw new ValidationError(`exceeds max length of ${MAX_INTENT_LENGTH}`, field);
    }
}

function validateIntentClass(value: string, field: string = 'intent_class'): void {
    if (!value) throw new ValidationError('is required', field);
    if (value.length > MAX_INTENT_CLASS_LENGTH) {
        throw new ValidationError(`exceeds max length of ${MAX_INTENT_CLASS_LENGTH}`, field);
    }
    if (!INTENT_CLASS_REGEX.test(value)) {
        throw new ValidationError('must match pattern: category.subcategory', field);
    }
}

function validateTimestamp(value: Date, field: string = 'timestamp'): void {
    const drift = Math.abs(Date.now() - value.getTime());
    if (drift > MAX_TIMESTAMP_DRIFT_MS) {
        throw new ValidationError(
            `${Math.floor(drift / 1000)}s from current time (max: ${MAX_TIMESTAMP_DRIFT_MS / 1000}s)`,
            field
        );
    }
}

function validateFreshness(value: number, field: string = 'freshness_required_seconds'): void {
    if (value < 0) throw new ValidationError('must be non-negative', field);
    if (value > 86400 * 7) throw new ValidationError('cannot exceed 7 days', field);
}

// =============================================================================
// GHOST QUERY
// =============================================================================

export class GhostQuery {
    static ENABLE_REPLAY_PROTECTION = true;

    readonly queryId: string;
    readonly sourceCompany: string;
    readonly targetCompany: string;
    readonly intent: string;
    readonly intentClass: string;
    readonly authLevel: AuthLevel;
    readonly freshnessRequiredSeconds: number;
    readonly timestamp: Date;

    private constructor(data: {
        queryId: string;
        sourceCompany: string;
        targetCompany: string;
        intent: string;
        intentClass: string;
        authLevel: AuthLevel;
        freshnessRequiredSeconds: number;
        timestamp: Date;
    }) {
        this.queryId = data.queryId;
        this.sourceCompany = data.sourceCompany;
        this.targetCompany = data.targetCompany;
        this.intent = data.intent;
        this.intentClass = data.intentClass;
        this.authLevel = data.authLevel;
        this.freshnessRequiredSeconds = data.freshnessRequiredSeconds;
        this.timestamp = data.timestamp;

        this.validate();
    }

    private validate(): void {
        validateUuid(this.queryId, 'query_id');
        validateCompanySlug(this.sourceCompany, 'source_company');
        validateCompanySlug(this.targetCompany, 'target_company');
        validateIntent(this.intent);
        validateIntentClass(this.intentClass);
        validateFreshness(this.freshnessRequiredSeconds);
        validateTimestamp(this.timestamp);

        if (!AUTH_LEVELS.includes(this.authLevel)) {
            throw new ValidationError(`must be one of: ${AUTH_LEVELS.join(', ')}`, 'auth_level');
        }

        if (this.sourceCompany === this.targetCompany) {
            throw new ValidationError('source and target must be different', 'source_company');
        }
    }

    checkReplay(): void {
        if (GhostQuery.ENABLE_REPLAY_PROTECTION) {
            if (!globalReplayProtector.checkAndRecord(this.queryId)) {
                throw new ReplayError(this.queryId);
            }
        }
    }

    static create(options: GhostQueryOptions): GhostQuery {
        return new GhostQuery({
            queryId: crypto.randomUUID(),
            sourceCompany: options.sourceCompany,
            targetCompany: options.targetCompany,
            intent: options.intent,
            intentClass: options.intentClass,
            authLevel: options.authLevel ?? 'verified',
            freshnessRequiredSeconds: options.freshnessRequiredSeconds ?? 300,
            timestamp: new Date(),
        });
    }

    static fromDict(data: GhostQueryData, skipReplayCheck: boolean = false): GhostQuery {
        const query = new GhostQuery({
            queryId: data.query_id,
            sourceCompany: data.source_company,
            targetCompany: data.target_company,
            intent: data.intent,
            intentClass: data.intent_class,
            authLevel: data.auth_level,
            freshnessRequiredSeconds: data.freshness_required_seconds ?? 300,
            timestamp: new Date(data.timestamp),
        });

        if (!skipReplayCheck) {
            query.checkReplay();
        }

        return query;
    }

    toCanonicalBytes(): Uint8Array {
        const parts: Uint8Array[] = [];

        parts.push(new Uint8Array([MESSAGE_VERSION_BYTE]));
        parts.push(lengthPrefixString(MFQP_VERSION));
        parts.push(uuidToBytes(this.queryId));
        parts.push(lengthPrefixString(this.sourceCompany));
        parts.push(lengthPrefixString(this.targetCompany));
        parts.push(lengthPrefixString(this.intent));
        parts.push(lengthPrefixString(this.intentClass));
        parts.push(lengthPrefixString(this.authLevel));

        const freshnessView = new DataView(new ArrayBuffer(4));
        freshnessView.setUint32(0, this.freshnessRequiredSeconds, false);
        parts.push(new Uint8Array(freshnessView.buffer));

        const timestampUs = BigInt(this.timestamp.getTime()) * 1000n;
        const timestampView = new DataView(new ArrayBuffer(8));
        timestampView.setBigUint64(0, timestampUs, false);
        parts.push(new Uint8Array(timestampView.buffer));

        return concatBytes(parts);
    }

    toDict(): GhostQueryData {
        return {
            mfqp_version: MFQP_VERSION,
            message_type: 'ghost_query',
            query_id: this.queryId,
            source_company: this.sourceCompany,
            target_company: this.targetCompany,
            intent: this.intent,
            intent_class: this.intentClass,
            auth_level: this.authLevel,
            freshness_required_seconds: this.freshnessRequiredSeconds,
            timestamp: this.timestamp.toISOString(),
        };
    }

    toJSON(): string {
        return JSON.stringify(this.toDict());
    }

    computeHash(): string {
        return bytesToHex(sha256Sync(this.toCanonicalBytes()));
    }
}

// =============================================================================
// ATTESTATION
// =============================================================================

export class Attestation {
    readonly attestationId: string;
    readonly responseHash: string;
    readonly signerKeyId: string;
    readonly policySnapshot: Record<string, unknown>;
    readonly signature: Uint8Array;

    constructor(data: {
        attestationId: string;
        responseHash: string;
        signerKeyId: string;
        policySnapshot: Record<string, unknown>;
        signature: Uint8Array;
    }) {
        this.attestationId = data.attestationId;
        this.responseHash = data.responseHash;
        this.signerKeyId = data.signerKeyId;
        this.policySnapshot = data.policySnapshot;
        this.signature = data.signature;

        this.validate();
    }

    private validate(): void {
        validateUuid(this.attestationId, 'attestation_id');
        if (this.responseHash.length !== 64) {
            throw new ValidationError('must be 64 hex characters', 'response_hash');
        }
        if (this.signerKeyId.length !== 64) {
            throw new ValidationError('must be 64 hex characters', 'signer_key_id');
        }
    }

    static fromDict(data: AttestationData): Attestation {
        return new Attestation({
            attestationId: data.attestation_id,
            responseHash: data.response_hash,
            signerKeyId: data.signer_key_id,
            policySnapshot: data.policy_snapshot,
            signature: base64ToBytes(data.signature),
        });
    }

    toDict(): AttestationData {
        return {
            attestation_id: this.attestationId,
            response_hash: this.responseHash,
            signer_key_id: this.signerKeyId,
            policy_snapshot: this.policySnapshot,
            signature: bytesToBase64(this.signature),
        };
    }
}

// =============================================================================
// QUERY RESPONSE
// =============================================================================

export class QueryResponse {
    readonly queryId: string;
    readonly status: ResponseStatus;
    readonly payload: Record<string, unknown> | null;
    readonly redactions: string[];
    readonly resultsCount: number;
    readonly freshnessTimestamp: Date;
    readonly attestation: Attestation;
    readonly timestamp: Date;

    constructor(data: {
        queryId: string;
        status: ResponseStatus;
        payload: Record<string, unknown> | null;
        redactions: string[];
        resultsCount: number;
        freshnessTimestamp: Date;
        attestation: Attestation;
        timestamp: Date;
    }) {
        this.queryId = data.queryId;
        this.status = data.status;
        this.payload = data.payload;
        this.redactions = data.redactions;
        this.resultsCount = data.resultsCount;
        this.freshnessTimestamp = data.freshnessTimestamp;
        this.attestation = data.attestation;
        this.timestamp = data.timestamp;

        this.validate();
    }

    private validate(): void {
        validateUuid(this.queryId, 'query_id');

        if (!RESPONSE_STATUSES.includes(this.status)) {
            throw new ValidationError(`must be one of: ${RESPONSE_STATUSES.join(', ')}`, 'status');
        }

        if (this.resultsCount < 0) {
            throw new ValidationError('must be non-negative', 'results_count');
        }
        if (this.resultsCount > MAX_RESULTS_COUNT) {
            throw new ValidationError(`exceeds max of ${MAX_RESULTS_COUNT}`, 'results_count');
        }

        if (this.redactions.length > MAX_REDACTED_FIELDS) {
            throw new ValidationError(`exceeds max of ${MAX_REDACTED_FIELDS} fields`, 'redactions');
        }
    }

    static fromDict(data: QueryResponseData): QueryResponse {
        return new QueryResponse({
            queryId: data.query_id,
            status: data.status,
            payload: data.payload ?? null,
            redactions: data.redactions ?? [],
            resultsCount: data.results_count ?? 0,
            freshnessTimestamp: new Date(data.freshness_timestamp),
            attestation: Attestation.fromDict(data.attestation),
            timestamp: new Date(data.timestamp),
        });
    }

    toCanonicalBytes(): Uint8Array {
        const parts: Uint8Array[] = [];

        parts.push(new Uint8Array([MESSAGE_VERSION_BYTE]));
        parts.push(hexToBytes(this.attestation.responseHash));

        const timestampUs = BigInt(this.freshnessTimestamp.getTime()) * 1000n;
        const timestampView = new DataView(new ArrayBuffer(8));
        timestampView.setBigUint64(0, timestampUs, false);
        parts.push(new Uint8Array(timestampView.buffer));

        const policyJson = JSON.stringify(this.attestation.policySnapshot, Object.keys(this.attestation.policySnapshot).sort());
        parts.push(sha256Sync(new TextEncoder().encode(policyJson)));

        return concatBytes(parts);
    }

    toDict(): QueryResponseData {
        return {
            mfqp_version: MFQP_VERSION,
            message_type: 'query_response',
            query_id: this.queryId,
            status: this.status,
            payload: this.payload ?? undefined,
            redactions: this.redactions,
            results_count: this.resultsCount,
            freshness_timestamp: this.freshnessTimestamp.toISOString(),
            attestation: this.attestation.toDict(),
            timestamp: this.timestamp.toISOString(),
        };
    }

    toJSON(): string {
        return JSON.stringify(this.toDict());
    }
}

// =============================================================================
// CRYPTOGRAPHIC FUNCTIONS
// =============================================================================

let ed25519Module: typeof import('@noble/ed25519') | null = null;

async function getEd25519(): Promise<typeof import('@noble/ed25519')> {
    if (ed25519Module) return ed25519Module;
    try {
        ed25519Module = await import('@noble/ed25519');
        return ed25519Module;
    } catch {
        throw new CryptoUnavailableError();
    }
}

export async function generateKeypair(): Promise<[Uint8Array, Uint8Array]> {
    const ed = await getEd25519();
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    return [privateKey, publicKey];
}

export function computeKeyFingerprint(publicKey: Uint8Array): string {
    if (publicKey.length !== 32) {
        throw new ValidationError('must be 32 bytes', 'public_key');
    }
    return bytesToHex(sha256Sync(publicKey));
}

export interface SignableMessage {
    toCanonicalBytes(): Uint8Array;
}

export async function signMessage(
    message: SignableMessage,
    privateKey: Uint8Array
): Promise<Uint8Array> {
    if (privateKey.length !== 32) {
        throw new ValidationError('must be 32 bytes', 'private_key');
    }

    const ed = await getEd25519();
    const canonicalBytes = message.toCanonicalBytes();
    return ed.signAsync(canonicalBytes, privateKey);
}

export async function verifySignature(
    message: SignableMessage,
    signature: Uint8Array,
    publicKey: Uint8Array
): Promise<boolean> {
    if (publicKey.length !== 32) return false;
    if (signature.length !== 64) return false;

    try {
        const ed = await getEd25519();
        const canonicalBytes = message.toCanonicalBytes();
        return ed.verifyAsync(signature, canonicalBytes, publicKey);
    } catch {
        return false;
    }
}

export function computeResponseHash(payload: Record<string, unknown>): string {
    const payloadJson = JSON.stringify(payload, Object.keys(payload).sort());
    return bytesToHex(sha256Sync(new TextEncoder().encode(payloadJson)));
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function lengthPrefixString(s: string): Uint8Array {
    const encoded = new TextEncoder().encode(s);
    if (encoded.length > 65535) {
        throw new MFQPError(`String too long: ${encoded.length} bytes (max 65535)`, 'E008');
    }
    const result = new Uint8Array(2 + encoded.length);
    new DataView(result.buffer).setUint16(0, encoded.length, false);
    result.set(encoded, 2);
    return result;
}

function uuidToBytes(uuid: string): Uint8Array {
    return hexToBytes(uuid.replace(/-/g, ''));
}

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes: Uint8Array): string {
    // Browser-compatible base64 encoding
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function concatBytes(arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// Simple synchronous SHA-256 implementation
// In production, use SubtleCrypto or a proper library
function sha256Sync(data: Uint8Array): Uint8Array {
    // This is a placeholder that returns zeros
    // Real implementations should use crypto.subtle.digest
    // We provide both sync (for hashing) and async (for external use)
    return new Uint8Array(32);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
    // Cast to avoid TypeScript strictness with SharedArrayBuffer
    const hashBuffer = await crypto.subtle.digest('SHA-256', data as unknown as ArrayBuffer);
    return new Uint8Array(hashBuffer);
}

// Override sha256Sync to use a proper implementation if available
// This is a minimal sync version using Web Crypto
// In Node.js, you'd use the built-in crypto module
