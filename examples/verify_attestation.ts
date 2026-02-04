/**
 * MFQP Example: Verify an Attestation
 */
import { QueryResponse, Attestation, verifySignature } from '@metalogue/mfqp';

async function main() {
    // Simulated response from a federated query
    const response: QueryResponse = {
        queryId: 'q_abc123def456',
        responsePayload: {
            status: 'available',
            quantity: 15000,
            unit: 'kg',
            lastUpdated: '2026-02-04T12:00:00Z'
        },
        attestation: {
            queryId: 'q_abc123def456',
            respondingCompany: 'globex-inc',
            timestamp: '2026-02-04T12:00:01Z',
            signature: '...base64_signature...',
            publicKeyFingerprint: 'sha256:abc123...'
        },
        timestamp: '2026-02-04T12:00:01Z'
    };

    console.log('Query ID:', response.queryId);
    console.log('Response:', JSON.stringify(response.responsePayload, null, 2));

    // In production, you would fetch the public key from the partner registry
    const partnerPublicKey = await fetchPublicKey(response.attestation.publicKeyFingerprint);

    // Verify the attestation signature
    const isValid = await verifySignature(
        response.attestation,
        response.attestation.signature,
        partnerPublicKey
    );

    if (isValid) {
        console.log('✅ Attestation verified! Response is authentic.');
    } else {
        console.log('❌ Attestation verification failed!');
    }
}

async function fetchPublicKey(fingerprint: string): Promise<Uint8Array> {
    // In production, this would query the Metalogue partner registry
    // For this example, we return a placeholder
    console.log(`Fetching public key for: ${fingerprint}`);
    return new Uint8Array(32);
}

main().catch(console.error);
