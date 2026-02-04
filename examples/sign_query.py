"""
MFQP Example: Sign a Ghost Query
"""
from mfqp import GhostQuery, sign_message, verify_signature
from mfqp.crypto import generate_keypair

def main():
    # Generate Ed25519 keypair
    private_key, public_key = generate_keypair()
    print(f"Public key fingerprint: {public_key[:16].hex()}...")
    
    # Create a Ghost Query
    query = GhostQuery(
        source_company="acme-corp",
        target_company="globex-inc",
        intent="What is the current inventory status for titanium alloy?",
        intent_class="inventory.status",
        auth_level="verified"
    )
    print(f"Query ID: {query.query_id}")
    print(f"Intent: {query.intent}")
    
    # Sign the query
    signature = sign_message(query, private_key)
    print(f"Signature: {signature[:32].hex()}...")
    
    # Verify the signature (simulating receiving end)
    is_valid = verify_signature(query, signature, public_key)
    print(f"Signature valid: {is_valid}")
    
    if is_valid:
        print("✅ Query authenticated successfully!")
    else:
        print("❌ Signature verification failed!")

if __name__ == "__main__":
    main()
