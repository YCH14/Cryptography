import json, base64, time, os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..exceptions import SignatureVerificationError, MissingSignatureError
from .keys import get_signer_fingerprint

def build_canonical_payload(metadata: dict, recipients: list, nonce: str, ciphertext: str, tag: str) -> bytes:
    data = {
        "metadata": metadata,
        "recipients": recipients,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def encrypt_and_sign(data: bytes, sender_id: str, sender_private_key: ed25519.Ed25519PrivateKey, recipients: list) -> dict:
    dek = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(dek)
    
    metadata = {
        "algorithm": "AES-256-GCM",
        "signature_algorithm": "Ed25519",
        "timestamp": int(time.time()),
        "signer_id": sender_id,
        "signer_fingerprint": get_signer_fingerprint(sender_private_key.public_key())
    }
    
    # Simple simulated recipient wrap for D5
    recipient_entries = [{"id": r, "encrypted_dek": base64.b64encode(dek).decode("utf-8")} for r in recipients]
    
    aad = json.dumps({"metadata": metadata, "recipients": recipient_entries}, sort_keys=True).encode("utf-8")
    ct_with_tag = aesgcm.encrypt(nonce, data, aad)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    
    b64_nonce = base64.b64encode(nonce).decode("utf-8")
    b64_ct = base64.b64encode(ciphertext).decode("utf-8")
    b64_tag = base64.b64encode(tag).decode("utf-8")
    
    payload_to_sign = build_canonical_payload(metadata, recipient_entries, b64_nonce, b64_ct, b64_tag)
    signature = sender_private_key.sign(payload_to_sign)
    
    return {
        "magic": "VLT3",
        "version": 5,
        "metadata": metadata,
        "recipients": recipient_entries,
        "nonce": b64_nonce,
        "ciphertext": b64_ct,
        "tag": b64_tag,
        "signature": base64.b64encode(signature).decode("utf-8")
    }

def verify_and_decrypt(container: dict, sender_public_key: ed25519.Ed25519PublicKey, recipient_id: str) -> bytes:
    if "signature" not in container or not container["signature"]:
        raise MissingSignatureError("Missing signature")
        
    try:
        sig_bytes = base64.b64decode(container["signature"])
        payload = build_canonical_payload(
            container["metadata"],
            container["recipients"],
            container["nonce"],
            container["ciphertext"],
            container["tag"]
        )
        sender_public_key.verify(sig_bytes, payload)
    except Exception as e:
        raise SignatureVerificationError(f"Signature verification failed: {e}")
        
    rec = next((r for r in container["recipients"] if r["id"] == recipient_id), None)
    if not rec:
        raise SignatureVerificationError("Recipient not found")
        
    dek = base64.b64decode(rec["encrypted_dek"])
    nonce = base64.b64decode(container["nonce"])
    ct = base64.b64decode(container["ciphertext"])
    tag = base64.b64decode(container["tag"])
    
    aad = json.dumps({"metadata": container["metadata"], "recipients": container["recipients"]}, sort_keys=True).encode("utf-8")
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ct + tag, aad)
