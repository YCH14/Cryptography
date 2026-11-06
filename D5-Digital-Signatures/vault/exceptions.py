class DecryptionFailedError(Exception):
    pass

class SignatureVerificationError(DecryptionFailedError):
    pass

class MissingSignatureError(DecryptionFailedError):
    pass
