"""Ed25519 signing with a key held in an HSM over PKCS#11. The private key never leaves the token."""

import pkcs11
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass


class Pkcs11Signer:
    def __init__(self, module: str, token_label: str, key_label: str, pin: str):
        token = pkcs11.lib(module).get_token(token_label=token_label)
        self._session = token.open(user_pin=pin)
        self._priv = self._session.get_key(object_class=ObjectClass.PRIVATE_KEY,
                                           key_type=KeyType.EC_EDWARDS, label=key_label)
        pub = self._session.get_key(object_class=ObjectClass.PUBLIC_KEY,
                                    key_type=KeyType.EC_EDWARDS, label=key_label)
        point = bytes(pub[Attribute.EC_POINT])
        # EC_POINT is usually DER: OCTET STRING (0x04), length 32, then the raw key.
        raw = point[2:] if len(point) == 34 and point[:2] == b"\x04\x20" else point
        self._pub = Ed25519PublicKey.from_public_bytes(raw)

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data, mechanism=Mechanism.EDDSA)

    def public_key(self) -> Ed25519PublicKey:
        return self._pub

    def close(self) -> None:
        self._session.close()
