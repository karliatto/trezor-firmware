from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain

if TYPE_CHECKING:
    from trezor.messages import NostrDecryptNip17, NostrDecryptedNip17

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def decrypt_nip17(
    msg: NostrDecryptNip17, keychain: Keychain
) -> NostrDecryptedNip17:
    from ubinascii import hexlify

    from trezor.crypto import chacha20poly1305, hmac
    from trezor.crypto.curve import secp256k1
    from trezor.messages import NostrDecryptedNip17
    from trezor.ui.layouts import confirm_address
    from trezor.wire import DataError, ProcessError

    from apps.common import paths

    address_n = msg.address_n
    sender_pubkey = msg.sender_pubkey  # 32-byte x-only pubkey
    payload = msg.payload  # NIP-44 v2 payload bytes

    await paths.validate_path(keychain, address_n)

    node = keychain.derive(address_n)
    privkey = node.private_key()

    # Parse the NIP-44 v2 payload: version(1) + nonce(32) + ciphertext + mac(32)
    if len(payload) < 1 + 32 + 1 + 32:
        raise DataError("Invalid payload length")

    version = payload[0]
    if version != 2:
        raise DataError("Unsupported NIP-44 version")

    nonce = payload[1:33]
    ciphertext = payload[33:-32]
    mac = payload[-32:]

    if len(ciphertext) == 0:
        raise DataError("Empty ciphertext")

    # ECDH: sender_pubkey is x-only (32 bytes); prefix with 0x02 for secp256k1.multiply
    sender_pubkey_compressed = b"\x02" + sender_pubkey
    shared_point = secp256k1.multiply(privkey, sender_pubkey_compressed)
    shared_x = shared_point[1:33]  # x-coordinate only (32 bytes)

    # HKDF-Extract: conversation_key = HMAC-SHA256(salt=b"nip44-v2", ikm=shared_x)
    conversation_key = hmac(hmac.SHA256, b"nip44-v2", shared_x).digest()

    # HKDF-Expand: derive 76 bytes keying material (nonce is the HKDF info)
    # T(1) = HMAC(conversation_key, nonce || 0x01)
    h = hmac(hmac.SHA256, conversation_key)
    h.update(nonce)
    h.update(b"\x01")
    t1 = h.digest()
    # T(2) = HMAC(conversation_key, T(1) || nonce || 0x02)
    h = hmac(hmac.SHA256, conversation_key)
    h.update(t1)
    h.update(nonce)
    h.update(b"\x02")
    t2 = h.digest()
    # T(3) = HMAC(conversation_key, T(2) || nonce || 0x03)  (only need 12 bytes)
    h = hmac(hmac.SHA256, conversation_key)
    h.update(t2)
    h.update(nonce)
    h.update(b"\x03")
    t3 = h.digest()

    # Split keying material: chacha_key(32) + chacha_nonce(12) + hmac_key(32)
    chacha_key = t1            # 32 bytes
    chacha_nonce = t2[:12]     # 12 bytes
    hmac_key = t2[12:] + t3[:12]  # 20 + 12 = 32 bytes

    # Verify MAC: HMAC-SHA256(hmac_key, nonce || ciphertext)
    h = hmac(hmac.SHA256, hmac_key)
    h.update(nonce)
    h.update(ciphertext)
    expected_mac = h.digest()
    if expected_mac != bytes(mac):
        raise ProcessError("Invalid MAC")

    # Show confirmation before decrypting
    await confirm_address(
        "Decrypt DM",
        hexlify(sender_pubkey).decode(),
        chunkify=True,
    )

    # Decrypt with ChaCha20 (using chacha20poly1305, ignoring Poly1305 auth)
    ctx = chacha20poly1305(chacha_key, chacha_nonce)
    padded_plaintext = ctx.decrypt(ciphertext)

    # Unpad: first 2 bytes are plaintext length (big-endian uint16)
    if len(padded_plaintext) < 2:
        raise DataError("Invalid plaintext")
    plaintext_len = (padded_plaintext[0] << 8) | padded_plaintext[1]
    if plaintext_len + 2 > len(padded_plaintext):
        raise DataError("Invalid plaintext length in padding")

    plaintext = padded_plaintext[2 : 2 + plaintext_len]

    return NostrDecryptedNip17(plaintext=bytes(plaintext))
