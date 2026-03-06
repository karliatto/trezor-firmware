# This file is part of the Trezor project.
#
# Copyright (C) SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from __future__ import annotations

import json
import typing as t

import click

from .. import messages, nostr, tools
from . import with_session

if t.TYPE_CHECKING:
    from ..client import Session


PATH_TEMPLATE = "m/44h/1237h/{}h/0/0"


@click.group(name="nostr")
def cli() -> None:
    """Nostr commands."""


@cli.command()
@click.option("-a", "--account", default=0, help="Account index")
@click.option("-d", "--show-display", is_flag=True, help="Show pubkey on device display")
@with_session
def get_pubkey(
    session: "Session",
    account: int,
    show_display: bool,
) -> str:
    """Return the pubkey derived by the given path."""

    address_n = tools.parse_path(PATH_TEMPLATE.format(account))

    return nostr.get_pubkey(
        session,
        address_n,
        show_display=show_display,
    ).hex()


@cli.command()
@click.option("-a", "--account", default=0, help="Account index")
@click.argument("event")
@with_session
def sign_event(
    session: "Session",
    account: int,
    event: str,
) -> dict[str, str]:
    """Sign an event using the key derived by the given path."""

    event_json = json.loads(event)

    address_n = tools.parse_path(PATH_TEMPLATE.format(account))

    res = nostr.sign_event(
        session,
        messages.NostrSignEvent(
            address_n=address_n,
            created_at=event_json["created_at"],
            kind=event_json["kind"],
            tags=[
                messages.NostrTag(
                    key=t[0], value=t[1] if len(t) > 1 else None, extra=t[2:]
                )
                for t in event_json["tags"]
            ],
            content=event_json["content"],
        ),
    )

    event_json["id"] = res.id.hex()
    event_json["pubkey"] = res.pubkey.hex()
    event_json["sig"] = res.signature.hex()

    return {
        "signed_event": event_json,
    }


@cli.command()
@click.argument("event")
@with_session
def verify_event(
    session: "Session",
    event: str,
) -> str:
    """Verify a signed Nostr event on the device."""

    event_json = json.loads(event)

    ok = nostr.verify_event(
        session,
        messages.NostrVerifyEvent(
            pubkey=bytes.fromhex(event_json["pubkey"]),
            created_at=event_json["created_at"],
            kind=event_json["kind"],
            tags=[
                messages.NostrTag(
                    key=t[0], value=t[1] if len(t) > 1 else None, extra=t[2:]
                )
                for t in event_json["tags"]
            ],
            content=event_json["content"],
            id=bytes.fromhex(event_json["id"]),
            signature=bytes.fromhex(event_json["sig"]),
        ),
    )

    if not ok:
        raise click.ClickException("Event signature is invalid!")
    return "Event signature is valid."


@cli.command()
@click.option("-a", "--account", default=0, help="Account index")
@click.argument("sender_pubkey")
@click.argument("payload")
@with_session
def decrypt_nip17(
    session: "Session",
    account: int,
    sender_pubkey: str,
    payload: str,
) -> str:
    """Decrypt a NIP-17 direct message (NIP-44 encrypted) on the device.

    SENDER_PUBKEY is the sender's x-only public key as hex (32 bytes).
    PAYLOAD is the base64url-encoded NIP-44 v2 ciphertext from the event's content field.
    """
    import base64

    address_n = tools.parse_path(PATH_TEMPLATE.format(account))

    # NIP-44 payloads are base64url-encoded (URL-safe, no padding)
    payload_bytes = base64.urlsafe_b64decode(payload + "==")

    plaintext = nostr.decrypt_nip17(
        session,
        messages.NostrDecryptNip17(
            address_n=address_n,
            sender_pubkey=bytes.fromhex(sender_pubkey),
            payload=payload_bytes,
        ),
    )
    return plaintext.decode("utf-8")


@cli.command()
@click.argument("recipient_pubkey")
@click.argument("plaintext")
def encrypt_nip44(
    recipient_pubkey: str,
    plaintext: str,
) -> None:
    """Encrypt a message using NIP-44 v2 for a given recipient pubkey.

    RECIPIENT_PUBKEY is the recipient's x-only public key as hex (32 bytes).
    PLAINTEXT is the message to encrypt.

    Outputs the sender pubkey and base64url payload for use with decrypt-nip17.
    """
    import base64
    import hashlib
    import hmac as hmac_mod
    import secrets
    import struct

    try:
        from ecdsa import SECP256k1, SigningKey
        from ecdsa.keys import VerifyingKey
    except ImportError:
        raise click.ClickException("Install the 'ecdsa' package: pip install ecdsa")

    try:
        from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.backends import default_backend
        def _chacha20(key: bytes, nonce12: bytes, data: bytes) -> bytes:
            algo = ChaCha20(key, b"\x00\x00\x00\x00" + nonce12)
            enc = Cipher(algo, mode=None, backend=default_backend()).encryptor()
            return enc.update(data) + enc.finalize()
    except ImportError:
        try:
            from Crypto.Cipher import ChaCha20 as _CC20
            def _chacha20(key: bytes, nonce12: bytes, data: bytes) -> bytes:
                return _CC20.new(key=key, nonce=nonce12).encrypt(data)
        except ImportError:
            raise click.ClickException(
                "Install 'cryptography' or 'pycryptodome': pip install cryptography"
            )

    recipient_xonly = bytes.fromhex(recipient_pubkey)
    if len(recipient_xonly) != 32:
        raise click.ClickException("RECIPIENT_PUBKEY must be 32 bytes (64 hex chars)")

    # Generate ephemeral sender keypair
    sender_sk = SigningKey.generate(curve=SECP256k1)
    sender_vk_bytes = sender_sk.get_verifying_key().to_string()  # 64 bytes
    sender_xonly = sender_vk_bytes[:32]

    # ECDH: sender_priv * recipient_pubkey → shared x
    recipient_point = VerifyingKey.from_string(b"\x02" + recipient_xonly, curve=SECP256k1).pubkey.point
    priv_int = int.from_bytes(sender_sk.to_string(), "big")
    shared_x = (priv_int * recipient_point).x().to_bytes(32, "big")

    # NIP-44 v2 key derivation
    conversation_key = hmac_mod.new(b"nip44-v2", shared_x, hashlib.sha256).digest()
    nonce = secrets.token_bytes(32)

    def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
        blocks, t = [], b""
        for i in range(1, (length + 31) // 32 + 1):
            t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            blocks.append(t)
        return (b"".join(blocks))[:length]

    keys = _hkdf_expand(conversation_key, nonce, 76)
    chacha_key, chacha_nonce, hmac_key = keys[:32], keys[32:44], keys[44:76]

    # NIP-44 padding: round up to next power of 2 (min 32), prepend 2-byte length
    pt_bytes = plaintext.encode("utf-8")
    pad_len = max(32, 1 << (len(pt_bytes) - 1).bit_length())
    padded = struct.pack(">H", len(pt_bytes)) + pt_bytes + b"\x00" * (pad_len - len(pt_bytes))

    ciphertext = _chacha20(chacha_key, chacha_nonce, padded)
    mac = hmac_mod.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    payload = bytes([2]) + nonce + ciphertext + mac

    payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    click.echo(f"sender_pubkey: {sender_xonly.hex()}")
    click.echo(f"payload:       {payload_b64}")
    click.echo()
    click.echo(
        f"trezorctl nostr decrypt-nip17 {sender_xonly.hex()} {payload_b64}"
    )


@cli.command()
@click.option("-a", "--account", default=0, help="Account index")
@click.argument("address")
@click.argument("signature")
@with_session
def verify_address(
    session: "Session",
    account: int,
    address: str,
    signature: str,
) -> str:
    """Verify a Nostr-signed Bitcoin address using the key from the device."""
    from hashlib import sha256

    from ecdsa import SECP256k1, BadSignatureError, VerifyingKey
    from ecdsa.util import sigdecode_string

    address_n = tools.parse_path(PATH_TEMPLATE.format(account))
    pubkey = nostr.get_pubkey(session, address_n)

    sig_bytes = bytes.fromhex(signature)
    # secp256k1.sign() output: 1 byte recovery id + 32 r + 32 s
    sig_rs = sig_bytes[1:]

    digest = sha256(address.encode()).digest()

    # nostr pubkey is x-only (32 bytes); try both y-parities
    for prefix in (b"\x02", b"\x03"):
        try:
            vk = VerifyingKey.from_string(prefix + pubkey, curve=SECP256k1)
            vk.verify_digest(sig_rs, digest, sigdecode=sigdecode_string)
            return "Signature valid!"
        except BadSignatureError:
            continue

    raise click.ClickException("Signature invalid!")
