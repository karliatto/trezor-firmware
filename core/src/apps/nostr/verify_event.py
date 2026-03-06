from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import NostrVerifyEvent, Success


async def verify_event(msg: NostrVerifyEvent) -> Success:
    from ubinascii import hexlify

    from trezor import TR
    from trezor.crypto.curve import bip340
    from trezor.crypto.hashlib import sha256
    from trezor.messages import Success
    from trezor.ui.layouts import confirm_value, show_success
    from trezor.wire import ProcessError

    pubkey = msg.pubkey
    created_at = msg.created_at
    kind = msg.kind
    tags = [[t.key] + ([t.value] if t.value else []) + t.extra for t in msg.tags]
    content = msg.content
    event_id = msg.id
    signature = msg.signature

    # Reconstruct the event serialization to verify the ID
    # See NIP-01: https://github.com/nostr-protocol/nips/blob/master/01.md
    serialized_tags = ",".join(
        ["[" + ",".join(f'"{t}"' for t in tag) + "]" for tag in tags]
    )
    serialized_event = f'[0,"{hexlify(pubkey).decode()}",{created_at},{kind},[{serialized_tags}],"{content}"]'
    expected_id = sha256(serialized_event).digest()

    # Verify the event ID matches the serialized event
    if expected_id != bytes(event_id):
        raise ProcessError("Invalid event ID")

    # Verify the Schnorr signature
    if not bip340.verify(pubkey, signature, event_id):
        raise ProcessError("Invalid signature")

    title = TR.nostr__event_kind_template.format(kind)
    info_items = [
        ("Created", str(created_at), None),
        ("Tags", serialized_tags, None),
    ]
    await confirm_value(title, content, "", "nostr_verify_event", info_items=info_items)

    await show_success("nostr_verify_event", TR.nostr__valid_event)
    return Success(message="Event verified")
