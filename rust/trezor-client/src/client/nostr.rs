use super::{handle_interaction, Trezor};
use crate::{error::Result, protos};

/// A signed Nostr event.
pub struct NostrEventSignature {
    pub pubkey: Vec<u8>,
    pub id: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Trezor {
    pub fn nostr_get_pubkey(&mut self, path: Vec<u32>) -> Result<Vec<u8>> {
        let mut req = protos::NostrGetPubkey::new();
        req.address_n = path;
        let pubkey = handle_interaction(
            self.call(req, Box::new(|_, m: protos::NostrPubkey| Ok(m.pubkey().to_vec())))?,
        )?;
        Ok(pubkey)
    }

    pub fn nostr_sign_event(
        &mut self,
        path: Vec<u32>,
        created_at: u32,
        kind: u32,
        tags: Vec<protos::NostrTag>,
        content: String,
    ) -> Result<NostrEventSignature> {
        let mut req = protos::NostrSignEvent::new();
        req.address_n = path;
        req.set_created_at(created_at);
        req.set_kind(kind);
        req.tags = tags;
        req.set_content(content);
        let res = handle_interaction(self.call(
            req,
            Box::new(|_, m: protos::NostrEventSignature| {
                Ok(NostrEventSignature {
                    pubkey: m.pubkey().to_vec(),
                    id: m.id().to_vec(),
                    signature: m.signature().to_vec(),
                })
            }),
        )?)?;
        Ok(res)
    }
}
