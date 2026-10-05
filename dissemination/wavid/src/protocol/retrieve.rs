use crate::{Event, Kind, State};
use anyhow::{ensure, Result};
impl State {
    pub fn authorize(&mut self, retrievers: Vec<usize>) -> Result<()> {
        self.membership
            .weight(retrievers.iter().copied())
            .map_err(anyhow::Error::msg)?;
        // This API adds edges. No authorized edge can be revoked.
        self.retrievers.extend(retrievers);
        self.advance();
        Ok(())
    }
    pub fn retrieve(&mut self) -> Result<()> {
        ensure!(
            self.retrievers.contains(&self.id),
            "local party not authorized to retrieve"
        );
        self.want = true;
        self.advance();
        Ok(())
    }
    pub(crate) fn accept_data(&mut self, verified: crate::protocol::codec::VerifiedBundle) {
        if self.directory.is_none() {
            self.directory = Some(verified.directory);
        }
        for (z, stripe) in verified.stripes.into_iter().enumerate() {
            for fragment in stripe {
                if self.rows[z].len() < self.codec.k {
                    self.rows[z].entry(fragment.index()).or_insert(fragment);
                }
            }
        }
    }
    pub(crate) fn advance_retrieval(&mut self) {
        if self.want && !self.asked {
            if let Some(root) = self.completed_root {
                self.asked = true;
                self.broadcast(Kind::Request(root));
            }
        }
        if let Some(root) = self.completed_root {
            if self.stored_root == Some(root) {
                let peers: Vec<_> = self
                    .requests
                    .iter()
                    .filter(|(peer, r)| {
                        **r == root && self.retrievers.contains(peer) && !self.served.contains(peer)
                    })
                    .map(|(p, _)| *p)
                    .collect();
                if !peers.is_empty() {
                    let raw = self.stored_packet.as_ref().unwrap().clone();
                    for peer in peers {
                        self.served.insert(peer);
                        self.packet(peer, true, &raw);
                    }
                }
            }
            if self.asked && self.result.is_none() {
                if let Some(directory) = &self.directory {
                    match self.codec.recover_verified(root, directory, &mut self.rows) {
                        Ok(Some(result)) => {
                            self.result = Some(result.clone());
                            self.events.push(Event::Result {
                                instance: self.instance,
                                result,
                            });
                            self.data_slots.clear();
                            self.rows.iter_mut().for_each(|r| r.clear());
                            self.directory = None;
                        }
                        Ok(None) => {}
                        Err(e) => log::warn!("ignored invalid recovery state: {}", e),
                    }
                }
            }
        }
        // Never clear stored_packet, authorized edges, or served slots at local output.
    }
}
