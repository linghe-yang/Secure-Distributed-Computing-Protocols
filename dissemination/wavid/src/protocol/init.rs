use crate::{Prepared, State};
use anyhow::{ensure, Result};
impl State {
    pub fn disperse(&mut self, data: &[u8]) -> Result<()> {
        let prepared = self.codec.prepare(data)?;
        self.disperse_prepared(prepared)
    }
    pub fn disperse_prepared(&mut self, prepared: Prepared) -> Result<()> {
        ensure!(
            Some(self.id) == self.instance.dealer && !self.dispersed,
            "only dealer may disperse, once"
        );
        ensure!(
            self.descriptor.root.is_none_or(|r| r == prepared.root),
            "encoding differs from pinned root"
        );
        ensure!(
            prepared.bundles.len() == self.membership.n()
                && prepared.bundles.iter().enumerate().all(|(p, b)| self
                    .codec
                    .verify_bundle(p, b, Some(prepared.root))
                    .is_some()),
            "prepared encoding context differs"
        );
        self.dispersed = true;
        for (peer, bundle) in prepared.bundles.iter().enumerate() {
            let raw = bincode::serialize(bundle)?;
            self.packet(peer, false, &raw);
        }
        Ok(())
    }
}
