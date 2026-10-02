use crate::{Kind, State};
use anyhow::{ensure, Result};
impl State {
    pub fn input(&mut self, value: bool) -> Result<()> {
        ensure!(self.input_value.is_none(), "RA input already supplied");
        self.input_value = Some(value);
        self.broadcast(Kind::Echo(value));
        Ok(())
    }
}
