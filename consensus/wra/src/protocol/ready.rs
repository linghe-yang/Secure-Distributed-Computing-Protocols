use crate::{Event, Kind, State};
impl State {
    pub(crate) fn advance(&mut self) {
        if self.ready_value.is_none() {
            for bit in [false, true] {
                if self.echo_weights[bit as usize] > self.membership.quorum
                    || self.ready_weights[bit as usize] >= self.membership.threshold
                {
                    self.ready_value = Some(bit);
                    self.broadcast(Kind::Ready(bit));
                    break;
                }
            }
        }
        if self.output.is_none() {
            for bit in [false, true] {
                if self.ready_weights[bit as usize] > self.membership.quorum {
                    self.output = Some(bit);
                    self.events.push(Event::Output {
                        instance: self.instance,
                        value: bit,
                    });
                    break;
                }
            }
        }
    }
}
