use crate::{Event, Kind, State};
impl State {
    pub(crate) fn advance(&mut self) {
        if !self.started {
            return;
        }
        if !self.announced && self.validated_weight > self.membership.quorum {
            self.announced = true;
            self.broadcast(Kind::Inform(self.validated.clone()));
        }
        for sender in 0..self.membership.n() {
            if !self.ack_sent[sender]
                && self.informs[sender]
                    .as_ref()
                    .is_some_and(|b| self.subset(b))
            {
                self.ack_sent[sender] = true;
                self.send(sender, Kind::Ack);
            }
        }
        if self.announced && !self.prepared && self.ack_weight > self.membership.quorum {
            self.prepared = true;
            self.broadcast(Kind::Prepare(self.validated.clone()));
        }
        for sender in 0..self.membership.n() {
            if !self.prepare_senders[sender]
                && self.prepares[sender]
                    .as_ref()
                    .is_some_and(|b| self.subset(b))
            {
                self.prepare_senders[sender] = true;
                self.prepare_weight += &self.membership.weights[sender].0;
            }
        }
        if self.output.is_none() && self.prepare_weight > self.membership.quorum {
            let mut union = vec![0u8; self.validated.len()];
            for sender in 0..self.membership.n() {
                if self.prepare_senders[sender] {
                    for (a, b) in union
                        .iter_mut()
                        .zip(self.prepares[sender].as_ref().unwrap())
                    {
                        *a |= *b;
                    }
                }
            }
            let dealers: Vec<_> = (0..self.membership.n())
                .filter(|i| union[i / 8] & (1 << (i % 8)) != 0)
                .collect();
            self.output = Some(dealers.clone());
            self.events.push(Event::DeliverSet {
                instance: self.instance,
                dealers,
            });
        }
        // Continue sending ACK and PREPARE for late local validation after output.
    }
}
