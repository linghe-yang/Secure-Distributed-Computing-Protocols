use crate::{Entry, Event, ProtMsg, State};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use types::{Dyadic, SendAction, Weight};
impl State {
    fn record(&mut self, c: usize, r: u32, code: BigInt, lower: u8, upper: u8) {
        if let Some(code) = code.to_u8().filter(|code| *code >= lower && *code <= upper) {
            self.pending.entry(r).or_default().push(Entry {
                coordinate: c as u32,
                code,
            });
        } else {
            log::error!("BinAA adjacent-grid invariant failed; no value is rounded");
        }
    }
    pub(crate) fn enter(&mut self, c: usize, r: u32, numerator: BigInt) {
        let previous = if r == 1 {
            BigInt::from(0)
        } else {
            self.states[&(c, r - 1)].initial.as_ref().unwrap().clone()
        };
        let state = self.states.entry((c, r)).or_default();
        state.initial = Some(numerator.clone());
        state.sent1.insert(numerator.clone());
        self.record(c, r, numerator - previous * 2 + 2, 0, 4);
        self.work.push_back((c, r));
    }
    pub(crate) fn advance(&mut self) {
        while let Some((c, r)) = self.work.pop_front() {
            let Some(initial) = self.states.get(&(c, r)).and_then(|s| s.initial.clone()) else {
                continue;
            };
            let relays: Vec<_> = self.states[&(c, r)]
                .w1
                .iter()
                .filter(|(value, vote)| {
                    vote.weight >= self.membership.threshold
                        && !self.states[&(c, r)].sent1.contains(*value)
                })
                .map(|(v, _)| v.clone())
                .collect();
            for value in relays {
                let state = self.states.get_mut(&(c, r)).unwrap();
                if state.sent1.len() >= 2 {
                    continue;
                }
                state.sent1.insert(value.clone());
                self.record(c, r, value - &initial + 6, 5, 7);
            }
            // The Python reference uses >= W-T at this stage (RA/Gather use strict >).
            let certified: Vec<_> = self.states[&(c, r)]
                .w1
                .iter()
                .filter(|(_, v)| v.weight >= self.membership.quorum)
                .map(|(v, _)| v.clone())
                .collect();
            if !certified.is_empty() && self.states[&(c, r)].sent2.is_none() {
                let value = certified[0].clone();
                self.states.get_mut(&(c, r)).unwrap().sent2 = Some(value.clone());
                self.record(c, r, value - &initial + 9, 8, 10);
            }
            if self.states[&(c, r)].result.is_some() {
                continue;
            }
            let result = if certified.len() >= 2 {
                Some(&certified[0] + &certified[1])
            } else {
                self.states[&(c, r)]
                    .w2
                    .iter()
                    .find(|(_, v)| v.weight >= self.membership.quorum)
                    .map(|(v, _)| v * 2)
            };
            if let Some(result) = result {
                self.states.get_mut(&(c, r)).unwrap().result = Some(result.clone());
                if r < self.rounds {
                    self.enter(c, r + 1, result);
                } else {
                    self.finished.insert(c, result);
                    if self.output.is_none() && self.finished.len() == self.membership.n() {
                        let values: Vec<_> = (0..self.membership.n())
                            .map(|c| Dyadic {
                                numerator: Weight(
                                    self.finished[&c]
                                        .to_biguint()
                                        .expect("nonnegative BinAA numerator"),
                                ),
                                exponent: self.rounds,
                            })
                            .collect();
                        self.output = Some(values.clone());
                        self.events.push(Event::DeliverVector {
                            instance: self.instance,
                            values,
                        });
                    }
                }
            }
        }
        // Bundle ready coordinates without imposing a cross-coordinate round barrier.
        for (round, entries) in std::mem::take(&mut self.pending) {
            for entries in entries.chunks(256) {
                let msg = ProtMsg {
                    instance: self.instance,
                    round,
                    entries: entries.to_vec(),
                };
                for recipient in 0..self.membership.n() {
                    self.outgoing.push(SendAction {
                        recipient,
                        message: msg.clone(),
                    });
                }
            }
        }
    }
}
