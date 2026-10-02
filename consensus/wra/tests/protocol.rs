use std::collections::VecDeque;
use types::{InstanceId, Weight, WeightedMembership};
use wra::{Kind, ProtMsg, State};
fn membership(w: &[u64], t: u64) -> WeightedMembership {
    WeightedMembership::new(
        w.iter().map(|w| Weight::from(*w)).collect(),
        Weight::from(t),
    )
    .unwrap()
}
fn drive(states: &mut [State], absent: &[usize]) {
    let mut queue = VecDeque::new();
    let mut steps = 0;
    loop {
        for (sender, state) in states.iter_mut().enumerate() {
            for a in std::mem::take(&mut state.outgoing) {
                if !absent.contains(&sender) && !absent.contains(&a.recipient) {
                    queue.push_back((sender, a));
                }
            }
        }
        let Some((sender, a)) = queue.pop_back() else {
            break;
        };
        states[a.recipient].receive(sender, a.message);
        steps += 1;
        assert!(steps < 10000);
    }
}
#[test]
fn all_input_patterns_preserve_agreement() {
    for pattern in 0..16 {
        let m = membership(&[3; 4], 4);
        let inst = InstanceId::new(1, None, 0);
        let mut states: Vec<_> = (0..4)
            .map(|i| State::new(m.clone(), i, inst, [1; 32]).unwrap())
            .collect();
        for (i, s) in states.iter_mut().enumerate() {
            s.input(pattern & (1 << i) != 0).unwrap();
        }
        drive(&mut states, &[]);
        let outputs: Vec<_> = states.iter().filter_map(|s| s.output).collect();
        assert!(outputs.windows(2).all(|v| v[0] == v[1]));
        if pattern == 0 || pattern == 15 {
            assert_eq!(outputs.len(), 4);
            assert!(outputs.iter().all(|b| *b == (pattern == 15)));
        }
    }
}
#[test]
fn weighted_majority_of_faulty_identities_is_allowed() {
    let m = membership(&[10, 1, 1, 1, 1], 4);
    let inst = InstanceId::new(0, None, 0);
    let mut states: Vec<_> = (0..5)
        .map(|i| State::new(m.clone(), i, inst, [2; 32]).unwrap())
        .collect();
    states[0].input(true).unwrap();
    states[1].input(true).unwrap();
    drive(&mut states, &[2, 3, 4]);
    assert_eq!(states[0].output, Some(true));
    assert_eq!(states[1].output, Some(true));
}
#[test]
fn strict_boundaries_deduplication_and_late_input() {
    let m = membership(&[4, 4, 1, 3], 4);
    let inst = InstanceId::new(0, None, 0);
    let mut s = State::new(m, 3, inst, [3; 32]).unwrap();
    let msg = |kind| ProtMsg {
        instance: inst,
        header_id: [3; 32],
        kind,
    };
    s.receive(0, msg(Kind::Echo(true)));
    s.receive(1, msg(Kind::Echo(true)));
    assert_eq!(s.ready_value, None);
    s.receive(0, msg(Kind::Echo(false)));
    assert_eq!(s.echo_weights[1], 8u8.into());
    assert_eq!(s.echo_weights[0], 0u8.into());
    s.receive(2, msg(Kind::Echo(true)));
    assert_eq!(s.ready_value, Some(true));
    s.receive(0, msg(Kind::Ready(true)));
    s.receive(1, msg(Kind::Ready(true)));
    assert_eq!(s.output, None);
    s.receive(2, msg(Kind::Ready(true)));
    assert_eq!(s.output, Some(true));
    s.input(false).unwrap();
    assert_eq!(s.output, Some(true));
    assert!(s.input(true).is_err());
    s.receive(
        3,
        ProtMsg {
            instance: inst,
            header_id: [4; 32],
            kind: Kind::Ready(false),
        },
    );
    assert_eq!(s.ready_weights[0], 0u8.into());
}
