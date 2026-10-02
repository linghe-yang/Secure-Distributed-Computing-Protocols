use std::collections::VecDeque;
use types::{InstanceId, Weight, WeightedMembership};
use wgather::{Kind, ProtMsg, State};
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
fn monotone_validation_and_post_output_service() {
    let m = membership(&[3; 4], 4);
    let inst = InstanceId::new(0, None, 0);
    let mut states: Vec<_> = (0..4)
        .map(|i| State::new(m.clone(), i, inst).unwrap())
        .collect();
    for (i, s) in states.iter_mut().enumerate() {
        if i < 3 {
            s.start().unwrap();
        }
        for d in 0..3 {
            s.add(d).unwrap();
        }
    }
    drive(&mut states, &[]);
    assert!(states[..3].iter().all(|s| s.output == Some(vec![0, 1, 2])));
    assert!(states[3].output.is_none());
    states[3].start().unwrap();
    drive(&mut states, &[]);
    assert_eq!(states[3].output, Some(vec![0, 1, 2]));
    for s in &mut states {
        s.add(3).unwrap();
        assert_eq!(s.output, Some(vec![0, 1, 2]));
    }
}
#[test]
fn low_weight_silent_majority_and_invalid_bitmaps() {
    let m = membership(&[10, 1, 1, 1, 1], 4);
    let inst = InstanceId::new(0, None, 0);
    let mut states: Vec<_> = (0..5)
        .map(|i| State::new(m.clone(), i, inst).unwrap())
        .collect();
    for s in &mut states[..2] {
        s.start().unwrap();
        s.add(0).unwrap();
        s.add(1).unwrap();
    }
    states[0].receive(
        2,
        ProtMsg {
            instance: inst,
            kind: Kind::Inform(vec![255]),
        },
    );
    drive(&mut states, &[2, 3, 4]);
    for s in &states[..2] {
        assert_eq!(s.output, Some(vec![0, 1]));
    }
}
#[test]
fn prepare_waits_for_local_application_validation() {
    let m = membership(&[3; 4], 4);
    let inst = InstanceId::new(0, None, 0);
    let mut s = State::new(m, 0, inst).unwrap();
    s.start().unwrap();
    for sender in 0..3 {
        s.receive(
            sender,
            ProtMsg {
                instance: inst,
                kind: Kind::Prepare(vec![7]),
            },
        );
    }
    assert!(s.output.is_none());
    for d in 0..3 {
        s.add(d).unwrap();
    }
    assert_eq!(s.output, Some(vec![0, 1, 2]));
}
