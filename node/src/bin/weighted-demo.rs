//! Local TCP integration harness. Its startup barrier and deadline are not protocol decisions.
use anyhow::{anyhow, ensure, Result};
use clap::{App, Arg};
use config::Node;
use serde_json::{json, Value};
use std::{collections::BTreeSet, time::Duration};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    oneshot,
};
use types::InstanceId;

type Spawn<R, E> = fn(Node, Receiver<R>, Sender<E>) -> Result<oneshot::Sender<()>>;
async fn exercise<R: Send + 'static, E: Send + 'static>(
    configs: &[Node],
    active: &[usize],
    spawn: Spawn<R, E>,
    register: impl Fn(usize) -> R,
    start: impl Fn(usize) -> Vec<R>,
    registered: impl Fn(&E) -> bool,
    collect: impl Fn(E) -> Result<Option<Value>>,
) -> Result<Vec<Value>> {
    let mut participants = vec![];
    let mut exits = vec![];
    for &id in active {
        let (tx, rx) = channel(10000);
        let (out, mut events) = channel(10000);
        exits.push(spawn(configs[id].clone(), rx, out)?);
        tx.send(register(id))
            .await
            .map_err(|_| anyhow!("service closed"))?;
        loop {
            let event = events
                .recv()
                .await
                .ok_or_else(|| anyhow!("registration stream closed"))?;
            if registered(&event) {
                break;
            }
            if collect(event)?.is_some() {
                return Err(anyhow!("output before start"));
            }
        }
        participants.push((id, tx, events));
    }
    for (id, tx, _) in &participants {
        for request in start(*id) {
            tx.send(request)
                .await
                .map_err(|_| anyhow!("request stream closed"))?;
        }
    }
    let mut outputs = vec![];
    for (id, _, events) in &mut participants {
        loop {
            let event = events
                .recv()
                .await
                .ok_or_else(|| anyhow!("output stream closed"))?;
            if let Some(output) = collect(event)? {
                let result = json!({"node":*id,"result":output});
                log::info!("Node {}: output {}", id, output);
                outputs.push(result);
                break;
            }
        }
    }
    for exit in exits {
        let _ = exit.send(());
    }
    Ok(outputs)
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            log::error!("Single-process test failed: {:#}", error);
            std::process::ExitCode::FAILURE
        }
    }
}
async fn run() -> Result<()> {
    let args = App::new("weighted-demo")
        .about("Local TCP test for weighted primitives")
        .arg(
            Arg::with_name("config-dir")
                .long("config-dir")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("protocol")
                .long("protocol")
                .takes_value(true)
                .required(true)
                .possible_values(&["wra", "wavid", "wrbc", "wgather", "wbinaa"]),
        )
        .arg(
            Arg::with_name("absent")
                .long("absent")
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .takes_value(true)
                .default_value("30"),
        )
        .get_matches();
    node::logging::init(log::LevelFilter::Info)?;
    let directory = args.value_of("config-dir").unwrap();
    let first = Node::from_json(format!("{}/nodes-0.json", directory));
    let configs: Vec<_> = (0..first.num_nodes)
        .map(|i| Node::from_json(format!("{}/nodes-{}.json", directory, i)))
        .collect();
    for c in &configs {
        c.validate_weighted()?;
        ensure!(
            c.weighted_public_id("test") == first.weighted_public_id("test"),
            "inconsistent public configuration"
        );
    }
    let absent: Vec<usize> = args
        .value_of("absent")
        .unwrap()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse())
        .collect::<std::result::Result<_, _>>()?;
    let m = first.weighted_membership()?;
    let absent_weight = m
        .weight(absent.iter().copied())
        .map_err(anyhow::Error::msg)?;
    ensure!(
        absent_weight < m.threshold,
        "absent parties exceed the strict corrupt-weight bound"
    );
    let active: Vec<_> = (0..first.num_nodes)
        .filter(|i| !absent.contains(i))
        .collect();
    let dealer = *active
        .first()
        .ok_or_else(|| anyhow!("no active participant"))?;
    let protocol = args.value_of("protocol").unwrap();
    let timeout = args.value_of("timeout").unwrap().parse()?;
    let outputs=tokio::time::timeout(Duration::from_secs(timeout),async{
        match protocol{
            "wra"=>{
                let instance=InstanceId::new(0,None,0);
                exercise(&configs,&active,wra::Context::spawn,|_|wra::Request::Register{instance,header_id:[17;32]},|_|vec![wra::Request::Input{instance,value:true}],
                    |e|matches!(e,wra::Event::Registered{..}),|e|match e{wra::Event::Output{value,..}=>Ok(Some(json!(value))),wra::Event::Rejected{reason,..}=>Err(anyhow!(reason)),_=>Ok(None)}).await
            },
            "wavid"=>{
                let instance=InstanceId::new(0,Some(dealer),0);let data=b"weighted AVID integration payload".to_vec();
                exercise(&configs,&active,wavid::Context::spawn,|_|wavid::Request::Register{instance,descriptor:wavid::Descriptor{coding: Default::default(),file_bytes:data.len(),root:None,retrievers:active.clone(),completion:wavid::CompletionMode::Storage}},
                    |id|{let mut r=vec![wavid::Request::Retrieve{instance}];if id==dealer{r.push(wavid::Request::Disperse{instance,data:data.clone()});}r},
                    |e|matches!(e,wavid::Event::Registered{..}),|e|match e{
                        wavid::Event::Result{result:wavid::Retrieval::File(bytes),..}=>{ensure!(bytes==data,"incorrect retrieved file");Ok(Some(json!(String::from_utf8(bytes.into_vec())?)))},
                        wavid::Event::Result{result:wavid::Retrieval::Invalid(_),..}=>Err(anyhow!("honest file rejected")),wavid::Event::Rejected{reason,..}=>Err(anyhow!(reason)),_=>Ok(None)
                    }).await
            },
            "wrbc"=>{
                let instance=InstanceId::new(0,Some(dealer),0);let data=b"weighted RBC integration payload".to_vec();
                exercise(&configs,&active,wrbc::Context::spawn,|_|wrbc::Request::Register{coding: Default::default(),instance,file_bytes:data.len()},|id|if id==dealer{vec![wrbc::Request::Broadcast{instance,data:data.clone()}]}else{vec![]},
                    |e|matches!(e,wrbc::Event::Registered{..}),|e|match e{
                        wrbc::Event::Deliver{data:bytes,..}=>{ensure!(bytes==data,"incorrect RBC delivery");Ok(Some(json!(String::from_utf8(bytes.into_vec())?)))},
                        wrbc::Event::Invalid{..}=>Err(anyhow!("honest RBC rejected")),wrbc::Event::Rejected{reason,..}=>Err(anyhow!(reason)),_=>Ok(None)
                    }).await
            },
            "wgather"=>{
                let instance=InstanceId::new(0,None,0);
                exercise(&configs,&active,wgather::Context::spawn,|_|wgather::Request::Register{instance},|_|{let mut r=vec![wgather::Request::Start{instance}];r.extend(active.iter().map(|dealer|wgather::Request::Add{instance,dealer:*dealer}));r},
                    |e|matches!(e,wgather::Event::Registered{..}),|e|match e{wgather::Event::DeliverSet{dealers,..}=>Ok(Some(json!(dealers))),wgather::Event::Rejected{reason,..}=>Err(anyhow!(reason)),_=>Ok(None)}).await
            },
            "wbinaa"=>{
                let instance=InstanceId::new(0,None,0);
                exercise(&configs,&active,wbinaa::Context::spawn,|_|wbinaa::Request::Register{instance,precision:wbinaa::Precision::bits(8)},|id|vec![wbinaa::Request::Start{instance,inputs:(0..m.n()).map(|c|if c==0{false}else if c==1{true}else{(id+c)%2==0}).collect()}],
                    |e|matches!(e,wbinaa::Event::Registered{..}),|e|match e{wbinaa::Event::DeliverVector{values,..}=>Ok(Some(json!(values.iter().map(|d|json!({"numerator":d.numerator.to_string(),"exponent":d.exponent})).collect::<Vec<_>>()))),wbinaa::Event::Rejected{reason,..}=>Err(anyhow!(reason)),_=>Ok(None)}).await
            },_=>unreachable!(),
        }
    }).await.map_err(|_|anyhow!("integration harness timed out; no protocol rejection or default output inferred"))??;
    if protocol == "wgather" {
        let mut core: BTreeSet<usize> = active.iter().copied().collect();
        for result in &outputs {
            let set: BTreeSet<_> = result["result"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect();
            core = core.intersection(&set).copied().collect();
        }
        ensure!(
            m.weight(core).map_err(anyhow::Error::msg)? > m.quorum,
            "Gather common core below quorum"
        );
    } else if protocol == "wbinaa" {
        for c in 0..m.n() {
            let values: Vec<u64> = outputs
                .iter()
                .map(|v| {
                    v["result"][c]["numerator"]
                        .as_str()
                        .unwrap()
                        .parse()
                        .unwrap()
                })
                .collect();
            ensure!(
                values.iter().max().unwrap() - values.iter().min().unwrap() <= 1,
                "BinAA exceeds requested precision"
            );
            if c == 0 {
                ensure!(values.iter().all(|v| *v == 0), "unanimous zero invalid");
            }
            if c == 1 {
                ensure!(values.iter().all(|v| *v == 256), "unanimous one invalid");
            }
        }
    } else {
        ensure!(
            outputs.windows(2).all(|v| v[0]["result"] == v[1]["result"]),
            "outputs disagree"
        );
    }
    log::info!(
        "{} single-process TCP test passed; participants={:?}, absent={:?}",
        protocol,
        active,
        absent
    );
    Ok(())
}
