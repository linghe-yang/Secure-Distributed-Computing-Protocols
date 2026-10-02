// A tool that builds config files for all the nodes and the clients for the
// protocol.

use clap::{load_yaml, App};
use config::{Client, Node};
use crypto::{Algorithm, SecretKey};
use fnv::FnvHashMap as HashMap;
use rand::Rng;
use rand::RngCore;
use std::{
    error::Error,
    fs::File,
    io::{BufWriter, Write},
};
use types::Replica;
use types::{Weight, WeightedMembership};
use util::io::*;

fn main() -> Result<(), Box<dyn Error>> {
    let yaml = load_yaml!("cli.yml");
    let m = App::from_yaml(yaml).get_matches();
    let num_nodes: usize = m
        .value_of("num_nodes")
        .expect("number of nodes not specified")
        .parse::<usize>()
        .expect("unable to convert number of nodes into a number");
    if num_nodes == 0 || num_nodes > 4096 {
        return Err("NumNodes must be in 1..=4096".into());
    }
    let weights: Vec<Weight> = match m.value_of("weights") {
        Some(value) => value
            .split(',')
            .map(|s| s.trim().parse::<Weight>())
            .collect::<Result<_, _>>()?,
        None => vec![Weight::from(1); num_nodes],
    };
    if weights.len() != num_nodes || weights.iter().any(|w| w.0 == 0u8.into()) {
        return Err("provide one positive weight per node".into());
    }
    let weight_threshold: Option<Weight> = match m.value_of("weight_threshold") {
        Some(value) => Some(value.parse()?),
        None if m.is_present("weights") => {
            let total = weights
                .iter()
                .fold(weights[0].0.clone() * 0u8, |sum, w| sum + &w.0);
            Some(Weight(total / 3u8))
        }
        None => None,
    };
    if let Some(threshold) = &weight_threshold {
        WeightedMembership::new(weights.clone(), threshold.clone())?;
    }
    let mut session_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_id);
    let num_faults: usize = match m.value_of("num_faults") {
        Some(x) => x
            .parse::<usize>()
            .expect("unable to convert number of faults into a number"),
        None => (num_nodes - 1) / 3,
    };
    let delay: u64 = m
        .value_of("delay")
        .expect("delay value not specified")
        .parse::<u64>()
        .expect("unable to parse delay value into a number");
    let base_port: u16 = m
        .value_of("base_port")
        .expect("base_port value not specified")
        .parse::<u16>()
        .expect("failed to parse base_port into a number");
    let blocksize: usize = m
        .value_of("block_size")
        .expect("no block_size specified")
        .parse::<usize>()
        .expect("unable to convert blocksize into a number");
    let client_base_port: u16 = m
        .value_of("client_base_port")
        .expect("no client_base_port specified")
        .parse::<u16>()
        .expect("unable to parse client_base_port into an integer");
    let t: Algorithm = m
        .value_of("algorithm")
        .unwrap_or("NOPKI")
        .parse::<Algorithm>()
        .unwrap_or(Algorithm::NOPKI);
    let out = m.value_of("out_type").unwrap_or("json");
    let target = m
        .value_of("target")
        .expect("target directory for the config not specified");
    let payload: usize = m.value_of("payload").unwrap_or("0").parse().unwrap();
    let local: String = m.value_of("local").unwrap_or("false").parse().unwrap();
    let c_rport: u16 = m
        .value_of("client_run_port")
        .expect("Client port expected")
        .parse::<u16>()
        .expect("unable to parse client's port into an integer");
    if usize::from(base_port) + num_nodes - 1 > 65535
        || usize::from(client_base_port) + num_nodes - 1 > 65535
    {
        return Err("port range exceeds 65535".into());
    }
    std::fs::create_dir_all(target)?;
    let mut client = Client::new();
    client.block_size = blocksize;
    client.crypto_alg = t.clone();
    client.num_nodes = num_nodes;
    client.num_faults = num_faults;

    let mut node: Vec<Node> = Vec::with_capacity(num_nodes);

    let pk = HashMap::default();
    let mut ip = HashMap::default();

    //let (cert, privkey) = new_root_cert()?;
    let mut sec_keys: Vec<Vec<SecretKey>> = Vec::with_capacity(num_nodes);
    (0..num_nodes).for_each(|_i| {
        sec_keys.push(Vec::with_capacity(num_nodes));
    });
    if t == Algorithm::NOPKI {
        // Generate secret keys above and pass them to the context
        for i in 0..num_nodes {
            for j in i..num_nodes {
                let skey: SecretKey = SecretKey::new();
                sec_keys[i].push(skey.clone());
                if j != i {
                    sec_keys[j].push(skey.clone());
                }
                //sec_keys.push(SecretKey::generate());
            }
        }
    }
    for i in 0..num_nodes {
        node.push(Node::new());

        node[i].delta = delay;
        node[i].id = i as Replica;
        node[i].num_nodes = num_nodes;
        node[i].weights = weights.clone();
        node[i].weight_threshold = weight_threshold.clone();
        node[i].session_id = session_id;
        node[i].num_faults = num_faults;
        node[i].block_size = blocksize;
        node[i].payload = payload;
        node[i].client_port = client_base_port + (i as u16);
        // generate random number for approximate consensus
        let num = rand::thread_rng().gen_range(0, 20000000);
        node[i].prot_payload = format!("a,{},50000,100", num);
        node[i].crypto_alg = t.clone();
        match t {
            Algorithm::NOPKI => {
                for j in 0..num_nodes {
                    node[i].sk_map.insert(j, sec_keys[i][j].to_vec());
                }
            }
        };
        ip.insert(
            i as Replica,
            format!("{}:{}", "127.0.0.1", base_port + (i as u16)),
        );
        client.net_map.insert(
            i as Replica,
            format!("127.0.0.1:{}", client_base_port + (i as u16)),
        );

        //let (new_cert, new_pkey) = get_signed_cert(&cert, &privkey)?;

        //node[i].root_cert = cert.to_der()?;
        //node[i].my_cert = new_cert.to_der()?;
        //node[i].my_cert_key = new_pkey.private_key_to_der()?;
    }
    ip.insert(num_nodes, format!("127.0.0.1:{}", c_rport));
    //client.root_cert = cert.to_der()?;

    for i in 0..num_nodes {
        node[i].pk_map = pk.clone();
        node[i].net_map = ip.clone();
    }
    if local != String::from("false") {
        // write ip map to file
        //let filename = format!("ip_file");
        println!("Writing ips to ip_file");
        // write ips to ip_file
        {
            let file = File::create("ip_file")?;
            let mut writer = BufWriter::new(file);
            for iter in 0..num_nodes + 1 {
                writeln!(writer, "{}", ip.get(&iter).unwrap())?;
            }
            writer.flush()?;
        }
        {
            let file = File::create(format!("{}/syncer", target))?;
            let mut writer = BufWriter::new(file);
            for iter in 0..num_nodes {
                writeln!(writer, "{}", client.net_map.get(&iter).unwrap())?;
            }
            writer.flush()?;
        }
        //write_json(filename, &ip.clone());
    }
    let filename = format!("{}/syncer.json", target);
    write_json(filename, &client.net_map.clone());
    client.server_pk = pk;

    // Validate the complete bundle before creating output files.
    for config in &node {
        if weight_threshold.is_some() {
            config.validate_weighted()?;
        } else {
            config.validate()?;
        }
    }
    client.validate()?;

    // Write all the files
    for i in 0..num_nodes {
        match out {
            "json" => {
                let filename = format!("{}/nodes-{}.json", target, i);
                write_json(filename, &node[i]);
            }
            "binary" => {
                let filename = format!("{}/nodes-{}.dat", target, i);
                write_bin(filename, &node[i]);
            }
            "toml" => {
                let filename = format!("{}/nodes-{}.toml", target, i);
                write_toml(filename, &node[i]);
            }
            "yaml" => {
                let filename = format!("{}/nodes-{}.yml", target, i);
                write_yaml(filename, &node[i]);
            }
            _ => (),
        }
    }

    // Write the client file
    match out {
        "json" => {
            let filename = format!("{}/client.json", target);
            write_json(filename, &client);
        }
        "binary" => {
            let filename = format!("{}/client.dat", target);
            write_bin(filename, &client);
        }
        "toml" => {
            let filename = format!("{}/client.toml", target);
            write_toml(filename, &client);
        }
        "yaml" => {
            let filename = format!("{}/client.yml", target);
            write_yaml(filename, &client);
        }
        _ => (),
    }

    Ok(())
}

#[test]
fn test_codec() -> Result<(), Box<dyn Error>> {
    Ok(())
}
