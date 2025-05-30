use clap::{command, Parser};
use pcap::Device;
use etherparse::PacketHeaders;
use std::net::Ipv4Addr;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashSet;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,

    #[arg(short, long)]
    filepath: String,
}

fn main() {
    let args = Args::parse();

    let malicious_ips = load_malicious_ips(&args.filepath);

    let device = Device::list()
        .expect("Failed to retrieve the list of devices")
        .into_iter()
        .find(|d| d.name == args.interface)
        .expect("Failed to find the specified network interface");

    let mut cap = device.open().expect("Faield to open the network interface");

    while let Ok(packet) = cap.next_packet() {
        let headers = match PacketHeaders::from_ethernet_slice(packet.data) {
            Ok(headers) => headers,
            Err(e) => {
                println!("Failed to parse packet: {}", e);
                continue;
            }
        };

        if let Some(net_header) = headers.net {
            match net_header {
                etherparse::NetHeaders::Ipv4(ip_header, _) => {
                    let source_ip = Ipv4Addr::from(ip_header.source);
                    if is_harmful_traffic(&source_ip, &malicious_ips) {
                        println!("Potentially harmful traffic detected from: {}", source_ip);
                    }
                },
                _ => eprintln!("Unsupported network header type"),
            }
        }
    }
}

fn is_harmful_traffic(ip_addr: &Ipv4Addr, malicious_ips: &HashSet<Ipv4Addr>) -> bool {
    malicious_ips.contains(ip_addr)
}

fn load_malicious_ips(filename: &str) -> HashSet<Ipv4Addr> {
    let file = File::open(filename).expect("Unable to open file");
    let reader = BufReader::new(file);
    
    reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|ip_str| ip_str.parse().ok())
        .collect()
}
