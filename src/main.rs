use clap::{command, Parser};
use pcap::Device;
use etherparse::PacketHeaders;
use std::net::Ipv4Addr;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,
}

fn main() {
    let args = Args::parse();

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
                    if is_harmful_traffic(&source_ip) {
                        println!("Potentially harmful traffic detected from: {}", source_ip);
                    }
                },
                _ => eprintln!("Unsupported network header type"),
            }
        }
    }
}

fn is_harmful_traffic(ip_addr: &Ipv4Addr) -> bool {
    let malicious_ips = [
    Ipv4Addr::new(1, 0, 252, 227),
    Ipv4Addr::new(1, 10, 132, 62)
    ];

    malicious_ips.contains(ip_addr)
}
