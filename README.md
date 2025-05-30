# Network Monitor

A simple Rust application for monitoring network traffic and detecting potentially harmful packets based on their source IP addresses.

## Features

- Capture network packets on a specified interface.
- Analyze packets to detect potentially harmful traffic.
- Display source IP addresses of detected harmful packets.

## Prerequisites

- Rust programming language installed.
- Network interface with permission to capture packets.
- Root or elevated privileges for packet capturing.

## Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/DanielKoklev/rust-network-monitoring.git
   cd rust-network-monitoring
   ``` 
2. **Build the project**
    ```bash
    cargo build
    ```
3. **Set capabilities**
    - To avoid running the entire application as root:
    ```bash
    sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' target/debug/network_monitor
    ```
4. **Run the application and specify which interface to be monitored**
    ```bash
    cargo run -- --interface eth0
    ```

