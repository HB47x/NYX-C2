# NYX C2

**NYX C2**  
**Purpose**: A stealthy, dependency-free Command and Control (C2) framework designed to evade EDRs, compatible with all Windows and Linux versions.

---

## Overview

"NYX C2" is a Rust-based C2 framework featuring a client (beacon) and server, leveraging encrypted DNS tunneling and HTTPS-like (RC4-encrypted TCP) communication. It uses LOLBins for persistence and execution, process hollowing (Windows), and a dropper for resilience against EDR cleaning, all without external dependencies.

- **Client**: `nyx_c2_client.rs` - Runs on Windows (XP+) and Linux (all distros).
- **Server**: `nyx_c2_server.rs` - Windows-only with a basic GUI via WinAPI.

---

## Features

### Client
- **Stealth**: Polymorphism, string obfuscation, anti-debugging, VM detection, random delays, network noise.
- **Persistence**: Windows (regsvr32, mshta, bitsadmin/at, hollowing); Linux (at, cron, rc.local).
- **Dropper**: Re-deploys with new names/hashes if cleaned.
- **Comms**: DNS tunneling (UDP/53), HTTPS-like (TCP/8443 with RC4).

### Server
- **GUI**: Basic WinAPI window and popups (MessageBoxA).
- **Comms**: Handles DNS and RC4-encrypted HTTPS-like traffic.
- **Control**: Console commands to register agents and list tasks.

---

## Build Instructions

### Prerequisites
1. **Rust Installation**: Install via `rustup` (https://rustup.rs/).
   - Windows: Use Command Prompt or PowerShell.
   - Linux: Use a terminal (e.g., `bash`).
2. **Target Compatibility** (optional for older systems):
   - Windows XP+: `rustup target add i686-pc-windows-msvc`.
   - Old Linux: `rustup target add i686-unknown-linux-gnu`.

### Building the Client (`nyx_c2_client.rs`)
1. **Windows**:
   - Save as `nyx_c2_client.rs`.
   - Standard: `rustc nyx_c2_client.rs -o nyx_c2_client.exe`.
   - XP: `rustc --target i686-pc-windows-msvc nyx_c2_client.rs -o nyx_c2_client.exe`.
2. **Linux**:
   - Save as `nyx_c2_client.rs`.
   - Standard: `rustc nyx_c2_client.rs -o nyx_c2_client`.
   - Old kernels: `rustc --target i686-unknown-linux-gnu nyx_c2_client.rs -o nyx_c2_client`.

### Building the Server (`nyx_c2_server.rs`)
1. **Windows**:
   - Save as `nyx_c2_server.rs`.
   - Compile: `rustc nyx_c2_server.rs -o nyx_c2_server.exe`.

---

## Execution Instructions

### Client
1. **Windows**:
   - Run: `nyx_c2_client.exe` (no admin needed for user-level persistence; admin enhances hollowing).
   - Persistence via `regsvr32`, `mshta`, `bitsadmin`/`at`, and hollowing into `svchost.exe`.
2. **Linux**:
   - Run: `./nyx_c2_client` (no root needed unless `rc.local` is read-only).
   - Persistence via `at`, cron, and `rc.local` if writable.

### Server
1. **Windows**:
   - Run: `nyx_c2_server.exe` (admin required for port 53; e.g., `.\nyx_c2_server.exe` in Command Prompt).
   - GUI window opens; popups show events; use console for commands:
     - `register agent_001 whoami`: Queues "whoami" for agent_001.
     - `list`: Shows queued commands.

---

## Configuration Instructions

### Client (`nyx_c2_client.rs`)
1. **Encryption Key**:
   - Change `KEY` to a unique value (e.g., `b"mysecretkey123"`); must match server.
2. **Domain**:
   - Update `DOMAIN_ENC` with your RC4-encrypted domain (e.g., `my.domain.com`):
     - Encrypt: Use Python: `from binascii import hexlify; key = b"secret"; data = b"my.domain.com"; print(hexlify(bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1))))`.
     - Replace `DOMAIN_ENC` with the hex output (e.g., `b"\x6d\x79\x2e\x64\x6f\x6d\x61\x69\x6e\x2e\x63\x6f\x6d"`).
3. **Agent ID**:
   - Update `AGENT_ID_ENC` with your encrypted ID (e.g., `agent_007`):
     - Encrypt similarly and replace (e.g., `b"\x61\x67\x65\x6e\x74\x5f\x30\x30\x37"`).
4. **Drop Names**:
   - Customize `DROP_NAMES` to mimic legit processes (e.g., `"updater"`, `"svcmon"`).

### Server (`nyx_c2_server.rs`)
1. **Encryption Key**:
   - Update `KEY` to match client (e.g., `b"mysecretkey123"`).
2. **Domain**:
   - Set `DOMAIN` to your domain (e.g., `my.domain.com`).
3. **Ports**:
   - Keep UDP/53 (DNS) and TCP/8443 (HTTPS); configure firewall to allow inbound traffic.
4. **DNS Setup**:
   - Register your domain (e.g., `my.domain.com`).
   - Point NS record to server IP (e.g., `ns1.my.domain.com A <server_ip>`).
   - Update `dns_query` in client from `8.8.8.8` to your server IP for direct comms.

### Network Configuration
- **Server IP**: Ensure public or local network IP is accessible.
- **Firewall**:
  - Windows Server:
    - `netsh advfirewall firewall add rule name="NYX C2 DNS" dir=in action=allow protocol=UDP localport=53`.
    - `netsh advfirewall firewall add rule name="NYX C2 HTTPS" dir=in action=allow protocol=TCP localport=8443`.
  - Client (Windows/Linux): Allow outbound UDP/53 and TCP/8443.

---

## Deployment Steps
1. **Prepare Environment**:
   - Server: Windows machine with public IP or local network for testing.
   - Client: Windows (XP+) or Linux (any distro).
2. **Update Code**:
   - Configure `KEY`, `DOMAIN_ENC`, `AGENT_ID_ENC` in client; `KEY`, `DOMAIN` in server.
3. **Build**:
   - Compile as per build instructions.
4. **Deploy Server**:
   - Move `nyx_c2_server.exe` to Windows server.
   - Run: `nyx_c2_server.exe` (as admin).
   - Verify ports: `netstat -an | findstr "53 8443"`.
5. **Deploy Client**:
   - Move `nyx_c2_client.exe` (Windows) or `nyx_c2_client` (Linux) to target.
   - Run: `nyx_c2_client.exe` (Windows) or `./nyx_c2_client` (Linux).
   - Check persistence (e.g., Windows Startup folder, Linux `crontab -l`).
6. **Test**:
   - Server: `register agent_001 whoami`.
   - Client: Beacons, executes "whoami," returns result (check server popups).

---

## Troubleshooting
- **Client Not Beaconing**:
  - Verify firewall (UDP/53, TCP/8443 outbound), DNS (`nslookup c2.yourdomain.com`), `KEY` match.
- **Server GUI Issues**:
  - Run as admin; check port conflicts (`netstat -an`).
- **EDR Detection**:
  - If caught (e.g., CrowdStrike), adjust sleep times, noise sizes, or test in VM with logs.
  - Check process trees (`rundll32`, `svchost`), network traffic, memory dumps.

---
