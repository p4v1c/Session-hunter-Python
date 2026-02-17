# SessionHunter

**SessionHunter** is a Python-based tool designed for real-time monitoring of active user sessions on remote Windows machines.

It queries the **Remote Registry** to identify logged-on users and resolves their SIDs into human-readable usernames using a multi-layered approach (LDAP, SAMR, and LSA).

## Features

* **Real-time Monitoring**: Dashboard view that refreshes automatically (default every 30 mins, adjustable).
* **Clean Output**: Only displays hosts with active identified sessions.
* **Agentless**: No installation or footprint required on the target machines.
* **Triple-Layer Resolution**:
* **LDAP**: High-speed resolution via the Domain Controller (requires `-dc-ip`).
* **SAMR**: Local resolution fallback for local accounts.
* **LSA (New)**: Robust SID-to-Name translation via `lsarpc` (bypasses SAMR restrictions).


* **Domain-wide Scanning**: Automatically fetches all computer objects from Active Directory when no specific target is provided.
* **Multi-threaded**: High performance even when scanning hundreds of hosts.

## 📋 Prerequisites

* **Python 3.x**
* **Network Access**: SMB/RPC access to target machines (Port 445).
* **RemoteRegistry Service**: Must be active on targets (enabled by default on Windows Server, often disabled on Windows 10/11 workstations).
* **Permissions**: A valid domain user account is required. Local Administrative rights are needed to access the `HKEY_USERS` hive via Remote Registry.

## 🛠️ Installation

1. Install via pip :

```bash
pip3 install git+https://github.com/p4v1c/Session-hunter-Python.git
```

2. Setup alias :

```bash
echo "alias session-hunter='python3 -m session_hunter'" >> ~/.zshrc && source ~/.zshrc
``` 

## 🚀 Usage

### Basic Syntax

```bash
session_hunter [TARGET_IP] -u [USER] -p [PASSWORD] -d [DOMAIN]

```

### Examples

#### 1. Monitor a specific machine

```bash
session_hunter 10.0.1.26 -u jimmy -p 'Password1234!' -d INTRA.LOCAL

```

#### 2. Scan the entire Domain (AD Discovery)

If no target is specified but a DC IP is provided, the script retrieves all computers from AD via LDAP and monitors them.

```bash
session_hunter -u jimmy -p 'Password1234!' -d INTRA.LOCAL -dc-ip 10.0.1.10

```

#### 3. Optimized Resolution with LDAP (Recommended)

Providing the DC IP allows the script to resolve SIDs much faster using LDAP queries.

```bash
ession_hunter 10.0.1.26 -u jimmy -p 'Password!' -d INTRA.LOCAL -dc-ip 10.0.1.10 -ldap-base "dc=intra,dc=local"

```

#### 4. Pass-the-Hash (PtH)

```bash
session_hunter 10.0.1.26 -u jimmy -H 'LMHASH:NTHASH' -d INTRA.LOCAL

```

## ⚙️ Arguments

| Argument | Description |
| --- | --- |
| `target` | (Optional) IP or Hostname of the target. If omitted, `-dc-ip` is required for discovery. |
| `-u`, `--username` | Username for authentication. |
| `-p`, `--password` | Password for authentication. |
| `-d`, `--domain` | Active Directory domain name. |
| `-H`, `--hashes` | NTLM hash for authentication (Format `LM:NT`). |
| `-dc-ip` | Domain Controller IP (Required for AD scan and LDAP resolution). |
| `-ldap-base` | (Optional) Custom Base DN for LDAP searches. |
| `-t`, `--threads` | Number of concurrent threads (Default: 10). |

## ⚠️ Troubleshooting

* **No output?**: The script filters out machines without active sessions. If the table is empty, no users are currently logged into the scanned targets.
* **"Unreachable / Service Stopped"**:
* Ensure the firewall allows **File and Printer Sharing (SMB-In)** and **Remote Administration**.
* Ensure the **RemoteRegistry** service is running.
* *Pro-tip:* On Windows 10/11, you may need to start the service manually: `Start-Service RemoteRegistry`.


* **"Admin: NON"**: Your current user does not have administrative privileges on the target machine, which is required to read `HKEY_USERS`.
