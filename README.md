# portspy
Tiny Linux utility to inspect port usage and associated processes
=======
# portspy - Tiny Linux Port Inspector Utility

`portspy` is a simple Python utility to quickly identify which process is listening on a specific port, or list all listening ports with their associated processes.

## Features

* Show process name, PID, user for a specific TCP/UDP port (e.g., `portspy 80`).
* Show process specifically for a TCP port (e.g., `portspy --tcp 443`).
* Show process specifically for a UDP port (e.g., `portspy --udp 53`).
* Show all ports used by a specific PID (e.g., `portspy <PID>`).
* List all listening ports with PIDs/names (e.g., `portspy --all`).

## Requirements

* Python 3.x
* Linux operating system (relies on the `/proc` filesystem)

## Installation

1.  **Download and Extract:**
    Download the `portspy.tar.gz` file and extract it:
    ```bash
    tar -xzvf portspy.tar.gz
    cd portspy
    ```

2.  **Run the Installer:**
    The installer script will copy `portspy` to `/usr/local/bin/`. You'll need root privileges.
    ```bash
    sudo bash install.sh
    ```

3.  **Verify Installation:**
    Open a new terminal or type `hash -r` (for bash) or `rehash` (for zsh) to update your shell's command cache. Then run:
    ```bash
    portspy --all
    portspy 80
    ```

## Usage Examples

* `portspy 80`       # Shows process(es) on TCP/UDP port 80
* `portspy --tcp 443`# Shows process(es) on TCP port 443
* `portspy --udp 53` # Shows process(es) on UDP port 53
* `portspy 1234`     # Shows all ports used by PID 1234
* `portspy --all`    # Lists all listening TCP and open UDP ports

For help:
```bash
portspy --help
