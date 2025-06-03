#!/usr/bin/env python3

import argparse
import os
import pwd
import re
import socket
import struct
from collections import defaultdict

# --- Constants ---
PROC_NET_TCP = "/proc/net/tcp"
PROC_NET_TCP6 = "/proc/net/tcp6"
PROC_NET_UDP = "/proc/net/udp"
PROC_NET_UDP6 = "/proc/net/udp6"
PROC_PATH = "/proc"

# Socket states for listening
# From include/net/tcp_states.h in Linux kernel
TCP_LISTEN = '0A'  # TCP_LISTEN

# --- Helper Functions ---

def get_user_by_uid(uid):
    """Gets username from UID."""
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return str(uid)

def get_process_info(pid):
    """Gets command and user for a given PID."""
    try:
        with open(os.path.join(PROC_PATH, pid, "comm"), 'r') as f:
            command = f.read().strip()
    except FileNotFoundError:
        command = "N/A" # Process might have terminated

    try:
        # More reliable way to get user is from the status file's Uid line
        with open(os.path.join(PROC_PATH, pid, "status"), 'r') as f:
            for line in f:
                if line.startswith("Uid:"):
                    # Real, effective, saved, filesystem UIDs
                    uid = line.split()[1] # Get the real UID
                    user = get_user_by_uid(uid)
                    break
            else:
                user = "N/A"
    except FileNotFoundError:
        user = "N/A"
    return command, user

def parse_net_file(filepath, target_port=None, target_inode=None, protocol_name="tcp"):
    """
    Parses /proc/net/tcp, /proc/net/udp files.
    Returns a dictionary {inode: {"local_port": port, "state": state, "protocol": proto_name}}
    or {port: {"inode": inode, "state": state, "protocol": proto_name}} if target_inode is used for reverse lookup.
    """
    results = {}
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            if not lines:
                return results

            for line in lines[1:]: # Skip header
                parts = line.split()
                local_address = parts[1]
                state = parts[3]
                inode = parts[9] # Inode number of the socket

                if protocol_name.startswith("tcp") and state != TCP_LISTEN:
                    continue # For TCP, only show listening sockets

                if ":" in local_address: # IPv4 or IPv6
                    if filepath.endswith("6"): # IPv6
                        # Example: 00000000000000000000000000000000:0050
                        hex_port = local_address.split(':')[-1]
                        current_protocol = protocol_name + "6"
                    else: # IPv4
                        # Example: 00000000:0050
                        hex_port = local_address.split(':')[-1]
                        current_protocol = protocol_name

                    port = int(hex_port, 16)

                    if target_port is not None and port == target_port:
                        results[inode] = {"local_port": port, "state": state, "protocol": current_protocol}
                    elif target_inode is not None and inode == target_inode:
                        # Used for PID lookup to find port from inode
                        results[port] = {"inode": inode, "state": state, "protocol": current_protocol}
                    elif target_port is None and target_inode is None: # --all or general parsing
                        results[inode] = {"local_port": port, "state": state, "protocol": current_protocol}

    except FileNotFoundError:
        # Silently ignore if a file (e.g., /proc/net/udp6) doesn't exist if UDPv6 is disabled
        pass
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
    return results

def find_processes_for_inodes(inodes_info):
    """
    Finds PIDs, commands, and users for given socket inodes.
    inodes_info is {inode: {"local_port": port, "protocol": proto}}
    Returns {port_protocol_combo: [{"pid": pid, "user": user, "command": command, "protocol": proto}]}
    """
    processes_by_port_proto = defaultdict(list)
    try:
        pids = [pid for pid in os.listdir(PROC_PATH) if pid.isdigit()]
    except FileNotFoundError:
        print(f"Error: Could not list {PROC_PATH}. Are you on Linux?")
        return processes_by_port_proto

    for pid in pids:
        try:
            fd_path = os.path.join(PROC_PATH, pid, "fd")
            for fd_name in os.listdir(fd_path):
                try:
                    link_target = os.readlink(os.path.join(fd_path, fd_name))
                    if link_target.startswith("socket:["):
                        inode = link_target[8:-1]
                        if inode in inodes_info:
                            port_info = inodes_info[inode]
                            cmd, usr = get_process_info(pid)
                            key = (port_info["local_port"], port_info["protocol"])
                            processes_by_port_proto[key].append({
                                "pid": pid,
                                "user": usr,
                                "command": cmd,
                                "protocol": port_info["protocol"],
                                "port": port_info["local_port"]
                            })
                except (FileNotFoundError, PermissionError): # Process or fd might vanish
                    continue
        except (FileNotFoundError, PermissionError): # Process dir might vanish
            continue
    return processes_by_port_proto

def find_ports_for_pid(target_pid):
    """Finds all ports (TCP/UDP, listening or connected) used by a specific PID."""
    pid_ports = []
    socket_inodes = []

    try:
        fd_path = os.path.join(PROC_PATH, str(target_pid), "fd")
        if not os.path.isdir(fd_path):
            print(f"Error: Process with PID {target_pid} not found or no permissions.")
            return pid_ports

        for fd_name in os.listdir(fd_path):
            try:
                link_target = os.readlink(os.path.join(fd_path, fd_name))
                if link_target.startswith("socket:["):
                    socket_inodes.append(link_target[8:-1])
            except (FileNotFoundError, PermissionError):
                continue # FD might have been closed
    except (FileNotFoundError, PermissionError):
        print(f"Error: Could not access process {target_pid} information.")
        return pid_ports

    if not socket_inodes:
        return pid_ports

    # Check TCP, TCP6, UDP, UDP6 files for these inodes
    # Note: This will find both listening and established connections for the PID
    # The original request for PID implies any port used, not just listening
    all_socket_info = {}
    for inode in socket_inodes:
        # For TCP, we are interested in any state, not just LISTEN
        tcp_sockets = parse_net_file(PROC_NET_TCP, target_inode=inode, protocol_name="tcp")
        tcp6_sockets = parse_net_file(PROC_NET_TCP6, target_inode=inode, protocol_name="tcp") # proto is tcp6 later
        udp_sockets = parse_net_file(PROC_NET_UDP, target_inode=inode, protocol_name="udp")
        udp6_sockets = parse_net_file(PROC_NET_UDP6, target_inode=inode, protocol_name="udp") # proto is udp6 later

        for port, info in tcp_sockets.items():
            all_socket_info[(port, "tcp", inode)] = info
        for port, info in tcp6_sockets.items():
            all_socket_info[(port, "tcp6", inode)] = info
        for port, info in udp_sockets.items():
            all_socket_info[(port, "udp", inode)] = info
        for port, info in udp6_sockets.items():
            all_socket_info[(port, "udp6", inode)] = info


    cmd, usr = get_process_info(str(target_pid))

    for (port, proto_base, inode), info_val in all_socket_info.items():
        pid_ports.append({
            "protocol": info_val["protocol"], # Use the refined protocol (tcp/tcp6/udp/udp6)
            "port": port,
            "pid": str(target_pid),
            "user": usr,
            "command": cmd,
            "inode": inode,
            "state": info_val.get("state", "N/A") # UDP doesn't have state in the same way
        })
    return pid_ports


def print_header():
    print(f"{'PROTO':<7} {'PORT':<6} {'PID':<7} {'USER':<15} {'COMMAND'}")

def print_all_header():
     print(f"{'PORT/PROTO':<12} {'PID':<7} {'USER':<15} {'COMMAND'}")


def main():
    parser = argparse.ArgumentParser(description="Tiny Linux Utility: portspy (Port Inspector)")
    parser.add_argument("target", nargs='?', help="Port number or PID")
    parser.add_argument("--tcp", metavar="PORT", type=int, help="Show process for specific TCP port")
    parser.add_argument("--udp", metavar="PORT", type=int, help="Show process for specific UDP port")
    parser.add_argument("--all", action="store_true", help="List all listening ports with PIDs/names")

    args = parser.parse_args()

    target_port = None
    target_pid_val = None
    specific_proto = None

    if args.tcp:
        target_port = args.tcp
        specific_proto = "tcp"
    elif args.udp:
        target_port = args.udp
        specific_proto = "udp"
    elif args.target:
        try:
            target_port = int(args.target)
        except ValueError:
            try:
                target_pid_val = int(args.target)
                if target_pid_val <= 0:
                    raise ValueError
            except ValueError:
                parser.error("Argument must be a port number or a PID.")
    elif not args.all:
        parser.print_help()
        return

    # Handle PID lookup
    if target_pid_val:
        results = find_ports_for_pid(target_pid_val)
        if results:
            print_header()
            # Sort by protocol, then port
            results.sort(key=lambda x: (x["protocol"], x["port"]))
            for res in results:
                # For PID lookup, it's useful to see the state
                print(f"{res['protocol']:<7} {res['port']:<6} {res['pid']:<7} {res['user']:<15} {res['command']}")
        else:
            cmd, _ = get_process_info(str(target_pid_val))
            if cmd != "N/A":
                 print(f"Process PID {target_pid_val} ({cmd}) is not found using any monitored network ports.")
            else:
                 print(f"Process PID {target_pid_val} not found or not using monitored network ports.")
        return

    # Handle port lookup or --all
    all_listening_inodes = {}
    if args.all or target_port is not None:
        if specific_proto is None or specific_proto == "tcp":
            all_listening_inodes.update(parse_net_file(PROC_NET_TCP, target_port, protocol_name="tcp"))
            all_listening_inodes.update(parse_net_file(PROC_NET_TCP6, target_port, protocol_name="tcp")) # will be tcp6
        if specific_proto is None or specific_proto == "udp":
            all_listening_inodes.update(parse_net_file(PROC_NET_UDP, target_port, protocol_name="udp"))
            all_listening_inodes.update(parse_net_file(PROC_NET_UDP6, target_port, protocol_name="udp")) # will be udp6

    if not all_listening_inodes and target_port:
        proto_filter_msg = f" for protocol {specific_proto.upper()}" if specific_proto else ""
        print(f"No process found listening on port {target_port}{proto_filter_msg}.")
        return
    elif not all_listening_inodes and args.all:
        print("No listening ports found.")
        return

    processes_on_ports = find_processes_for_inodes(all_listening_inodes)

    if not processes_on_ports and target_port:
        proto_filter_msg = f" for protocol {specific_proto.upper()}" if specific_proto else ""
        print(f"No process found listening on port {target_port}{proto_filter_msg} (socket found but no process linked via /proc).")
        return
    elif not processes_on_ports and args.all:
        print("No processes found for listening ports (sockets found but no processes linked via /proc).")
        return


    if args.all:
        print_all_header()
        # Sort by port number then protocol for --all
        sorted_results = sorted(processes_on_ports.items(), key=lambda item: (item[0][0], item[0][1]))
        for (port, proto), procs in sorted_results:
            for proc_info in procs:
                 print(f"{str(port) + '/' + proc_info['protocol']:<12} {proc_info['pid']:<7} {proc_info['user']:<15} {proc_info['command']}")
    else: # Specific port query
        print_header()
        # Create a flat list and sort it
        flat_list = []
        for (port, proto_key), procs in processes_on_ports.items():
            if port == target_port: # Ensure we only print for the target port
                for p_info in procs:
                    # If specific_proto is given, filter by it
                    if specific_proto:
                        # p_info['protocol'] can be 'tcp6', specific_proto 'tcp'
                        if specific_proto in p_info['protocol']:
                             flat_list.append(p_info)
                    else:
                        flat_list.append(p_info)

        # Sort by protocol, then pid
        flat_list.sort(key=lambda x: (x["protocol"], int(x["pid"])))
        if not flat_list:
            proto_filter_msg = f" for protocol {specific_proto.upper()}" if specific_proto else ""
            print(f"No process found listening on port {target_port}{proto_filter_msg}.")

        for res in flat_list:
            print(f"{res['protocol']:<7} {res['port']:<6} {res['pid']:<7} {res['user']:<15} {res['command']}")


if __name__ == "__main__":
    if os.geteuid() != 0:
        # While not strictly necessary for all /proc reads, some PIDs might be restricted.
        # For consistency and full access, root is often helpful.
        # print("Warning: Running as non-root. May not be able to access all process information.")
        pass # Decided to allow non-root, with potential for missing info
    main()
