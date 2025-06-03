#!/bin/bash

# Uninstaller for portspy utility

# --- Configuration ---
INSTALL_DIR="/usr/local/bin"
SYMLINK_NAME="portspy"

# --- Functions ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root or with sudo."
        exit 1
    fi
}

uninstall_portspy() {
    echo "Uninstalling portspy..."

    if [ -L "$INSTALL_DIR/$SYMLINK_NAME" ] || [ -f "$INSTALL_DIR/$SYMLINK_NAME" ]; then
        echo "Removing $INSTALL_DIR/$SYMLINK_NAME..."
        rm -f "$INSTALL_DIR/$SYMLINK_NAME"
        if [ $? -ne 0 ]; then
            echo "Error: Failed to remove script. Check permissions."
            exit 1
        fi
        echo "portspy uninstalled successfully."
    else
        echo "portspy not found in $INSTALL_DIR. Nothing to uninstall."
    fi
}

# --- Main ---
check_root
uninstall_portspy

exit 0
