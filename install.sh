#!/bin/bash

# Installer for portspy utility

# --- Configuration ---
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="portspy.py"
SYMLINK_NAME="portspy" # How users will call the command

# --- Functions ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root or with sudo."
        exit 1
    fi
}

install_portspy() {
    echo "Installing portspy..."

    if [ ! -f "$SCRIPT_NAME" ]; then
        echo "Error: $SCRIPT_NAME not found in the current directory."
        echo "Please run this script from the directory where $SCRIPT_NAME is located."
        exit 1
    fi

    echo "Copying $SCRIPT_NAME to $INSTALL_DIR/$SYMLINK_NAME..."
    cp "$SCRIPT_NAME" "$INSTALL_DIR/$SYMLINK_NAME"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to copy script. Check permissions for $INSTALL_DIR."
        exit 1
    fi

    echo "Making $INSTALL_DIR/$SYMLINK_NAME executable..."
    chmod +x "$INSTALL_DIR/$SYMLINK_NAME"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to set execute permissions."
        # Attempt to clean up if chmod fails
        rm -f "$INSTALL_DIR/$SYMLINK_NAME"
        exit 1
    fi

    # Verify it's in PATH (basic check)
    if ! command -v $SYMLINK_NAME &> /dev/null; then
        echo ""
        echo "Warning: $INSTALL_DIR might not be in your PATH or your shell hasn't updated its command cache."
        echo "You might need to open a new terminal or run 'hash -r' (bash) or 'rehash' (zsh)."
        echo "You can try running it with the full path: $INSTALL_DIR/$SYMLINK_NAME"
    fi

    echo ""
    echo "portspy installed successfully!"
    echo "You can now run it using the command: $SYMLINK_NAME"
}

# --- Main ---
check_root
install_portspy

exit 0
