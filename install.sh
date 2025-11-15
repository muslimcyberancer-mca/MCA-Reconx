#!/bin/bash
echo "Installing MCA-Reconx Dependencies..."
apt update -y
apt install python -y
pip install -r requirements.txt
echo "Installation Completed!"
