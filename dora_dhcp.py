from scapy.all import *
from scapy.fields import *
import random
import time

# Disable IP address checking
conf.checkIPaddr = False

# Constants
MAX_RETRIES = 5         # Maximum number of retries per phase
DISCOVER_TIMEOUT = 1    # Timeout for Discover phase in seconds
REQUEST_TIMEOUT = 1      # Timeout for Request phase in seconds
INTERFACE = 'en0'        # Network interface to use
VERBOSE = 0

# Generate random MAC and transaction ID


def generate_mac():
    return "5c:39:" + ":".join([f"{random.randint(0, 255):02x}" for _ in range(4)])


def generate_transaction_id():
    return random.randint(1, 400) * random.randint(1, 1236)


hw_mac = generate_mac()
transaction_id = generate_transaction_id()
hw_mac_bytes = mac2str(hw_mac)

print(f"Generated MAC: {hw_mac}")
hostname = hw_mac.replace(":", "")

# Function to create DHCP Discover packet


def create_discover(hw_mac_bytes, transaction_id, hostname):
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=hw_mac_bytes) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, xid=transaction_id, chaddr=hw_mac_bytes, flags=0x8000) /
        DHCP(options=[
            ('message-type', 'discover'),
            ('param_req_list', [1, 121, 3, 6, 15, 108, 114, 119, 252, 95, 44, 46]),
            ('max_dhcp_size', 1500),
            ('client_id', b'\x01' + hw_mac_bytes),
            ('lease_time', 30),
            ('hostname', hostname),
            'end'
        ])
    )

# Function to create DHCP Request packet


def create_request(hw_mac_bytes, transaction_id, dhcp_server, offered_ip, hostname):
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=hw_mac_bytes) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, xid=transaction_id, chaddr=hw_mac_bytes, flags=0x8000) /
        DHCP(options=[
            ('message-type', 'request'),
            ('server_id', dhcp_server),
            ('requested_addr', offered_ip),
            ('param_req_list', [1, 121, 3, 6, 15, 108, 114, 119, 252, 95, 44, 46]),
            ('hostname', hostname),
            'end'
        ])
    )

# Function to send Discover and handle retries


def send_discover(retries=MAX_RETRIES):
    discover_pkt = create_discover(hw_mac_bytes, transaction_id, hostname)
    for attempt in range(1, retries + 1):
        print(f"\nSending DHCP Discover (Attempt {attempt}/{retries})...")
        ans, unans = srp(discover_pkt, iface=INTERFACE, timeout=DISCOVER_TIMEOUT, verbose=VERBOSE)
        if ans:
            print("DHCP Offer received.")
            return ans[0][1]  # Return the first offer received
        else:
            print("No DHCP Offer received.")
    return None  # No offer received after retries

# Function to send Request and handle retries


def send_request(retries=MAX_RETRIES, dhcp_server=None, offered_ip=None):
    request_pkt = create_request(hw_mac_bytes, transaction_id, dhcp_server, offered_ip, hostname)
    for attempt in range(1, retries + 1):
        print(f"\nSending DHCP Request (Attempt {attempt}/{retries})...")
        ans, unans = srp(request_pkt, iface=INTERFACE, timeout=REQUEST_TIMEOUT, verbose=VERBOSE)
        if ans:
            print("DHCP Acknowledgment received.")
            return ans[0][1]  # Return the first acknowledgment received
        else:
            print("No DHCP Acknowledgment received.")
    return None  # No acknowledgment received after retries

# Main DORA Process with Retries


def dhcp_dora():
    # Phase 1: Discover
    offer = send_discover()
    if not offer:
        print("\nFailed to receive DHCP Offer after multiple attempts. Exiting.")
        return

    # Extract offered IP and DHCP server ID
    offered_ip = offer[BOOTP].yiaddr
    dhcp_server = None
    for opt in offer[DHCP].options:
        if opt[0] == 'server_id':
            dhcp_server = opt[1]
            break

    if not dhcp_server:
        print("No DHCP Server ID found in Offer. Exiting.")
        return

    print(f"\nOffered IP: {offered_ip}")
    print(f"DHCP Server ID: {dhcp_server}")

    # Phase 2: Request
    ack = send_request(dhcp_server=dhcp_server, offered_ip=offered_ip)
    if not ack:
        print("\nFailed to receive DHCP Acknowledgment after multiple attempts. Exiting.")
        return

    # Extract additional DHCP options from ACK
    print(f"\nObtained IP: {offered_ip}")
    print(f"DHCP Server: {dhcp_server}")

    for opt in ack[DHCP].options:
        if opt[0] == 'subnet_mask':
            print(f"Subnet Mask: {opt[1]}")
        elif opt[0] == 'router':
            print(f"Default Gateway: {opt[1]}")
        elif opt[0] == 'lease_time':
            print(f"Lease Time: {opt[1]} seconds")


if __name__ == "__main__":
    dhcp_dora()
