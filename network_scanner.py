import scapy.all as scapy
import argparse
import csv


def get_arguments():
    """Gets the target IP range from command-line arguments or user input."""
    parser = argparse.ArgumentParser(description="Network Scanner using ARP")
    parser.add_argument("-t", "--target", dest="target",
                        help="Target IP range (e.g., 192.168.1.1/24)")
    args = parser.parse_args()

    if not args.target:
        args.target = input(
            "Enter the target IP range (e.g., 192.168.1.1/24): ")

    return args.target


def scan(ip):
    """Scans the given IP range for active devices using ARP requests."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=2, verbose=False)[0]

    devices = []
    for sent, received in answered_list:
        devices.append({"IP": received.psrc, "MAC": received.hwsrc})

    return devices


def save_to_csv(devices, filename="network_scan_results.csv"):
    """Saves scanned devices to a CSV file."""
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "MAC Address"])  # Header
        for device in devices:
            writer.writerow([device["IP"], device["MAC"]])

    print(f"\nResults saved to {filename}")


def print_results(devices):
    """Prints the scanned devices in a formatted table."""
    print("\nIP Address\t\tMAC Address\n-----------------------------------------")
    for device in devices:
        print(f"{device['IP']}\t\t{device['MAC']}")


if __name__ == "__main__":
    target_ip = get_arguments()
    scanned_devices = scan(target_ip)
    print_results(scanned_devices)

    if scanned_devices:
        save_to_csv(scanned_devices)
