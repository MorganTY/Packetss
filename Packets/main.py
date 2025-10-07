import subprocess
import sys
import importlib.util

sys.stdout.reconfigure(encoding='utf-8')
# install required packages
REQUIRED_PACKAGES = ["scapy", "rich"]

def install_if_missing(package):
    """Check if a package is installed; if not, install it."""
    if importlib.util.find_spec(package) is None:
        print(f"[+] Installing missing dependency: {package}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

for pkg in REQUIRED_PACKAGES:
    install_if_missing(pkg)

# Import after installation 
from scapy.all import sniff
from Utills.packet_parser import parse_packet
from Utills.logger import log_packet
from rich.console import Console

console = Console()

# Sniffer logic
def process_packet(packet):
    parsed = parse_packet(packet)
    if parsed:
        console.print(f"[cyan]{parsed['timestamp']}[/cyan] | "
                      f"[bold]{parsed['src']}[/bold] > [bold]{parsed['dst']}[/bold] | "
                      f"{parsed['protocol']} | {parsed['info']}")
        log_packet(parsed)

def main():
    console.print("[green]Starting packet sniffer... (Press Ctrl+C to stop)[/green]")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
