# /// script
# dependencies = [
#   "requests",
# ]
# ///
import requests
import ipaddress

URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

def fetch_hosts(url: str) -> list[str]:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text.splitlines()

def is_not_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError:
        return True

def extract_hostnames(lines: list[str]) -> set[str]:
    hostnames = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "0.0.0.0":
            hostname = parts[1]
            if is_not_ip(hostname):
                hostnames.add(hostname)
    return hostnames

def main():
    all_hosts = set()
    for url in URLS:
        lines = fetch_hosts(url)
        all_hosts |= extract_hostnames(lines)
    hosts = "\n".join(list(sorted(all_hosts)))
    with open("default.blocklist", "w") as f:
        f.write(hosts)

if __name__ == "__main__":
    main()
