import argparse
import subprocess
import mwdblib
import time
import pytz
from datetime import datetime, timedelta
import re
import dns.resolver
import sys


DEFAULT_MWDB_URL = "https://spawnwalk.duckdns.org"
DEFAULT_SCAN_INTERVAL_SECONDS = 30*60
masscan_path = None
masscan_rate = None
include_ports = ""

# TODO: Perform additional processing to capture
# objects that do not conform to the below structure.
def get_c2s(config):
    cncs = []
    family = config.cfg.get("type")
    for cnc in config.cfg.get("cncs", []):
        if type(cnc["host"]) is str and type(cnc["port"]) is int:
            for ip in resolve(cnc["host"]):
                cncs.append({"family": family, "ip": ip, "port": cnc["port"]})
    for cnc in config.cfg.get("c2", []):
        if type(cnc) is str:
            url_regex = "^[a-z]+://.*"
            if re.match(url_regex, cnc):
                continue
        elif type(cnc) is dict:
            cnc = cnc["host"]
        else:
            continue
        cnc_parts = cnc.split(":")
        for ip in resolve(cnc_parts[0]):
            cnc = {"family": family, "ip": ip}
            if len(cnc_parts) > 1:
                cnc["port"] = cnc_parts[1]
            cncs.append(cnc)
    return cncs

def get_port_range(ports):
    port_range = []
    port_start = -1
    for port in sorted(map(int, ports)):
        if port_start == -1:
            # the first port in the list
            port_start = port
        elif port != last_port + 1:
            # when the current port is not continuous
            if last_port == port_start:
                # he/she is alone ;-;
                port_range.append(str(port_start))
            else:
                # port range
                port_range.append("{}-{}".format(port_start, last_port))
            port_start = port

        last_port = port

    if last_port == port_start:
        port_range.append(str(port_start))
    else:
        port_range.append("{}-{}".format(port_start, last_port))

    return ','.join(port_range)

def get_port_list(port_range):
    ports = set()
    for rng in port_range.split(","):
        port = rng.split("-")
        if len(port) == 1:
            ports.add(port[0])
        else:
            ports.update(map(str, range(int(port[0]), int(port[1])+1)))

    return ports

def run_scan(hosts):
    print("Running scan")

    ips = set()
    ports = set()
    for host in hosts:
        ips.add(host["ip"])
        if host.get("port"):
            ports.add(host["port"])

    if include_ports != "":
        ports.update(get_port_list(include_ports))

    port_str = get_port_range(ports)

    ips_csv = ",".join(ips)
    ports_csv = ",".join([ str(x) for x in ports])
    masscan_cmd = [masscan_path, "--redis-queue", "127.0.0.1", "--rate", str(masscan_rate), "-p", port_str, ips_csv]
    print("Running command '{}'".format(" ".join(masscan_cmd)))
    p = subprocess.Popen(masscan_cmd)
    return p


def resolve(address):
    ips = []
    ip_address_regex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not re.match(ip_address_regex, address):
        try:
            result = dns.resolver.resolve(address, "A")
        except Exception:
            return []
        for ip in result:
            ips.append(ip.to_text())
    else:
        ips = [address]

    return ips


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeserver observer.")
    parser.add_argument("--mwdb-url", help="The URL to the MWDB instance.", default=DEFAULT_MWDB_URL + "/api")
    parser.add_argument("--secret", help="The secret key.", required=True)
    parser.add_argument("--masscan", help="The path to the masscan binary.", default="masscan")
    parser.add_argument("--cutoff", help="Cutoff time in hours for time based retrieval.", default=24, type=int)
    parser.add_argument("--scan-interval", help="Scan interval.", default=DEFAULT_SCAN_INTERVAL_SECONDS)
    parser.add_argument("--masscan-rate", help="Masscan rate.", default=1000, type=int)
    parser.add_argument("--port", help="Ports to always scan.", default="", type=str)
    args = parser.parse_args()
    secret = args.secret
    masscan_path = args.masscan
    masscan_rate = args.masscan_rate
    cutoff_hours = args.cutoff
    scan_interval = args.scan_interval
    include_ports = args.port

    mwdb = mwdblib.MWDB(api_url=args.mwdb_url, api_key=secret)

    last_id = None
    cncs = []
    while True:
        if not last_id:
            print("First scan. Getting C2s from the last {} hours.".format(cutoff_hours))

            utc=pytz.UTC
            cutoff_time =  utc.localize(datetime.utcnow() - timedelta(hours=cutoff_hours))

            recent_configs = mwdb.recent_configs()
            for idx, config in enumerate(recent_configs):
                if config.upload_time < cutoff_time:
                    print("Cutoff {} hours {} reached".format(cutoff_hours, config.upload_time))
                    break
                # The first one we receive will be the latest one, store that id
                if idx == 0:
                    last_id = config.id

                cncs.extend(get_c2s(config))
                print(".", end="")
                sys.stdout.flush()

        print("\nListening for configs")
        configs = mwdb.listen_for_configs(last_id, blocking=False)
        start_time = time.localtime()
        for config in configs:
            cncs.extend(get_c2s(config))

        if len(cncs) > 0:
            print("Have CnCs. Scanning")
            p = run_scan(cncs)
            time.sleep(scan_interval)
            p.wait()
            print("Scan finished")
            cncs = []
        else:
            time.sleep(scan_interval)
        # TODO: Only sleep for the required time since we started the last scan.
        print("Sleeping for {} seconds".format(scan_interval))
