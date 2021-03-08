import argparse
import subprocess
import mwdblib
import time
import pytz
from datetime import datetime, timedelta
import re
import dns.resolver
import sys
import tempfile

DEFAULT_MWDB_URL = "https://spawnwalk.duckdns.org"
DEFAULT_SCAN_INTERVAL_SECONDS = 30*60
masscan_path = None
masscan_rate = None
include_ports = ""

# TODO: Perform additional processing to capture
# objects that do not conform to the below structure.
def get_c2s(config):
    cncs = []
    mwdb_id = config.id
    family = config.family
    for cnc in config.cfg.get("cncs", []):
        if type(cnc["host"]) is str and type(cnc["port"]) is int:
            for ip in resolve(cnc["host"]):
                cncs.append({"id": mwdb_id, "family": family, "ip": ip, "port": cnc["port"]})
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
            cnc = {"id": mwdb_id, "family": family, "ip": ip}
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
            ports.add(int(port[0]))
        else:
            ports.update(range(int(port[0]), int(port[1])+1))

    return ports

def run_scan(hosts):
    ips = set()
    ports = set()
    for host in hosts:
        ips.add(host["ip"])
        if host.get("port"):
            ports.add(int(host["port"]))

    if include_ports != "":
        ports.update(get_port_list(include_ports))

    port_str = get_port_range(ports)

    ips_list = "\n".join(ips)
    ips_file = tempfile.NamedTemporaryFile(mode="w+b")
    ips_file.write(ips_list.encode("utf-8"))
    ips_file.flush()

    masscan_cmd = [masscan_path, "--redis-queue", "127.0.0.1", "--rate", str(masscan_rate), "-p", port_str, "--include-file", ips_file.name]
    print("Running command '{}'".format(" ".join(masscan_cmd)))
    p = subprocess.Popen(masscan_cmd)
    return p, ips_file


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

def write_cnc_metadata(cncs, out_path):
    with open(out_path, "a") as f:
        for cnc in cncs:
            f.write("{},{},{},{}\n".format(cnc.get("id"), cnc.get("ip"),
                    cnc.get("port",""), cnc.get("family", "unknown")))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeserver observer.")
    parser.add_argument("--mwdb-url", help="The URL to the MWDB instance.", default=DEFAULT_MWDB_URL + "/api")
    parser.add_argument("--secret", help="The secret key.", required=True)
    parser.add_argument("--masscan", help="The path to the masscan binary.", default="masscan")
    parser.add_argument("--cutoff", help="Cutoff time in hours for time based retrieval.", default=24, type=int)
    parser.add_argument("--scan-interval", help="Scan interval.", default=DEFAULT_SCAN_INTERVAL_SECONDS)
    parser.add_argument("--masscan-rate", help="Masscan rate.", default=1000, type=int)
    parser.add_argument("--port", help="Ports to always scan.", default="", type=str)
    parser.add_argument("--out", help="The path to store C&C metadata.", default="cnc.csv", type=str)
    parser.add_argument("--checkpoint", help="The path to checkpoint file, resume from the last retrieval.", type=str)
    args = parser.parse_args()
    secret = args.secret
    masscan_path = args.masscan
    masscan_rate = args.masscan_rate
    cutoff_hours = args.cutoff
    scan_interval = args.scan_interval
    include_ports = args.port
    out_path = args.out

    mwdb = mwdblib.MWDB(api_url=args.mwdb_url, api_key=secret)

    last_id = None
    if args.checkpoint:
        try:
            with open(args.checkpoint, "r") as f:
                last_id = f.read().strip()
            print("Found checkpoint, resuming from {}".format(last_id))
        except IOError:
            print("Checkpoint file not found")
            pass

    cncs = []
    while True:
        if not last_id:
            print("First scan. Getting configurations from the last {} hours.".format(cutoff_hours))

            utc=pytz.UTC
            cutoff_time =  utc.localize(datetime.utcnow() - timedelta(hours=cutoff_hours))

            recent_configs = mwdb.recent_configs()
            for idx, config in enumerate(recent_configs):
                if config.upload_time < cutoff_time:
                    print("\nCutoff {} hours {} reached.".format(cutoff_hours, config.upload_time))
                    break
                # The first one we receive will be the latest one, store that id
                if idx == 0:
                    last_id = config.id

                cfgc2s = get_c2s(config)
                if cfgc2s:
                    print("+", end="")
                    cncs.extend(cfgc2s)
                else:
                    print(".", end="")
                sys.stdout.flush()
        else:
            print("\nListening for configs...")
            configs = mwdb.listen_for_configs(last_id, blocking=False)
            for idx, config in enumerate(configs):
                if idx == 0:
                    last_id = configs[0].id
                print(config)
                cncs.extend(get_c2s(config))

        if args.checkpoint and last_id:
            print("Writing checkpoint: {}".format(last_id))
            with open(args.checkpoint, "w") as f:
                f.write("{}\n".format(last_id))

        if len(cncs) > 0:
            print("Have C2s. Sending scan command.")
            write_cnc_metadata(cncs, out_path)
            p, f = run_scan(cncs)
            print("Scan command sent. Waiting for scan interval to end...")
            time.sleep(scan_interval)
            p.wait()
            f.close()
            cncs = []
        else:
            time.sleep(scan_interval)

