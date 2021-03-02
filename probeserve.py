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


def run_scan(hosts):
    print("Running scan")

    ips = set()
    ports = set()
    for host in hosts:
        ips.add(host["ip"])
        #if host.get("port"):
            #ports.add(host["port"])
    # TODO: convert ports to ranges where possible

    ips_csv = ",".join(ips)
    ports_csv = ",".join([ str(x) for x in ports])
    masscan_cmd = [masscan_path, "--redis-queue", "127.0.0.1", "--rate", str(masscan_rate), "-p", "1-65535", ips_csv]
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
    parser.add_argument("--out", help="The path to store C&C metadata.", default="cnc.csv", type=str)
    args = parser.parse_args()
    secret = args.secret
    masscan_path = args.masscan
    masscan_rate = args.masscan_rate
    cutoff_hours = args.cutoff
    scan_interval = args.scan_interval
    out_path = args.out

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
            write_cnc_metadata(cncs, out_path)
            p = run_scan(cncs)
            time.sleep(scan_interval)
            p.wait()
            print("Scan finished")
            cncs = []
        else:
            time.sleep(scan_interval)
        # TODO: Only sleep for the required time since we started the last scan.
        print("Sleeping for {} seconds".format(scan_interval))
