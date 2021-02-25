import argparse
import subprocess
import mwdblib
import time
import pytz
from datetime import datetime, timedelta
import re
import dns.resolver

DEFAULT_MWDB_URL = "https://spawnwalk.duckdns.org"
DEFAULT_SCAN_INTERVAL_SECONDS = 10*60
masscan_path = None

# TODO: Perform additional processing to capture
# objects that do not conform to the below structure.
# TODO: Fix the shit code.
def get_c2s(config):
    cncs = []
    if config.cfg.get("cncs"):
        for cnc in config.cfg.get("cncs"):
            if type(cnc["host"]) is str and type(cnc["port"]) is int:
                for ip in resolve(cnc["host"]):
                    print("Received C2:", ip + ":" + str(cnc["port"]))
                    cncs.append({"ip": ip, "port": cnc["port"]})
    if config.cfg.get("c2"):
        for cnc in config.cfg.get("c2"):
            if type(cnc) is str:
                cnc_parts = cnc.split(":")
                for ip in resolve(cnc_parts[0]):
                    print("Received C2:", ip + ":" + cnc_parts[1])
                    cncs.append({"ip": ip, "port": cnc_parts[1]})
    return cncs


def init_scan(hosts):
    print("Running scan")

    ips = set()
    ports = set()
    for host in hosts:
        ips.add(host["ip"])
        ports.add(host["port"])

    ips_csv = ",".join(ips)
    ports_csv = ",".join([ str(x) for x in ports])
    masscan_cmd = [masscan_path, "--redis-queue", "127.0.0.1", "-p", ports_csv, ips_csv]
    print("Running command '{}'".format(" ".join(masscan_cmd)))
    subprocess.Popen(masscan_cmd)
    print("Masscan started")


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
    parser.add_argument("--cutoff", help="Cutoff time in hours for time based retrieval.", default=24)
    parser.add_argument("--scan-interval", help="Scan interval.", default=DEFAULT_SCAN_INTERVAL_SECONDS)
    args = parser.parse_args()
    secret = args.secret
    masscan_path = args.masscan
    cutoff_hours = args.cutoff

    mwdb = mwdblib.MWDB(api_url=args.mwdb_url, api_key=secret)

    last_id = None
    cncs = []
    while True:
        if not last_id:
            print("No last_config_id loaded, get configurations based on date.")

            # Calculate cutoff time to get configs for the last 24 hours
            utc=pytz.UTC
            cutoff_time =  utc.localize(datetime.utcnow() - timedelta(hours=cutoff_hours))

            recent_configs = mwdb.recent_configs()
            for idx, config in enumerate(recent_configs):
                if config.upload_time < cutoff_time:
                    print("Cutoff time {} reached".format(config.upload_time))
                    break

                # The first one we receive will be the latest one, store that id
                if idx == 0:
                    last_id = config.id

                cncs.extend(get_c2s(config))

        print("Listening for configs")
        configs = mwdb.listen_for_configs(last_id, blocking=False)
        start_time = time.localtime()
        for config in configs:
            cncs.extend(get_c2s(config))

        if len(cncs) > 0:
            print("Have CnCs. Scanning")
            init_scan(cncs)
            print("Scan finished")
            cncs = []
        print("Sleeping for {} seconds".format(SCAN_INTERVAL_SECONDS))
        time.sleep(SCAN_INTERVAL_SECONDS)
