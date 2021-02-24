import argparse
import mwdblib
import time
import re
import dns.resolver

MWDB_URL = "https://spawnwalk.duckdns.org"

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
    parser.add_argument("--mwdb-url", help="The URL to the MWDB instance.", default=MWDB_URL + "/api")
    parser.add_argument("--secret", help="The secret key.", required=True)
    args = parser.parse_args()
    secret = args.secret

    mwdb = mwdblib.MWDB(api_url=args.mwdb_url, api_key=secret)

    for config in mwdb.listen_for_configs():
        cncs = []
        # TODO: Perform additional processing to capture
        # objects that do not conform to the below structure.
        if config.cfg.get("cncs"):
            for cnc in config.cfg.get("cncs"):
                if type(cnc["host"]) is str and type(cnc["port"]) is int:
                    for ip in resolve(cnc["host"]):
                        cncs.append(ip + ":" + str(cnc["port"]))
        if config.cfg.get("c2"):
            for cnc in config.cfg.get("c2"):
                if type(cnc) is str:
                    cnc_parts = cnc.split(":")
                    for ip in resolve(cnc_parts[0]):
                        cncs.append(ip + ":" + cnc_parts[1])

        for cnc in cncs:
            print("Have CnC:", cnc)
    time.sleep(3600)
