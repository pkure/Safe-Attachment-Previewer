#!/usr/bin/env python3
# hal-id: #HAL-20261110-0001-PK-M1
"""Live cost meter for the sandbox resource group (stdlib only; run with `python3 -I`).

Azure Cost Management lags 8-24 h, so this is an ESTIMATE:
  resources in the RG (az CLI) x public list price (Azure Retail Prices API, no auth) x time since created.
VMs count only while running. Usage-billed items (blob, Automation minutes, Run Command) are pennies and shown as ~0.
Reconcile the next day with `poc.sh cost-actual` (real billed cost from Cost Management).

  cost_meter.py [--rg rg-attsandbox] [--interval 15] [--once] [--json]
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

PRICES = "https://prices.azure.com/api/retail/prices"
HOURS_PER_MONTH = 730
SSD_TIERS = [(4, "E1"), (8, "E2"), (16, "E3"), (32, "E4"), (64, "E6"), (128, "E10"), (256, "E15"), (512, "E20"), (1024, "E30")]
_price_cache: dict[str, float] = {}


def az(*args: str):
    out = subprocess.run(["az", *args, "-o", "json"], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"az {' '.join(args[:3])} failed: {out.stderr.strip()[:300]}")
    return json.loads(out.stdout or "null")


def price(filt: str, pick=lambda items: items[0]) -> float:
    """First matching retail price (USD) for an OData filter, cached."""
    if filt not in _price_cache:
        url = f"{PRICES}?{urllib.parse.urlencode({'$filter': filt})}"
        with urllib.request.urlopen(url, timeout=20) as r:  # public price list, JSON only
            items = [i for i in json.load(r)["Items"] if i.get("type") == "Consumption"]
        _price_cache[filt] = float(pick(items)["retailPrice"]) if items else 0.0
    return _price_cache[filt]


def vm_rate(size: str, region: str, windows: bool) -> float:
    def pick(items):
        ok = [i for i in items if "Spot" not in i["skuName"] and "Low Priority" not in i["skuName"]
              and ("Windows" in i["productName"]) == windows]
        return ok[0] if ok else {"retailPrice": 0}
    return price(f"serviceName eq 'Virtual Machines' and armRegionName eq '{region}' and armSkuName eq '{size}'", pick)


def disk_rate(sku: str, size_gb: int, region: str) -> float:
    if not sku.startswith("StandardSSD"):
        return 0.0  # only what this repo deploys; extend if needed
    tier = next((t for gb, t in SSD_TIERS if size_gb <= gb), "E30")
    monthly = price(f"serviceName eq 'Storage' and armRegionName eq '{region}' and skuName eq '{tier} LRS' "
                    f"and meterName eq '{tier} LRS Disk' and contains(productName,'Standard SSD')")
    return monthly / HOURS_PER_MONTH


def hourly_rates(rg: str):
    sub = az("account", "show")["id"]
    res = az("rest", "--method", "get", "--url",
             f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/resources"
             "?$expand=createdTime&api-version=2021-04-01")["value"]
    vms = {v["name"].lower(): v for v in az("vm", "list", "-g", rg, "-d")}
    rows = []
    for r in res:
        t = r["type"].lower()
        name, region = r["name"], r["location"]
        created = datetime.fromisoformat(r["createdTime"].replace("Z", "+00:00"))
        rate, note = 0.0, "usage-based, ~$0"
        if t == "microsoft.compute/virtualmachines":
            v = vms.get(name.lower(), {})
            running = v.get("powerState") == "VM running"
            size = v.get("hardwareProfile", {}).get("vmSize", "")
            win = v.get("storageProfile", {}).get("osDisk", {}).get("osType") == "Windows"
            rate = vm_rate(size, region, win) if running else 0.0
            note = f"{size} {'Windows' if win else 'Linux'}, {v.get('powerState', '?')}"
        elif t == "microsoft.compute/disks":
            d = az("disk", "show", "--ids", r["id"])
            gb = int(d.get("diskSizeGB") or d.get("diskSizeGb") or 0)
            rate, note = disk_rate(d["sku"]["name"], gb, region), f"{d['sku']['name']} {gb} GB"
        elif t == "microsoft.network/bastionhosts":
            sku = r.get("sku", {}).get("name", "Developer")
            rate = 0.0 if sku == "Developer" else price(
                f"serviceName eq 'Azure Bastion' and armRegionName eq '{region}' and meterName eq '{sku} Gateway'")
            note = f"{sku} SKU" + (" (free)" if sku == "Developer" else "")
        elif t == "microsoft.network/privateendpoints":
            rate, note = price("productName eq 'Virtual Network Private Link' and meterName eq 'Standard Private Endpoint'"), "per endpoint"
        elif t == "microsoft.network/publicipaddresses":
            rate, note = price(f"serviceName eq 'Virtual Network' and armRegionName eq '{region}' and meterName eq 'Standard IPv4 Static Public IP'"), "Standard static"
        elif t == "microsoft.network/privatednszones":
            rate, note = 0.50 / HOURS_PER_MONTH, "$0.50/month"
        elif t in ("microsoft.network/virtualnetworks", "microsoft.network/networksecuritygroups",
                   "microsoft.network/networkinterfaces", "microsoft.network/privatednszones/virtualnetworklinks"):
            note = "free"
        rows.append({"name": name, "type": r["type"].split("/", 1)[1], "created": created, "rate": rate, "note": note})
    return rows


def render(rows, rg: str, expires: str | None, as_json: bool) -> None:
    now = datetime.now(timezone.utc)
    total = 0.0
    for r in rows:
        r["hours"] = max((now - r["created"]).total_seconds() / 3600, 0)
        r["cost"] = r["rate"] * r["hours"]
        total += r["cost"]
    burn = sum(r["rate"] for r in rows)
    if as_json:
        print(json.dumps({"rg": rg, "at": now.isoformat(), "estimate_usd": round(total, 4), "burn_usd_per_hour": round(burn, 4),
                          "resources": [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()} for r in rows]}))
        return
    print("\033[2J\033[H", end="")  # clear screen
    print(f"  ATTACHMENT SANDBOX - LIVE COST METER (estimate)   {now:%Y-%m-%d %H:%M:%S} UTC\n  resource group: {rg}\n")
    print(f"  {'resource':<28}{'type':<34}{'$/hour':>9}{'hours':>8}{'so far':>10}  note")
    for r in sorted(rows, key=lambda r: -r["cost"]):
        print(f"  {r['name'][:27]:<28}{r['type'][:33]:<34}{r['rate']:>9.4f}{r['hours']:>8.2f}{r['cost']:>10.4f}  {r['note']}")
    print(f"\n  BURN RATE  ${burn:.3f}/hour      SESSION SO FAR  \033[1m${total:.2f}\033[0m")
    if expires:
        left = (datetime.fromisoformat(expires.replace("Z", "+00:00")) - now).total_seconds() / 3600
        if left > 0:
            print(f"  self-destruct in {left:.1f} h -> worst case if forgotten: ${total + burn * left:.2f}")
    print("\n  List prices from prices.azure.com x uptime. Actual billed cost: `poc.sh cost-actual` (next day).")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rg", default="rg-attsandbox")
    ap.add_argument("--interval", type=int, default=15)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if not az("group", "exists", "-n", a.rg):
        sys.exit(f"{a.rg} does not exist (nothing running, $0/hour)")
    expires = (az("group", "show", "-n", a.rg).get("tags") or {}).get("expires")
    rows, refreshed = hourly_rates(a.rg), time.time()
    while True:
        if time.time() - refreshed > 120:  # re-read inventory/power state every 2 min; the clock ticks every interval
            rows, refreshed = hourly_rates(a.rg), time.time()
        render(rows, a.rg, expires, a.json)
        if a.once or a.json:
            return
        time.sleep(a.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
