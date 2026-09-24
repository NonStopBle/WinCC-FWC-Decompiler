#!/usr/bin/env python3
"""
opcua_export_csv.py - export a live WinCC OPC UA server's tags as a
Screen,Tag,OPC_NodeId,PLC_Address,DataType,Access,HMI_Tag_ID,HMI_Slot_Address
CSV, the last two columns optionally cross-referenced against
fwc_recovery.py's offline tags.json.

Honesty note, read before trusting the output:
  - Screen, Tag, OPC_NodeId, DataType, Access are all read LIVE from the
    real OPC UA server - genuine values, not guesses.
  - Screen is best-effort: it's taken from the node's parent folder name in
    the OPC UA namespace, which only matches the actual HMI screen name if
    the project's tag groups happen to be organized that way. Verify a few
    rows against the real project before trusting this column.
  - PLC_Address is ALWAYS written as "unknown". The S7-side address
    (DBx.DBWy / %IB / %QB) that a tag is bound to is not exposed over OPC
    UA and was not recoverable from pdata.fwc either (see the main
    README's "Tag-record parsing" section for why). This script does not
    guess it - do not fill it in from anywhere except the real PLC/HMI
    connection configuration in TIA Portal/WinCC Engineering itself.
  - With --fwc-dir, HMI_Tag_ID and HMI_Slot_Address are filled in by exact
    name match against that folder's tags.json (from fwc_recovery.py) -
    also genuine, offline-recovered data, matched by tag name string. A
    tag live on the server but missing from tags.json (or vice versa)
    just means the two sources disagree - could be a version mismatch
    between the running project and the .fwc file, a renamed tag, or a
    tag added/removed since the .fwc was captured. Worth checking, not
    silently ignoring - the summary at the end reports both counts.

Usage:
    python3 opcua_export_csv.py opc.tcp://<wincc-pc-ip>:4840 -o tags_export.csv
    python3 opcua_export_csv.py opc.tcp://<ip>:4840 --fwc-dir ../recon_pdata -o tags_export.csv
"""

import argparse
import asyncio
import csv
import json
from pathlib import Path

from asyncua import Client, ua

# OPC UA DataType NodeIds -> readable names, for the common scalar types
DATATYPE_NAMES = {
    1: "Bool", 2: "SByte", 3: "Byte", 4: "Int16", 5: "UInt16",
    6: "Int32", 7: "UInt32", 8: "Int64", 9: "UInt64",
    10: "Float", 11: "Double", 12: "String", 13: "DateTime",
}

# AccessLevel is a bitmask: bit 0 = CurrentRead, bit 1 = CurrentWrite
ACCESS_READ = 0x01
ACCESS_WRITE = 0x02


def access_string(access_level: int) -> str:
    r = bool(access_level & ACCESS_READ)
    w = bool(access_level & ACCESS_WRITE)
    if r and w:
        return "RW"
    if r:
        return "R"
    if w:
        return "W"
    return "-"


def load_fwc_tags(fwc_dir: str) -> dict:
    """Load fwc_recovery.py's tags.json into a {name: record} dict for
    exact-name lookup. Returns {} if --fwc-dir wasn't given or the file
    isn't there - callers then just get 'unknown' for those columns."""
    if not fwc_dir:
        return {}
    path = Path(fwc_dir) / "tags.json"
    if not path.exists():
        print(f"[!] {path} not found - HMI_Tag_ID/HMI_Slot_Address will be 'unknown'")
        return {}
    records = json.loads(path.read_text())
    return {r["name"]: r for r in records}


async def walk(node, screen, rows, fwc_tags, depth=0, max_depth=8):
    if depth > max_depth:
        return
    try:
        children = await node.get_children()
    except Exception:
        return
    for child in children:
        try:
            name = (await child.read_browse_name()).Name
            node_class = await child.read_node_class()
        except Exception:
            continue

        if int(node_class) == 2:  # Variable = an actual tag
            try:
                dtype_node = await child.read_data_type()
                dtype_id = dtype_node.Identifier if hasattr(dtype_node, "Identifier") else None
                dtype_name = DATATYPE_NAMES.get(dtype_id, f"type_id_{dtype_id}")
            except Exception:
                dtype_name = "unknown"
            try:
                access_level = await child.read_attribute(ua.AttributeIds.AccessLevel)
                access = access_string(access_level.Value.Value)
            except Exception:
                access = "unknown"

            fwc_rec = fwc_tags.get(name)
            rows.append({
                "Screen": screen or "(root)",
                "Tag": name,
                "OPC_NodeId": child.nodeid.to_string(),
                "PLC_Address": "unknown",  # see module docstring - never guessed
                "DataType": dtype_name,
                "Access": access,
                "HMI_Tag_ID": fwc_rec["tag_id"] if fwc_rec else "unknown",
                "HMI_Slot_Address": fwc_rec["hmi_slot_address_hex"] if fwc_rec else "unknown",
            })
        else:
            # Objects/Folders become the "screen" grouping for whatever's under them
            await walk(child, name, rows, fwc_tags, depth + 1, max_depth)


async def main(url, outfile, fwc_dir):
    fwc_tags = load_fwc_tags(fwc_dir)
    if fwc_dir:
        print(f"[*] loaded {len(fwc_tags)} tags from {fwc_dir}/tags.json for cross-reference")

    async with Client(url=url) as client:
        root = client.get_objects_node()
        rows = []
        await walk(root, None, rows, fwc_tags)

    fieldnames = ["Screen", "Tag", "OPC_NodeId", "PLC_Address", "DataType", "Access",
                  "HMI_Tag_ID", "HMI_Slot_Address"]
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"[+] wrote {len(rows)} tags -> {outfile}")
    print("[!] PLC_Address is always 'unknown' - see the module docstring for why "
          "that column can't be filled in from this data source.")

    if fwc_dir:
        live_names = {r["Tag"] for r in rows}
        matched = sum(1 for r in rows if r["HMI_Tag_ID"] != "unknown")
        only_offline = set(fwc_tags) - live_names
        print(f"[i] {matched}/{len(rows)} live tags matched a tags.json entry by name")
        print(f"[i] {len(only_offline)} tags in tags.json were not found live on the server "
              f"(renamed, removed, or a version mismatch between .fwc and the running project)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="OPC UA server URL, e.g. opc.tcp://192.168.1.10:4840")
    ap.add_argument("-o", "--outfile", default="tags_export.csv")
    ap.add_argument("--fwc-dir", help="fwc_recovery.py output folder (containing tags.json) to "
                                       "cross-reference live tags against, adding HMI_Tag_ID and "
                                       "HMI_Slot_Address columns")
    args = ap.parse_args()
    asyncio.run(main(args.url, args.outfile, args.fwc_dir))
