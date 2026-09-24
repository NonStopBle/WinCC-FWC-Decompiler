#!/usr/bin/env python3
"""
opcua_browse.py - connect to a WinCC Runtime Advanced OPC UA server and dump
every exposed tag's Node ID next to its name, so you can match it against the
tag names recovered by fwc_recovery.py (tags.csv).

WinCC Runtime Advanced's tags are NOT addressed by the internal HMI slot
address fwc_recovery.py extracts - that address is internal process memory
on the runtime PC and isn't reachable over any network protocol. OPC UA is
the supported channel: tags are exposed there under a server-defined Node ID,
usually derived from the tag name, but the exact NodeId format depends on the
project's OPC UA export/naming settings - so browse first, don't guess.

Usage:
    python3 opcua_browse.py opc.tcp://<wincc-pc-ip>:4840
"""

import asyncio
import sys
from asyncua import Client


async def walk(node, path, out, depth=0, max_depth=8):
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
        full_path = f"{path}/{name}"
        # node_class == 2 means Variable - these are the actual readable/writable tags
        if int(node_class) == 2:
            try:
                value = await child.read_value()
            except Exception:
                value = "<unreadable>"
            out.append((full_path, child.nodeid.to_string(), value))
        await walk(child, full_path, out, depth + 1, max_depth)


async def main(url):
    async with Client(url=url) as client:
        root = client.get_objects_node()
        out = []
        await walk(root, "", out)
        print(f"[+] found {len(out)} variable nodes\n")
        for path, nodeid, value in out:
            print(f"{nodeid}\t{path}\t{value}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 opcua_browse.py opc.tcp://<wincc-pc-ip>:4840")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
