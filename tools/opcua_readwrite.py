#!/usr/bin/env python3
"""
opcua_readwrite.py - read or write one tag on a live WinCC Runtime Advanced
OPC UA server, addressed by its Node ID (get this from opcua_browse.py first
- don't guess it from the tag name).

SAFETY: this can write a live value into a running machine's control system.
Never write without knowing exactly what that tag does on the real equipment.
Read-only first. Confirm the node ID, current value and expected effect with
whoever owns/operates the machine before writing anything.

Usage:
    python3 opcua_readwrite.py opc.tcp://<ip>:4840 read  "ns=2;s=HMI_Mold2_set_Setup_PID_Gain"
    python3 opcua_readwrite.py opc.tcp://<ip>:4840 write "ns=2;s=HMI_Mold2_set_Setup_PID_Gain" 12.5
"""

import asyncio
import sys
from asyncua import Client, ua


async def main(url, action, nodeid_str, value=None):
    async with Client(url=url) as client:
        node = client.get_node(nodeid_str)
        current = await node.read_value()
        print(f"[i] current value: {current!r}")

        if action == "read":
            return

        if action == "write":
            # match the OPC UA variant type of the existing value so the
            # write doesn't get silently rejected/coerced wrong
            dv = await node.read_data_value()
            variant_type = dv.Value.VariantType
            py_type = type(current)
            typed_value = py_type(value) if py_type in (int, float, bool) else value
            await node.write_value(ua.DataValue(ua.Variant(typed_value, variant_type)))
            new_value = await node.read_value()
            print(f"[+] wrote {typed_value!r}, read back: {new_value!r}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    url, action, nodeid_str = sys.argv[1], sys.argv[2], sys.argv[3]
    value = sys.argv[4] if len(sys.argv) > 4 else None
    if action not in ("read", "write"):
        print("action must be 'read' or 'write'")
        sys.exit(1)
    if action == "write" and value is None:
        print("write requires a value argument")
        sys.exit(1)
    asyncio.run(main(url, action, nodeid_str, value))
