#!/usr/bin/env python3
"""
fwc_recovery.py - WinCC Runtime Advanced pdata.fwc data recovery tool.

Reverse engineering credit: Rezier Labs
Every structure documented here (PNG/zlib carving, the tag-record binary
layout, the class-ID catalog) was reverse engineered from scratch against a
real production pdata.fwc with no reference documentation or prior public
research to build on. Treat the constants below as a research finding, not
a spec - they're the result of manual byte-level analysis, not anything
officially published.

pdata.fwc is a proprietary binary container for a compiled
WinCC Runtime Advanced project (screens, tags, scripts, fonts, graphics all packed
together). There is no public format spec for it. Everything
below was reverse engineered by hand against one real project file and is offered
as-is: constants (magic numbers, record sizes) were confirmed against thousands of
records in that file but may shift between WinCC/TIA Portal versions or builds.
Always sanity-check counts/output against `--verbose` before trusting results.

What this recovers:
  1. PNG icon/graphic assets            (pngs/*.png)
  2. Decompressed zlib object streams   (zlib_out/*.bin)   - binary, mostly still
                                                              undeciphered screen/
                                                              widget object data
  3. All UTF-16LE / ASCII strings       (strings/*.txt)    - tag names, alarm text,
                                                              device/driver strings,
                                                              IPs, everything textual
  4. Tag name -> internal HMI address   (tags.csv / .json) - decoded from the fixed
                                                              28-byte record that
                                                              precedes every tag's
                                                              name string. This is
                                                              the WinCC Runtime's
                                                              *internal* tag-table
                                                              slot address, NOT the
                                                              PLC-side S7 address
                                                              (DBx.DBWy / %IB / %QB).
  5. IPv4 addresses                     (ip_addresses.txt)
  6. Embedded class-ID (GUID) catalog   (class_ids.txt)    - cross-referenced against
                                                              a sidecar pdata.tfz if
                                                              present in the same dir
  7. WinCC Runtime Advanced version     (version_info.txt) - decoded from a sidecar
                                                              ProjectCharacteristics.rdf
                                                              if present. NOT embedded
                                                              in pdata.fwc itself.

Usage:
    python3 fwc_recovery.py pdata.fwc [-o OUTDIR] [--min-string-len N] [-v]

Output layout (default outdir: recon_<fwc_basename>/):
    pngs/                 carved PNG files
    zlib_out/              decompressed zlib blocks
    strings/ascii.txt       ASCII strings with file offsets
    strings/utf16.txt       UTF-16LE strings with file offsets
    ip_addresses.txt
    class_ids.txt
    tags.csv, tags.json     tag_name, tag_id, type_code, hmi_slot_address, file_offset
    version_info.txt        decoded WinCC Runtime Advanced version, if found
    summary.json            counts + key facts, machine readable
"""

import argparse
import csv
import json
import os
import re
import struct
import sys
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Tag-record binary layout, reverse engineered from this file's byte stream.
#
#   [ 0: 4] u32  packed: high16 = sequential tag ID, low16 = constant 0x0035
#   [ 4: 8] u32  constant marker                     == TAG_MARKER_1
#   [ 8:12] u32  category/flags (0 for analog tags, nonzero for switch/bit tags)
#   [12:16] u32  constant marker                     == TAG_MARKER_2
#   [16:20] u32  packed: low16 = type code (0x84 analog / 0x8b switch), high16 = 1
#   [20:24] u32  internal HMI runtime tag-table slot address (+8 per tag record)
#   [24:28] u32  padding, always 0
#   [28:30] u16  name length, in UTF-16 code units
#   [30:  ] ...  UTF-16LE tag name (no null terminator counted in length)
#
# These marker constants are what we use to reject false-positive string matches;
# if a future WinCC build changes them, update TAG_MARKER_1 / TAG_MARKER_2 below
# (dump a known-good tag record with --verbose to find the new values).
# ---------------------------------------------------------------------------
TAG_RECORD_LEN = 28
TAG_MARKER_1 = 0x80E30000   # header dword[1]
TAG_MARKER_2 = 0x00E30000   # header dword[3]
TAG_TYPE_NAMES = {0x84: "analog", 0x8B: "switch/bit"}

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_END = b"IEND"

# Component-version tokens, e.g. "WCRT061700" in ProjectCharacteristics.rdf.
# Format confirmed against the installed runtime's own component manifests
# (Automation/sws/SrcRepos/WinCC RT Advanced/WCRT061600.xml contains exactly
# <license ID="WCRT06" VERSION="16.0" .../> for the token "WCRT061600") - the
# last 4 digits are MMmm (major, minor), "9999" means "any version" (a wildcard
# used for some component entries, not a real version).
WCRT_VERSION_RE = re.compile(rb"\bWCRT(\d{2})(\d{4})\b")

IPV4_RE = re.compile(
    rb"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
)
ASCII_STR_RE = re.compile(rb"[ -~]{4,}")
UTF16_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def log(msg, verbose, force=False):
    if verbose or force:
        print(msg)


def extract_pngs(data: bytes, out_dir: Path, verbose: bool) -> int:
    pngs_dir = out_dir / "pngs"
    pngs_dir.mkdir(parents=True, exist_ok=True)
    i, n = 0, 0
    while True:
        i = data.find(PNG_SIG, i)
        if i == -1:
            break
        j = data.find(PNG_END, i)
        if j == -1:
            break
        j += 8  # IEND chunk + 4-byte CRC
        chunk = data[i:j]
        (pngs_dir / f"img_{n:04d}_0x{i:x}.png").write_bytes(chunk)
        n += 1
        i = j
    log(f"[pngs] carved {n} PNG images -> {pngs_dir}", verbose, force=True)
    return n


def is_valid_zlib_header(b0: int, b1: int) -> bool:
    """Any CMF/FLG pair satisfying the zlib header checksum, with FDICT unset -
    catches 0x789c, 0x785e, 0x78da, 0x7801 etc., not just one fixed byte pair."""
    if b0 != 0x78:
        return False
    if b1 & 0x20:  # FDICT bit set - needs a preset dictionary, skip
        return False
    return ((b0 << 8) | b1) % 31 == 0


def extract_zlib_blocks(data: bytes, out_dir: Path, verbose: bool) -> int:
    zout = out_dir / "zlib_out"
    zout.mkdir(parents=True, exist_ok=True)
    n = 0
    i = 0
    end = len(data) - 1
    while i < end:
        if data[i] == 0x78 and is_valid_zlib_header(data[i], data[i + 1]):
            try:
                d = zlib.decompressobj()
                out = d.decompress(data[i:])
                if len(out) > 100 and out.count(0) < len(out) * 0.9:
                    (zout / f"blk_{n:04d}_0x{i:x}.bin").write_bytes(out)
                    n += 1
                # skip past exactly the bytes this stream consumed, so we
                # don't re-match spurious headers inside its own payload
                consumed = (len(data) - i) - len(d.unused_data)
                i += consumed if consumed > 2 else 2
                continue
            except Exception:
                pass
        i += 1
    log(f"[zlib] decompressed {n} candidate streams -> {zout}", verbose, force=True)
    return n


def extract_strings(data: bytes, out_dir: Path, min_len: int, verbose: bool):
    sdir = out_dir / "strings"
    sdir.mkdir(parents=True, exist_ok=True)

    ascii_re = re.compile(rb"[ -~]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)

    ascii_count = 0
    with open(sdir / "ascii.txt", "w", encoding="utf-8") as f:
        for m in ascii_re.finditer(data):
            f.write(f"0x{m.start():x}\t{m.group().decode('ascii')}\n")
            ascii_count += 1

    utf16_count = 0
    with open(sdir / "utf16.txt", "w", encoding="utf-8") as f:
        for m in utf16_re.finditer(data):
            try:
                s = m.group().decode("utf-16-le")
            except UnicodeDecodeError:
                continue
            f.write(f"0x{m.start():x}\t{s}\n")
            utf16_count += 1

    log(f"[strings] {ascii_count} ASCII, {utf16_count} UTF-16LE -> {sdir}", verbose, force=True)
    return ascii_count, utf16_count


def extract_ip_addresses(data: bytes, out_dir: Path, verbose: bool) -> int:
    found = set()
    for m in IPV4_RE.finditer(data):
        found.add(m.group().decode("ascii"))
    # also catch UTF-16 encoded IPs
    for m in UTF16_STR_RE.finditer(data):
        try:
            s = m.group().decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        for ip in IPV4_RE.finditer(s.encode("ascii", "ignore")):
            found.add(ip.group().decode("ascii"))
    out_path = out_dir / "ip_addresses.txt"
    out_path.write_text("\n".join(sorted(found, key=lambda x: tuple(map(int, x.split(".")))) ) + "\n")
    log(f"[ip] {len(found)} unique IPv4 addresses -> {out_path}", verbose, force=True)
    return len(found)


def guid_bytes(guid_str: str) -> bytes:
    parts = guid_str.strip("{}").split("-")
    d1 = int(parts[0], 16).to_bytes(4, "little")
    d2 = int(parts[1], 16).to_bytes(2, "little")
    d3 = int(parts[2], 16).to_bytes(2, "little")
    d4 = bytes.fromhex(parts[3] + parts[4])
    return d1 + d2 + d3 + d4


def extract_class_ids(data: bytes, fwc_path: Path, out_dir: Path, verbose: bool) -> int:
    """Scan for the raw 16-byte GUID catalog and label entries using a sidecar
    pdata.tfz file (same directory as the .fwc) if one exists - that file lists
    FW_CLASSID_* names in plain text next to their GUIDs."""
    names = {}
    ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"
    tfz_path = fwc_path.parent / "pdata.tfz"
    if tfz_path.exists():
        for line in tfz_path.read_text(errors="replace").splitlines():
            m = re.search(r"\{([0-9A-Fa-f-]{36})\}.*=\s*(FW_CLASSID_\S+)", line)
            if m:
                gstr = f"{{{m.group(1).upper()}}}"
                if gstr == ZERO_GUID:
                    continue  # used as a wildcard placeholder - matches any zero padding, not meaningful
                names[gstr] = m.group(2)

    # search for each known GUID's exact 16-byte binary form (unaligned -
    # the catalog and any inline per-object references aren't offset-aligned)
    hits = []
    for gstr, cname in names.items():
        needle = guid_bytes(gstr)
        i = 0
        while True:
            i = data.find(needle, i)
            if i == -1:
                break
            hits.append((i, gstr, cname))
            i += 1
    hits.sort()

    out_path = out_dir / "class_ids.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for off, gstr, cname in hits:
            f.write(f"0x{off:x}\t{gstr}\t{cname}\n")
    log(f"[class-ids] {len(hits)} known FW_CLASSID GUIDs located -> {out_path}", verbose, force=True)
    return len(hits)


def extract_wincc_version(fwc_path: Path, out_dir: Path, verbose: bool):
    """Decode the WinCC Runtime Advanced version this project was built/run
    with, from a sidecar ProjectCharacteristics.rdf next to the .fwc file.
    This is NOT stored inside pdata.fwc itself - only in that sidecar, which
    is part of the same deployed project bundle (see Scs_project_files.download
    in the same folder, which lists both as one project's files).

    TIA Portal ships a matching-numbered WinCC Runtime Advanced with each of
    its own releases (WinCC RT Advanced V17 pairs with TIA Portal V17), so
    this version is a reliable stand-in for "which TIA Portal version this
    project was engineered in" - but that's an inference from the vendor's
    release pairing, not something this file states directly."""
    rdf_path = fwc_path.parent / "ProjectCharacteristics.rdf"
    out_path = out_dir / "version_info.txt"

    if not rdf_path.exists():
        log(f"[version] no sidecar ProjectCharacteristics.rdf next to {fwc_path.name} - version unknown",
            verbose, force=True)
        out_path.write_text("ProjectCharacteristics.rdf not found next to the .fwc file - version unknown\n")
        return None

    rdf_data = rdf_path.read_bytes()
    matches = WCRT_VERSION_RE.findall(rdf_data)
    if not matches:
        log(f"[version] {rdf_path.name} present but no WCRT version token found in it", verbose, force=True)
        out_path.write_text(f"{rdf_path.name} present but no WCRT version token found in it\n")
        return None

    sub_id, version_digits = matches[0]
    version_digits = version_digits.decode()
    if version_digits == "9999":
        version_str = "unspecified (wildcard token, not a real version)"
    else:
        version_str = f"{int(version_digits[:2])}.{int(version_digits[2:])}"

    lines = [
        f"WinCC Runtime Advanced version: {version_str}",
        f"(decoded from WCRT{sub_id.decode()}{version_digits} in {rdf_path.name})",
        "",
        "TIA Portal ships a matching-numbered WinCC Runtime Advanced with each "
        "release, so this is a reliable stand-in for the TIA Portal version this "
        "project was engineered in - but that pairing is the vendor's release "
        "convention, not something stated in the file itself.",
    ]
    out_path.write_text("\n".join(lines) + "\n")
    log(f"[version] WinCC Runtime Advanced {version_str} -> {out_path}", verbose, force=True)
    return version_str


def extract_tag_records(data: bytes, out_dir: Path, verbose: bool):
    pat = re.compile(rb"(?:[\x20-\x7e]\x00){3,80}")
    results = {}
    for m in pat.finditer(data):
        start, end = m.start(), m.end()
        nchars = (end - start) // 2
        cand = start - 4
        if cand - TAG_RECORD_LEN < 0:
            continue
        namelen = struct.unpack_from("<H", data, cand + 2)[0]
        if namelen != nchars:
            continue
        header = data[cand - TAG_RECORD_LEN : cand]
        if len(header) != TAG_RECORD_LEN:
            continue
        vals = struct.unpack_from("<7I", header)
        if vals[1] != TAG_MARKER_1 or vals[6] != 0 or vals[3] != TAG_MARKER_2:
            continue
        name = data[start:end].decode("utf-16-le")
        tag_id = vals[0] >> 16
        type_code = vals[4] & 0xFFFF
        slot_addr = vals[5]
        if name not in results:
            results[name] = {
                "name": name,
                "tag_id": tag_id,
                "type_code": f"0x{type_code:02x}",
                "type_name": TAG_TYPE_NAMES.get(type_code, "unknown"),
                "hmi_slot_address_hex": f"0x{slot_addr:x}",
                "hmi_slot_address_dec": slot_addr,
                "file_offset": f"0x{start:x}",
            }

    rows = sorted(results.values(), key=lambda r: r["name"])

    csv_path = out_dir / "tags.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "name", "tag_id", "type_code", "type_name",
                "hmi_slot_address_hex", "hmi_slot_address_dec", "file_offset",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    json_path = out_dir / "tags.json"
    json_path.write_text(json.dumps(rows, indent=1))

    log(f"[tags] {len(rows)} tag name -> address records -> {csv_path}", verbose, force=True)
    return rows


def main():
    ap = argparse.ArgumentParser(description="Extract data from a WinCC Runtime Advanced pdata.fwc file.")
    ap.add_argument("fwc_file", help="path to pdata.fwc")
    ap.add_argument("-o", "--outdir", help="output directory (default: recon_<basename>)")
    ap.add_argument("--min-string-len", type=int, default=6, help="minimum string length to record (default: 6)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    fwc_path = Path(args.fwc_file).resolve()
    if not fwc_path.exists():
        print(f"error: {fwc_path} not found", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.outdir) if args.outdir else fwc_path.parent / f"recon_{fwc_path.stem}"
    out_dir.mkdir(parents=True, exist_ok=True)

    data = fwc_path.read_bytes()
    print(f"[*] {fwc_path}  ({len(data):,} bytes)")
    print(f"[*] output -> {out_dir}")
    print()

    n_pngs = extract_pngs(data, out_dir, args.verbose)
    n_zlib = extract_zlib_blocks(data, out_dir, args.verbose)
    n_ascii, n_utf16 = extract_strings(data, out_dir, args.min_string_len, args.verbose)
    n_ips = extract_ip_addresses(data, out_dir, args.verbose)
    n_classids = extract_class_ids(data, fwc_path, out_dir, args.verbose)
    tags = extract_tag_records(data, out_dir, args.verbose)
    wincc_version = extract_wincc_version(fwc_path, out_dir, args.verbose)

    summary = {
        "source_file": str(fwc_path),
        "source_size_bytes": len(data),
        "wincc_runtime_advanced_version": wincc_version or "unknown",
        "pngs_extracted": n_pngs,
        "zlib_blocks_decompressed": n_zlib,
        "ascii_strings": n_ascii,
        "utf16_strings": n_utf16,
        "ip_addresses": n_ips,
        "known_class_ids_found": n_classids,
        "tags_with_hmi_address": len(tags),
        "note": (
            "hmi_slot_address is the WinCC Runtime's internal tag-table slot "
            "address, not the PLC-side S7 address (DBx.DBWy / %IB / %QB). That "
            "binding was not located in this file."
        ),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print()
    print(f"Full report: {out_dir / 'summary.json'}")


if __name__ == "__main__":
    main()
