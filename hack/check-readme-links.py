#!/usr/bin/env python3
# Checks that every relative link and image in README.md points at a file
# that exists in the repository. Run from the repository root.
import os, re, sys

text = open("README.md", encoding="utf-8").read()
refs = re.findall(r'\]\(([^)\s#]+)(?:#[^)]*)?\)', text) + re.findall(r'(?:src|href)="([^"]+)"', text)
missing = []
for ref in refs:
    if re.match(r'^(https?:|mailto:)', ref):
        continue
    if not os.path.exists(ref):
        missing.append(ref)
for m in sorted(set(missing)):
    print("missing:", m)
sys.exit(1 if missing else 0)
