#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Moves every copy of the guacd image to a new tag and digest at once.

Usage, from the repository root:

    hack/bump-guacd.py guacamole/guacd:<tag>@sha256:<digest>

The compose file names the image the others must match (TestGuacdImageInStep
fails while one of them differs): the dev compose file, the deploy guide, the
AWS user data and the command `zanskar init` prints carry the same reference,
and the Helm chart carries its tag and digest. A Dependabot pull request that
bumps the compose file is finished by running this with the image it bumped
to, on its branch.
"""
import re
import sys
from pathlib import Path

REF = re.compile(r"guacamole/guacd:([^@\s\"]+)@(sha256:[0-9a-f]{64})")
COMPOSE = "deploy/docker-compose.yml"
GUIDE = "docs/deploy.md"
COPIES = [
    COMPOSE,
    "deploy/docker-compose.dev.yml",
    GUIDE,
    "deploy/aws/userdata/gateway.sh.tftpl",
    "cmd/zanskar/init.go",
]
VALUES = "deploy/helm/zanskar/values.yaml"


def main() -> None:
    new = REF.fullmatch(sys.argv[1]) if len(sys.argv) == 2 else None
    if new is None:
        sys.exit("usage: hack/bump-guacd.py guacamole/guacd:<tag>@sha256:<64 hex digits>")
    # The old image is read from the deploy guide, which Dependabot never
    # edits: on its branch both compose files already name the new one.
    old = next((m for m in REF.finditer(Path(GUIDE).read_text()) if m.group(0) != new.group(0)), None)
    if old is None:
        print(f"the deploy guide already names {new.group(0)}; nothing to move")
        return
    for name in COPIES:
        path = Path(name)
        text = path.read_text()
        if old.group(0) not in text and new.group(0) not in text:
            sys.exit(f"{name} names neither {old.group(0)} nor the new image; fix it by hand, then rerun")
        path.write_text(text.replace(old.group(0), new.group(0)))
    path = Path(VALUES)
    text = path.read_text()
    for field, before, after in (("tag", old.group(1), new.group(1)), ("digest", old.group(2), new.group(2))):
        line = f'{field}: "{before}"'
        if text.count(line) != 1:
            sys.exit(f"{VALUES}: expected one {line} under guacd.image")
        text = text.replace(line, f'{field}: "{after}"')
    path.write_text(text)
    print(f"{old.group(0)} -> {new.group(0)} in {len(COPIES) + 1} files")


if __name__ == "__main__":
    main()
