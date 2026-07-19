#!/usr/bin/env python3
"""internal-chat server — single-command entry point.

The implementation lives in the `internalchat/` package (see its __init__
for the module map). This file stays as the runnable script so existing
deployments and docs keep working unchanged:

    python3 chatserver.py adduser <name> [--data DIR]
    python3 chatserver.py serve   [--data DIR] [--host H] [--port N]
                                  [--cert server.pem] [--static DIR]
                                  [--retain-days N]

Equivalent to `python3 -m internalchat`. Importing this module also re-exports
the package's public names (Store, Api, build_server, …) for backwards
compatibility with code and tests that did `import chatserver`.
"""
from pathlib import Path            # noqa: F401  (some callers use chatserver.Path)
from internalchat import *          # noqa: F401,F403  (public API re-export)
from internalchat import main

if __name__ == "__main__":
    main()
