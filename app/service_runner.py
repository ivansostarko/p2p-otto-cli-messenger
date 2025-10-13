#!/usr/bin/env python3
# service_runner.py - non-interactive wrapper to run chat host/client from ENV
import os, sys
from chat import run_host, run_client

NICKNAME = os.environ.get("P2PCHAT_NICKNAME", "service")
MODE = os.environ.get("P2PCHAT_MODE", "host").lower()  # host|client
PORT = int(os.environ.get("P2PCHAT_PORT", "5000"))
HOST = os.environ.get("P2PCHAT_HOST", "").strip()

if MODE.startswith("h"):
    run_host(NICKNAME, PORT)
elif MODE.startswith("c"):
    if not HOST:
        print("P2PCHAT_HOST is required in client mode", file=sys.stderr)
        sys.exit(1)
    run_client(NICKNAME, HOST, PORT)
else:
    print("P2PCHAT_MODE must be 'host' or 'client'", file=sys.stderr); sys.exit(2)
