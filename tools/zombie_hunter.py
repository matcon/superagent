#!/usr/bin/env python3

import sys
import subprocess

def scan_zombies():
    res = subprocess.run(['ps', '-eo', 'pid,stat,comm'], capture_output=True, text=True)
    zombies = [l for l in res.stdout.splitlines() if len(l.split()) >= 2 and 'Z' in l.split()[1]]
    print(f'Procesos Zombie Detectados: {len(zombies)}')
    return 0

if __name__ == '__main__':
    sys.exit(scan_zombies())
