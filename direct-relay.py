#!/usr/bin/env python3
"""Kernel UDP forwarding for an existing encrypted AWG endpoint."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys

ROOT = Path('/opt/awge-direct-relay')
TAG = 'awge-direct-relay'
CHAINS = {'nat': ['AWGED_DNAT', 'AWGED_SNAT'], 'filter': ['AWGED_FWD']}


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)


def hostname(value):
    value = value.lower().rstrip('.')
    if not value or len(value) > 253:
        raise ValueError('Invalid OUT host')
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        if re.fullmatch(r'[0-9.]+', value) or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in value.split('.')
        ):
            raise ValueError('Invalid OUT host') from None
    else:
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError('Invalid OUT address')
    return value


def port(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError('Port must be 1..65535')
    return number


def write(path, content, mode=0o600):
    path = Path(path)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(content)
    temp.chmod(mode)
    temp.replace(path)


def resolve(out_host):
    address = socket.getaddrinfo(out_host, None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    return hostname(address)


def rules(state, target, wan):
    """Only owned jumps, scoped to this ingress port and translated flow."""
    ingress = ['-i', wan, '-p', 'udp', '--dport', str(state['listen_port']),
               '-m', 'addrtype', '--dst-type', 'LOCAL']
    original = ['-m', 'conntrack', '--ctstate', 'DNAT',
                '--ctorigdstport', str(state['listen_port'])]
    comment = ['-m', 'comment', '--comment', TAG]
    return [
        ('nat', 'PREROUTING', ingress + comment + ['-j', 'AWGED_DNAT']),
        ('nat', 'POSTROUTING', ['-o', wan, '-p', 'udp', '-d', target, '--dport', str(state['out_port'])]
         + original + ['--ctdir', 'ORIGINAL'] + comment + ['-j', 'AWGED_SNAT']),
        ('filter', 'FORWARD', ['-i', wan, '-o', wan, '-p', 'udp', '-d', target,
                               '--dport', str(state['out_port'])]
         + original + ['--ctdir', 'ORIGINAL'] + comment + ['-j', 'AWGED_FWD']),
        ('filter', 'FORWARD', ['-i', wan, '-o', wan, '-p', 'udp', '-s', target,
                               '--sport', str(state['out_port'])]
         + original + ['--ctdir', 'REPLY'] + comment + ['-j', 'AWGED_FWD']),
    ]


def ipt(table, *args, check=True):
    return run('iptables', '-w', '5', '-t', table, *args, check=check)


def owned_cleanup():
    # Delete only tagged references to our chains, then our private chains.
    # Never flush a shared built-in or another application's chain.
    for table, chains in CHAINS.items():
        for line in ipt(table, '-S').stdout.splitlines():
            tokens = shlex.split(line)
            if tokens[:1] == ['-A'] and TAG in tokens and any(c in tokens for c in chains):
                ipt(table, '-D', *tokens[1:])
        for chain in chains:
            ipt(table, '-F', chain, check=False)
            ipt(table, '-X', chain, check=False)


def apply(state):
    # Resolve before touching working rules: a DNS failure preserves the old path.
    target = resolve(state['out_host'])
    addresses = json.loads(run('ip', '-j', '-4', 'addr').stdout)
    if any(a['local'] == target for link in addresses for a in link.get('addr_info', [])):
        raise ValueError('OUT must be another VPS, not this relay')
    route = json.loads(run('ip', '-j', '-4', 'route', 'get', target).stdout)[0]
    wan = route['dev']
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', wan):
        raise ValueError('Unsupported outbound interface name')
    config = dict(state, target=target, wan=wan)
    active_path = ROOT / 'active.json'
    if active_path.exists() and json.loads(active_path.read_text()) != config:
        # A deliberate DNS/route update replaces only our old scoped rules.
        owned_cleanup()
    for table, chains in CHAINS.items():
        for chain in chains:
            ipt(table, '-N', chain, check=False)
    managed = [
        ('nat', 'AWGED_DNAT', ['-p', 'udp', '-j', 'DNAT', '--to-destination', target + ':' + str(state['out_port'])]),
        ('nat', 'AWGED_SNAT', ['-j', 'MASQUERADE']),
        ('filter', 'AWGED_FWD', ['-j', 'ACCEPT']),
    ]
    for table, chain, args in managed:
        if ipt(table, '-C', chain, *args, check=False).returncode:
            ipt(table, '-A', chain, *args)
    for table, chain, args in rules(state, target, wan):
        if ipt(table, '-C', chain, *args, check=False).returncode:
            ipt(table, '-I', chain, '1', *args)
    write(active_path, json.dumps(config, indent=2) + '\n')


def install(state):
    if ROOT.exists() and (ROOT / 'state.json').exists():
        if json.loads((ROOT / 'state.json').read_text()) != state:
            raise ValueError('Existing configuration differs; run --action remove before changing it')
    else:
        # Existing tunnels may remain as rollback, but do not capture a local socket.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('0.0.0.0', state['listen_port']))
        existing = run('iptables-save').stdout
        if any(chain in existing for chains in CHAINS.values() for chain in chains):
            raise ValueError('Reserved AWGED chain already exists without installer state')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    ROOT.chmod(0o700)
    write(ROOT / 'state.json', json.dumps(state, indent=2) + '\n')
    write(ROOT / 'direct-relay.py', Path(__file__).read_text(), 0o700)
    write('/etc/sysctl.d/91-awge-direct-forward.conf', 'net.ipv4.ip_forward = 1\n', 0o644)
    run('sysctl', '-w', 'net.ipv4.ip_forward=1')
    apply(state)
    write('/etc/systemd/system/awge-direct.service', '''[Unit]
Description=AWG kernel UDP relay rules and OUT DNS refresh
Wants=network-online.target
After=network-online.target docker.service ufw.service netfilter-persistent.service awge-firewall.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/awge-direct-relay/direct-relay.py --action apply
TimeoutStartSec=40
''', 0o644)
    write('/etc/systemd/system/awge-direct.timer', '''[Unit]
Description=Restore AWG UDP relay rules and refresh OUT DNS each minute

[Timer]
OnBootSec=20s
OnUnitInactiveSec=60s
Unit=awge-direct.service

[Install]
WantedBy=timers.target
''', 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'awge-direct.timer')
    # The service uses the same lock; queue it without waiting on our own lock.
    run('systemctl', 'start', '--no-block', 'awge-direct.service')
    print('Kernel UDP relay ready: :%s -> %s:%s' % (state['listen_port'], state['out_host'], state['out_port']))
    print('Panel, client keys and passwords remain on OUT. No extra VPN encryption layer between VPSs.')
    print('Rollback: python3 /opt/awge-direct-relay/direct-relay.py --action remove')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--action', choices=['install', 'apply', 'remove', 'status'], default='install')
    p.add_argument('--out-host', type=hostname)
    p.add_argument('--listen-port', type=port, default=2447)
    p.add_argument('--out-port', type=port, default=2445)
    a = p.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run as root on Ubuntu 24.04')
    os.umask(0o077)
    # Stop an in-flight timer before taking its lock during rollback.
    if a.action == 'remove':
        run('systemctl', 'disable', '--now', 'awge-direct.timer', check=False)
        run('systemctl', 'stop', 'awge-direct.service', check=False)
    import fcntl
    lock = open('/run/awge-direct.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX)
    if a.action == 'install':
        if not a.out_host:
            p.error('--out-host is required')
        for binary in ['ip', 'iptables', 'iptables-save', 'systemctl', 'sysctl']:
            import shutil
            if not shutil.which(binary):
                raise ValueError('Missing %s; install iproute2 iptables procps first' % binary)
        install({'version': 1, 'out_host': a.out_host, 'listen_port': a.listen_port, 'out_port': a.out_port})
    elif a.action == 'apply':
        apply(json.loads((ROOT / 'state.json').read_text()))
    elif a.action == 'remove':
        if not (ROOT / 'state.json').exists():
            raise ValueError('No managed configuration; refusing to delete rules')
        run('systemctl', 'disable', '--now', 'awge-direct.timer', check=False)
        run('systemctl', 'stop', 'awge-direct.service', check=False)
        owned_cleanup()
        for path in ['/etc/systemd/system/awge-direct.timer', '/etc/systemd/system/awge-direct.service',
                     '/etc/sysctl.d/91-awge-direct-forward.conf']:
            Path(path).unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')
        (ROOT / 'active.json').unlink(missing_ok=True)
        # Preserve state and executable for inspection/reinstallation.
        print('Managed NAT rules removed; previous forwarding path can be used again')
    else:
        print((ROOT / 'state.json').read_text())
        print(run('systemctl', 'is-active', 'awge-direct.timer', check=False).stdout.strip())
        print(ipt('nat', '-nvL', 'AWGED_DNAT').stdout)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr.strip(), file=sys.stderr)
        sys.exit(1)
