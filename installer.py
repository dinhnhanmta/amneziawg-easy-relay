#!/usr/bin/env python3
"""Noninteractive AWG Easy OUT + AWG 3.1 UDP relay installer (Ubuntu 24.04)."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path('/opt/amnezia-easy-relay')
STATE = ROOT / 'state.json'
BACKHAUL = 'awge-backhaul'
EASY = 'amnezia-wg-easy'
IFACE = 'awgeb0'
AWG_IMAGE = 'amneziavpn/amneziawg-go:3.1.20260828'
EASY_IMAGE = 'ghcr.io/w0rng/amnezia-wg-easy:latest'
URL = 'https://raw.githubusercontent.com/dinhnhanmta/amneziawg-easy-relay/main/install.sh'
LABEL = 'io.github.dinhnhanmta.amnezia-easy-relay'


def run(*args, capture=False, input=None, check=True, timeout=600):
    result = subprocess.run(list(map(str, args)), input=input, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None,
                            check=False, timeout=timeout)
    if check and result.returncode:
        # Never include command arguments, stdin, stderr or configuration in errors.
        raise RuntimeError(f'{args[0]} failed (exit {result.returncode}); inspect service/container logs locally')
    return result.stdout.strip() if capture else result.returncode


def write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.new-', dir=path.parent)
    try:
        os.fchmod(fd, mode) if hasattr(os, 'fchmod') else None
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def host(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError('Invalid IPv4 address or DNS hostname')
    try:
        address = ipaddress.ip_address(value)
        if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError('Use a reachable IPv4 address or DNS hostname')
        return value
    except ValueError:
        if re.fullmatch(r'[0-9.]+', value):
            raise ValueError('Invalid IPv4 address') from None
    if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p)
               for p in value.split('.')):
        raise ValueError('Invalid DNS hostname')
    return value.lower()


def key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError('Invalid pairing key')
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError()
    except (ValueError, base64.binascii.Error):
        raise ValueError('Invalid pairing key') from None
    return value


def encode_pair(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).decode()


def decode_pair(token):
    try:
        if len(token) > 4096:
            raise ValueError()
        data = json.loads(base64.b64decode(token, altchars=b'-_', validate=True))
        if not isinstance(data, dict) or set(data) != {'version', 'out_host', 'relay_host', 'private', 'peer', 'hpk', 'mtu'}:
            raise ValueError()
        if type(data['version']) is not int or data['version'] != 1:
            raise ValueError()
        data['out_host'] = host(data['out_host'])
        data['relay_host'] = host(data['relay_host'])
        for name in ('private', 'peer', 'hpk'):
            key(data[name])
        if type(data['mtu']) is not int or not 1280 <= data['mtu'] <= 1380:
            raise ValueError()
        return data
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ValueError('Invalid pairing token; copy the complete token from OUT') from None


def genkey(image):
    return key(run('docker', 'run', '--rm', '--entrypoint', 'awg', image, 'genkey', capture=True))


def pubkey(image, private):
    return key(run('docker', 'run', '--rm', '-i', '--entrypoint', 'awg', image, 'pubkey',
                   input=private + '\n', capture=True))


def tunnel_config(role, private, peer, hpk, out_host):
    return f'''[Interface]
PrivateKey = {key(private)}
ListenPort = {34431 if role == 'out' else 45131}
Jc = 5
Jmin = 61
Jmax = 190
S1 = 88
S2 = 47
S3 = 29
S4 = 17
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = {key(hpk)}
ContentPaddingAddition = 32-128

[Peer]
PublicKey = {key(peer)}
AllowedIPs = 10.88.31.{2 if role == 'out' else 1}/32
''' + (f'Endpoint = {host(out_host)}:34431\nPersistentKeepalive = 25\n' if role == 'relay' else '')


def tunnel_command(mtu, role):
    address = '10.88.31.1/30' if role == 'out' else '10.88.31.2/30'
    return f'''set -eu
amneziawg-go -f {IFACE} &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" || true' EXIT
trap 'exit 0' TERM INT
for n in $(seq 1 50); do
  awg show {IFACE} listen-port >/dev/null 2>&1 && break
  kill -0 "$pid"
  sleep 0.1
done
awg setconf {IFACE} /cfg/backhaul.conf
ip addr replace {address} dev {IFACE}
ip link set {IFACE} mtu {mtu} up
wait "$pid"
'''


def firewall_script(role):
    # Recheck rules after Docker/firewall restarts. Never flush unrelated chains.
    common = f'''#!/bin/bash
set -Eeuo pipefail
exec 9>/run/awge-firewall.lock
flock -w 10 9
''' + '''add() {
  local table="$1" chain="$2"
  shift 2
  iptables -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null ||
    iptables -w 5 -t "$table" -I "$chain" 1 "$@"
}
''' + f'add filter INPUT -i {IFACE} -p icmp -j ACCEPT\n'
    if role == 'out':
        return common + 'add filter INPUT -p udp --dport 34431 -j ACCEPT\n'
    return common + f'''WAN=$(ip -4 route show default | awk '{{for(i=1;i<=NF;i++) if($i=="dev"){{print $(i+1);exit}}}}')
[ -n "$WAN" ]
ip link show {IFACE} >/dev/null 2>&1 || exit 0
add nat PREROUTING -i "$WAN" -p udp --dport 2445 -j DNAT --to-destination 10.88.31.1:2445
add nat POSTROUTING -o {IFACE} -p udp -d 10.88.31.1 --dport 2445 -j MASQUERADE
add filter FORWARD -i "$WAN" -o {IFACE} -p udp -d 10.88.31.1 --dport 2445 -j ACCEPT
add filter FORWARD -i {IFACE} -o "$WAN" -p udp -s 10.88.31.1 --sport 2445 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
add filter INPUT -p udp --dport 45131 -j ACCEPT
'''


def watchdog_script(state):
    role = state['role']
    result = f'''#!/bin/bash
set -Eeuo pipefail
exec 9>/run/awge-maintain.lock
flock -n 9 || exit 0
timeout 10 docker info >/dev/null 2>&1 || exit 0
if ! timeout 10 docker exec {BACKHAUL} awg show {IFACE} listen-port >/dev/null 2>&1; then
  logger -t awge-maintain 'Local backhaul engine unavailable; restarting managed container'
  timeout 25 docker restart {BACKHAUL} >/dev/null
fi
'''
    if role == 'out':
        result += f'''if ! timeout 10 docker exec {EASY} wg show wg0 listen-port >/dev/null 2>&1; then
  logger -t awge-maintain 'Local AWG Easy interface unavailable; restarting managed container'
  timeout 25 docker restart {EASY} >/dev/null
fi
'''
    else:
        result += f'''IP=$(getent ahostsv4 {host(state['out_host'])} | awk 'NR==1{{print $1}}') || IP=''
if [ -n "$IP" ]; then
  PEER={shlex.quote(state['peer'])}
  OLD=$(timeout 10 docker exec {BACKHAUL} awg show {IFACE} endpoints | awk -v p="$PEER" '$1==p{{print $2}}')
  if [ "$OLD" != "$IP:34431" ]; then
    timeout 10 docker exec {BACKHAUL} awg set {IFACE} peer "$PEER" endpoint "$IP:34431"
    logger -t awge-maintain 'Refreshed OUT endpoint from DNS'
  fi
fi
if ! ping -c 1 -W 2 10.88.31.1 >/dev/null 2>&1; then
  logger -t awge-maintain 'OUT unreachable; check peer, DNS and network (no restart for network-only failure)'
fi
'''
    return result + str(ROOT / 'firewall.sh') + '\n'


def mss_hooks(mss):
    if not mss:
        return {}
    rules = [f'-i wg0 -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss {mss + 1}:65535 -j TCPMSS --set-mss {mss}',
             f'-o wg0 -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss {mss + 1}:65535 -j TCPMSS --set-mss {mss}']
    up = 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -A INPUT -p udp --dport 2445 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; '
    down = up.replace(' -A ', ' -D ')
    return {'WG_POST_UP': up + '; '.join('iptables -t mangle -A FORWARD ' + r for r in rules),
            'WG_POST_DOWN': down + '; '.join('iptables -t mangle -D FORWARD ' + r for r in rules)}


def exists(container):
    return bool(run('docker', 'container', 'inspect', '--format', '{{.Id}}', container, capture=True, check=False))


def preflight():
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise ValueError('Run as root on Ubuntu 24.04 amd64; sudo -n can be used with existing passwordless sudo')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
        raise ValueError('This installer targets Ubuntu 24.04')
    if platform.machine() not in ('x86_64', 'amd64'):
        raise ValueError('Only amd64 is supported by this release')
    if not Path('/dev/net/tun').is_char_device():
        raise ValueError('/dev/net/tun is missing; enable TUN at your VPS provider')


def dependencies():
    env = os.environ.copy()
    env.update(DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='a')
    subprocess.run(['apt-get', 'update', '-qq'], env=env, check=True, timeout=600)
    subprocess.run(['apt-get', 'install', '-y', 'docker.io', 'iptables', 'iproute2', 'iputils-ping',
                    'curl', 'ca-certificates', 'util-linux'], env=env, check=True, timeout=900)
    run('systemctl', 'enable', '--now', 'docker')


def resolve_host(value):
    return socket.getaddrinfo(host(value), None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]


def pin_image(image):
    run('docker', 'pull', image)
    digests = json.loads(run('docker', 'image', 'inspect', '--format', '{{json .RepoDigests}}', image, capture=True))
    if not digests:
        raise RuntimeError('Cannot pin container image digest')
    return digests[0]


def start_container(name, args, image, command=()):
    if exists(name):
        label = run('docker', 'inspect', '--format', '{{index .Config.Labels "' + LABEL + '"}}', name, capture=True)
        if label != '1':
            raise ValueError(f'Container {name} is not owned by this installer; refusing to replace it')
        run('docker', 'start', name, capture=True)
        return
    run('docker', 'run', '-d', '--name', name, '--label', LABEL + '=1', '--restart', 'unless-stopped',
        '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3', *args, image, *command, capture=True)


def install_services(state):
    write(ROOT / 'firewall.sh', firewall_script(state['role']), 0o700)
    write(ROOT / 'maintain.sh', watchdog_script(state), 0o700)
    write('/etc/systemd/system/awge-firewall.service', f'''[Unit]
Description=AWG Easy relay firewall
Wants=network-online.target docker.service
After=network-online.target docker.service ufw.service netfilter-persistent.service

[Service]
Type=oneshot
ExecStart={ROOT}/firewall.sh
RemainAfterExit=yes
Restart=on-failure
RestartSec=10
TimeoutStartSec=45

[Install]
WantedBy=multi-user.target
''', 0o644)
    write('/etc/systemd/system/awge-maintain.service', f'''[Unit]
Description=AWG Easy local engine recovery, DNS and firewall maintenance
After=docker.service network-online.target

[Service]
Type=oneshot
ExecStart={ROOT}/maintain.sh
TimeoutStartSec=120
''', 0o644)
    write('/etc/systemd/system/awge-maintain.timer', '''[Unit]
Description=Check AWG Easy relay every minute

[Timer]
OnBootSec=60
OnUnitInactiveSec=60
AccuracySec=5

[Install]
WantedBy=timers.target
''', 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'awge-firewall.service', 'awge-maintain.timer')
    run('systemctl', 'restart', 'awge-firewall.service')


def install(state):
    write('/etc/sysctl.d/95-awge-relay.conf', 'net.ipv4.ip_forward=1\n', 0o644)
    run('sysctl', '-q', '-p', '/etc/sysctl.d/95-awge-relay.conf')
    write(ROOT / 'backhaul' / 'backhaul.conf', tunnel_config(state['role'], state['private'], state['peer'], state['hpk'], state['out_host']))
    start_container(BACKHAUL, ['--network', 'host', '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun',
                              '-v', str(ROOT / 'backhaul') + ':/cfg:ro', '--entrypoint', 'sh'],
                    state['awg_image'], ['-ec', tunnel_command(state['mtu'], state['role'])])
    if state['role'] == 'out':
        (ROOT / 'easy').mkdir(exist_ok=True, mode=0o700)
        if not (ROOT / 'panel-password.txt').exists():
            password = secrets.token_urlsafe(24)
            hashed = run('docker', 'run', '--rm', '-i', '--entrypoint', 'node', state['easy_image'], '-e',
                         'const fs=require("fs"); const b=require("bcryptjs"); console.log(b.hashSync(fs.readFileSync(0,"utf8").trim(),10));',
                         input=password, capture=True)
            if not re.fullmatch(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}', hashed):
                raise RuntimeError('AWG Easy password hashing failed')
            # Persist together before starting a container; retries preserve the same credentials.
            state['password_hash'] = hashed
            write(STATE, json.dumps(state, indent=2) + '\n')
            write(ROOT / 'panel-password.txt', password + '\n')
        env = {'WG_HOST': state['relay_host'], 'WG_PORT': '2445', 'WG_CONFIG_PORT': '2445',
               'WG_MTU': str(state['client_mtu']), 'WG_ALLOWED_IPS': '0.0.0.0/0, ::/0',
               'WG_PERSISTENT_KEEPALIVE': '25', 'WG_DEFAULT_DNS': '1.1.1.1',
               'PASSWORD_HASH': state['password_hash'], 'LANG': 'en', 'PORT': '51821'}
        env.update(mss_hooks(state['mss']))
        write(ROOT / 'easy.env', ''.join(k + '=' + v + '\n' for k, v in env.items()))
        start_container(EASY, ['--cap-add', 'NET_ADMIN', '--cap-add', 'SYS_MODULE', '--device', '/dev/net/tun',
                               '--sysctl', 'net.ipv4.conf.all.src_valid_mark=1', '--sysctl', 'net.ipv4.ip_forward=1',
                               '--env-file', str(ROOT / 'easy.env'), '-v', str(ROOT / 'easy') + ':/etc/wireguard',
                               '-p', '2445:2445/udp', '-p', '127.0.0.1:51821:51821/tcp'], state['easy_image'])
    install_services(state)


def check_status(state):
    good = True
    checks = [('Backhaul engine', ['docker', 'exec', BACKHAUL, 'awg', 'show', IFACE, 'listen-port']),
              ('IPv4 forwarding', ['sysctl', '-n', 'net.ipv4.ip_forward']),
              ('Maintenance timer', ['systemctl', 'is-active', 'awge-maintain.timer'])]
    if state['role'] == 'out':
        checks += [('AWG Easy interface', ['docker', 'exec', EASY, 'wg', 'show', 'wg0', 'listen-port']),
                   ('Web UI', ['curl', '-fsS', '--max-time', '5', '-o', '/dev/null', 'http://127.0.0.1:51821/'])]
    else:
        checks += [('Tunnel to OUT', ['ping', '-c', '3', '-W', '2', '10.88.31.1'])]
    for label, cmd in checks:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        ok = result.returncode == 0
        if label == 'IPv4 forwarding':
            ok &= result.stdout.strip() == '1'
        elif label == 'Maintenance timer':
            ok &= result.stdout.strip() == 'active'
        print(('OK   ' if ok else 'FAIL ') + label)
        good &= ok
    print('Client Internet/DNS/UDP and reboot checks require a connected client; not certified by these local checks.')
    return good


def parser():
    p = argparse.ArgumentParser(description='AWG Easy OUT + AWG 3.1 relay. No installation password or interactive prompts.')
    p.add_argument('--role', required=True, choices=('out', 'relay', 'status', 'backup'))
    p.add_argument('--out-host', type=host, help='OUT public IPv4 or DNS hostname')
    p.add_argument('--relay-host', type=host, help='Relay public IPv4 or DNS hostname, used in client configs')
    group = p.add_mutually_exclusive_group()
    group.add_argument('--pair', help='Secret pairing token printed by OUT')
    group.add_argument('--pair-file', type=Path, help='File containing the pairing token, avoids shell-history exposure')
    p.add_argument('--mtu', type=int, default=1380, help='Backhaul MTU, 1280..1380 (default 1380)')
    p.add_argument('--client-mtu', type=int, default=1280, help='Client MTU (default 1280; must leave 80 bytes inside backhaul)')
    p.add_argument('--mss', type=int, default=0, help='Optional persistent TCP MSS, 0 means off')
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    pairing = None
    if args.role == 'out':
        if not args.out_host or not args.relay_host:
            p.error('OUT needs --out-host and --relay-host')
        if not 1280 <= args.mtu <= 1380 or not 576 <= args.client_mtu <= args.mtu - 80:
            p.error('Require backhaul MTU 1280..1380 and client MTU 576..(backhaul MTU - 80)')
        if args.mss and not 536 <= args.mss <= args.client_mtu - 40:
            p.error('MSS must be 0 or between 536 and client MTU minus 40')
    elif args.role == 'relay':
        if not args.pair and not args.pair_file:
            p.error('Relay needs --pair or --pair-file from OUT')
        pairing = decode_pair(args.pair or args.pair_file.read_text().strip())
    preflight()
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    os.chmod(ROOT, 0o700)
    import fcntl
    with (ROOT / '.install.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.role in ('status', 'backup'):
            state = json.loads(STATE.read_text())
            if args.role == 'status':
                return 0 if check_status(state) else 1
            # Stop writes while copying the Easy database; always restart even if tar fails.
            output = Path('/root') / ('awge-' + state['role'] + '-' + time.strftime('%Y%m%d-%H%M%S') + '.tar.gz')
            if state['role'] == 'out':
                run('docker', 'stop', EASY, capture=True)
            try:
                run('tar', '--exclude=.install.lock', '-czf', output, '-C', ROOT, '.')
                os.chmod(output, 0o600)
            finally:
                if state['role'] == 'out':
                    run('docker', 'start', EASY, capture=True)
            print('Backup (contains private keys):', output)
            return 0
        if STATE.exists():
            state = json.loads(STATE.read_text())
            if state['role'] != args.role:
                raise ValueError('This VPS already has a different managed role')
            if args.role == 'out' and (state['out_host'], state['relay_host'], state['mtu'], state['client_mtu'], state['mss']) != (args.out_host, args.relay_host, args.mtu, args.client_mtu, args.mss):
                raise ValueError('Existing installation differs; restore or edit saved state deliberately instead of overwriting keys')
            if pairing and any(state[k] != pairing[k] for k in ('out_host', 'relay_host', 'private', 'peer', 'hpk', 'mtu')):
                raise ValueError('Pairing differs from the existing relay; refusing to replace its identity')
            dependencies()
            for name in ('awg_image', 'easy_image'):
                if name in state:
                    run('docker', 'pull', state[name])
        else:
            if shutil.which('docker') and (exists(BACKHAUL) or exists(EASY)):
                raise ValueError('Existing AWG containers found; this installer targets fresh VPS instances')
            if shutil.which('ip') and run('ip', 'link', 'show', IFACE, capture=True, check=False):
                raise ValueError('Backhaul interface already exists')
            resolve_host(args.out_host if args.role == 'out' else pairing['out_host'])
            dependencies()
            image = pin_image(AWG_IMAGE)
            if args.role == 'out':
                easy_image = pin_image(EASY_IMAGE)
                private, relay_private, hpk = (genkey(image) for _ in range(3))
                state = {'version': 1, 'role': 'out', 'out_host': args.out_host, 'relay_host': args.relay_host,
                         'private': private, 'peer': pubkey(image, relay_private), 'hpk': hpk, 'mtu': args.mtu,
                         'client_mtu': args.client_mtu, 'mss': args.mss, 'awg_image': image, 'easy_image': easy_image}
                token = encode_pair({'version': 1, 'out_host': args.out_host, 'relay_host': args.relay_host,
                                     'private': relay_private, 'peer': pubkey(image, private), 'hpk': hpk, 'mtu': args.mtu})
                write(ROOT / 'relay-pair.txt', token + '\n')
            else:
                state = dict(pairing, role='relay', awg_image=image)
            write(STATE, json.dumps(state, indent=2) + '\n')
        install(state)
        # Interface creation is asynchronous; wait before reporting success.
        for _ in range(30):
            if run('docker', 'exec', BACKHAUL, 'awg', 'show', IFACE, 'listen-port', capture=True, check=False) == str(34431 if args.role == 'out' else 45131):
                if args.role != 'out' or run('docker', 'exec', EASY, 'wg', 'show', 'wg0', 'listen-port', capture=True, check=False) == '2445':
                    break
            time.sleep(1)
        if not check_status(state):
            raise RuntimeError('Installation saved but health checks failed; inspect docker logs and provider firewall, then rerun the same command')
        if args.role == 'out':
            token = (ROOT / 'relay-pair.txt').read_text().strip()
            print('\nOUT_READY. Run this ONE line as root on the RELAY (token is SECRET):')
            print(f'bash <(curl -fsSL {URL}) --role relay --pair {shlex.quote(token)}')
            print(f'\nUI: ssh -L 51821:127.0.0.1:51821 root@{state["out_host"]}')
            print('Then open http://127.0.0.1:51821; generated UI password:', ROOT / 'panel-password.txt')
            print('Provider firewall: allow OUT UDP 34431 from relay. Relay must allow client UDP 2445.')
        else:
            print('RELAY_READY. Client endpoint:', state['relay_host'] + ':2445')
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        # Do not print potentially sensitive exception contents from subprocesses.
        message = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__
        print('ERROR:', message, file=sys.stderr)
        sys.exit(1)
