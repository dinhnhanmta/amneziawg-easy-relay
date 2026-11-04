import importlib.util
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('direct', Path(__file__).resolve().parents[1] / 'direct-relay.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class DirectRelayTests(unittest.TestCase):
    def test_untrusted_hostnames_cannot_be_shell_or_iptables_arguments(self):
        for value in ['$(reboot)', '--help', 'a\nb', 'x;id', '127.0.0.1', '0.0.0.0',
                      '224.0.0.1', '999.1.1.1', 'x..y', '-bad.test', 'a/b']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                D.hostname(value)
        self.assertEqual(D.hostname('OUT.Example.COM.'), 'out.example.com')

    def test_forwarding_is_scoped_to_the_translated_udp_flow(self):
        state = {'listen_port': 2447, 'out_port': 2445}
        rules = D.rules(state, '198.51.100.25', 'eth0')
        for table, chain, args in rules:
            self.assertIn('udp', args)
            self.assertIn(D.TAG, args)
            if chain in ['FORWARD', 'POSTROUTING']:
                self.assertIn('DNAT', args)
                self.assertEqual(args[args.index('--ctorigdstport') + 1], '2447')
            if chain == 'FORWARD':
                self.assertIn('--ctdir', args)
                self.assertIn('198.51.100.25', args)

    def test_dns_failure_leaves_existing_rules_untouched(self):
        with patch.object(D, 'resolve', side_effect=socket.gaierror('DNS unavailable')), patch.object(D, 'ipt') as ipt:
            with self.assertRaises(socket.gaierror):
                D.apply({'out_host': 'out.example.com'})
            ipt.assert_not_called()

    def test_rollback_only_removes_owned_rules_and_chains(self):
        seen = []
        def ipt(table, *args, **kwargs):
            seen.append((table, args))
            sample = '-A PREROUTING -p udp --dport 2447 -m comment --comment awge-direct-relay -j AWGED_DNAT\n'
            sample += '-A PREROUTING -p udp --dport 2445 -j OTHER_APP\n'
            return subprocess.CompletedProcess([], 0, sample, '')
        with patch.object(D, 'ipt', side_effect=ipt):
            D.owned_cleanup()
        self.assertFalse(any('OTHER_APP' in args for table, args in seen))
        for table, args in seen:
            if args[0] in ['-F', '-X']:
                self.assertIn(args[1], D.CHAINS[table])


if __name__ == '__main__':
    unittest.main()
