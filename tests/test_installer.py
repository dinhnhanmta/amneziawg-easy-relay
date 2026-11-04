import base64
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('installer', Path(__file__).resolve().parents[1] / 'installer.py')
I = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(I)


def sample_pair():
    return {'version': 1, 'out_host': 'out.example.com', 'relay_host': 'relay.example.com',
            'private': base64.b64encode(bytes(range(32))).decode(),
            'peer': base64.b64encode(bytes(range(32, 64))).decode(),
            'hpk': base64.b64encode(bytes(range(64, 96))).decode(), 'mtu': 1380}


class PairTests(unittest.TestCase):
    def test_roundtrip_and_input_not_mutated(self):
        data = sample_pair()
        self.assertEqual(data, I.decode_pair(I.encode_pair(data)))

    def test_bad_tokens_rejected_without_echoing_secrets(self):
        for token in ['not-json', 'a' * 5000, I.encode_pair([]), I.encode_pair({'version': 2})]:
            with self.subTest(token=token[:8]), self.assertRaisesRegex(ValueError, 'Invalid pairing token'):
                I.decode_pair(token)

    def test_schema_and_keys_are_strict(self):
        for field, value in [('private', 'wrong'), ('private', '!' * 44), ('version', True), ('version', 2),
                             ('mtu', True), ('mtu', 9000), ('out_host', 'out.test; reboot'), ('extra', 'bad')]:
            data = dict(sample_pair(), **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                I.decode_pair(I.encode_pair(data))

    def test_hostnames_cannot_inject_shell_or_config(self):
        for value in ['--help', 'out\nPrivateKey=x', '$(id).com', 'x;id', 'x y', '', '127.0.0.1',
                      '0.0.0.0', '224.0.0.1', '::1', '999.1.1.1', 'x..y', '-x.com']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                I.host(value)
        self.assertEqual('out.example.com', I.host('OUT.EXAMPLE.COM'))
        self.assertEqual('10.0.0.1', I.host('10.0.0.1'))


class InstallTests(unittest.TestCase):
    def test_public_ui_requires_authentication_before_exposure(self):
        with patch.object(I, 'start_container') as start:
            with self.assertRaisesRegex(ValueError, 'without its generated authentication'):
                I.public_ui({'public_ui': True})
            start.assert_not_called()

    def test_invalid_options_fail_before_preflight_or_apt(self):
        cases = [['--role', 'out'], ['--role', 'relay'],
                 ['--role', 'out', '--out-host', 'out.test', '--relay-host', 'relay.test', '--mss', '1400'],
                 ['--role', 'out', '--out-host', 'out.test', '--relay-host', 'relay.test', '--mtu', '1280']]
        with patch.object(I, 'preflight') as preflight:
            for args in cases:
                with self.subTest(args=args), self.assertRaises(SystemExit), patch('sys.stderr', new=io.StringIO()):
                    I.main(args)
            preflight.assert_not_called()

    def test_nonexistent_container_is_not_reported_present(self):
        with patch.object(I, 'run', return_value=''):
            self.assertFalse(I.exists('absent'))

    def test_failed_empty_stdout_check_does_not_become_success(self):
        def failed(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 1, '', 'failed')
        with patch.object(I.subprocess, 'run', side_effect=failed), patch('sys.stdout', new=io.StringIO()):
            self.assertFalse(I.check_status({'role': 'out'}))

    def test_running_container_does_not_prove_wrong_owner_can_be_used(self):
        with patch.object(I, 'exists', return_value=True), patch.object(I, 'run', return_value='not-ours'):
            with self.assertRaisesRegex(ValueError, 'not owned'):
                I.start_container('amnezia-wg-easy', [], 'image')

    def test_errors_do_not_echo_stdin_or_arguments(self):
        result = subprocess.CompletedProcess([], 1, '', 'SECRET_STDERR')
        with patch.object(I.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as error:
                I.run('docker', '--secret=SECRET_ARGUMENT', capture=True, input='SECRET_STDIN')
            self.assertNotIn('SECRET', str(error.exception))

    def test_write_is_atomic_and_preserves_literal_newlines(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'state.json'
            I.write(path, '{"x":1}\n')
            I.write(path, '{"x":2}\n')
            self.assertEqual(b'{"x":2}\n', path.read_bytes())
            self.assertEqual(['state.json'], [p.name for p in Path(temp).iterdir()])

    def test_relay_rerun_rejects_different_pair_before_dependencies(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(I, 'preflight'), patch.object(I, 'dependencies') as deps:
            root = Path(temp)
            state = dict(sample_pair(), role='relay', awg_image='image')
            (root / 'state.json').write_text(json.dumps(state))
            different = dict(sample_pair(), out_host='different.test')
            # fcntl is a Linux runtime module, supplied by a mock on Windows for this path.
            import types
            fake_lock = types.SimpleNamespace(flock=lambda *a: None, LOCK_EX=1, LOCK_NB=2)
            with patch.object(I, 'ROOT', root), patch.object(I, 'STATE', root / 'state.json'), patch.dict('sys.modules', fcntl=fake_lock):
                with self.assertRaisesRegex(ValueError, 'Pairing differs'):
                    I.main(['--role', 'relay', '--pair', I.encode_pair(different)])
            deps.assert_not_called()


class ShellTests(unittest.TestCase):
    def test_generated_shell_parses_in_bash(self):
        if not I.shutil.which('bash'):
            self.skipTest('Linux Bash syntax check runs in GitHub Actions')
        scripts = [I.firewall_script(role) for role in ('out', 'relay')]
        scripts += [I.tunnel_command(1380, role) for role in ('out', 'relay')]
        scripts += [I.watchdog_script(dict(sample_pair(), role=role)) for role in ('out', 'relay')]
        for script in scripts:
            result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == '__main__':
    unittest.main()
