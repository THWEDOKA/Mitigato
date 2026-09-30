import collections
import ipaddress
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import mitigato


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"


class ConfigTests(unittest.TestCase):
    def test_example_requires_a_channel(self):
        with self.assertRaisesRegex(ValueError, "Configure SMTP"):
            mitigato.load_config(EXAMPLE)

    def test_config_accepts_valid_channel_and_trusted_network(self):
        content = EXAMPLE.read_text().replace('bot_token = ""', 'bot_token = "token"').replace('chat_id = ""', 'chat_id = "123"').replace('trusted_ips = []', 'trusted_ips = ["198.51.100.4/32"]')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.toml"
            path.write_text(content)
            config = mitigato.load_config(path)
            self.assertEqual(config.telegram_chat_id, "123")
            self.assertEqual(config.trusted_ips, ("198.51.100.4/32",))

    def test_rejects_unknown_and_invalid_values(self):
        content = EXAMPLE.read_text().replace('bot_token = ""', 'bot_token = "token"').replace('chat_id = ""', 'chat_id = "123"')
        for wrong in ("interval_seconds = 0", "interval_seconds = true", "syn_recv_total = -1", 'security = "plain"', 'trusted_ips = ["oops"]', 'trusted_ips = 1'):
            changed = content
            if wrong.startswith("interval_seconds"):
                changed = changed.replace("interval_seconds = 5", wrong)
            elif wrong.startswith("syn_recv_total"):
                changed = changed.replace("syn_recv_total = 500", wrong)
            elif wrong.startswith("security"):
                changed = changed.replace('security = "ssl"', wrong)
            else:
                changed = changed.replace("trusted_ips = []", wrong)
            with self.subTest(wrong=wrong), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "config.toml"
                path.write_text(changed)
                with self.assertRaises(ValueError):
                    mitigato.load_config(path)


class MetricsTests(unittest.TestCase):
    def test_kernel_address_decoding(self):
        self.assertEqual(str(mitigato.decode_remote_ip("0100007F", False)), "127.0.0.1")
        self.assertEqual(str(mitigato.decode_remote_ip("00000000000000000000000001000000", True)), "::1")

    def test_public_sources_only_and_trusted_ranges(self):
        trusted = (ipaddress.ip_network("8.8.8.0/24"),)
        self.assertFalse(mitigato.is_blockable("8.8.8.8", trusted))
        self.assertFalse(mitigato.is_blockable("127.0.0.1", ()))
        self.assertFalse(mitigato.is_blockable("192.168.1.10", ()))
        self.assertFalse(mitigato.is_blockable("224.0.0.1", ()))
        self.assertTrue(mitigato.is_blockable("1.1.1.1", trusted))

    @patch("mitigato.run_nft")
    def test_block_uses_address_family_and_timeout(self, nft):
        mitigato.block_ip("1.1.1.1", 600)
        mitigato.block_ip("2606:4700:4700::1111", 30)
        self.assertEqual(nft.call_args_list[0].args, ("add", "element", "inet", "mitigato", "blocked_v4", "{", "1.1.1.1", "timeout", "600s", "}"))
        self.assertEqual(nft.call_args_list[1].args[4], "blocked_v6")


class AlertTests(unittest.TestCase):
    @patch("mitigato.smtplib.SMTP_SSL")
    def test_smtp_ssl_uses_authentication_and_sends_message(self, smtp):
        client = smtp.return_value
        config = mitigato.Config(smtp_host="mail.example", smtp_port=465, smtp_user="user", smtp_password="password", smtp_from="sender@example.com", smtp_to="ops@example.com")
        self.assertTrue(mitigato.send_alert(config, "Test", "Body"))
        smtp.assert_called_once()
        client.login.assert_called_once_with("user", "password")
        self.assertEqual(client.send_message.call_args.args[0]["To"], "ops@example.com")

    @patch("mitigato.smtplib.SMTP")
    def test_smtp_starttls_upgrades_before_login(self, smtp):
        client = smtp.return_value
        config = mitigato.Config(smtp_host="mail.example", smtp_port=587, smtp_security="starttls", smtp_user="user", smtp_password="password", smtp_from="sender@example.com", smtp_to="ops@example.com")
        self.assertTrue(mitigato.send_alert(config, "Test", "Body"))
        client.starttls.assert_called_once()
        client.ehlo.assert_called_once()
        calls = [call[0] for call in client.method_calls]
        self.assertLess(calls.index("starttls"), calls.index("login"))

    @patch("mitigato.urllib.request.urlopen")
    def test_telegram_post_and_success(self, urlopen):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return None
            def read(self, *_):
                return b'{"ok":true}'
        urlopen.return_value = Response()
        config = mitigato.Config(telegram_bot_token="secret", telegram_chat_id="42")
        self.assertTrue(mitigato.send_alert(config, "Test", "Body"))
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn(b"chat_id=42", request.data)

    @patch("mitigato.urllib.request.urlopen", side_effect=OSError("network down"))
    def test_channel_failure_reported(self, _):
        config = mitigato.Config(telegram_bot_token="secret", telegram_chat_id="42")
        self.assertFalse(mitigato.send_alert(config, "Test", "Body"))


class MonitorTests(unittest.TestCase):
    @patch("mitigato.send_alert")
    @patch("mitigato.read_syn_recv", side_effect=[collections.Counter({"1.1.1.1": 120}), collections.Counter({"1.1.1.1": 120}), collections.Counter(), collections.Counter()])
    @patch("mitigato.read_counters", side_effect=[(0, 0), (100, 10), (200, 20), (300, 30), (400, 40)])
    @patch("mitigato.time.sleep", side_effect=[None, None, None, None, KeyboardInterrupt])
    @patch("mitigato.time.monotonic", side_effect=[0, 5, 10, 15, 20])
    def test_alert_and_recovery_after_consecutive_samples(self, _, __, ___, ____, alert):
        config = mitigato.Config(interface="eth0", firewall_enabled=False, alert_after_samples=2, recover_after_samples=2, telegram_bot_token="x", telegram_chat_id="1")
        with self.assertRaises(KeyboardInterrupt):
            mitigato.monitor(config)
        subjects = [call.args[1] for call in alert.call_args_list]
        self.assertEqual(subjects, ["Mitigato: possible DDoS attack", "Mitigato: traffic recovered"])

    @patch("mitigato.send_alert")
    @patch("mitigato.block_ip")
    @patch("mitigato.ensure_firewall")
    @patch("mitigato.read_syn_recv", return_value=collections.Counter({"1.1.1.1": 120, "127.0.0.1": 300}))
    @patch("mitigato.read_counters", side_effect=[(0, 0), (1_000_000, 200)])
    @patch("mitigato.time.sleep")
    @patch("mitigato.time.monotonic", side_effect=[10, 15])
    def test_sample_blocks_only_public_source(self, _, __, ___, ____, ensure, block, alert):
        config = mitigato.Config(interface="eth0", interval_seconds=5, telegram_bot_token="x", telegram_chat_id="1")
        mitigato.monitor(config, once=True)
        ensure.assert_called_once()
        block.assert_called_once_with("1.1.1.1", 600)
        alert.assert_not_called()  # Detection requires three samples.

    @patch("mitigato.send_alert")
    @patch("mitigato.read_syn_recv", return_value=collections.Counter())
    @patch("mitigato.read_counters", side_effect=[(500, 500), (5, 5)])
    @patch("mitigato.time.sleep")
    @patch("mitigato.time.monotonic", side_effect=[10, 15])
    def test_counter_reset_is_not_attack(self, _, __, ___, ____, alert):
        config = mitigato.Config(interface="eth0", firewall_enabled=False)
        mitigato.monitor(config, once=True)
        alert.assert_not_called()


class InstallTests(unittest.TestCase):
    def test_interactive_config_has_private_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.toml"
            with patch("mitigato.prompt", side_effect=["", "token", "123", "1.1.1.1"]):
                mitigato.create_config(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            config = mitigato.load_config(path)
            self.assertEqual(config.trusted_ips, ("1.1.1.1",))

    def test_install_and_uninstall_files(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            config = base / "etc" / "config.toml"
            config.parent.mkdir()
            config.write_text(EXAMPLE.read_text().replace('bot_token = ""', 'bot_token = "token"').replace('chat_id = ""', 'chat_id = "123"'))
            script = base / "lib" / "mitigato.py"
            unit = base / "systemd" / "mitigato.service"
            unit.parent.mkdir()
            command = base / "bin" / "mitigato"
            with patch.multiple(mitigato, INSTALLED_SCRIPT=script, UNIT_FILE=unit, COMMAND_FILE=command), patch("mitigato.os.geteuid", return_value=0), patch("mitigato.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch("mitigato.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run, patch("mitigato.remove_firewall"):
                mitigato.install(config)
                self.assertTrue(script.is_file())
                self.assertTrue(unit.is_file())
                self.assertTrue(command.is_file())
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                self.assertIn("ExecStart=", unit.read_text())
                self.assertIn("exec ", command.read_text())
                self.assertTrue(any(call.args[0][:2] == ["systemctl", "restart"] for call in run.call_args_list))
                mitigato.uninstall(False, config)
                self.assertTrue(config.exists())
                self.assertFalse(script.exists())
                self.assertFalse(unit.exists())
                self.assertFalse(command.exists())

    def test_failed_reconfigure_restores_previous_config(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            config = base / "config.toml"
            content = EXAMPLE.read_text().replace('bot_token = ""', 'bot_token = "token"').replace('chat_id = ""', 'chat_id = "123"')
            config.write_text(content)
            with patch.multiple(mitigato, INSTALLED_SCRIPT=base / "lib" / "mitigato.py", UNIT_FILE=base / "mitigato.service", COMMAND_FILE=base / "mitigato"), patch("mitigato.os.geteuid", return_value=0), patch("mitigato.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch("mitigato.create_config", side_effect=ValueError("cancelled")):
                with self.assertRaisesRegex(ValueError, "cancelled"):
                    mitigato.install(config, reconfigure=True)
            self.assertEqual(config.read_text(), content)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
