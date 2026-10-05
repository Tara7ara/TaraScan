"""Tests de los parsers (la parte frágil): se mockea subprocess.run con salida
real de cada herramienta y se comprueba el parseo. Se ejecutan sin pytest:

    python -m unittest discover -s tests
"""

import json
import os
import subprocess
import types
import unittest
from unittest import mock

from tarascan import cli
from tarascan.scanners import ai_advisor, gobuster, net_map, netexec, nmap, searchsploit, whatweb


def _fake_run(stdout="", stderr="", returncode=0):
    """Devuelve un CompletedProcess falso para parchear subprocess.run."""
    def _run(*args, **kwargs):
        return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)
    return _run


class HelperTests(unittest.TestCase):
    def test_is_ip(self):
        self.assertTrue(cli._is_ip("192.168.1.1"))
        self.assertTrue(cli._is_ip("::1"))
        self.assertFalse(cli._is_ip("example.com"))

    def test_status_markup_colors(self):
        self.assertIn("green", cli._status_markup("200"))
        self.assertIn("yellow", cli._status_markup("301"))
        self.assertIn("red", cli._status_markup("403"))
        self.assertEqual(cli._status_markup("abc"), "abc")  # no numérico

    def test_search_term_trims_version(self):
        # "6.6.1p1" -> producto + versión numérica limpia
        self.assertEqual(
            cli._search_term({"service": "ssh", "version": "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2"}),
            "OpenSSH 6.6.1",
        )
        # multi-palabra de producto
        self.assertEqual(
            cli._search_term({"service": "http", "version": "Apache httpd 2.4.7 ((Ubuntu))"}),
            "Apache httpd 2.4.7",
        )
        # sin versión -> nombre del servicio
        self.assertEqual(cli._search_term({"service": "ssh", "version": ""}), "ssh")
        # servicio desconocido -> vacío
        self.assertEqual(cli._search_term({"service": "?", "version": ""}), "")


class NmapTests(unittest.TestCase):
    def test_parses_open_ports_with_version(self):
        line = (
            "Host: 45.33.32.156 (scanme)\tPorts: "
            "22/open/tcp//ssh//OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)/, "
            "80/open/tcp//http//Apache httpd 2.4.7/, "
            "443/closed/tcp//https///\tIgnored State: closed\n"
        )
        with mock.patch.object(subprocess, "run", _fake_run(stdout=line)):
            ports = nmap.scan("scanme")
        self.assertEqual([p["port"] for p in ports], ["22", "80"])  # el cerrado se descarta
        self.assertEqual(ports[0]["service"], "ssh")
        self.assertTrue(ports[0]["version"].startswith("OpenSSH 6.6.1p1"))


class SearchsploitTests(unittest.TestCase):
    def test_parses_json(self):
        out = (
            '{"RESULTS_EXPLOIT": [{"Title": "vsftpd 2.3.4 - Backdoor", '
            '"EDB-ID": "17491", "Type": "remote"}]}'
        )
        with mock.patch.object(subprocess, "run", _fake_run(stdout=out)):
            res = searchsploit.scan("vsftpd 2.3.4")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["edb"], "17491")
        self.assertEqual(res[0]["type"], "remote")

    def test_empty_output(self):
        with mock.patch.object(subprocess, "run", _fake_run(stdout="")):
            self.assertEqual(searchsploit.scan("nada"), [])


class GobusterTests(unittest.TestCase):
    def test_parses_paths_and_status(self):
        out = "/admin (Status: 301) [Size: 0]\n/login (Status: 200) [Size: 12]\n\n"
        with mock.patch.object(subprocess, "run", _fake_run(stdout=out)):
            res = gobuster.scan("http://x")
        self.assertEqual(res[0], {"path": "/admin", "status": "301"})
        self.assertEqual(res[1], {"path": "/login", "status": "200"})


class WhatwebTests(unittest.TestCase):
    def test_parses_plugins(self):
        out = '[{"http_status": 200, "plugins": {"WordPress": {"version": ["7.1.1"]}, "PHP": {}}}]'
        with mock.patch.object(subprocess, "run", _fake_run(stdout=out)):
            info = whatweb.scan("http://x")
        self.assertIn("WordPress", info["plugins"])
        self.assertEqual(info["plugins"]["WordPress"], "7.1.1")
        self.assertEqual(info["plugins"]["PHP"], "detectado")


class NetexecTests(unittest.TestCase):
    def test_cleans_nulls_and_headers(self):
        out = (
            "SMB  1.2.3.4  445  HOST  [*] Unix - Samba (name:HOST) (domain:\x00) (Null Auth:True)\n"
            "SMB  1.2.3.4  445  HOST  [+] \x00\\:\n"
            "SMB  1.2.3.4  445  HOST  [*] Enumerated shares\n"
            "SMB  1.2.3.4  445  HOST  Share  Permissions  Remark\n"
            "SMB  1.2.3.4  445  HOST  -----  -----------  ------\n"
            "SMB  1.2.3.4  445  HOST  public  READ,WRITE\n"
        )
        with mock.patch.object(subprocess, "run", _fake_run(stdout=out)):
            res = netexec.scan("1.2.3.4")
        # host: solo la línea útil, sin "\:" ni "Enumerated shares"
        self.assertEqual(len(res["host"]), 1)
        self.assertIn("Null Auth:True", res["host"][0])
        self.assertNotIn("\x00", res["host"][0])
        # shares: sin cabecera ni guiones
        self.assertEqual(res["shares"], ["public  READ,WRITE"])

    def test_broken_nxc_raises(self):
        # nxc roto (traceback, sin líneas SMB, returncode != 0) -> se propaga
        with mock.patch.object(subprocess, "run", _fake_run(stderr="ImportError: tsts", returncode=1)):
            with self.assertRaises(subprocess.CalledProcessError):
                netexec.scan("1.2.3.4")


class TargetResolutionTests(unittest.TestCase):
    def test_default_target_from_env(self):
        with mock.patch.dict(os.environ, {"T": "10.10.11.200"}):
            self.assertEqual(cli._get_default_target(), "10.10.11.200")

    def test_default_target_from_state_file(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("pathlib.Path.is_file", return_value=True), \
                 mock.patch("pathlib.Path.read_text", return_value="10.10.14.5\n"):
                self.assertEqual(cli._get_default_target(), "10.10.14.5")

    def test_default_target_none_when_empty(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("pathlib.Path.is_file", return_value=False):
                self.assertIsNone(cli._get_default_target())


class NetMapTests(unittest.TestCase):
    def test_parse_nmap_sn(self):
        output = (
            "# Nmap scan\n"
            "Host: 192.168.1.1 (gateway.local)\tStatus: Up\n"
            "Host: 192.168.1.154 ()\tStatus: Up\n"
            "Host: 192.168.1.200 ()\tStatus: Down\n"
        )
        hosts = net_map.parse_nmap_sn(output)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts["192.168.1.1"], "gateway.local")
        self.assertEqual(hosts["192.168.1.154"], "")

    def test_load_oui_prefixes(self):
        content = "# Comment\n00000C Cisco Systems\n244BFE ASUSTek Computer\n"
        with mock.patch("pathlib.Path.is_file", return_value=True), \
             mock.patch("pathlib.Path.read_text", return_value=content):
            table = net_map.load_oui_prefixes()
            self.assertEqual(table.get("00000C"), "Cisco Systems")
            self.assertEqual(table.get("244BFE"), "ASUSTek Computer")

    def test_format_windows_version(self):
        self.assertEqual(net_map.format_windows_version("10.0.26100"), "Windows 11 (b26100)")
        self.assertEqual(net_map.format_windows_version("10.0.19045"), "Windows 10 (b19045)")
        self.assertEqual(net_map.format_windows_version("6.3.9600"), "Windows 8.1")
        self.assertEqual(net_map.format_windows_version("6.1.7601"), "Windows 7")

    def test_parse_rdp_ntlm(self):
        out = (
            "Nmap scan report for 192.168.1.146\n"
            "PORT     STATE SERVICE\n"
            "3389/tcp open  ms-wbt-server\n"
            "| rdp-ntlm-info:\n"
            "|   NetBIOS_Computer_Name: WIN-DESKTOP-01\n"
            "|   Product_Version: 10.0.26100\n"
        )
        res = net_map.parse_rdp_ntlm(out)
        self.assertEqual(res["192.168.1.146"]["name"], "WIN-DESKTOP-01")
        self.assertEqual(res["192.168.1.146"]["os"], "Windows 11 (b26100)")

    def test_parse_nxc_smb(self):
        out = "SMB  192.168.1.145  445  PC-OFICINA-01  [*] Windows 11 / Server 2025 Build 26100 x64 (name:PC-OFICINA-01)\n"
        res = net_map.parse_nxc_smb(out)
        self.assertEqual(res["192.168.1.145"]["name"], "PC-OFICINA-01")
        self.assertIn("Windows 11", res["192.168.1.145"]["os"])

    def test_parse_ssh_os(self):
        self.assertEqual(net_map.parse_ssh_os("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"), "Linux (Ubuntu)")
        self.assertEqual(net_map.parse_ssh_os("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"), "Linux (Debian)")
        self.assertEqual(net_map.parse_ssh_os(""), "")


class AIAdvisorTests(unittest.TestCase):
    def test_get_key_prefers_tarascan_var(self):
        with mock.patch.dict(os.environ, {"TARASCAN_AI_KEY": "a", "NVIDIA_API_KEY": "b"}, clear=True):
            self.assertEqual(ai_advisor.get_key(), "a")
        with mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "b"}, clear=True):
            self.assertEqual(ai_advisor.get_key(), "b")

    def test_get_key_none_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(ai_advisor.get_key())

    def test_analyze_without_key_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ai_advisor.AIError):
                ai_advisor.analyze("informe de prueba")

    def test_analyze_parses_response(self):
        class _FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self):
                payload = {"choices": [{"message": {"content": "## Resumen\nok"}}]}
                return json.dumps(payload).encode("utf-8")

        with mock.patch.dict(os.environ, {"TARASCAN_AI_KEY": "x"}, clear=True), \
                mock.patch.object(ai_advisor.urllib.request, "urlopen", return_value=_FakeResp()):
            out, model = ai_advisor.analyze("puerto 80 abierto")
        self.assertIn("Resumen", out)
        self.assertTrue(model)

    def test_candidate_models_override_first(self):
        with mock.patch.dict(os.environ, {"TARASCAN_AI_MODEL": "meta/llama-3.2-11b-vision-instruct"}, clear=True):
            models = ai_advisor._candidate_models()
        self.assertEqual(models[0], "meta/llama-3.2-11b-vision-instruct")
        self.assertEqual(len(models), len(set(models)))  # sin duplicados

    def test_analyze_falls_back_on_retriable(self):
        calls = []

        def _fake_request(model, *a, **k):
            calls.append(model)
            if len(calls) == 1:
                raise ai_advisor.AIError("saturado", retriable=True)
            return "## Resumen\nok"

        with mock.patch.dict(os.environ, {"TARASCAN_AI_KEY": "x"}, clear=True), \
                mock.patch.object(ai_advisor, "_request", side_effect=_fake_request):
            out, model = ai_advisor.analyze("puerto 80 abierto")
        self.assertIn("Resumen", out)
        self.assertEqual(len(calls), 2)  # falló el 1º, respondió el 2º


if __name__ == "__main__":
    unittest.main()
