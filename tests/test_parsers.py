"""Tests de los parsers (la parte frágil): se mockea subprocess.run con salida
real de cada herramienta y se comprueba el parseo. Se ejecutan sin pytest:

    python -m unittest discover -s tests
"""

import subprocess
import types
import unittest
from unittest import mock

from tarascan import cli
from tarascan.scanners import gobuster, netexec, nmap, searchsploit, whatweb


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


if __name__ == "__main__":
    unittest.main()
