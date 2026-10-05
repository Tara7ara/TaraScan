"""Tests de integración: lanzan subcomandos de tarascan CONTRA el laboratorio.

A diferencia de test_commands/test_parsers (lógica pura, siempre corren), estos
necesitan el `test-lab/` levantado (docker compose up -d) y las herramientas del
sistema (searchsploit, etc.). Si el lab no responde o falta una herramienta, el
test se SALTA en vez de fallar, para no romper la suite en una máquina sin Docker.

    python -m unittest discover -s tests

Subred del lab: 172.30.0.0/24 (web .10, https .11, smb .20, ssh .30).
"""

import socket
import subprocess
import sys
import unittest

WEB = "172.30.0.10"
SMB = "172.30.0.20"
SSH = "172.30.0.30"


def _lab_up(host: str = WEB, port: int = 80, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _run(args: list[str], timeout: int = 120) -> str:
    """Lanza 'python -m tarascan.cli <args>' y devuelve su salida combinada."""
    proc = subprocess.run(
        [sys.executable, "-m", "tarascan.cli", *args],
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.stdout + proc.stderr


@unittest.skipUnless(_lab_up(), "test-lab no levantado (docker compose up -d en test-lab/)")
class TestLab(unittest.TestCase):
    def test_recon_ssh_detecta_puerto_22(self):
        out = _run([SSH, "--only", "nmap", "--fresh"], timeout=120)
        self.assertIn("22", out)

    def test_audit_smb_null_session(self):
        out = _run(["audit", "smb", SMB], timeout=90)
        if "no está instalado" in out:
            self.skipTest("netexec (nxc) no instalado")
        self.assertRegex(out.lower(), r"null|signing|public")

    def test_web_detecta_catch_all(self):
        out = _run(["web", f"http://{WEB}"], timeout=60)
        # El WordPress del lab es catch-all: debe avisar, no listar todo como API.
        self.assertIn("catch-all", out.lower())

    def test_cve_vsftpd_backdoor(self):
        out = _run(["cve", "vsftpd", "2.3.4"], timeout=60)
        if "no está instalado" in out:
            self.skipTest("searchsploit no instalado")
        self.assertIn("Backdoor", out)


class TestPipesEndToEnd(unittest.TestCase):
    """Tuberías: no necesitan lab, solo el binario; van por subprocess real."""

    def test_decode_por_tuberia(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tarascan.cli", "decode"],
            input="YWRtaW4=\n", capture_output=True, text=True, timeout=30,
        )
        self.assertIn("admin", proc.stdout)

    def test_hash_por_tuberia(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tarascan.cli", "hash"],
            input="5f4dcc3b5aa765d61d8327deb882cf99\n", capture_output=True, text=True, timeout=30,
        )
        self.assertIn("MD5", proc.stdout)


if __name__ == "__main__":
    unittest.main()
