"""Tests de la lógica de los subcomandos nuevos (roadmap).

La parte frágil aquí es la identificación de hashes, la cascada de decode, el
desglose del JWT, el parseo del JSON del modo guiado y el fundido de la
persistencia. Se ejecutan sin pytest:

    python -m unittest discover -s tests
"""

import base64
import json
import os
import tempfile
import unittest

from tarascan.commands import crypto
from tarascan.scanners import ai_advisor


class TestHashIdentify(unittest.TestCase):
    def _labels(self, h):
        return [label for label, _, _ in crypto._identify_hash(h)]

    def test_md5_y_ntlm_comparten_longitud(self):
        labels = self._labels("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertIn("MD5", labels)
        self.assertIn("NTLM", labels)

    def test_bcrypt_por_prefijo(self):
        cands = crypto._identify_hash("$2y$10$" + "a" * 53)
        self.assertEqual(cands[0][0], "bcrypt")
        self.assertEqual(cands[0][1], "3200")

    def test_sha1_y_sha512_por_longitud(self):
        self.assertIn("SHA1", self._labels("a" * 40))
        self.assertIn("SHA512", self._labels("a" * 128))

    def test_sha512crypt_unix(self):
        self.assertEqual(crypto._identify_hash("$6$salt$hash")[0][0], "sha512crypt (Unix)")

    def test_desconocido(self):
        self.assertIn("desconocido", crypto._identify_hash("no-es-un-hash!!")[0][0])

    def test_kerberos_kerberoasting(self):
        cands = crypto._identify_hash("$krb5tgs$23$*user$DOMAIN$...*abcd")
        self.assertEqual(cands[0][1], "13100")

    def test_kerberos_asreproast(self):
        cands = crypto._identify_hash("$krb5asrep$23$user@DOMAIN:abcd")
        self.assertEqual(cands[0][1], "18200")

    def test_pwdump_lm_nt(self):
        h = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        labels = [l for l, _, _ in crypto._identify_hash(h)]
        self.assertTrue(any("pwdump" in l for l in labels))

    def test_django(self):
        self.assertEqual(crypto._identify_hash("pbkdf2_sha256$260000$salt$hash")[0][1], "10000")


class TestDecodeCascade(unittest.TestCase):
    def test_base64_no_encadena_rot13(self):
        # "Hello world" en base64 debe quedarse ahí, sin aplicarle ROT13 encima.
        layers = crypto.decode_cascade(base64.b64encode(b"Hello world").decode())
        self.assertEqual(layers[-1][1], "Hello world")
        self.assertNotIn("ROT13", [n for n, _ in layers])

    def test_rot13_solo_como_ultimo_recurso(self):
        layers = crypto.decode_cascade("Uryyb jbeyq")
        self.assertEqual(layers, [("ROT13", "Hello world")])

    def test_hex(self):
        layers = crypto.decode_cascade("48656c6c6f")
        self.assertEqual(layers[0], ("Hex", "Hello"))

    def test_binario(self):
        layers = crypto.decode_cascade("01001000 01101001")
        self.assertEqual(layers[0][1], "Hi")

    def test_sin_codificacion(self):
        self.assertEqual(crypto.decode_cascade("12"), [])

    def test_hash_no_recibe_rot13(self):
        # Un MD5 hex no debe "decodificarse" a ROT13 (sería ruido).
        self.assertEqual(crypto.decode_cascade("5f4dcc3b5aa765d61d8327deb882cf99", allow_rot13=False), [])


class TestStdin(unittest.TestCase):
    def test_arg_tiene_prioridad_sobre_tuberia(self):
        self.assertEqual(crypto._arg_or_stdin("abc"), "abc")

    def test_lee_primera_linea_de_la_tuberia(self):
        import io
        from unittest import mock
        fake = io.StringIO("YWRtaW4=\notra\n")
        fake.isatty = lambda: False
        with mock.patch.object(crypto.sys, "stdin", fake):
            self.assertEqual(crypto._arg_or_stdin(None), "YWRtaW4=")

    def test_varias_lineas(self):
        import io
        from unittest import mock
        fake = io.StringIO("uno\n\ndos\n")
        fake.isatty = lambda: False
        with mock.patch.object(crypto.sys, "stdin", fake):
            self.assertEqual(crypto._stdin_lines(), ["uno", "dos"])


class TestJWT(unittest.TestCase):
    def _b64(self, obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    def test_decodifica_header_payload(self):
        token = self._b64({"alg": "none"}) + "." + self._b64({"user": "admin"}) + "."
        rc = crypto.cmd_jwt([token])
        self.assertEqual(rc, 0)

    def test_token_invalido(self):
        self.assertEqual(crypto.cmd_jwt(["no-es-jwt"]), 1)


class TestGuidedJSON(unittest.TestCase):
    def test_json_limpio(self):
        data = ai_advisor._extract_json('{"resumen":"x","acciones":[]}')
        self.assertEqual(data["resumen"], "x")

    def test_json_en_fence(self):
        raw = "aquí tienes:\n```json\n{\"acciones\": [{\"comando\": \"tarascan 1.2.3.4 --sqli\"}]}\n```\ngracias"
        data = ai_advisor._extract_json(raw)
        self.assertEqual(data["acciones"][0]["comando"], "tarascan 1.2.3.4 --sqli")

    def test_json_con_texto_alrededor(self):
        data = ai_advisor._extract_json('bla bla {"resumen": "ok"} fin')
        self.assertEqual(data["resumen"], "ok")


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._old = os.environ.get("XDG_CACHE_HOME")
        os.environ["XDG_CACHE_HOME"] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XDG_CACHE_HOME", None)
        else:
            os.environ["XDG_CACHE_HOME"] = self._old

    def test_record_funde_sin_duplicar(self):
        from tarascan import store
        store.record_scan("10.0.0.1", ports=[{"port": "22", "service": "ssh"}], findings=["a"])
        store.record_scan("10.0.0.1", ports=[{"port": "22", "service": "ssh", "version": "8.2"}], findings=["a", "b"])
        data = store.load_target("10.0.0.1")
        self.assertEqual(len(data["ports"]), 1)
        self.assertEqual(data["ports"][0]["version"], "8.2")
        self.assertEqual(data["findings"], ["a", "b"])

    def test_slug_seguro(self):
        from tarascan import store
        self.assertEqual(store.slug("http://a.b/c"), "a.b_c")

    def test_merge_no_borra_version_previa(self):
        # Un barrido de red (sin versión) no debe pisar la versión de un recon.
        from tarascan import store
        store.record_scan("10.0.0.9", ports=[{"port": "22", "service": "ssh", "version": "OpenSSH 8.2"}])
        store.record_scan("10.0.0.9", ports=[{"port": "22", "service": "ssh", "version": ""}])
        v = store.load_target("10.0.0.9")["ports"][0]["version"]
        self.assertEqual(v, "OpenSSH 8.2")

    def test_audit_services_from_cache(self):
        from tarascan import store
        from tarascan.commands import audit
        store.record_scan("10.0.0.8", ports=[{"port": "445", "service": "smb"}, {"port": "22", "service": "ssh"}])
        self.assertEqual(set(audit._services_from_cache("10.0.0.8")), {"smb", "ssh"})


class TestWebApiDetection(unittest.TestCase):
    def test_por_content_type(self):
        from tarascan.commands import web
        self.assertTrue(web._looks_like_api("application/json"))
        self.assertTrue(web._looks_like_api("application/yaml"))

    def test_por_cuerpo_aunque_el_ctype_mienta(self):
        from tarascan.commands import web
        # swagger.json servido como text/html: se detecta por el cuerpo.
        self.assertTrue(web._looks_like_api("text/html", '{"swagger":"2.0","paths":{}}'))
        self.assertTrue(web._looks_like_api("text/html", '{"openapi":"3.0.0"}'))

    def test_html_normal_no_es_api(self):
        from tarascan.commands import web
        self.assertFalse(web._looks_like_api("text/html", "<!doctype html><html>hola</html>"))


class TestCveTerm(unittest.TestCase):
    def test_producto_mas_version(self):
        from tarascan.commands import cve
        self.assertEqual(cve._term_from_port({"service": "ftp", "version": "vsftpd 2.3.4"}), "vsftpd 2.3.4")

    def test_recorta_version_a_numerica(self):
        from tarascan.commands import cve
        self.assertEqual(cve._term_from_port({"service": "ssh", "version": "OpenSSH 8.2p1 Ubuntu"}), "OpenSSH 8.2")

    def test_sin_version_usa_servicio(self):
        from tarascan.commands import cve
        self.assertEqual(cve._term_from_port({"service": "http", "version": ""}), "http")

    def test_servicio_desconocido_vacio(self):
        from tarascan.commands import cve
        self.assertEqual(cve._term_from_port({"service": "?", "version": ""}), "")


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._old = os.environ.get("XDG_CACHE_HOME")
        os.environ["XDG_CACHE_HOME"] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XDG_CACHE_HOME", None)
        else:
            os.environ["XDG_CACHE_HOME"] = self._old

    def test_snapshot_cap_historico(self):
        from tarascan import store
        for i in range(15):
            store.add_snapshot("1.1.1.1", [{"port": str(i)}])
        self.assertEqual(len(store.load_target("1.1.1.1")["history"]), store._HISTORY_MAX)

    def test_diff_necesita_dos(self):
        from tarascan import store
        from tarascan.commands import diff
        store.add_snapshot("2.2.2.2", [{"port": "80"}])
        self.assertEqual(diff.cmd_diff(["2.2.2.2"]), 1)  # solo uno -> error

    def test_diff_detecta_cambios(self):
        from tarascan import store
        from tarascan.commands import diff
        store.add_snapshot("3.3.3.3", [{"port": "21", "service": "ftp", "version": "v1"}])
        store.add_snapshot("3.3.3.3", [{"port": "80", "service": "http", "version": "v2"}])
        self.assertEqual(diff.cmd_diff(["3.3.3.3"]), 0)  # dos snapshots -> ok


class TestCompletion(unittest.TestCase):
    def test_zsh_tiene_piezas_clave(self):
        from tarascan.commands import completion
        s = completion._zsh_script()
        self.assertIn("#compdef tarascan", s)
        self.assertIn("compadd ssh tls smb", s)
        self.assertIn("compdef _tarascan tarascan", s)

    def test_bash_tiene_complete(self):
        from tarascan.commands import completion
        s = completion._bash_script()
        self.assertIn("complete -F _tarascan tarascan", s)

    def test_incluye_subcomandos_actuales(self):
        from tarascan.commands import completion
        s = completion._zsh_script()
        for sub in ("audit", "gtfobins", "diff", "report"):
            self.assertIn(sub, s)


class TestGtfobins(unittest.TestCase):
    def test_db_carga_y_tiene_clasicos(self):
        from tarascan.commands import gtfobins
        db = gtfobins._load_db()
        for b in ("find", "vim", "python3", "env", "awk"):
            self.assertIn(b, db)

    def test_find_tiene_sudo_suid(self):
        from tarascan.commands import gtfobins
        entry = gtfobins._load_db()["find"]
        self.assertIn("sudo", entry)
        self.assertIn("suid", entry)
        self.assertTrue(any("/bin/sh" in x for x in entry["sudo"]))

    def test_normaliza_ruta_a_nombre(self):
        from tarascan.commands import gtfobins
        self.assertEqual(gtfobins._binname("/usr/bin/find"), "find")
        self.assertEqual(gtfobins._binname("VIM"), "vim")

    def test_meta_no_es_binario(self):
        from tarascan.commands import gtfobins
        db = gtfobins._load_db()
        disponibles = [k for k in db if not k.startswith("_")]
        self.assertNotIn("_meta", disponibles)

    def test_fallback_antes_del_punto(self):
        # vim.basic / python3.11 deben resolver a vim / python3.
        from tarascan.commands import gtfobins
        db = gtfobins._load_db()
        for real, base in (("vim.basic", "vim"), ("python3.11", "python3")):
            name = gtfobins._binname(real)
            entry = db.get(name) or db.get(name.split(".")[0])
            self.assertIsNotNone(entry, real)
            self.assertEqual(db.get(base), entry)


class TestGuidedValidator(unittest.TestCase):
    """El copiloto conoce toda la herramienta: valida flags y subcomandos."""

    def setUp(self):
        from tarascan import cli
        self.cli = cli
        self.ALLOW = cli._GUIDED_ALLOWED

    def test_recon_con_flag_se_ancla_al_target(self):
        out = self.cli._validate_guided_cmd("tarascan 9.9.9.9 --full", target="1.2.3.4", allow_flags=self.ALLOW)
        self.assertEqual(out, "tarascan 1.2.3.4 --full")

    def test_recon_sin_flag_se_descarta_en_modo_objetivo(self):
        self.assertIsNone(self.cli._validate_guided_cmd("tarascan 1.2.3.4", target="1.2.3.4", allow_flags=self.ALLOW))

    def test_subcomando_audit_aceptado_si_referencia_al_target(self):
        out = self.cli._validate_guided_cmd("tarascan audit smb 1.2.3.4", target="1.2.3.4", allow_flags=self.ALLOW)
        self.assertEqual(out, "tarascan audit smb 1.2.3.4")

    def test_subcomando_web_con_url_del_target(self):
        out = self.cli._validate_guided_cmd("tarascan web http://1.2.3.4:8080", target="1.2.3.4", allow_flags=self.ALLOW)
        self.assertEqual(out, "tarascan web http://1.2.3.4:8080")

    def test_utilidad_sin_target(self):
        self.assertEqual(self.cli._validate_guided_cmd("tarascan pivot", target="1.2.3.4", allow_flags=self.ALLOW), "tarascan pivot")

    def test_copiloto_propone_gtfobins(self):
        out = self.cli._validate_guided_cmd("tarascan gtfobins find", target="1.2.3.4", allow_flags=self.ALLOW)
        self.assertEqual(out, "tarascan gtfobins find")

    def test_copiloto_analiza_hash_encontrado(self):
        out = self.cli._validate_guided_cmd("tarascan hash 5f4dcc3b5aa765d61d8327deb882cf99", target="1.2.3.4", allow_flags=self.ALLOW)
        self.assertEqual(out, "tarascan hash 5f4dcc3b5aa765d61d8327deb882cf99")

    def test_copiloto_decodifica_base64_encontrado(self):
        out = self.cli._validate_guided_cmd("tarascan decode U3VwZXJTZWNyZXQ=", target="1.2.3.4", allow_flags=self.ALLOW)
        self.assertEqual(out, "tarascan decode U3VwZXJTZWNyZXQ=")

    def test_copiloto_desglosa_jwt_encontrado(self):
        out = self.cli._validate_guided_cmd("tarascan jwt eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.sig", target="1.2.3.4", allow_flags=self.ALLOW)
        self.assertEqual(out, "tarascan jwt eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.sig")

    def test_subcomando_inventado_rechazado(self):
        self.assertIsNone(self.cli._validate_guided_cmd("tarascan exploitame 1.2.3.4", target="1.2.3.4", allow_flags=self.ALLOW))

    def test_no_tarascan_rechazado(self):
        self.assertIsNone(self.cli._validate_guided_cmd("rm -rf /", target="1.2.3.4", allow_flags=self.ALLOW))

    def test_net_ip_debe_estar_en_la_tabla(self):
        ips = {"10.0.0.5", "10.0.0.6"}
        self.assertEqual(self.cli._validate_guided_cmd("tarascan 10.0.0.5", net_ips=ips, allow_flags=self.cli._GUIDED_NET_ALLOWED), "tarascan 10.0.0.5")
        self.assertIsNone(self.cli._validate_guided_cmd("tarascan 1.2.3.4", net_ips=ips, allow_flags=self.cli._GUIDED_NET_ALLOWED))

    def test_net_rechaza_flag_intrusiva(self):
        ips = {"10.0.0.5"}
        self.assertIsNone(self.cli._validate_guided_cmd("tarascan 10.0.0.5 --brute ssh", net_ips=ips, allow_flags=self.cli._GUIDED_NET_ALLOWED))


if __name__ == "__main__":
    unittest.main()
