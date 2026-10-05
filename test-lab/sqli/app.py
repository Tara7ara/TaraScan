"""App web deliberadamente vulnerable a SQLi, para probar `tarascan <ip> --sqli`.

Minúscula y autocontenida (stdlib + sqlite3). El índice enlaza a /item?id=1, que
concatena el parámetro directo en la consulta SQL (inyectable error-based y
booleano). sqlmap con --crawl=1 descubre el enlace y detecta la inyección.

SOLO para el laboratorio local. No usar nada de esto en producción.
"""

import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE items (id INTEGER, name TEXT, secret TEXT)")
    con.executemany("INSERT INTO items VALUES (?,?,?)", [
        (1, "Camiseta", "flag_item_1"),
        (2, "Pantalón", "flag_item_2"),
        (3, "Zapatos", "flag_item_3"),
    ])
    con.commit()
    return con


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencio
        pass

    def _send(self, body: str, code: int = 200):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self._send(
                "<html><body><h1>Tienda del lab</h1>"
                "<p>Ver producto: <a href=\"/item?id=1\">#1</a> "
                "<a href=\"/item?id=2\">#2</a> <a href=\"/item?id=3\">#3</a></p>"
                "</body></html>"
            )
            return
        if parsed.path == "/item":
            qs = parse_qs(parsed.query)
            id_val = qs.get("id", ["1"])[0]
            # VULNERABLE A PROPÓSITO: concatenación directa en la consulta.
            query = "SELECT id, name FROM items WHERE id = " + id_val
            con = _db()
            try:
                rows = con.execute(query).fetchall()
                html = "<html><body>" + "".join(
                    f"<div>#{r[0]}: {r[1]}</div>" for r in rows
                ) + "</body></html>"
                self._send(html if rows else "<html><body>sin resultados</body></html>")
            except sqlite3.Error as exc:
                # El error SQL reflejado ayuda a la detección error-based.
                self._send(f"<html><body>SQL error: {exc}</body></html>", 500)
            finally:
                con.close()
            return
        self._send("<html><body>404</body></html>", 404)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
