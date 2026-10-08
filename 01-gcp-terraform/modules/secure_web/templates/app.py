"""Dependency-free interview backend; serves fixed responses, never disk contents."""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "InterviewBackend"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def do_GET(self):
        responses = {
            "/": b"Secure private GCP backend\n",
            "/healthz": b"ok\n",
        }
        body = responses.get(self.path, b"Not found\n")
        self.send_response(200 if self.path in responses else 404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
