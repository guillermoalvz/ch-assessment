"""Smoke-test the actual backend locally without binding privileged port 80."""

import importlib.util
from pathlib import Path
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen


APP = Path(__file__).parents[1] / "modules/secure_web/templates/app.py"
spec = importlib.util.spec_from_file_location("interview_app", APP)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class BackendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.HTTPServer(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_health(self):
        with urlopen(self.url + "/healthz", timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"ok\n")

    def test_backend_response(self):
        with urlopen(self.url + "/", timeout=5) as response:
            self.assertEqual(response.read(), b"Secure private GCP backend\n")
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_no_filesystem_exposure(self):
        for path in ["/etc/passwd", "/../etc/passwd", "/app.py", "/missing"]:
            with self.subTest(path=path), self.assertRaises(HTTPError) as result:
                urlopen(self.url + path, timeout=5)
            self.assertEqual(result.exception.code, 404)
            self.assertEqual(result.exception.read(), b"Not found\n")
            result.exception.close()


if __name__ == "__main__":
    unittest.main()
