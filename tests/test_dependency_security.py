"""Security regressions for declared Python versions and Flask session access."""
import re
import unittest
from importlib.metadata import version
from pathlib import Path

from flask import Flask, session


ROOT = Path(__file__).resolve().parents[1]


def release(value):
    return tuple(int(part) for part in value.split("."))


class DependencySecurityTests(unittest.TestCase):
    def test_requirements_disallow_vulnerable_python_versions(self):
        requirements = (ROOT / "requirements.txt").read_text()
        floor = re.search(r"(?im)^flask>=(\d+\.\d+\.\d+),<4$", requirements)
        self.assertIsNotNone(floor)
        self.assertGreaterEqual(release(floor.group(1)), (3, 1, 3))
        full = (ROOT / "requirements_full.txt").read_text()
        self.assertIn("-r requirements.txt", full)
        floor = re.search(r"(?im)^python-dotenv>=(\d+\.\d+\.\d+),<2$", full)
        self.assertIsNotNone(floor)
        self.assertGreaterEqual(release(floor.group(1)), (1, 2, 2))

    def test_flask_session_membership_sets_vary_cookie(self):
        self.assertGreaterEqual(release(version("flask")), (3, 1, 3))
        app = Flask(__name__)
        app.secret_key = "synthetic-session-test-key"

        @app.get("/")
        def index():
            return {"authenticated": "user_id" in session}

        with app.test_client() as client:
            for authenticated in [False, True]:
                if authenticated:
                    with client.session_transaction() as state:
                        state["user_id"] = "synthetic-user"
                response = client.get("/")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json["authenticated"], authenticated)
                self.assertIn("Cookie", response.vary)


if __name__ == "__main__":
    unittest.main()
