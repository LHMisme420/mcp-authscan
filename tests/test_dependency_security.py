"""Security regressions for declared Python versions and Flask session access."""
import re
import tomllib
import unittest
from importlib.metadata import distributions, version
from io import BytesIO
from pathlib import Path

from flask import Flask, session
from PIL import Image
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parents[1]
SECURITY_FLOORS = {
    "pillow": "13.0.0",
    "certifi": "2026.10.23",
    "idna": "3.20",
    "requests": "2.34.2",
}


def release(value):
    return tuple(int(part) for part in value.split("."))


class DependencySecurityTests(unittest.TestCase):
    def test_security_floors_cover_web_jwt_and_installed_scanner_metadata(self):
        project = tomllib.loads((ROOT / "mcp_authscan" / "pyproject.toml").read_text())["project"]
        self.assertEqual(project["requires-python"], ">=3.11")
        sources = {
            "web": (ROOT / "requirements-runtime.txt").read_text().splitlines(),
            "jwt": (ROOT / "jwt-requirements.txt").read_text().splitlines(),
            "scanner": project["dependencies"],
        }
        for source, lines in sources.items():
            declared = {}
            for line in lines:
                match = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)\s*(.*)$", line.strip())
                if match:
                    declared[match.group(1).lower()] = match.group(2)
            for name, floor in SECURITY_FLOORS.items():
                if source == "jwt" and name == "pillow":
                    continue  # JWT tooling does not install image/PDF packages.
                with self.subTest(source=source, package=name):
                    specifier = declared[name]
                    self.assertNotIn(";", specifier)
                    lower_bounds = re.findall(
                        r"(?:^|,)\s*(?:>=|==)\s*(\d+(?:\.\d+)+)(?=\s*(?:,|$))",
                        specifier,
                    )
                    self.assertTrue(any(
                        release(bound) >= release(floor) for bound in lower_bounds
                    ))

    def test_runtime_has_no_stale_vulnerable_package_metadata(self):
        for name, floor in SECURITY_FLOORS.items():
            with self.subTest(package=name):
                installed = {
                    distribution.version for distribution in distributions()
                    if distribution.metadata["Name"].lower() == name
                }
                self.assertEqual(installed, {version(name)})
                self.assertGreaterEqual(release(version(name)), release(floor))

    def test_patched_pillow_and_reportlab_embed_an_image_in_a_pdf(self):
        self.assertEqual(Image.__version__, version("pillow"))
        self.assertGreaterEqual(release(version("reportlab")), release("5.1.0"))
        with Image.new("RGB", (8, 8), (10, 100, 200)) as image:
            for image_format in ("PNG", "JPEG", "TIFF", "WEBP"):
                with self.subTest(format=image_format):
                    image_data = BytesIO()
                    image.save(image_data, format=image_format)
                    image_data.seek(0)
                    with Image.open(image_data) as decoded:
                        decoded.load()
                        self.assertEqual(decoded.size, (8, 8))
            png = BytesIO()
            image.save(png, format="PNG")
        png.seek(0)
        output = BytesIO()
        document = canvas.Canvas(output)
        document.drawImage(ImageReader(png), 10, 10, width=32, height=32)
        document.save()
        self.assertTrue(output.getvalue().startswith(b"%PDF-"))
        self.assertIn(b"/Subtype /Image", output.getvalue())

    def test_requirements_disallow_vulnerable_python_versions(self):
        requirements = (ROOT / "requirements-runtime.txt").read_text()
        floor = re.search(r"(?im)^flask>=(\d+\.\d+\.\d+),<4$", requirements)
        self.assertIsNotNone(floor)
        self.assertGreaterEqual(release(floor.group(1)), (3, 1, 3))
        full = (ROOT / "requirements_full.txt").read_text()
        self.assertIn("-r requirements-runtime.txt", full)
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
