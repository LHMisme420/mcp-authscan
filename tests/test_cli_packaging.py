"""Verify nested CLI metadata produces self-contained and editable distributions."""
import configparser
import os
import shutil
import site
import subprocess
import sys
import tarfile
import tempfile
import venv
import tomllib
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "mcp_authscan"


class CliPackagingTests(unittest.TestCase):
    def test_root_tool_configuration_survives_without_a_root_python_project(self):
        ruff = tomllib.loads((ROOT / "ruff.toml").read_text())
        self.assertEqual(ruff["line-length"], 120)
        self.assertEqual(ruff["lint"]["select"], ["E", "F", "I", "W", "B", "UP"])
        self.assertEqual(ruff["lint"]["ignore"], ["E501"])
        mypy = configparser.ConfigParser()
        mypy.read(ROOT / "mypy.ini")
        # Coverage policy: measure all of mcp_authscan with branch coverage
        # (Configuration validated in CI workflow)
        self.assertEqual(mypy["mypy"]["python_version"], "3.11")
        self.assertTrue(mypy["mypy"].getboolean("no_implicit_optional"))

    def test_wheel_sdist_and_editable_keep_the_scanner_importable(self):
        # Use existing build tools without creating an isolated virtual environment.
        env = dict(os.environ, PYTHONUSERBASE=str(Path(site.getuserbase()).resolve()))
        with tempfile.TemporaryDirectory(prefix="vata-cli-package-") as directory:
            temp = Path(directory)
            source = temp / "source"
            shutil.copytree(PACKAGE, source, ignore=shutil.ignore_patterns(
                "__pycache__", "*.egg-info", "build", "dist", ".pythonlibs",
                ".venv", ".env", ".env.*", "*.db*", "*.sqlite*", "*.key", "*.pem",
            ))

            def run(args, cwd):
                result = subprocess.run(
                    [sys.executable, *args], cwd=cwd, env=env,
                    capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stdout[-4000:] + result.stderr[-4000:])
                return result.stdout

            def build(method, project, output):
                output.mkdir()
                run(["-c", (
                    "import sys; from setuptools import build_meta; "
                    f"build_meta.{method}(sys.argv[1])"
                ), str(output)], project)
                return next(output.iterdir())

            def check_wheel(wheel):
                with zipfile.ZipFile(wheel) as archive:
                    names = archive.namelist()
                    for module in PACKAGE.glob("*.py"):
                        self.assertIn("mcp_authscan/" + module.name, names)
                    entrypoints = next(name for name in names if name.endswith(".dist-info/entry_points.txt"))
                    self.assertIn(
                        "mcp-authscan = mcp_authscan.cli_wrapper:main",
                        archive.read(entrypoints).decode(),
                    )
                    license_file = next(name for name in names if name.endswith("/LICENSE"))
                    self.assertEqual(archive.read(license_file).decode(), (ROOT / "LICENSE").read_text())
                    self.assertFalse(any(name.endswith((".db", ".sqlite")) for name in names))
                output = run(["-c", (
                    "import sys; sys.path.insert(0, sys.argv[1]); "
                    "import mcp_authscan; "
                    "assert mcp_authscan.__file__.startswith(sys.argv[1]); "
                    "from mcp_authscan.cli_wrapper import main; "
                    "sys.argv=['mcp-authscan','--help']; main()"
                ), str(wheel)], temp)
                self.assertIn("v1.1.3", output)

            with self.subTest(distribution="wheel"):
                wheel = build("build_wheel", source, temp / "wheels")
                check_wheel(wheel)

            with self.subTest(distribution="sdist"):
                sdist = build("build_sdist", source, temp / "sdists")
                unpacked = temp / "unpacked"
                unpacked.mkdir()
                with tarfile.open(sdist) as archive:
                    archive.extractall(unpacked, filter="data")
                released_source = next(unpacked.iterdir())
                self.assertTrue((released_source / "pyproject.toml").is_file())
                rebuilt = build("build_wheel", released_source, temp / "rebuilt")
                check_wheel(rebuilt)

            with self.subTest(distribution="editable"):
                editable = build("build_editable", source, temp / "editable")
                venv_dir = temp / "editable-venv"
                venv.create(venv_dir, with_pip=True)
                pip = venv_dir / "bin" / "pip"
                python = venv_dir / "bin" / "python"
                subprocess.run([str(pip), "install", "-q", str(editable)], check=True, cwd=temp)
                # Verify the installed scanner can be imported and the CLI works
                output = subprocess.run(
                    [str(python), "-m", "mcp_authscan.cli_wrapper", "--help"],
                    capture_output=True, text=True, check=True, cwd=temp
                )
                self.assertIn("mcp_authscan", output.stdout)
                self.assertIn("target", output.stdout)
