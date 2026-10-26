"""Prevent the reviewed Python dependency fixes from being silently downgraded."""
import importlib
import importlib.metadata
from io import BytesIO
from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATCHED = {
    'requests': '2.34.2',
    'certifi': '2026.10.23',
    'idna': '3.20',
    'pillow': '13.0.0',
}


def release_version(value):
    # Only final releases (not prereleases/local revisions) qualify for this gate.
    if not re.fullmatch(r'\d+(?:\.\d+)*', value):
        raise ValueError(f'Expected a final release version, got {value!r}')
    return tuple(int(part) for part in value.split('.'))


def requirements(path, visited=None):
    """Resolve the project's requirements includes without invoking an installer."""
    visited = set() if visited is None else visited
    path = path.resolve()
    if path in visited:
        return []
    visited.add(path)
    result = []
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if line.startswith('-r '):
            result.extend(requirements(path.parent / line[3:].strip(), visited))
        elif line:
            result.append(line)
    return result


class PythonDependencySecurityTests(unittest.TestCase):
    def test_setuptools_runtime_and_build_require_patched_release(self):
        self.assertIn('setuptools==84.2.1', requirements(ROOT / 'requirements-runtime.txt'))
        metadata = tomllib.loads((ROOT / 'mcp_authscan/pyproject.toml').read_text())
        self.assertIn('setuptools>=84.2.1,<85', metadata['build-system']['requires'])
        self.assertIn(
            '"setuptools>=84.2.1,<85"',
            (ROOT / '.github/workflows/ci.yml').read_text())
        self.assertGreaterEqual(
            release_version(importlib.metadata.version('setuptools')),
            release_version('84.2.1'))
        setuptools = importlib.import_module('setuptools')
        self.assertEqual(setuptools.__version__, importlib.metadata.version('setuptools'))
        # The immutable Nix copy may remain visible to broad inventory scans.
        # Never hide its metadata: prove the active import selects the fixed copy.
        self.assertNotIn('/nix/store/', str(Path(setuptools.__file__).resolve()))

    def test_all_requirements_paths_keep_patched_versions(self):
        for filename in (
            'requirements-runtime.txt', 'requirements-web.txt',
            'requirements_full.txt', 'requirements-dev.txt', 'jwt-requirements.txt',
        ):
            entries = requirements(ROOT / filename)
            expected = set(PATCHED) - ({'pillow'} if filename == 'jwt-requirements.txt' else set())
            found = set()
            for entry in entries:
                name = re.split(r'[<>=!~;\[]', entry, maxsplit=1)[0].lower()
                if name not in PATCHED:
                    continue
                with self.subTest(manifest=filename, package=name):
                    match = re.fullmatch(r'[\w-]+==(\d+(?:\.\d+)*)', entry)
                    self.assertIsNotNone(match, f'Expected a reviewed exact pin: {entry}')
                    self.assertGreaterEqual(
                        release_version(match[1]), release_version(PATCHED[name]))
                    found.add(name)
            self.assertEqual(found, expected, filename)

    def test_standalone_package_declares_patched_minimums(self):
        metadata = tomllib.loads((ROOT / 'mcp_authscan/pyproject.toml').read_text())
        dependencies = metadata['project']['dependencies']
        self.assertEqual(metadata['project']['requires-python'], '>=3.11')
        for name, minimum in PATCHED.items():
            with self.subTest(package=name):
                candidates = [entry for entry in dependencies if entry.startswith(name + '>=')]
                self.assertEqual(len(candidates), 1)
                floor = candidates[0].split('>=', 1)[1].split(',', 1)[0]
                self.assertGreaterEqual(release_version(floor), release_version(minimum))

    def test_imported_packages_and_all_visible_metadata_are_patched(self):
        modules = {'pillow': 'PIL', 'requests': 'requests', 'certifi': 'certifi', 'idna': 'idna'}
        for name, minimum in PATCHED.items():
            with self.subTest(package=name):
                module = importlib.import_module(modules[name])
                active = importlib.metadata.version(name)
                self.assertEqual(module.__version__, active)
                self.assertGreaterEqual(release_version(active), release_version(minimum))
                # sys.path can repeat a prefix. Deduplicate paths, not versions:
                # stale dist-info alongside a replacement must still be inspected.
                visible = {
                    (str(Path(dist.locate_file('')).resolve()), dist.version)
                    for dist in importlib.metadata.distributions()
                    if dist.metadata['Name'].lower() == name
                }
                self.assertTrue(visible)
                for _, version in visible:
                    self.assertGreaterEqual(release_version(version), release_version(minimum))

    def test_pillow_native_image_round_trip(self):
        from PIL import Image

        for image_format in ('PNG', 'JPEG'):
            with self.subTest(format=image_format):
                content = BytesIO()
                with Image.new('RGB', (16, 16), (23, 96, 74)) as image:
                    image.save(content, format=image_format)
                content.seek(0)
                with Image.open(content) as restored:
                    restored.load()
                    self.assertEqual(restored.size, (16, 16))
                    self.assertEqual(restored.mode, 'RGB')


if __name__ == '__main__':
    unittest.main()
