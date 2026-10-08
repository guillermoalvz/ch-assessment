"""Exercise bucket bootstrap safely with a fake gcloud executable."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "bootstrap.sh"


class BootstrapTest(unittest.TestCase):
    def run_script(self, arguments, fail_create=False):
        with tempfile.TemporaryDirectory(prefix="state-bootstrap-test-") as directory:
            task_dir = Path(directory)
            fake = task_dir / "gcloud"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['BOOTSTRAP_TEST_LOG'], 'a') as out:\n"
                "    out.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "if 'create' in sys.argv and os.environ['BOOTSTRAP_TEST_FAIL'] == '1':\n"
                "    sys.exit(1)\n"
            )
            fake.chmod(0o755)
            log = task_dir / "calls.jsonl"
            env = os.environ.copy()
            env.update(
                PATH=f"{task_dir}:{env['PATH']}",
                BOOTSTRAP_TEST_LOG=str(log),
                BOOTSTRAP_TEST_FAIL="1" if fail_create else "0",
            )
            result = subprocess.run(
                ["bash", str(SCRIPT), *arguments], env=env,
                capture_output=True, text=True, check=False,
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_bucket_protected_before_terraform_initialization(self):
        result, calls = self.run_script(["test-project", "test-project-tfstate"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][:4], ["storage", "buckets", "create", "gs://test-project-tfstate"])
        for flag in ["--uniform-bucket-level-access", "--public-access-prevention", "--soft-delete-duration=7d", "--location=us-central1"]:
            self.assertIn(flag, calls[0])
        self.assertIn("--versioning", calls[1])

    def test_creation_failure_never_updates_existing_bucket(self):
        result, calls = self.run_script(["test-project", "test-project-tfstate"], fail_create=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("create", calls[0])

    def test_invalid_inputs_never_call_gcloud(self):
        for arguments in [[], ["test-project", "bad/bucket"], ["--project=unexpected", "valid-bucket"]]:
            with self.subTest(arguments=arguments):
                result, calls = self.run_script(arguments)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
