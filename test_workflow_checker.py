import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import workflow_checker as wc

SHA = "0123456789abcdef0123456789abcdef01234567"

CLEAN = """name: ok
on: [push]
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@%s
        with:
          persist-credentials: false
      - run: python -m unittest
""" % SHA


def check(text):
    return wc.check_workflow(text.splitlines())


def rules(text):
    return {f["rule"] for f in check(text)}


def job(step_lines, head="on: [push]\npermissions:\n  contents: read\n"):
    return head + "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n" + step_lines + "\n"


class RunLineTests(unittest.TestCase):
    def test_inline_run(self):
        lines = ["steps:", "  - run: echo hi"]
        self.assertEqual(wc.run_lines(lines), {2: "echo hi"})

    def test_block_run(self):
        lines = ["  - name: a", "    run: |", "      echo one", "", "      echo two", "  - name: b"]
        self.assertEqual(wc.run_lines(lines), {3: "echo one", 5: "echo two"})

    def test_folded_run(self):
        lines = ["    run: >-", "      echo a", "      echo b"]
        self.assertEqual(set(wc.run_lines(lines)), {2, 3})

    def test_comments_inside_run_are_skipped(self):
        lines = ["    run: |", "      # curl x | sh", "      echo ok"]
        self.assertEqual(wc.run_lines(lines), {3: "echo ok"})

    def test_non_run_keys_are_not_code(self):
        self.assertEqual(wc.run_lines(["    name: run: thing", "    env:", "      A: b"]), {})

    def test_commented_run_key(self):
        self.assertEqual(wc.run_lines(["    # run: echo hi"]), {})


class PermissionTests(unittest.TestCase):
    def test_clean_file(self):
        self.assertEqual(check(CLEAN), [])

    def test_missing_permissions(self):
        self.assertIn("no-permissions", rules(job("      - run: echo", head="on: [push]\n")))

    def test_job_level_permissions_count(self):
        text = "on: [push]\njobs:\n  t:\n    permissions:\n      contents: read\n    runs-on: x\n    steps:\n      - run: echo\n"
        self.assertNotIn("no-permissions", rules(text))

    def test_write_all(self):
        found = [f for f in check(job("      - run: echo", head="on: [push]\npermissions: write-all\n"))
                 if f["rule"] == "permissions-write-all"]
        self.assertEqual(found[0]["severity"], "high")
        self.assertEqual(found[0]["line"], 2)

    def test_read_all_is_fine(self):
        self.assertNotIn("permissions-write-all", rules(job("      - run: echo", head="on: [push]\npermissions: read-all\n")))


class TriggerTests(unittest.TestCase):
    def test_pull_request_target(self):
        self.assertIn("pull-request-target", rules("on:\n  pull_request_target:\npermissions: {}\n"))
        self.assertNotIn("pull-request-target", rules("on:\n  pull_request:\npermissions: {}\n"))

    def test_commented_trigger_is_ignored(self):
        self.assertNotIn("pull-request-target", rules("on: [push]\n# pull_request_target\npermissions: {}\n"))

    def test_checkout_of_pr_head_is_high(self):
        text = ("on:\n  pull_request_target:\npermissions: {}\njobs:\n  t:\n    steps:\n"
                "      - uses: actions/checkout@%s\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                "          persist-credentials: false\n" % SHA)
        found = [f for f in check(text) if f["rule"] == "pr-target-checkout"]
        self.assertEqual(found[0]["severity"], "high")

    def test_pr_head_without_target_trigger_is_fine(self):
        text = "on: [pull_request]\npermissions: {}\njobs:\n  t:\n    steps:\n      - run: echo ${{ github.event.pull_request.head.sha }}\n"
        self.assertNotIn("pr-target-checkout", rules(text))

    def test_self_hosted(self):
        text = "permissions: {}\njobs:\n  t:\n    runs-on: self-hosted\n"
        self.assertIn("self-hosted-runner", rules(text))
        self.assertIn("self-hosted-runner", rules(text.replace("self-hosted", "[self-hosted, linux]")))
        self.assertNotIn("self-hosted-runner", rules(text.replace("self-hosted", "ubuntu-latest")))


class ActionPinTests(unittest.TestCase):
    def test_sha_is_pinned(self):
        self.assertNotIn("action-not-pinned", rules(job("      - uses: foo/bar@%s" % SHA)))

    def test_tag_is_low(self):
        found = [f for f in check(job("      - uses: foo/bar@v2")) if f["rule"] == "action-not-pinned"]
        self.assertEqual(found[0]["severity"], "low")

    def test_branch_is_high(self):
        for ref in ("main", "master", "latest", "HEAD"):
            found = [f for f in check(job("      - uses: foo/bar@%s" % ref)) if f["rule"] == "action-branch-ref"]
            self.assertEqual(found[0]["severity"], "high", ref)

    def test_local_action_is_skipped(self):
        found = rules(job("      - uses: ./.github/actions/mine"))
        self.assertNotIn("action-not-pinned", found)
        self.assertNotIn("action-branch-ref", found)

    def test_docker_images(self):
        self.assertIn("action-not-pinned", rules(job("      - uses: docker://alpine:3.20")))
        self.assertNotIn("action-not-pinned", rules(job("      - uses: docker://alpine@sha256:abc")))

    def test_action_in_subfolder(self):
        self.assertIn("action-not-pinned", rules(job("      - uses: foo/bar/sub@v1")))

    def test_quoted_uses(self):
        self.assertIn("action-not-pinned", rules(job("      - uses: 'foo/bar@v1'")))

    def test_commented_uses_is_ignored(self):
        self.assertNotIn("action-not-pinned", rules(job("      # - uses: foo/bar@v1")))


class RunRuleTests(unittest.TestCase):
    def test_script_injection(self):
        for expr in ("github.event.comment.body", "github.event.issue.title",
                     "github.event.pull_request.title", "github.head_ref",
                     "github.event.head_commit.message"):
            self.assertIn("script-injection", rules(job('      - run: echo "${{ %s }}"' % expr)), expr)

    def test_safe_expressions_are_not_injection(self):
        for expr in ("github.sha", "github.run_id", "github.event.pull_request.number", "github.repository"):
            self.assertNotIn("script-injection", rules(job('      - run: echo "${{ %s }}"' % expr)), expr)

    def test_env_line_is_not_flagged(self):
        text = job("      - env:\n          T: ${{ github.event.pull_request.title }}\n        run: echo \"$T\"")
        self.assertNotIn("script-injection", rules(text))

    def test_injection_in_block(self):
        text = job("      - run: |\n          echo start\n          echo ${{ github.event.comment.body }}")
        found = [f for f in check(text) if f["rule"] == "script-injection"]
        self.assertEqual(len(found), 1)

    def test_input_in_run(self):
        self.assertIn("input-in-run", rules(job("      - run: ./go ${{ github.event.inputs.target }}")))
        self.assertIn("input-in-run", rules(job("      - run: ./go ${{ inputs.target }}")))

    def test_secret_in_run(self):
        self.assertIn("secret-in-run", rules(job("      - run: ./login ${{ secrets.TOKEN }}")))
        self.assertNotIn("secret-in-run", rules(job("      - env:\n          T: ${{ secrets.TOKEN }}\n        run: ./login \"$T\"")))

    def test_curl_pipe_shell(self):
        self.assertIn("curl-pipe-shell", rules(job("      - run: curl -fsSL https://x.test | bash")))
        self.assertNotIn("curl-pipe-shell", rules(job("      - run: curl -o a.sh https://x.test")))


class CheckoutTests(unittest.TestCase):
    def test_missing_persist_credentials(self):
        self.assertIn("checkout-keeps-token", rules(job("      - uses: actions/checkout@%s" % SHA)))

    def test_persist_false_in_same_step(self):
        text = job("      - uses: actions/checkout@%s\n        with:\n          persist-credentials: false" % SHA)
        self.assertNotIn("checkout-keeps-token", rules(text))

    def test_persist_false_in_other_step_does_not_count(self):
        text = job("      - uses: actions/checkout@%s\n      - uses: other/thing@%s\n        with:\n          persist-credentials: false" % (SHA, SHA))
        self.assertIn("checkout-keeps-token", rules(text))

    def test_checkout_not_first_key(self):
        text = job("      - name: Get code\n        uses: actions/checkout@%s" % SHA)
        self.assertIn("checkout-keeps-token", rules(text))

    def test_two_checkouts(self):
        text = job("      - uses: actions/checkout@%s\n      - uses: actions/checkout@%s" % (SHA, SHA))
        found = [f for f in check(text) if f["rule"] == "checkout-keeps-token"]
        self.assertEqual(len(found), 2)


class OutputTests(unittest.TestCase):
    def test_sorted_high_first(self):
        order = [wc.SEVERITIES[f["severity"]] for f in check("permissions: write-all\non: [push]\n")]
        self.assertEqual(order, sorted(order, reverse=True))

    def test_filter(self):
        high = wc.filter_findings(check("permissions: write-all\n"), "high")
        self.assertTrue(all(f["severity"] == "high" for f in high))

    def test_text_and_json(self):
        results = [("w.yml", check("permissions: write-all\n"))]
        self.assertIn("permissions-write-all", wc.format_text(results))
        self.assertEqual(json.loads(wc.format_json(results))[0]["file"], "w.yml")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, content):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def binary(self):
        path = os.path.join(self.dir.name, "bin.yml")
        with open(path, "wb") as handle:
            handle.write(b"\xff\xfe\x00\x80")
        return path

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = wc.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_0(self):
        code, out, _ = self.run_cli(self.write("a.yml", CLEAN))
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_high_exit_1(self):
        self.assertEqual(self.run_cli(self.write("a.yml", "permissions: write-all\n"))[0], 1)

    def test_fail_on(self):
        path = self.write("a.yml", CLEAN.replace("@" + SHA, "@v4"))
        self.assertEqual(self.run_cli(path)[0], 0)
        self.assertEqual(self.run_cli(path, "--fail-on", "low")[0], 1)

    def test_min_severity(self):
        path = self.write("a.yml", CLEAN.replace("@" + SHA, "@v4"))
        _, out, _ = self.run_cli(path, "--min-severity", "medium")
        self.assertNotIn("action-not-pinned", out)

    def test_json(self):
        path = self.write("a.yml", "permissions: write-all\n")
        _, out, _ = self.run_cli(path, "--format", "json")
        self.assertEqual(json.loads(out)[0]["findings"][0]["rule"], "permissions-write-all")

    def test_missing_file(self):
        code, _, err = self.run_cli(os.path.join(self.dir.name, "none.yml"))
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_binary_file(self):
        code, _, err = self.run_cli(self.binary())
        self.assertEqual(code, 2)
        self.assertIn("not a text file", err)

    def test_empty_file(self):
        code, out, err = self.run_cli(self.write("e.yml", "# nothing\n"))
        self.assertEqual(code, 0)
        self.assertIn("is empty", err)

    def test_several_files(self):
        a = self.write("a.yml", CLEAN)
        b = self.write("b.yml", "permissions: write-all\n")
        code, out, _ = self.run_cli(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(out.count("finding(s)"), 2)


class SampleTests(unittest.TestCase):
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_workflows")

    def findings(self, name):
        return wc.check_workflow(wc.load_workflow(os.path.join(self.base, name)))

    def test_risky(self):
        found = self.findings("01_risky.yml")
        self.assertEqual(len(found), 11)
        self.assertEqual(sum(f["severity"] == "high" for f in found), 5)

    def test_okay_with_gaps(self):
        found = self.findings("02_okay_with_gaps.yml")
        self.assertEqual(sorted(f["rule"] for f in found),
                         ["action-not-pinned", "action-not-pinned", "checkout-keeps-token", "no-permissions"])

    def test_hardened(self):
        self.assertEqual(self.findings("03_hardened.yml"), [])


if __name__ == "__main__":
    unittest.main()
