#!/usr/bin/env python3
"""GitHub Actions workflow checker.

Reads workflow files (.yml / .yaml) and flags risky settings. It reads the
text line by line and never runs anything or contacts GitHub.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = bad input.
"""
import argparse
import json
import re
import sys

SEVERITIES = {"low": 1, "medium": 2, "high": 3}

BRANCH_REFS = {"main", "master", "latest", "develop", "dev", "head", "trunk"}
SHA = re.compile(r"^[0-9a-f]{40}$", re.I)
RUN_KEY = re.compile(r"^(\s*)(-\s+)?run:\s*(.*?)\s*$")
BLOCK_SCALAR = re.compile(r"^[|>][+-]?\d*\s*(#.*)?$")
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^\s'\"#]+)")
CURL_PIPE = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I)
EVENT_TEXT = re.compile(
    r"\$\{\{[^}]*(github\.head_ref"
    r"|github\.event\.(issue|pull_request|comment|review|review_comment|discussion|pages|commits|head_commit)"
    r"[^}]*\b(title|body|name|label|ref|message|email|login|page_name)\b)[^}]*\}\}", re.I)
INPUTS = re.compile(r"\$\{\{[^}]*\b(github\.event\.inputs\.|inputs\.)[^}]*\}\}", re.I)
SECRET_REF = re.compile(r"\$\{\{\s*secrets\.", re.I)


class WorkflowError(Exception):
    """Raised when a workflow file cannot be used."""


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def load_workflow(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        raise WorkflowError("file not found: %s" % path)
    except UnicodeDecodeError:
        raise WorkflowError("not a text file: %s" % path)
    except OSError as exc:
        raise WorkflowError("cannot read %s: %s" % (path, exc.strerror))


def _finding(rule, severity, line, message, fix):
    return {"rule": rule, "severity": severity, "line": line, "message": message, "fix": fix}


def run_lines(lines):
    """Return a dict {line_number: text} for every line that is shell code
    inside a `run:` key (inline or block)."""
    found = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        match = RUN_KEY.match(line)
        if match and not line.lstrip().startswith("#"):
            key_indent = len(match.group(1)) + (len(match.group(2)) if match.group(2) else 0)
            value = match.group(3)
            if value and not BLOCK_SCALAR.match(value):
                found[i + 1] = value
            elif BLOCK_SCALAR.match(value):
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or indent_of(lines[j]) > key_indent):
                    if lines[j].strip() and not lines[j].lstrip().startswith("#"):
                        found[j + 1] = lines[j].strip()
                    j += 1
                i = j
                continue
        i += 1
    return found


def step_range(lines, uses_index):
    """Return (start, end) indexes of the step that holds line uses_index."""
    line = lines[uses_index]
    dash = re.match(r"^(\s*)-\s+", line)
    if dash:
        start, dash_indent = uses_index, len(dash.group(1))
    else:
        start, dash_indent = uses_index, indent_of(line) - 2
        for k in range(uses_index - 1, -1, -1):
            m = re.match(r"^(\s*)-\s", lines[k])
            if m and len(m.group(1)) < indent_of(line):
                start, dash_indent = k, len(m.group(1))
                break
    end = len(lines)
    for k in range(start + 1, len(lines)):
        text = lines[k]
        if text.strip() and not text.lstrip().startswith("#") and indent_of(text) <= dash_indent:
            end = k
            break
    return start, end


def check_workflow(lines):
    findings = []
    code = run_lines(lines)
    live = [(n + 1, t) for n, t in enumerate(lines) if t.strip() and not t.lstrip().startswith("#")]
    text_all = "\n".join(t for _, t in live)

    has_permissions = any(re.match(r"^\s*permissions\s*:", t) for _, t in live)
    if not has_permissions:
        findings.append(_finding(
            "no-permissions", "medium", 1,
            "No permissions block, so the token may have wider access than needed.",
            "Add permissions: contents: read at the top, then widen only where needed."))

    target_line = None
    for number, text in live:
        if re.search(r"\bpull_request_target\b", text):
            target_line = target_line or number
            findings.append(_finding(
                "pull-request-target", "medium", number,
                "Runs with repository secrets on pull requests, including from forks.",
                "Use pull_request unless you really need secrets, and never run PR code here."))
            break

    for number, text in live:
        if re.match(r"^\s*permissions\s*:\s*write-all\b", text):
            findings.append(_finding(
                "permissions-write-all", "high", number,
                "The token gets write access to everything.",
                "Grant only the scopes the job needs, such as contents: read."))
        if re.match(r"^\s*runs-on\s*:.*self-hosted", text):
            findings.append(_finding(
                "self-hosted-runner", "medium", number,
                "Runs on a self-hosted machine.",
                "Do not use self-hosted runners for public repos or untrusted code."))
        if target_line and "github.event.pull_request.head" in text:
            findings.append(_finding(
                "pr-target-checkout", "high", number,
                "Checks out code from the pull request while running with secrets.",
                "Never check out PR code in a pull_request_target workflow."))

        match = USES.match(text)
        if match:
            spec = match.group(1)
            if spec.startswith("./"):
                continue
            if spec.startswith("docker://"):
                if "@sha256:" not in spec:
                    findings.append(_finding(
                        "action-not-pinned", "low", number,
                        "Docker image %s is not pinned to a digest." % spec,
                        "Pin it with @sha256:<digest>."))
                continue
            if "@" in spec:
                name, ref = spec.rsplit("@", 1)
                if SHA.match(ref):
                    continue
                if ref.lower() in BRANCH_REFS:
                    findings.append(_finding(
                        "action-branch-ref", "high", number,
                        "%s follows the branch '%s', so it can change under you." % (name, ref),
                        "Pin to a full commit SHA."))
                else:
                    findings.append(_finding(
                        "action-not-pinned", "low", number,
                        "%s uses the tag '%s', which can be moved." % (name, ref),
                        "Pin to a full commit SHA for important workflows."))

    for number, text in sorted(code.items()):
        if EVENT_TEXT.search(text):
            findings.append(_finding(
                "script-injection", "high", number,
                "Text from an issue, comment or branch name is pasted into a shell command.",
                "Pass it through env: and read it as a shell variable instead."))
        if INPUTS.search(text):
            findings.append(_finding(
                "input-in-run", "medium", number,
                "A workflow input is pasted into a shell command.",
                "Pass it through env: and read it as a shell variable instead."))
        if SECRET_REF.search(text):
            findings.append(_finding(
                "secret-in-run", "medium", number,
                "A secret is written directly in a command.",
                "Put it in env: for that step and read the variable."))
        if CURL_PIPE.search(text):
            findings.append(_finding(
                "curl-pipe-shell", "high", number,
                "Downloads a script and runs it straight away.",
                "Download it, check its checksum, then run it."))

    for index, line in enumerate(lines):
        match = re.match(r"^\s*(?:-\s+)?uses:\s*['\"]?actions/checkout@", line)
        if match and not line.lstrip().startswith("#"):
            start, end = step_range(lines, index)
            block = "\n".join(lines[start:end])
            if not re.search(r"persist-credentials\s*:\s*['\"]?false", block):
                findings.append(_finding(
                    "checkout-keeps-token", "low", index + 1,
                    "The checkout step leaves the token in the local git config.",
                    "Add persist-credentials: false under with:."))

    findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["line"], f["rule"]))
    return findings


def filter_findings(findings, min_severity):
    floor = SEVERITIES[min_severity]
    return [f for f in findings if SEVERITIES[f["severity"]] >= floor]


def format_text(results):
    out = []
    for name, findings in results:
        out.append("%s: %d finding(s)" % (name, len(findings)))
        for f in findings:
            out.append("  [%s] line %d  %s: %s" % (f["severity"].upper(), f["line"], f["rule"], f["message"]))
            out.append("      Fix: %s" % f["fix"])
        if not findings:
            out.append("  No findings.")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def format_json(results):
    return json.dumps([{"file": n, "findings": f} for n, f in results], indent=2) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(description="Check GitHub Actions workflow files for risky settings.")
    parser.add_argument("files", nargs="+", help="workflow file(s)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--min-severity", choices=tuple(SEVERITIES), default="low",
                        help="hide findings below this level")
    parser.add_argument("--fail-on", choices=tuple(SEVERITIES), default="high",
                        help="exit 1 if any finding is at or above this level")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    results = []
    worst = 0
    for path in args.files:
        try:
            lines = load_workflow(path)
        except WorkflowError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        if not any(t.strip() and not t.lstrip().startswith("#") for t in lines):
            print("note: %s is empty." % path, file=sys.stderr)
            results.append((path, []))
            continue
        findings = check_workflow(lines)
        for f in findings:
            worst = max(worst, SEVERITIES[f["severity"]])
        results.append((path, filter_findings(findings, args.min_severity)))
    output = format_json(results) if args.format == "json" else format_text(results)
    sys.stdout.write(output)
    return 1 if worst >= SEVERITIES[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
