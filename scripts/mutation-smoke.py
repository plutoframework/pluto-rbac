#!/usr/bin/env python3
"""Bounded policy mutations in disposable copies; no comprehensive coverage claim."""
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
MUTATIONS = [
    (
        "unknown assigned role accepted",
        "policy.go",
        "if _, exists := p.roles[role]; !exists {",
        "if _, exists := p.roles[role]; false && !exists {",
        "TestPolicyDecisions",
    ),
    (
        "permission grant ignored",
        "policy.go",
        "if _, granted := p.grants[role][permission]; granted {",
        "if _, granted := p.grants[role][permission]; granted || len(roles) > 0 {",
        "TestPolicyDecisions",
    ),
    (
        "inheritance cycle accepted",
        "hierarchy.go",
        "if len(ready) != len(p.roles) {",
        "if false && len(ready) != len(p.roles) {",
        "TestInvalidDefinitions",
    ),
    (
        "tenant removed from resolution key",
        "static.go",
        "roles := s.assignments[assignmentKey{subjectID, scope}]",
        "roles := s.assignments[assignmentKey{subjectID, Scope{}}]",
        "TestTenantIsolation",
    ),
    (
        "resolver error ignored",
        "authorizer.go",
        'if err != nil {\n\t\treturn fmt.Errorf("%w: %w", ErrResolveRoles, err)',
        'if false && err != nil {\n\t\treturn fmt.Errorf("%w: %w", ErrResolveRoles, err)',
        "TestResolverFailures",
    ),
    (
        "assignment input alias retained",
        "static.go",
        "resolver.assignments[key] = slices.Clone(assignment.Roles)",
        "resolver.assignments[key] = assignment.Roles",
        "TestStaticResolverCopies",
    ),
]


def execute(args, cwd, timeout):
    return subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, timeout=timeout,
    )


def main():
    baseline = execute(["go", "test", "./..."], ROOT, 60)
    if baseline.returncode:
        raise SystemExit(baseline.stdout + baseline.stderr)

    counts = dict.fromkeys(["killed", "survived", "invalid", "timed-out"], 0)
    for name, filename, before, after, test in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="pluto-rbac-mutation-") as temporary:
            checkout = Path(temporary) / "library"
            shutil.copytree(
                ROOT, checkout,
                ignore=shutil.ignore_patterns(".git", "bin", "*.test", "coverage.*"),
            )
            path = checkout / filename
            content = path.read_text()
            if content.count(before) != 1:
                raise SystemExit(f"Mutation target drifted: {name}")
            path.write_text(content.replace(before, after, 1))
            output = ""
            try:
                binary = Path(temporary) / "mutant.test"
                built = execute(
                    ["go", "test", "-c", "-o", str(binary), "."], checkout, 60,
                )
                if built.returncode:
                    outcome = "invalid"
                    output = built.stdout + built.stderr
                else:
                    run = execute(
                        [str(binary), "-test.run", f"^{test}$", "-test.timeout", "15s"],
                        checkout, 20,
                    )
                    output = run.stdout + run.stderr
                    if "test timed out" in output:
                        outcome = "timed-out"
                    elif run.returncode:
                        outcome = "killed"
                    else:
                        outcome = "survived"
            except subprocess.TimeoutExpired:
                outcome = "timed-out"
            counts[outcome] += 1
            print(f"{outcome}: {name}", flush=True)
            if outcome != "killed":
                print(output, flush=True)

    print(counts)
    raise SystemExit(0 if counts["killed"] == len(MUTATIONS) else 1)


if __name__ == "__main__":
    main()
