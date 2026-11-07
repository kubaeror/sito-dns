#!/usr/bin/env python3
"""Estimate GitHub Actions runner minutes per workflow and per job.

The script is dependency-free: it uses only the Python standard library and the
authenticated ``gh`` CLI. It lists workflow runs created since ``--since``,
fetches the jobs for each run, and derives execution time from each job's
``started_at`` and ``completed_at`` timestamps. Every job is rounded up to a
full minute (minimum one minute for a job that ran), matching GitHub's
per-job billing model. Jobs without both timestamps are reported as missing and
excluded from the totals.

Examples:
  python3 scripts/ci_usage.py
  python3 scripts/ci_usage.py --repo kubaeror/sito-dns --since 30d
  python3 scripts/ci_usage.py --since 2026-10-01 --json > ci-usage.json

Requires an authenticated gh CLI (``gh auth login``) or a ``GH_TOKEN`` with
``actions:read`` access to the repository. The report covers job execution time
only: queue latency, cache/artifact storage, and per-OS billing multipliers are
outside its scope.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import subprocess
import sys
from typing import Any

UTC = dt.timezone.utc
PER_PAGE = 100
MAX_PAGES = 200
DEFAULT_SINCE = "30d"
DEFAULT_TIMEOUT = 120

_RELATIVE_SINCE = re.compile(r"^(\d+)([dwm])$", re.IGNORECASE)
_REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class UsageError(Exception):
    """A user-facing error (bad argument, missing gh, API failure)."""


def parse_timestamp(value: Any) -> dt.datetime | None:
    """Parse a GitHub timestamp, returning an aware UTC datetime or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_since(value: str, now: dt.datetime | None = None) -> dt.datetime:
    """Resolve a relative span or ISO date/timestamp into an aware datetime."""
    now = now or dt.datetime.now(UTC)
    text = value.strip()
    match = _RELATIVE_SINCE.fullmatch(text)
    if match:
        amount = int(match.group(1))
        if amount <= 0:
            raise UsageError("--since must be greater than zero")
        days = amount * {"d": 1, "w": 7, "m": 30}[match.group(2).lower()]
        return now - dt.timedelta(days=days)

    if len(text) == 10:
        try:
            date = dt.date.fromisoformat(text)
        except ValueError as exc:
            raise UsageError(
                f"invalid --since {value!r}: use an ISO date (2026-10-01), "
                "an ISO timestamp, or a span such as 30d, 2w, 6m"
            ) from exc
        return dt.datetime.combine(date, dt.time.min, tzinfo=UTC)

    parsed = parse_timestamp(text)
    if parsed is None:
        raise UsageError(
            f"invalid --since {value!r}: use an ISO date (2026-10-01), "
            "an ISO timestamp, or a span such as 30d, 2w, 6m"
        )
    return parsed


def _run_gh(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["gh", *args],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise UsageError(
            "the gh CLI was not found; install it from https://cli.github.com/ "
            "and authenticate with `gh auth login`"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise UsageError(f"gh {' '.join(args)} timed out") from exc


def gh_api(path: str) -> dict[str, Any]:
    """Call `gh api` and decode the JSON object it prints."""
    proc = _run_gh(
        [
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            path,
        ]
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if not detail:
            detail = f"exit status {proc.returncode}"
        raise UsageError(f"gh api {path} failed: {detail}")
    output = proc.stdout.strip()
    if not output:
        return {}
    try:
        decoded = json.loads(output)
    except json.JSONDecodeError as exc:
        raise UsageError(f"gh api {path} returned invalid JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise UsageError(f"gh api {path} returned an unexpected JSON shape")
    return decoded


def resolve_repo(repo: str | None) -> str:
    """Resolve --repo, GITHUB_REPOSITORY, or the current gh repository."""
    candidate = repo or os.environ.get("GITHUB_REPOSITORY", "")
    if candidate:
        if not _REPO_SLUG.fullmatch(candidate):
            raise UsageError(
                f"invalid repository {candidate!r}; expected OWNER/REPO"
            )
        return candidate

    proc = _run_gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"])
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise UsageError(
            "could not infer the repository; pass --repo OWNER/REPO "
            f"(gh repo view failed: {detail or 'unknown error'})"
        )
    inferred = proc.stdout.strip()
    if not _REPO_SLUG.fullmatch(inferred):
        raise UsageError(
            f"could not infer the repository; pass --repo OWNER/REPO (got {inferred!r})"
        )
    return inferred


def iter_runs(repo: str, since: dt.datetime) -> list[dict[str, Any]]:
    """Return workflow runs created at or after ``since``.

    The runs endpoint is ordered newest-first. Stop at the first run older than
    the window instead of using a server-side filter, so the behaviour does not
    depend on the API's date-query syntax.
    """
    selected: list[dict[str, Any]] = []
    page = 1
    while page <= MAX_PAGES:
        data = gh_api(
            f"repos/{repo}/actions/runs?per_page={PER_PAGE}&page={page}"
        )
        runs = data.get("workflow_runs")
        if not isinstance(runs, list) or not runs:
            return selected

        reached_older = False
        for run in runs:
            if not isinstance(run, dict):
                continue
            created = parse_timestamp(run.get("created_at"))
            if created is not None and created < since:
                reached_older = True
                break
            selected.append(run)

        if reached_older or len(runs) < PER_PAGE:
            return selected
        page += 1

    print(
        f"ci_usage: warning: stopped after {MAX_PAGES} pages of runs; "
        "the window is larger than this script handles in one pass",
        file=sys.stderr,
    )
    return selected


def fetch_jobs(repo: str, run_id: Any) -> list[dict[str, Any]]:
    """Fetch every job of a workflow run (paged)."""
    jobs: list[dict[str, Any]] = []
    page = 1
    while page <= MAX_PAGES:
        data = gh_api(
            f"repos/{repo}/actions/runs/{run_id}/jobs"
            f"?per_page={PER_PAGE}&page={page}"
        )
        batch = data.get("jobs")
        if not isinstance(batch, list) or not batch:
            break
        jobs.extend(job for job in batch if isinstance(job, dict))
        total = data.get("total_count")
        if (
            len(batch) < PER_PAGE
            or (isinstance(total, int) and len(jobs) >= total)
        ):
            break
        page += 1
    return jobs


def measure(repo: str, since: dt.datetime) -> dict[str, Any]:
    """Aggregate rounded job minutes by workflow and by job name."""
    workflows: dict[str, dict[str, Any]] = {}
    jobs: dict[tuple[str, str], dict[str, Any]] = {}
    runs_scanned = 0
    jobs_seen = 0
    jobs_counted = 0
    missing_timestamps = 0
    invalid_timestamps = 0

    for run in iter_runs(repo, since):
        runs_scanned += 1
        run_name = str(run.get("name") or "unknown").strip() or "unknown"

        run_id = run.get("id")
        run_jobs = fetch_jobs(repo, run_id) if run_id is not None else []

        workflow_name = run_name
        if run_jobs:
            workflow_name = (
                str(run_jobs[0].get("workflow_name") or run_name).strip()
                or run_name
            )

        workflow = workflows.setdefault(
            workflow_name,
            {"name": workflow_name, "runs": 0, "jobs": 0, "minutes": 0},
        )
        workflow["runs"] += 1

        for job in run_jobs:
            jobs_seen += 1
            started = parse_timestamp(job.get("started_at"))
            completed = parse_timestamp(job.get("completed_at"))
            if started is None or completed is None:
                missing_timestamps += 1
                continue

            seconds = (completed - started).total_seconds()
            if seconds < 0:
                invalid_timestamps += 1
                continue

            minutes = max(1, math.ceil(seconds / 60))
            job_name = str(job.get("name") or "unknown").strip() or "unknown"

            job = jobs.setdefault(
                (workflow_name, job_name),
                {
                    "workflow": workflow_name,
                    "name": job_name,
                    "runs": 0,
                    "minutes": 0,
                },
            )
            job["runs"] += 1
            job["minutes"] += minutes
            workflow["jobs"] += 1
            workflow["minutes"] += minutes
            jobs_counted += 1

    workflow_rows = sorted(
        workflows.values(),
        key=lambda row: (-row["minutes"], row["name"]),
    )
    job_rows = sorted(
        jobs.values(),
        key=lambda row: (-row["minutes"], row["workflow"], row["name"]),
    )
    total_minutes = sum(row["minutes"] for row in workflow_rows)

    return {
        "repo": repo,
        "since": since,
        "runs_scanned": runs_scanned,
        "jobs_seen": jobs_seen,
        "jobs_counted": jobs_counted,
        "jobs_missing_timestamps": missing_timestamps,
        "jobs_invalid_timestamps": invalid_timestamps,
        "total_minutes": total_minutes,
        "workflows": workflow_rows,
        "jobs": job_rows,
    }


def _print_table(
    headers: list[str],
    rows: list[list[str]],
    right_aligned: set[int],
) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def render(cells: list[str]) -> str:
        parts = []
        for index, cell in enumerate(cells):
            if index in right_aligned:
                parts.append(cell.rjust(widths[index]))
            else:
                parts.append(cell.ljust(widths[index]))
        return "  ".join(parts).rstrip()

    print(render(headers))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print(render(row))


def _format_utc(value: dt.datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def print_report(result: dict[str, Any]) -> None:
    print(f"GitHub Actions usage for {result['repo']}")
    print(f"Window: runs created since {_format_utc(result['since'])}")
    print(
        f"Runs scanned: {result['runs_scanned']}   "
        f"Jobs counted: {result['jobs_counted']}   "
        f"Missing timestamps: {result['jobs_missing_timestamps']}"
    )
    if result["jobs_invalid_timestamps"]:
        print(
            "Invalid timestamps: "
            f"{result['jobs_invalid_timestamps']} (completed before started)"
        )
    print()

    if result["workflows"]:
        print("Per workflow")
        _print_table(
            ["Workflow", "Runs", "Jobs", "Minutes"],
            [
                [
                    row["name"],
                    str(row["runs"]),
                    str(row["jobs"]),
                    str(row["minutes"]),
                ]
                for row in result["workflows"]
            ],
            right_aligned={1, 2, 3},
        )
    else:
        print("No workflow runs found in the window.")

    print()
    if result["jobs"]:
        print("Per job")
        _print_table(
            ["Workflow", "Job", "Runs", "Minutes"],
            [
                [
                    row["workflow"],
                    row["name"],
                    str(row["runs"]),
                    str(row["minutes"]),
                ]
                for row in result["jobs"]
            ],
            right_aligned={2, 3},
        )
    else:
        print("No completed jobs found in the window.")

    print()
    print(
        f"Total: {result['total_minutes']} minutes "
        "(each job rounded up to a full minute)"
    )


def to_json(result: dict[str, Any]) -> str:
    payload = {
        "repo": result["repo"],
        "since": _format_utc(result["since"]),
        "generated_at": _format_utc(dt.datetime.now(UTC)),
        "runs_scanned": result["runs_scanned"],
        "jobs_seen": result["jobs_seen"],
        "jobs_counted": result["jobs_counted"],
        "jobs_missing_timestamps": result["jobs_missing_timestamps"],
        "jobs_invalid_timestamps": result["jobs_invalid_timestamps"],
        "total_minutes": result["total_minutes"],
        "workflows": [
            {
                "name": row["name"],
                "runs": row["runs"],
                "jobs": row["jobs"],
                "minutes": row["minutes"],
            }
            for row in result["workflows"]
        ],
        "jobs": [
            {
                "workflow": row["workflow"],
                "name": row["name"],
                "runs": row["runs"],
                "minutes": row["minutes"],
            }
            for row in result["jobs"]
        ],
    }
    return json.dumps(payload, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ci_usage.py",
        description=(
            "Estimate GitHub Actions runner minutes per workflow and job.\n\n"
            "Runs are read with `gh api` for the requested window. Each job's\n"
            "started_at/completed_at interval is rounded up to a full minute\n"
            "(minimum one), then summed per workflow and per job name. Jobs\n"
            "without both timestamps are reported separately and excluded.\n\n"
            "Requires an authenticated gh CLI: `gh auth login` or GH_TOKEN."
        ),
        epilog=(
            "examples:\n"
            "  python3 scripts/ci_usage.py\n"
            "  python3 scripts/ci_usage.py --repo kubaeror/sito-dns --since 30d\n"
            "  python3 scripts/ci_usage.py --since 2026-10-01\n"
            "  python3 scripts/ci_usage.py --since 2w --json > ci-usage.json\n\n"
            "--since accepts Nd (days), Nw (weeks), Nm (30-day months), an ISO\n"
            "date (2026-10-01), or an ISO timestamp. The default is 30d.\n\n"
            "The result covers job execution time only; queue latency, storage,\n"
            "and per-OS billing multipliers are not included."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--repo",
        metavar="OWNER/REPO",
        help=(
            "repository to measure (default: $GITHUB_REPOSITORY, then "
            "`gh repo view` for the current checkout)"
        ),
    )
    parser.add_argument(
        "--since",
        default=DEFAULT_SINCE,
        metavar="WINDOW",
        help=(
            "start of the window as Nd/Nw/Nm, an ISO date, or an ISO "
            f"timestamp (default: {DEFAULT_SINCE})"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a JSON object instead of the text tables",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        repo = resolve_repo(args.repo)
        now = dt.datetime.now(UTC)
        since = parse_since(args.since, now=now)
        if since > now:
            raise UsageError(
                f"--since resolves to {_format_utc(since)}, which is in the future"
            )
        result = measure(repo, since)
    except UsageError as exc:
        print(f"ci_usage: error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(to_json(result))
    else:
        print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
