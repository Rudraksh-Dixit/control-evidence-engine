from __future__ import annotations

import argparse
import os
import subprocess
import sys
import webbrowser
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cee import __version__
from cee.attest import add_attestation, default_attester, load_registry
from cee.catalog import DEFAULT_FRAMEWORK, load_framework
from cee.config import DEFAULT_RUNS_DIR, load_config
from cee.engine import list_runs, load_run, run_assessment
from cee.evidence import verify_run
from cee.models import THEME_LABELS
from cee.report import load_run_for_report, write_reports

console = Console()

STATUS_STYLE = {
    "compliant": "green",
    "partial": "yellow",
    "non_compliant": "red",
    "manual": "bright_black",
    "attested": "cyan",
    "not_applicable": "bright_black",
    "error": "magenta",
    "pass": "green",
    "fail": "red",
}
SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "red",
    "medium": "yellow",
    "low": "bright_black",
    "info": "cyan",
}
THEME_SHORT = {
    "organizational": "Org",
    "people": "People",
    "physical": "Physical",
    "technological": "Tech",
}


def _status(value: str) -> Text:
    return Text(value.replace("_", " ").upper(), style=STATUS_STYLE.get(value, "white"))


def _runs_dir(args: argparse.Namespace) -> Path:
    return Path(args.runs_dir) if getattr(args, "runs_dir", None) else DEFAULT_RUNS_DIR


def _resolve_run(args: argparse.Namespace) -> Path:
    base = _runs_dir(args)
    run_id = getattr(args, "run", "latest")
    if not run_id or run_id == "latest":
        runs = list_runs(base)
        if not runs:
            raise FileNotFoundError(f"No assessment runs found in {base}. Run `python -m cee assess --demo` first.")
        return Path(runs[0]["path"])
    path = base / run_id
    if not (path / "run.json").exists():
        raise FileNotFoundError(f"Run not found: {path}")
    return path


def _print_summary(run) -> None:
    summary = run.summary
    score = f"{summary['score']:.1f}%" if summary.get("score") is not None else "n/a"
    lines = [
        f"[bold]Assurance score:[/bold] {score} [bright_black]({summary['assurance_band']})[/bright_black]",
        f"[bold]Controls assessed:[/bold] {summary['controls_assessed']}/{summary['controls_total']}  "
        f"[bold]Automated:[/bold] {summary['automated_controls']}  "
        f"[bold]Manual pending:[/bold] {summary['manual_pending']}  "
        f"[bold]Attested:[/bold] {summary['attested_controls']}",
        f"[bold]Checks:[/bold] {summary['checks']['pass']} passed, {summary['checks']['partial']} partial, "
        f"{summary['checks']['fail']} failed, {summary['checks']['error']} errored  "
        f"[bold]Evidence:[/bold] {summary['evidence_count']} artifacts  "
        f"[bold]Findings:[/bold] {summary['findings_total']}",
    ]
    console.print(Panel("\n".join(lines), title=f"CEE {__version__} - {run.framework_name}", expand=False))

    theme_table = Table(title="Coverage by theme", show_header=True, header_style="bold")
    theme_table.add_column("Theme")
    theme_table.add_column("Assessed", justify="right")
    theme_table.add_column("Score", justify="right")
    theme_table.add_column("Pass", justify="right", style="green")
    theme_table.add_column("Partial", justify="right", style="yellow")
    theme_table.add_column("Fail", justify="right", style="red")
    theme_table.add_column("Manual", justify="right", style="bright_black")
    for theme in summary["themes"]:
        theme_table.add_row(
            THEME_LABELS[theme["theme"]].replace(" (", "\n("),
            f"{theme['assessed']}/{theme['total']}",
            f"{theme['score']:.0f}%" if theme["score"] is not None else "-",
            str(theme["counts"]["compliant"]),
            str(theme["counts"]["partial"]),
            str(theme["counts"]["non_compliant"]),
            str(theme["counts"]["manual"]),
        )
    console.print(theme_table)

    if run.findings:
        findings = Table(title="Open findings", header_style="bold")
        findings.add_column("ID", style="bright_black")
        findings.add_column("Severity")
        findings.add_column("Control", style="bright_black")
        findings.add_column("Finding")
        for finding in run.findings[:10]:
            findings.add_row(
                finding["id"],
                Text(finding["severity"].upper(), style=SEVERITY_STYLE.get(finding["severity"], "white")),
                ", ".join(finding["controls"]),
                finding["title"],
            )
        console.print(findings)
        if len(run.findings) > 10:
            console.print(f"[bright_black]... {len(run.findings) - 10} more findings in the report.[/bright_black]")


def cmd_assess(args: argparse.Namespace) -> int:
    mode = "live" if args.live else "demo"
    config_path = Path(args.config) if args.config else None
    if mode == "live":
        if config_path is None:
            config_path = Path("cee.yaml")
        if not config_path.exists():
            console.print(
                "[red]Live assessment needs a configuration file.[/red] "
                "Copy `cee.example.yaml` to `cee.yaml`, fill in the systems you can access, then re-run."
            )
            return 2
    config = load_config(config_path)
    runs_dir = _runs_dir(args)

    with console.status(f"Running {mode} assessment..."):
        run = run_assessment(
            mode=mode,
            config=config,
            framework_id=args.framework,
            runs_dir=runs_dir,
        )

    _print_summary(run)
    run_dir = runs_dir / run.run_id
    console.print()
    console.print(f"[bold]HTML report:[/bold] {run_dir / 'report.html'}")
    console.print(f"[bold]Markdown report:[/bold] {run_dir / 'report.md'}")
    console.print(f"[bold]Audit bundle:[/bold] {run_dir / 'audit-bundle.zip'}")
    console.print(f"[bold]Verify evidence:[/bold] python -m cee verify --run {run.run_id}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    run_dir = _resolve_run(args)
    run = load_run_for_report(run_dir)
    config = load_config(Path(args.config) if args.config else None)
    if args.format == "html":
        html = write_reports(run_dir, run, config)["html"]
        console.print(f"[green]Wrote[/green] {html}")
        if args.open:
            webbrowser.open(html.resolve().as_uri())
        return 0
    if args.format == "md":
        md = write_reports(run_dir, run, config)["md"]
        console.print(f"[green]Wrote[/green] {md}")
        if args.open:
            webbrowser.open(md.resolve().as_uri())
        return 0
    paths = write_reports(run_dir, run, config)
    console.print(f"[green]Wrote[/green] {paths['html']}")
    console.print(f"[green]Wrote[/green] {paths['md']}")
    if args.open:
        webbrowser.open(paths["html"].resolve().as_uri())
    return 0


def cmd_controls(args: argparse.Namespace) -> int:
    framework = load_framework(args.framework)
    status_by_id = {}
    if args.run:
        run = load_run(_resolve_run(args))
        status_by_id = {control["control_id"]: control["status"] for control in run["controls"]}
    table = Table(title=f"{framework.name} ({len(framework.controls)} controls)", header_style="bold")
    table.add_column("ID", style="bright_black")
    table.add_column("Theme")
    table.add_column("Control")
    table.add_column("Evidence", justify="center")
    if args.run:
        table.add_column("Latest status")
    for control in framework.controls:
        if args.theme and control.theme != args.theme:
            continue
        row = [
            control.id,
            THEME_SHORT[control.theme],
            control.title,
            Text("AUTO", style="cyan") if control.automated else Text("manual", style="bright_black"),
        ]
        if args.run:
            status = status_by_id.get(control.id, "manual")
            row.append(_status(status))
        table.add_row(*row)
    console.print(table)
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config) if args.config else None)
    registry = Path(config["manual"]["registry"])
    if args.list:
        grouped = load_registry(registry)
        table = Table(title=f"Manual evidence registry: {registry}", header_style="bold")
        table.add_column("Control")
        table.add_column("File")
        table.add_column("Attested by")
        table.add_column("Date")
        table.add_column("Integrity")
        count = 0
        for control_id, entries in sorted(grouped.items()):
            for entry in entries:
                count += 1
                table.add_row(
                    control_id,
                    Path(str(entry.get("file", ""))).name,
                    entry.get("attested_by", ""),
                    entry.get("attested_at", ""),
                    Text("VERIFIED", style="green") if entry.get("valid") else Text("MISMATCH", style="red"),
                )
        console.print(table)
        if not count:
            console.print("[bright_black]No attestations registered yet.[/bright_black]")
        return 0

    if not args.control or not args.file:
        console.print("[red]--control and --file are required (or use --list).[/red]")
        return 2
    framework = load_framework(args.framework)
    valid_ids = {control.id for control in framework.controls}
    if args.control not in valid_ids:
        console.print(f"[red]Unknown control {args.control}.[/red] Valid examples: A.5.1, A.8.15")
        return 2
    entry = add_attestation(
        registry_path=registry,
        control_id=args.control,
        source_file=Path(args.file),
        note=args.note or "Manual evidence provided.",
        attested_by=args.by or default_attester(),
        framework_id=framework.id,
    )
    console.print(
        f"[green]Attested[/green] {args.control} with {entry['file']} "
        f"(sha256 {entry['sha256'][:16]}...)"
    )
    console.print("Run a new assessment to include this evidence: [bold]python -m cee assess --live[/bold]")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    run_dir = _resolve_run(args)
    console.print(f"Verifying evidence integrity in [bold]{run_dir}[/bold]")
    results = verify_run(run_dir)
    failed = [row for row in results if not row["ok"]]
    table = Table(title=f"Evidence integrity ({len(results)} artifacts)", header_style="bold")
    table.add_column("Result", width=12)
    table.add_column("Check")
    table.add_column("Evidence", overflow="fold")
    for row in results:
        kind = "manual" if row.get("kind") == "manual" else "check"
        table.add_row(
            Text("OK", style="green") if row["ok"] else Text("MISMATCH", style="red"),
            Text(row["check_id"] or "-", overflow="fold"),
            Text(f"{row['title']} ({kind})", overflow="fold"),
        )
    console.print(table)
    for row in failed:
        console.print(f"[red]Failed:[/red] {row['artifact'] or row['title']}")

    config = load_config(Path(args.config) if args.config else None)
    registry = Path(config["manual"]["registry"])
    manual_failed = 0
    if registry.exists():
        grouped = load_registry(registry)
        for control_id, entries in sorted(grouped.items()):
            for entry in entries:
                if not entry.get("valid"):
                    manual_failed += 1
                    console.print(f"[red]Manual evidence mismatch:[/red] {control_id} {entry.get('file')}")
    if failed or manual_failed:
        console.print(
            f"[red]Verification failed:[/red] {len(failed)} artifact(s) and "
            f"{manual_failed} manual attestation(s) did not match."
        )
        return 1
    console.print("[green]All evidence hashes verified.[/green]")
    return 0


def cmd_runs(args: argparse.Namespace) -> int:
    runs = list_runs(_runs_dir(args))
    if not runs:
        console.print("[bright_black]No runs yet. Start with `python -m cee assess --demo`.[/bright_black]")
        return 0
    table = Table(title="Assessment runs", header_style="bold")
    table.add_column("Run ID")
    table.add_column("Mode")
    table.add_column("Started")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")
    for run in runs:
        table.add_row(
            run["run_id"],
            run["mode"],
            run["started_at"],
            f"{run['score']:.1f}%" if run["score"] is not None else "-",
            str(run["findings"]),
        )
    console.print(table)
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    app = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    if not app.exists():
        console.print(f"[red]Dashboard app not found: {app}[/red]")
        return 1
    env = dict(os.environ)
    env["CEE_RUNS_DIR"] = str(_runs_dir(args))
    if args.config:
        env["CEE_CONFIG"] = str(Path(args.config).resolve())
    console.print(f"[green]Starting dashboard[/green] at http://localhost:{args.port}")
    console.print("[bright_black]Press Ctrl+C to stop.[/bright_black]")
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(app),
                "--server.port",
                str(args.port),
                "--server.headless",
                "true",
            ],
            env=env,
            check=False,
        )
    except KeyboardInterrupt:
        return 0
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cee",
        description="Control Evidence Engine - compliance-as-code evidence for ISO/IEC 27001:2022.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    assess = sub.add_parser("assess", help="Run an assessment and generate reports")
    mode = assess.add_mutually_exclusive_group()
    mode.add_argument("--demo", action="store_true", help="Use the synthetic demo environment (default)")
    mode.add_argument("--live", action="store_true", help="Collect evidence from configured live systems")
    assess.add_argument("--config", help="Path to cee.yaml (default: ./cee.yaml)")
    assess.add_argument("--framework", default=DEFAULT_FRAMEWORK, help="Framework ID (default: iso27001-2022)")
    assess.add_argument("--runs-dir", help="Directory for run output (default: ./runs)")
    assess.set_defaults(func=cmd_assess)

    report = sub.add_parser("report", help="Re-render a report from a stored run")
    report.add_argument("--run", default="latest", help="Run ID or 'latest'")
    report.add_argument("--format", choices=["html", "md", "both"], default="html")
    report.add_argument("--open", action="store_true", help="Open the report in a browser")
    report.add_argument("--config", help="Path to cee.yaml")
    report.add_argument("--runs-dir", help="Directory containing runs")
    report.set_defaults(func=cmd_report)

    controls = sub.add_parser("controls", help="List the control catalog")
    controls.add_argument("--framework", default=DEFAULT_FRAMEWORK)
    controls.add_argument("--theme", choices=list(THEME_LABELS), help="Filter by theme")
    controls.add_argument("--run", help="Join the latest status from a run ID or 'latest'")
    controls.add_argument("--runs-dir", help="Directory containing runs")
    controls.set_defaults(func=cmd_controls)

    attest = sub.add_parser("attest", help="Attach or list manual evidence for a control")
    attest.add_argument("--control", help="Control ID, e.g. A.5.1")
    attest.add_argument("--file", help="Evidence file to attach")
    attest.add_argument("--note", help="Context an auditor needs")
    attest.add_argument("--by", help="Name of the attester")
    attest.add_argument("--list", action="store_true", help="List registered attestations")
    attest.add_argument("--framework", default=DEFAULT_FRAMEWORK)
    attest.add_argument("--config", help="Path to cee.yaml")
    attest.set_defaults(func=cmd_attest)

    verify = sub.add_parser("verify", help="Recompute evidence hashes for a run")
    verify.add_argument("--run", default="latest", help="Run ID or 'latest'")
    verify.add_argument("--config", help="Path to cee.yaml")
    verify.add_argument("--runs-dir", help="Directory containing runs")
    verify.set_defaults(func=cmd_verify)

    runs = sub.add_parser("runs", help="List assessment runs")
    runs.add_argument("--runs-dir", help="Directory containing runs")
    runs.set_defaults(func=cmd_runs)

    dashboard = sub.add_parser("dashboard", help="Launch the Streamlit dashboard")
    dashboard.add_argument("--port", type=int, default=8502)
    dashboard.add_argument("--config", help="Path to cee.yaml")
    dashboard.add_argument("--runs-dir", help="Directory containing runs")
    dashboard.set_defaults(func=cmd_dashboard)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        console.print("\n[bright_black]Cancelled.[/bright_black]")
        return 130
    except (FileNotFoundError, ValueError, KeyError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1
