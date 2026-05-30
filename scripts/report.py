import argparse
import datetime as dt
import json
import pathlib
import sys


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _journal_path() -> pathlib.Path:
    return _skill_dir() / "out" / "findings.jsonl"


def _load_entries(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    items: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    return items


def _md_escape(s: str) -> str:
    return (s or "").replace("\r", "").strip()


def _render(entries: list[dict]) -> str:
    now = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    lines: list[str] = []
    lines.append(f"# SecOps Hub Report")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append(f"Entries: {len(entries)}")
    lines.append("")

    for i, e in enumerate(reversed(entries[-50:]), start=1):
        res = (e.get("result") or {}) if isinstance(e, dict) else {}
        lines.append(f"## Finding {i}")
        lines.append("")
        lines.append(f"- Time: {_md_escape(str(e.get('ts', '')))}")
        lines.append(f"- Capability: {_md_escape(str(e.get('capability', '')))}")
        lines.append(f"- Severity: {_md_escape(str(res.get('severity', '')))}")
        lines.append(f"- MITRE: {_md_escape(str(res.get('mitre', '')))}")
        lines.append("")
        lines.append("**Input**")
        lines.append("")
        lines.append("```text")
        lines.append(_md_escape(str(e.get("input", ""))))
        lines.append("```")
        lines.append("")
        lines.append("**Summary**")
        lines.append("")
        summary = str(res.get("summary", ""))
        if "title:" in summary and "detection:" in summary:
            lines.append("```yaml")
            lines.append(_md_escape(summary))
            lines.append("```")
        else:
            lines.append("```text")
            lines.append(_md_escape(summary))
            lines.append("```")
        lines.append("")
        lines.append("**Action**")
        lines.append("")
        lines.append(_md_escape(str(res.get("action", ""))))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--out", type=str, default="")
    ns = parser.parse_args()

    entries = _load_entries(_journal_path())
    md = _render(entries)

    out_path = (ns.out or "").strip()
    if out_path:
        p = pathlib.Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")

    sys.stdout.write(md)
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
