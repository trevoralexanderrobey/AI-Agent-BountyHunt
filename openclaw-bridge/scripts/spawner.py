#!/usr/bin/env python3
import argparse
import json
import platform
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path("/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge")
SKILLS_DIR = PROJECT_ROOT / "skills"
TEMPLATES_DIR = PROJECT_ROOT / "scripts" / "templates"
SYNC_SCRIPT = PROJECT_ROOT / "scripts" / "sync-skill-to-runtime.sh"
ECOSYSTEM_CONFIG = PROJECT_ROOT / "bridge-ecosystem.config.js"

GUI_TOOLS = {"burpsuite", "ghidra", "wireshark", "zap", "maltego"}
NET_TOOLS = {"nmap", "bettercap"}

EXIT_GENERATION_ERROR = 2
EXIT_SYNC_HOOK_ERROR = 3
EXIT_RESTART_HOOK_ERROR = 4


def normalize_slug(name: str) -> str:
    slug_chars: list[str] = []
    previous_dash = False
    for char in name.strip().lower():
        if char.isalnum():
            slug_chars.append(char)
            previous_dash = False
            continue
        if not previous_dash:
            slug_chars.append("-")
            previous_dash = True
    return "".join(slug_chars).strip("-")


def normalize_key(name: str) -> str:
    return "".join(char for char in name.lower() if char.isalnum())


def check_docker() -> bool:
    if shutil.which("docker") is not None:
        return True
    print("WARNING: 'docker' not found on PATH.")
    print("    Install with: brew install --cask docker")
    return False


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def exit_with_failure(exit_code: int, label: str, stderr: str, stdout: str = "") -> None:
    print(f"ERROR: {label} failed (exit {exit_code}).", file=sys.stderr)
    if stderr.strip():
        print(stderr.strip(), file=sys.stderr)
    elif stdout.strip():
        print(stdout.strip(), file=sys.stderr)
    sys.exit(exit_code)


def run_sync_hook(skill_slug: str) -> None:
    result = run_command([str(SYNC_SCRIPT), skill_slug])
    if result.returncode != 0:
        exit_with_failure(EXIT_SYNC_HOOK_ERROR, "Sync to runtime", result.stderr, result.stdout)
    print("Sync to runtime successful.")


def parse_pm2_jlist(stdout: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        raise ValueError("pm2 jlist returned invalid JSON")
    if not isinstance(parsed, list):
        raise ValueError("pm2 jlist did not return a JSON array")
    return [item for item in parsed if isinstance(item, dict)]


def bridge_tracked_by_pm2() -> bool:
    pm2_cmd = shutil.which("pm2")
    if pm2_cmd is None:
        raise RuntimeError("pm2 not found on PATH")

    jlist = run_command([pm2_cmd, "jlist"])
    if jlist.returncode != 0:
        message = jlist.stderr.strip() or jlist.stdout.strip() or "unknown pm2 error"
        raise RuntimeError(f"pm2 jlist failed: {message}")

    entries = parse_pm2_jlist(jlist.stdout)
    return any(entry.get("name") == "openclaw-bridge" for entry in entries)


def read_bridge_port_listener() -> str:
    lsof_cmd = shutil.which("lsof")
    if lsof_cmd is None:
        return "lsof not found; unable to inspect port 8787 listener."

    result = run_command([lsof_cmd, "-nP", "-iTCP:8787", "-sTCP:LISTEN"])
    if result.returncode != 0:
        return "No process is currently listening on TCP port 8787."
    return result.stdout.strip() or "No process is currently listening on TCP port 8787."


def print_restart_recovery(listener_info: str) -> None:
    print("Manual recovery steps:", file=sys.stderr)
    print(
        "  cd /Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge && "
        "pm2 start bridge-ecosystem.config.js --only openclaw-bridge --update-env",
        file=sys.stderr,
    )
    print("  pm2 restart openclaw-bridge --update-env", file=sys.stderr)
    print("Port 8787 listener diagnostics:", file=sys.stderr)
    print(listener_info, file=sys.stderr)


def run_restart_hook() -> None:
    try:
        is_tracked = bridge_tracked_by_pm2()
    except Exception as exc:  # noqa: BLE001
        listener_info = read_bridge_port_listener()
        print(f"ERROR: PM2 bridge detection failed: {exc}", file=sys.stderr)
        print_restart_recovery(listener_info)
        sys.exit(EXIT_RESTART_HOOK_ERROR)

    if is_tracked:
        restart_cmd = ["pm2", "restart", "openclaw-bridge", "--update-env"]
    else:
        restart_cmd = ["pm2", "start", str(ECOSYSTEM_CONFIG), "--only", "openclaw-bridge", "--update-env"]

    result = run_command(restart_cmd)
    if result.returncode == 0:
        if is_tracked:
            print("PM2 bridge restart successful.")
        else:
            print("PM2 bridge start successful (bridge was not tracked).")
        return

    listener_info = read_bridge_port_listener()
    print(f"ERROR: PM2 restart path failed. Command: {' '.join(restart_cmd)}", file=sys.stderr)
    print_restart_recovery(listener_info)
    exit_with_failure(EXIT_RESTART_HOOK_ERROR, "Bridge restart", result.stderr, result.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenClaw Master Skill Spawner")
    parser.add_argument("tool", help="Tool name to scaffold as an OpenClaw skill")
    parser.add_argument("--flags", default="", help="Default CLI flags baked into generated tools.js")
    parser.add_argument("--gui", action="store_true", help="Force GUI bridge mode")
    parser.add_argument("--description", help="Skill description for SKILL.md frontmatter")
    parser.add_argument("--owner-id", help="Owner ID for _meta.json (defaults to UUID4)")
    parser.add_argument("--daemon-url", default="http://127.0.0.1:8090", help="Local daemon URL for GUI bridge tools")
    parser.add_argument("--force", action="store_true", help="Overwrite managed files if skill directory exists")
    parser.add_argument("--dry-run", action="store_true", help="Render planning only; do not write files or run hooks")
    parser.add_argument("--no-restart-bridge", action="store_true", help="Disable PM2 restart hook")
    parser.add_argument("--no-host-net", action="store_true", help="Disable Linux auto-injection of --net=host")

    args = parser.parse_args()

    slug = normalize_slug(args.tool)
    if not slug:
        print("ERROR: could not derive a valid skill slug from tool name.", file=sys.stderr)
        sys.exit(EXIT_GENERATION_ERROR)

    tool_key = normalize_key(args.tool)
    target_dir = SKILLS_DIR / slug

    if target_dir.exists() and not target_dir.is_dir():
        print(f"ERROR: target path exists and is not a directory: {target_dir}", file=sys.stderr)
        sys.exit(EXIT_GENERATION_ERROR)

    if target_dir.exists() and not args.force:
        print(f"ERROR: skill '{slug}' already exists at {target_dir}. Use --force to overwrite managed files.", file=sys.stderr)
        sys.exit(EXIT_GENERATION_ERROR)

    try:
        from jinja2 import Environment, FileSystemLoader, StrictUndefined
    except ImportError:
        print("ERROR: jinja2 is required. Install with: python3 -m pip install jinja2", file=sys.stderr)
        sys.exit(EXIT_GENERATION_ERROR)

    if not TEMPLATES_DIR.is_dir():
        print(f"ERROR: templates directory not found: {TEMPLATES_DIR}", file=sys.stderr)
        sys.exit(EXIT_GENERATION_ERROR)

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), undefined=StrictUndefined, autoescape=False)

    is_gui = args.gui or tool_key in GUI_TOOLS
    is_linux = platform.system().lower() == "linux"
    is_macos = platform.system().lower() == "darwin"
    net_sensitive = tool_key in NET_TOOLS
    inject_host_net = net_sensitive and is_linux and not args.no_host_net
    show_macos_warning = net_sensitive and is_macos

    if show_macos_warning:
        print(
            "WARNING: macOS note: Docker Desktop uses network isolation. "
            "Container localhost/service visibility may differ from host networking."
        )

    check_docker()

    skill_type = "gui-bridge" if is_gui else "headless-kali"
    owner_id = args.owner_id or str(uuid.uuid4())
    description = args.description or f"Modular OpenClaw skill for {args.tool}"
    published_at = int(datetime.now(tz=timezone.utc).timestamp() * 1000)

    context: dict[str, Any] = {
        "tool_name": args.tool,
        "tool_name_json": json.dumps(args.tool),
        "slug": slug,
        "slug_json": json.dumps(slug),
        "default_flags": args.flags,
        "default_flags_json": json.dumps(args.flags),
        "is_gui": is_gui,
        "skill_type": skill_type,
        "inject_host_net": inject_host_net,
        "daemon_url": args.daemon_url,
        "daemon_url_json": json.dumps(args.daemon_url),
        "owner_id": owner_id,
        "owner_id_json": json.dumps(owner_id),
        "description": description,
        "description_json": json.dumps(description),
        "published_at": published_at,
        "generated_at_iso": datetime.now(tz=timezone.utc).isoformat(),
        "net_sensitive": net_sensitive,
        "macos_warning": show_macos_warning,
    }

    tools_template = "gui_bridge_tools.js.j2" if is_gui else "kali_cli_tools.js.j2"
    template_map = {
        tools_template: "tools.js",
        "skill_manifest.json.j2": "_meta.json",
        "skill_readme.md.j2": "SKILL.md",
    }

    if args.dry_run:
        print("Dry run summary:")
        print(f"  tool: {args.tool}")
        print(f"  slug: {slug}")
        print(f"  mode: {skill_type}")
        print(f"  target_dir: {target_dir}")
        print(f"  templates: {', '.join(template_map.keys())}")
        print(f"  sync_hook: {SYNC_SCRIPT} {slug}")
        if args.no_restart_bridge:
            print("  restart_hook: disabled (--no-restart-bridge)")
        else:
            print("  restart_hook: enabled (PM2 detection + fallback)")
        return

    target_dir.mkdir(parents=True, exist_ok=True)

    try:
        for template_name, output_name in template_map.items():
            rendered = env.get_template(template_name).render(context)
            (target_dir / output_name).write_text(rendered, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: rendering templates failed: {exc}", file=sys.stderr)
        sys.exit(EXIT_GENERATION_ERROR)

    run_sync_hook(slug)

    if not args.no_restart_bridge:
        run_restart_hook()

    print(f"Skill '{slug}' generated at {target_dir}")
    print(f"   Type: {skill_type}")
    print("   Files: tools.js, _meta.json, SKILL.md")


if __name__ == "__main__":
    main()
