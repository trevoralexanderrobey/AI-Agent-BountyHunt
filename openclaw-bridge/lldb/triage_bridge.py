"""
LLDB stop-hook bridge for defensive crash triage.

When a crash-like stop is detected (signal/exception), this module collects a
small crash context bundle (registers + backtrace + small extra telemetry) and POSTs it to the local
OpenClaw bridge service at /lldb-stop.

No exploitability scoring and no payload guidance: this is debugging triage.
"""

import hashlib
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional, Union

import lldb


DEFAULT_BRIDGE_BASE_URL = "https://127.0.0.1:8787"
STOP_HOOK_MARKER = "triage_bridge.handle_stop"

DISASM_ARM64_BYTES_PER_INSN = 4
DISASM_BEFORE = 4
DISASM_AFTER = 4
DISASM_TOTAL = DISASM_BEFORE + 1 + DISASM_AFTER

MEM_READ_SIZE = 64
MEM_SAMPLE_SIZE = 32

CRASH_STOP_REASONS = {
    lldb.eStopReasonSignal,
    lldb.eStopReasonException,
}

ARM64_REGISTERS = ["pc", "lr", "sp"] + [f"x{i}" for i in range(0, 9)]
X86_64_REGISTERS = ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9"]


def __lldb_init_module(debugger: lldb.SBDebugger, internal_dict) -> None:  # noqa: ANN001
    try:
        if _stop_hook_installed(debugger):
            return

        debugger.HandleCommand(
            'target stop-hook add -o "python triage_bridge.handle_stop(lldb.debugger)"'
        )
        print("triage_bridge: installed stop-hook (posts crash triage to /lldb-stop)")
    except Exception as exc:  # noqa: BLE001
        print(f"triage_bridge: failed to install stop-hook: {exc}")


def handle_stop(debugger: lldb.SBDebugger) -> None:
    try:
        target = debugger.GetSelectedTarget()
        if not target or not target.IsValid():
            return

        process = target.GetProcess()
        if not process or not process.IsValid():
            return

        selected = process.GetSelectedThread()
        thread = _find_crash_thread(process, selected)
        if thread is None:
            return

        frame = thread.GetFrameAtIndex(0)
        triple = _safe_str(target.GetTriple())
        arch = _infer_arch(triple)
        stop_desc = _stop_description(thread)
        registers = _read_registers(frame, arch)
        pc = _safe_int(frame.GetPC())

        event = {
            "version": 1,
            "timestamp": _now_utc_iso(),
            "pid": int(process.GetProcessID()),
            "executable": _executable_path(target),
            "triple": triple,
            "platform": _safe_str(target.GetPlatform().GetName()) if target.GetPlatform().IsValid() else "",
            "stop_reason": {
                "code": int(thread.GetStopReason()),
                "name": _stop_reason_name(thread.GetStopReason()),
                "description": stop_desc,
            },
            "thread": {
                "id": int(thread.GetThreadID()),
                "index_id": int(thread.GetIndexID()),
                "name": _safe_str(thread.GetName()),
            },
            "registers": registers,
            "exception_state": _read_exception_state_registers(frame, arch),
            "disassembly_window": _disassemble_around_pc(debugger, pc, arch) if pc else {},
            "memory_inspection": _inspect_x0_memory(process, registers, stop_desc, arch),
            "backtrace": _read_backtrace(thread, max_frames=30),
        }

        _post_event(event)
    except Exception as exc:  # noqa: BLE001
        # Never let a stop-hook throw.
        print(f"triage_bridge: handle_stop error: {exc}")


def _stop_hook_installed(debugger: lldb.SBDebugger) -> bool:
    interpreter = debugger.GetCommandInterpreter()
    result = lldb.SBCommandReturnObject()
    interpreter.HandleCommand("target stop-hook list", result)
    output = (result.GetOutput() or "") + (result.GetError() or "")
    return STOP_HOOK_MARKER in output


def _find_crash_thread(process: lldb.SBProcess, preferred: Optional[lldb.SBThread]) -> Optional[lldb.SBThread]:
    if preferred and preferred.IsValid() and _is_crash_stop_reason(preferred):
        return preferred

    for i in range(process.GetNumThreads()):
        thread = process.GetThreadAtIndex(i)
        if thread and thread.IsValid() and _is_crash_stop_reason(thread):
            return thread

    return None


def _is_crash_stop_reason(thread: lldb.SBThread) -> bool:
    try:
        return thread.GetStopReason() in CRASH_STOP_REASONS
    except Exception:  # noqa: BLE001
        return False


def _stop_reason_name(code: int) -> str:
    if code == lldb.eStopReasonSignal:
        return "signal"
    if code == lldb.eStopReasonException:
        return "exception"
    return str(code)


def _stop_description(thread: lldb.SBThread) -> str:
    try:
        return _safe_str(thread.GetStopDescription(1024))
    except TypeError:
        # Some LLDB builds expose GetStopDescription() without a buffer size.
        try:
            return _safe_str(thread.GetStopDescription())
        except Exception:  # noqa: BLE001
            return ""
    except Exception:  # noqa: BLE001
        return ""


def _infer_arch(triple: str) -> str:
    t = (triple or "").lower()
    if "arm64" in t or "aarch64" in t:
        return "arm64"
    if "x86_64" in t or "amd64" in t:
        return "x86_64"
    return "unknown"


def _read_registers(frame: lldb.SBFrame, arch: str) -> dict[str, str]:
    if not frame or not frame.IsValid():
        return {}

    names = ARM64_REGISTERS if arch == "arm64" else X86_64_REGISTERS if arch == "x86_64" else []
    out: dict[str, str] = {}

    for name in names:
        value = _read_register(frame, name)
        if value is not None:
            out[name] = value

    return out


def _read_exception_state_registers(frame: lldb.SBFrame, arch: str) -> dict[str, str]:
    if arch != "arm64" or not frame or not frame.IsValid():
        return {}

    out: dict[str, str] = {}

    # LLDB register names can vary by build/platform. Try common aliases.
    esr = _read_first_register(frame, ["esr_el1", "esr"])
    far = _read_first_register(frame, ["far_el1", "far"])
    cpsr = _read_first_register(frame, ["cpsr"])

    if esr is not None:
        out["esr_el1"] = esr
    if far is not None:
        out["far_el1"] = far
    if cpsr is not None:
        out["cpsr"] = cpsr

    return out


def _disassemble_around_pc(debugger: lldb.SBDebugger, pc: int, arch: str) -> dict:
    if not debugger or pc <= 0:
        return {}

    try:
        if arch == "arm64":
            start = max(0, int(pc) - (DISASM_BEFORE * DISASM_ARM64_BYTES_PER_INSN))
            count = int(DISASM_TOTAL)
        else:
            # Best-effort for variable-length ISAs.
            start = max(0, int(pc) - 64)
            count = 20

        interpreter = debugger.GetCommandInterpreter()
        result = lldb.SBCommandReturnObject()
        interpreter.HandleCommand(
            f"disassemble --start-address {hex(start)} --count {count}",
            result,
        )
        text = ((result.GetOutput() or "") + (result.GetError() or "")).strip()
        lines = [line.rstrip() for line in text.splitlines() if line.strip()]

        return {
            "pc": hex(int(pc)),
            "start_address": hex(int(start)),
            "count": int(count),
            "lines": lines,
        }
    except Exception:  # noqa: BLE001
        return {}


def _inspect_x0_memory(process: lldb.SBProcess, registers: dict[str, str], stop_desc: str, arch: str) -> dict:
    # Only attempt memory reads for segfault-like stops; keep output tiny to avoid leaking secrets.
    if arch != "arm64":
        return {}
    if not _is_segv_like(stop_desc):
        return {}

    x0_str = (registers.get("x0") or "").strip()
    if not x0_str:
        return {}

    addr = _parse_int(x0_str)
    if addr is None:
        return {"x0": {"address": x0_str, "error": "unparseable"}}
    if addr == 0:
        return {"x0": {"address": "0x0", "error": "null"}}

    try:
        err = lldb.SBError()
        data = process.ReadMemory(int(addr), int(MEM_READ_SIZE), err)
        if not err.Success() or data is None:
            return {"x0": {"address": hex(int(addr)), "error": _safe_str(err.GetCString())}}

        raw = data if isinstance(data, (bytes, bytearray)) else bytes(data)
        sample = raw[: int(MEM_SAMPLE_SIZE)]

        return {
            "x0": {
                "address": hex(int(addr)),
                "read_len": int(len(raw)),
                "sample_len": int(len(sample)),
                "sample_hex": sample.hex(),
                "sample_ascii": _to_printable_ascii(sample),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "pattern": _byte_pattern_summary(sample),
            }
        }
    except Exception as exc:  # noqa: BLE001
        return {"x0": {"address": hex(int(addr)), "error": _safe_str(exc)}}


def _read_backtrace(thread: lldb.SBThread, max_frames: int = 30) -> list[dict[str, Union[str, int]]]:
    frames: list[dict[str, Union[str, int]]] = []
    if not thread or not thread.IsValid():
        return frames

    count = min(int(thread.GetNumFrames()), int(max_frames))
    for i in range(count):
        frame = thread.GetFrameAtIndex(i)
        if not frame or not frame.IsValid():
            continue

        module = frame.GetModule()
        module_name = ""
        try:
            if module and module.IsValid():
                module_name = _safe_str(module.GetFileSpec().GetFilename())
        except Exception:  # noqa: BLE001
            module_name = ""

        symbol = _safe_str(frame.GetFunctionName())
        if not symbol:
            try:
                sym = frame.GetSymbol()
                if sym and sym.IsValid():
                    symbol = _safe_str(sym.GetName())
            except Exception:  # noqa: BLE001
                symbol = ""

        pc_val = 0
        try:
            pc_val = int(frame.GetPC())
        except Exception:  # noqa: BLE001
            pc_val = 0

        frames.append(
            {
                "index": int(i),
                "pc": hex(pc_val) if pc_val else "",
                "module": module_name,
                "symbol": symbol,
            }
        )

    return frames


def _executable_path(target: lldb.SBTarget) -> str:
    try:
        exe = target.GetExecutable()
        if not exe or not exe.IsValid():
            return ""
        return _safe_str(exe.GetPath())
    except Exception:  # noqa: BLE001
        return ""


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_str(value) -> str:  # noqa: ANN001
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        return ""


def _safe_int(value) -> int:
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return 0


def _read_register(frame: lldb.SBFrame, name: str) -> Optional[str]:
    try:
        reg = frame.FindRegister(name)
        if not reg or not reg.IsValid():
            return None
        value = reg.GetValue()
        if value is None:
            return None
        return str(value)
    except Exception:  # noqa: BLE001
        return None


def _read_first_register(frame: lldb.SBFrame, names: list[str]) -> Optional[str]:
    for name in names:
        value = _read_register(frame, name)
        if value is not None:
            return value
    return None


def _parse_int(raw: str) -> Optional[int]:
    s = (raw or "").strip()
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        # Heuristic: prefer hex when it "looks hex".
        if any(c in s.lower() for c in "abcdef"):
            return int(s, 16)
        return int(s, 10)
    except Exception:  # noqa: BLE001
        return None


def _is_segv_like(stop_desc: str) -> bool:
    d = (stop_desc or "").upper()
    return ("SIGSEGV" in d) or ("EXC_BAD_ACCESS" in d) or ("KERN_INVALID_ADDRESS" in d)


def _to_printable_ascii(data: bytes) -> str:
    out = []
    for b in data:
        ch = chr(b)
        out.append(ch if 32 <= b <= 126 else ".")
    return "".join(out)


def _byte_pattern_summary(sample: bytes) -> dict:
    if not sample:
        return {"empty": True}

    unique = sorted(set(sample))
    repeating = len(unique) == 1
    rep_byte = unique[0] if repeating else None

    # Count how much of the prefix is the same byte (useful for 0x41... patterns).
    prefix_len = 0
    first = sample[0]
    for b in sample:
        if b != first:
            break
        prefix_len += 1

    return {
        "unique_bytes": int(len(unique)),
        "repeating_byte": repeating,
        "byte": hex(int(rep_byte)) if rep_byte is not None else "",
        "prefix_repeating_len": int(prefix_len),
        "looks_like_AAAAAA": bool(repeating and rep_byte == 0x41 and prefix_len >= 8),
    }


def _bridge_base_url() -> str:
    for key in ("OPENCLAW_BRIDGE_BASE_URL", "BRIDGE_BASE_URL"):
        raw = (os.environ.get(key) or "").strip()
        if raw:
            return raw.rstrip("/")
    return DEFAULT_BRIDGE_BASE_URL


def _post_event(event: dict) -> None:
    base_url = _bridge_base_url()
    url = f"{base_url}/lldb-stop"

    payload = {"event": event}
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            _ = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        path_written = _write_fallback(event)
        print(f"triage_bridge: bridge POST failed ({exc}); wrote {path_written}")


def _write_fallback(event: dict) -> str:
    root = os.path.join(os.path.expanduser("~"), ".openclaw", "logs", "lldb-triage")
    os.makedirs(root, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pid = event.get("pid") or "unknown"
    out_path = os.path.join(root, f"{stamp}-pid{pid}.json")

    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(event, fp, indent=2, ensure_ascii=True)
        fp.write("\n")

    return out_path
