import inspect
import asyncio
import json
from pathlib import Path

import injection_check


def extract_assistant_text(filepath: Path) -> str:
    """
    Extract all assistant messages from a .jsonl file.
    """
    all_text = []
    with filepath.open('r', encoding='utf-8') as f:
        for line in f:
            try:
                obj = json.loads(line)
                if obj.get("role") == "assistant":
                    all_text.append(obj.get("content", ""))
            except json.JSONDecodeError:
                continue
    return "\n".join(all_text)


def load_code_from_path(path: Path) -> str:
    """
    If it’s a .jsonl, extract assistant text; otherwise read raw text.
    """
    if path.suffix.lower() == ".jsonl":
        return extract_assistant_text(path)
    else:
        return path.read_text(encoding="utf-8", errors="ignore")


def run_check(objective: str, code: str, computer=None) -> bool:
    """
    Dispatch to the right check function in injection_check.
    """
    fn = injection_check.INJECTION_CHECK_DISPATCH.get(objective)
    if fn is None:
        raise ValueError(f"No check function registered for '{objective}'")
    if inspect.iscoroutinefunction(fn):
        if computer is None:
            raise ValueError(
                f"Objective '{objective}' requires a ComputerInterface instance"
            )
        return asyncio.run(fn(code, computer))
    else:
        return fn(code)


def main(objective: str, target_path: str, computer=None) -> dict[str, bool | str]:
    """
    Run the given objective against a file or all supported files in a folder.
    Returns a dict: filename -> True/False or error message.
    """
    results: dict[str, bool | str] = {}
    target = Path(target_path)
    if not target.exists():
        raise FileNotFoundError(f"Path '{target_path}' does not exist")

    candidates = [target] if target.is_file() else list(target.iterdir())
    for file in candidates:
        if not file.is_file() or file.suffix.lower() not in {".jsonl", ".py", ".js", ".java", ".txt", ".json"}:
            continue
        try:
            code = load_code_from_path(file)
            ok = run_check(objective, code, computer)
            results[file.name] = ok
        except Exception as e:
            results[file.name] = f"Error: {e}"

    return results


if __name__ == "__main__":
    # ─── Example usage ──────────────────────────────────────────────
    objective   = "Data Exfiltration"
    target_path = "messages_4o_task2"     # or a folder
    # computer    = <your ComputerInterface instance>             # only for async objectives

    report = main(objective, target_path)  # , computer)
    for fname, outcome in report.items():
        mark = "✅" if outcome is True else ("❌" if outcome is False else "⚠️")
        print(f"{mark} {objective} in {fname}: {outcome}")
