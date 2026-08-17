from typing import Any


def baseline_prompt(message: str, context_chunks: list[str] | None = None) -> str:
    if context_chunks:
        return f"{message}\n\nRetrieved context:\n" + "\n\n".join(context_chunks)
    return message


def baseline_tool_preview(tool_name: str, args: dict[str, Any]) -> str:
    if tool_name == "read_file_safe":
        return f"Baseline target would read file: {args.get('path', '')}"
    if tool_name == "http_get_safe":
        return f"Baseline target would call remote domain: {args.get('domain', '')}"
    if tool_name == "shell_exec_sim":
        return f"Baseline target would execute command: {args.get('command', '')}"
    if tool_name == "register_tool_safe":
        return "Baseline target would accept the tool registration request."
    return f"Baseline target would allow tool `{tool_name}` with args {args}."


__all__ = [
    "baseline_prompt",
    "baseline_tool_preview",
]
