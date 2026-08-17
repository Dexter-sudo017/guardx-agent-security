from typing import Any
from urllib.parse import urlparse


def normalize_action_to_tool(surface: str, action: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    surface_lower = surface.strip().lower()
    action_name = str(action.get("name") or action.get("action") or "").strip().lower()
    args = action.get("args") if isinstance(action.get("args"), dict) else {}
    arguments = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
    if isinstance(args.get("arguments"), dict):
        arguments = {**arguments, **args["arguments"]}
    combined_args = {**arguments, **args}
    for content_key in ("content", "contents", "file_text", "inserted_text", "new_str", "old_str", "replacement", "text"):
        if content_key in action and content_key not in combined_args:
            combined_args[content_key] = action[content_key]
    for route_key in ("domain", "url", "uri", "path", "file_path", "dir_path", "command", "code", "query"):
        if route_key in action and route_key not in combined_args:
            combined_args[route_key] = action[route_key]
    for manifest_key in ("side_effects", "constraints", "source_uri", "provenance", "rollback_supported", "dry_run"):
        if manifest_key in action and manifest_key not in combined_args:
            combined_args[manifest_key] = action[manifest_key]
    tool_name_raw = str(action.get("tool_name") or combined_args.get("tool_name") or combined_args.get("name") or "").strip()
    tool_name = tool_name_raw.lower()
    value = action.get("value")
    if value is None:
        value = (
            action.get("path")
            or action.get("command")
            or action.get("code")
            or action.get("url")
            or action.get("query")
            or combined_args.get("path")
            or combined_args.get("file_path")
            or combined_args.get("dir_path")
            or combined_args.get("command")
            or combined_args.get("code")
            or combined_args.get("url")
            or combined_args.get("domain")
            or combined_args.get("query")
            or ""
        )
    if action_name in {"think", "finish", "agentfinishaction", "task_tracker", "messageaction", "nullaction", "noop"}:
        mapped_args = {"action": action_name}
        mapped_args.update(combined_args)
        return "agent_noop_safe", mapped_args
    if surface_lower in {"command", "bash", "shell", "ipython", "ipython code"} or action_name in {
        "run",
        "bash",
        "shell",
        "execute_bash",
        "execute_ipython_cell",
        "cmdrunaction",
        "ipythonruncellaction",
    }:
        mapped_args = {"command": str(value)}
        mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
        return "shell_exec_sim", mapped_args
    editor_command = str(combined_args.get("command") or action.get("command") or "").strip().lower()
    if action_name in {"str_replace_editor", "strreplaceeditoraction"} and editor_command in {"create", "str_replace", "insert", "undo_edit", "write", "edit"}:
        mapped_args = {"path": str(action.get("path") or combined_args.get("path") or value)}
        mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
        return "write_file_safe", mapped_args
    if surface_lower in {"file write path", "file edit path", "file_write", "file_edit"} or action_name in {
        "write",
        "edit",
        "fileeditaction",
        "filewriteaction",
        "filedeleteaction",
    }:
        mapped_args = {"path": str(value)}
        mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
        return "write_file_safe", mapped_args
    if surface_lower in {"file read path", "file", "file_read"} or action_name in {
        "read",
        "str_replace_editor",
        "strreplaceeditoraction",
        "filereadaction",
        "fileopenaction",
        "filelistaction",
        "filesearchaction",
        "filefindaction",
    }:
        mapped_args = {"path": str(value)}
        mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
        return "read_file_safe", mapped_args
    if surface_lower in {"network", "http", "browser"} or action_name in {
        "fetch",
        "http_get",
        "browser",
        "browseraction",
        "browserinteractiveaction",
        "browseurlaction",
    }:
        raw_target = str(combined_args.get("domain") or combined_args.get("url") or value)
        parsed = urlparse(raw_target if "://" in raw_target else f"https://{raw_target}")
        domain = parsed.hostname or raw_target
        mapped_args = {"domain": domain.lower()}
        mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
        return "http_get_safe", mapped_args
    if surface_lower in {"db", "database", "sql"} or action_name in {"sql", "dbqueryaction", "databasequeryaction"}:
        mapped_args = {"query": str(combined_args.get("query") or action.get("query") or value)}
        mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
        return "db_query_safe", mapped_args
    if surface_lower in {"mcp", "plugin", "tool", "tool_call"} or action_name in {"mcptoolcallaction", "mcp_tool_call", "toolcallaction"}:
        if tool_name in {"fetch", "http_get", "browser", "browse", "web_fetch"}:
            raw_target = str(combined_args.get("domain") or combined_args.get("url") or combined_args.get("uri") or value)
            parsed = urlparse(raw_target if "://" in raw_target else f"https://{raw_target}")
            domain = parsed.hostname or raw_target
            mapped_args = {"domain": domain.lower(), "tool_name": tool_name_raw or action_name}
            mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
            return "http_get_safe", mapped_args
        if tool_name in {"read_file", "open_file", "filesystem_read"}:
            mapped_args = {"path": str(combined_args.get("path") or combined_args.get("file_path") or value), "tool_name": tool_name_raw or action_name}
            mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
            return "read_file_safe", mapped_args
        if tool_name in {"write_file", "edit_file", "filesystem_write"}:
            mapped_args = {"path": str(combined_args.get("path") or combined_args.get("file_path") or value), "tool_name": tool_name_raw or action_name}
            mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
            return "write_file_safe", mapped_args
        if tool_name in {"sql", "db_query", "database_query"}:
            mapped_args = {"query": str(combined_args.get("query") or value), "tool_name": tool_name_raw or action_name}
            mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
            return "db_query_safe", mapped_args
        if action_name in {"register_tool", "registertoolsafe", "registertoolaction"}:
            mapped_args = {
                "name": str(combined_args.get("name") or tool_name_raw or action.get("name") or ""),
                "description": str(combined_args.get("description") or action.get("description") or value),
            }
            mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
            return "register_tool_safe", mapped_args
        mapped_args = {"tool_name": tool_name_raw or action_name}
        mapped_args.update(combined_args)
        return str(tool_name_raw or action_name or "unknown_tool"), mapped_args
    if surface_lower in {"mcp", "plugin", "tool_registration", "tool manifest"} or action_name in {
        "register_tool",
        "registertoolsafe",
        "registertoolaction",
    }:
        mapped_args = {
            "name": str(combined_args.get("name") or action.get("tool_name") or action.get("name") or ""),
            "description": str(combined_args.get("description") or action.get("description") or value),
        }
        mapped_args.update({key: val for key, val in combined_args.items() if key not in mapped_args})
        return "register_tool_safe", mapped_args
    return str(action.get("tool_name") or action_name or "unknown_tool"), dict(combined_args)
