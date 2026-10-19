"""Shared file-backed scanner configuration with editable defaults and overrides."""
from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from runtime_config import BASE_DIR, DATABASE_PATH

DEFAULT_CONFIG_PATH = BASE_DIR / "config" / "netchecker_defaults.json"
USER_CONFIG_PATH = DATABASE_PATH.parent / "netchecker_user_config.json"
_WRITE_LOCK = threading.Lock()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Konfiguration kann nicht gelesen werden: {path.name}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"Konfigurationsdatei muss ein JSON-Objekt enthalten: {path.name}")
    return value


def default_config() -> dict[str, Any]:
    return _read_json(DEFAULT_CONFIG_PATH)


def _merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def user_overrides() -> dict[str, Any]:
    return _read_json(USER_CONFIG_PATH)


def effective_config() -> dict[str, Any]:
    return _merge(default_config(), user_overrides())


def timing_value(key: str) -> int | float:
    return effective_config()["timings"][key]


def nmap_profile(name: str) -> dict[str, Any]:
    return effective_config()["nmap"][name]


def validate_overrides(value: Any) -> dict[str, Any]:
    defaults = default_config()
    if not isinstance(value, dict) or set(value) - {"timings", "nmap"}:
        raise ValueError("Erwartet werden die Bereiche timings und nmap.")
    result: dict[str, Any] = {"timings": {}, "nmap": {}}
    timings = value.get("timings", {})
    if not isinstance(timings, dict) or set(timings) - set(defaults["timings"]):
        raise ValueError("Unbekannte Timing-Einstellung.")
    for key, raw in timings.items():
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not 1 <= raw <= 86400:
            raise ValueError(f"Timing {key} muss zwischen 1 und 86400 Sekunden liegen.")
        result["timings"][key] = raw

    profiles = value.get("nmap", {})
    if not isinstance(profiles, dict) or set(profiles) - set(defaults["nmap"]):
        raise ValueError("Unbekanntes Nmap-Profil.")
    for name, profile in profiles.items():
        if not isinstance(profile, dict) or set(profile) - {"arguments", "timeout_seconds"}:
            raise ValueError(f"Ungültiges Nmap-Profil: {name}.")
        clean: dict[str, Any] = {}
        if "arguments" in profile:
            args = profile["arguments"]
            if (not isinstance(args, list) or len(args) > 64 or
                    any(not isinstance(arg, str) or not arg or len(arg) > 256 or
                        "\x00" in arg or "\n" in arg or "\r" in arg for arg in args)):
                raise ValueError(f"Nmap-Argumente für {name} müssen einzelne, nicht leere Zeilen sein.")
            reserved = {"-oX", "-oN", "-oG", "-oA", "-oS", "-iL", "-iR", "--resume"}
            if any(arg in reserved or any(arg.startswith(flag) and arg != flag
                                          for flag in ("-oX", "-oN", "-oG", "-oA", "-oS"))
                   for arg in args):
                raise ValueError("Ausgabe- und Zieleinstellungen werden von NetChecker verwaltet.")
            clean["arguments"] = args
        if "timeout_seconds" in profile:
            timeout = profile["timeout_seconds"]
            if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 86400:
                raise ValueError(f"Timeout für {name} muss zwischen 1 und 86400 Sekunden liegen.")
            clean["timeout_seconds"] = timeout
        result["nmap"][name] = clean
    return {key: section for key, section in result.items() if section}


def save_overrides(value: Any) -> dict[str, Any]:
    overrides = validate_overrides(value)
    if not overrides:
        clear_overrides()
        return {}
    USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _WRITE_LOCK:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".netchecker-config-", suffix=".tmp", dir=USER_CONFIG_PATH.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(overrides, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, USER_CONFIG_PATH)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
    return overrides


def clear_overrides() -> None:
    with _WRITE_LOCK:
        try:
            USER_CONFIG_PATH.unlink()
        except FileNotFoundError:
            pass
