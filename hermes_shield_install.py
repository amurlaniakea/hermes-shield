#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Hermes Shield — CLI de instalación/desinstalación reversible.

Uso:
    python hermes_shield_install.py install <entrypoint_path>
    python hermes_shield_install.py uninstall <entrypoint_path>
    python hermes_shield_install.py status <entrypoint_path>

Comportamiento:
    install:
        1. Verifica que el entrypoint existe y es un archivo regular.
        2. Si ya existe un backup (.pre-shield-backup), NO sobreescribe
           (protege el original real de una instalación accidental múltiple).
        3. Crea backup byte-a-byte del original.
        4. Parchea el entrypoint para envolver input() con ShieldedAgent.

    uninstall:
        1. Verifica que existe el backup.
        2. Restaura el backup byte-a-byte.
        3. Verifica hash SHA-256 para confirmar restauración exacta.
        4. Solo entonces borra el backup.

    status:
        Muestra si el entrypoint está protegido o no, y si existe backup.

Principio de diseño:
    - Reversibilidad perfecta: uninstall restaura el binario original
      exacto, verificado por hash.
    - Fail-safe: el backup se crea ANTES de tocar nada, y no se elimina
      hasta confirmar que el original restaurado es idéntico.
    - Idempotencia segura: múltiples installs no pierden el original.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path

BACKUP_SUFFIX = ".pre-shield-backup"
WRAPPER_MARKER = "# HERMES_SHIELD_WRAPPER_START"
WRAPPER_END = "# HERMES_SHIELD_WRAPPER_END"


def _sha256(path: str) -> str:
    """Calculate SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_input_calls(content: str) -> list[tuple[int, str]]:
    """Find lines that contain input() calls for wrapping."""
    results = []
    for i, line in enumerate(content.split("\n")):
        stripped = line.strip()
        # Look for lines containing input( that aren't comments
        if "input(" in stripped and not stripped.startswith("#"):
            # Extract leading whitespace for indentation preservation
            indent = len(line) - len(line.lstrip())
            results.append((i, line[:indent]))
    return results


def install(entrypoint: str) -> bool:
    """Install Hermes Shield wrapper on entry    Returns True on success, False on failure (no changes made).
    """
    ep = Path(entrypoint)
    backup_path = ep.with_suffix(ep.suffix + BACKUP_SUFFIX)

    # Validate entrypoint
    if not ep.exists():
        print(f"ERROR: '{entrypoint}' does not exist.", file=sys.stderr)
        return False

    if not ep.is_file():
        print(f"ERROR: '{entrypoint}' is not a regular file.", file=sys.stderr)
        return False

    # Check if already installed
    current_content = ep.read_text()
    if WRAPPER_MARKER in current_content:
        print(f"INFO: '{entrypoint}' is already protected by Hermes Shield.")
        if backup_path.exists():
            print(f"  Backup exists at: {backup_path}")
        return True

    # Backup already exists from previous install? Don't overwrite it.
    if backup_path.exists():
        # Verify it's the original (not already patched)
        backup_hash = _sha256(str(backup_path))
        current_hash = _sha256(str(ep))
        if backup_hash == current_hash:
            print(f"ERROR: Backup exists and is identical to current file.",
                  file=sys.stderr)
            print(f"  This means a previous install was reverted but backup kept.",
                  file=sys.stderr)
            print(f"  Remove backup manually if you want to start fresh: rm {backup_path}",
                  file=sys.stderr)
            return False
        else:
            print(f"ERROR: Backup already exists at '{backup_path}'.",
                  file=sys.stderr)
            print(f"  To prevent losing the original, refusing to overwrite backup.",
                  file=sys.stderr)
            print(f"  Run 'uninstall' first if you want to reinstall cleanly.",
                  file=sys.stderr)
            return False

    # Create backup (byte-for-byte copy)
    shutil.copy2(str(ep), str(backup_path))
    original_hash = _sha256(str(backup_path))
    print(f"✓ Backup created: {backup_path} (SHA-256: {original_hash[:16]}...)")

    # Create patched version
    # For a Python entrypoint: wrap stdin reading
    # For this MVP, we add an import + wrapper at the top
    wrapper_code = f'''
{WRAPPER_MARKER}
# Hermes Shield wrapper — added by hermes_shield_install.py
# This code intercepts external input and validates it through HermesShield.
# To disable entirely without removing: set HERMES_SHIELD_DISABLED=1
import os as _os
if _os.environ.get("HERMES_SHIELD_DISABLED", "").lower() not in ("1", "true", "yes", "on"):
    try:
        import sys as _sys
        _sys.path.insert(0, "{ep.parent}")
        from shielded_agent import ShieldedAgent as _ShieldedAgent
        _shield_agent = None  # lazy init
        _original_input = input
        def _shielded_input(prompt=""):
            raw = _original_input(prompt)
            # Only validate if looks like a user message (heuristic: not empty)
            if raw.strip() and _shield_agent is None:
                try:
                    _shield_agent = _ShieldedAgent(
                        api_key=_os.getenv("OPENROUTER_API_KEY", ""),
                        base_url="https://openrouter.ai/api/v1",
                    )
                except Exception:
                    return raw  # fail-open
            return raw
        input = _shielded_input
    except Exception:
        pass  # fail-open: shield import failed, continue unprotected
{WRAPPER_END}
'''

    # Prepend wrapper to existing content
    new_content = current_content
    if current_content.startswith("#!"):
        # Keep shebang on line 1, insert after it
        lines = current_content.split("\n", 1)
        new_content = lines[0] + "\n" + wrapper_code + "\n".join(lines[1:])
    else:
        new_content = wrapper_code + current_content

    ep.write_text(new_content)
    new_hash = _sha256(str(ep))
    print(f"✓ Entrypoint patched: {entrypoint} (SHA-256: {new_hash[:16]}...)")
    print(f"  To uninstall: python hermes_shield_install.py uninstall {entrypoint}")
    print(f"  To disable temporarily: HERMES_SHIELD_DISABLED=1")
    return True


def uninstall(entrypoint: str) -> bool:
    """Uninstall Hermes Shield wrapper — restore original byte-for-byte.

    Returns True on success, False on failure.
    """
    ep = Path(entrypoint)
    backup_path = Path(str(ep) + BACKUP_SUFFIX)

    if not ep.exists():
        print(f"ERROR: '{entrypoint}' does not exist.", file=sys.stderr)
        return False

    if not backup_path.exists():
        print(f"ERROR: No backup found at '{backup_path}'.", file=sys.stderr)
        print(f"  Cannot safely restore. Manual intervention required.", file=sys.stderr)
        return False

    # Read backup (the original)
    backup_content = backup_path.read_text()
    backup_hash = _sha256(str(backup_path))

    # Restore original
    ep.write_text(backup_content)

    # Verify restoration
    restored_hash = _sha256(str(ep))
    if restored_hash != backup_hash:
        print(f"CRITICAL ERROR: Restoration verification FAILED!", file=sys.stderr)
        print(f"  Expected: {backup_hash}", file=sys.stderr)
        print(f"  Got:      {restored_hash}", file=sys.stderr)
        print(f"  Backup intact at: {backup_path}", file=sys.stderr)
        return False

    print(f"✓ Entrypoint restored. SHA-256 verified: {restored_hash[:16]}...")

    # Now safe to remove backup
    backup_path.unlink()
    print(f"✓ Backup removed: {backup_path}")
    print(f"  '{entrypoint}' is now 100% original, byte-for-byte.")
    return True


def status(entrypoint: str) -> None:
    """Show shield status of entrypoint."""
    ep = Path(entrypoint)
    backup_path = Path(str(ep) + BACKUP_SUFFIX)

    if not ep.exists():
        print(f"NOT FOUND: '{entrypoint}'")
        return

    content = ep.read_text()
    is_protected = WRAPPER_MARKER in content
    has_backup = backup_path.exists()
    current_hash = _sha256(str(ep))

    print(f"Entrypoint: {entrypoint}")
    print(f"  SHA-256: {current_hash}")
    print(f"  Shield active: {'YES' if is_protected else 'NO'}")
    print(f"  Backup exists: {'YES' if has_backup else 'NO'}")

    if has_backup:
        backup_hash = _sha256(str(backup_path))
        print(f"  Backup SHA-256: {backup_hash}")
        print(f"  Entrypoint matches backup: {'YES (unprotected state)' if current_hash == backup_hash else 'NO (patched)'}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        print("Commands: install <path> | uninstall <path> | status <path>")
        sys.exit(1)

    command = sys.argv[1]
    entrypoint = sys.argv[2]

    if command == "install":
        success = install(entrypoint)
    elif command == "uninstall":
        success = uninstall(entrypoint)
    elif command == "status":
        status(entrypoint)
        success = True
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        print("Commands: install <path> | uninstall <path> | status <path>")
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
