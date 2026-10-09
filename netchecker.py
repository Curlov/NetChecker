#!/usr/bin/env python3
"""
NetChecker - Hauptlauncher mit integrierter Phase-3-Topologie.

Warum ein Launcher?
-------------------
Der bisherige, bereits getestete NetChecker-Scanner bleibt unveraendert in
"netchecker_core.py". Dieser Launcher startet ihn und fuehrt die Topologie
seriennah in scanfreien Fenstern aus. Dadurch muessen die stabilen Phase-1-/2-
Abläufe nicht neu geschrieben werden.

Produktionsschutz
-----------------
- Keine Konfigurationsaenderungen an Routern/Switches.
- Topologie laeuft standardmaessig nur lokal/passiv.
- RouterOS wird automatisch nur dann zusaetzlich gelesen, wenn bereits eine
  passwortfreie SSH-Authentifizierung vorhanden und erfolgreich testbar ist.
- Es werden keine Passwoerter gespeichert.
- Topologie wird nicht gestartet, solange ein NetChecker-Scanlauf den Status
  "running" hat.
"""

from __future__ import annotations

import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable


BASE_DIR = Path(__file__).resolve().parent
CORE_PATH = BASE_DIR / "netchecker_core.py"
TOPOLOGY_PATH = BASE_DIR / "topology.py"
DATABASE_PATH = BASE_DIR / "data" / "netchecker.db"

# Discovery bleibt Sache des bestehenden Core-NetCheckers.
# Die Topologie aendert sich deutlich seltener, daher genuegen 30 Minuten.
TOPOLOGY_INTERVAL_SECONDS = 30 * 60

# Nach Programmstart erst Core-NetChecker anlaufen lassen. So kann der erste
# Discovery-/Klassifikationslauf seine Daten in Ruhe aktualisieren.
INITIAL_TOPOLOGY_DELAY_SECONDS = 2 * 60

# Wenn gerade ein Scan laeuft, pruefen wir spaeter erneut statt parallel zu
# schreiben oder zusaetzlichen Netzwerkverkehr zu erzeugen.
IDLE_RECHECK_SECONDS = 15

# Schleifenintervall des Launchers selbst.
SUPERVISOR_TICK_SECONDS = 2

# Starke, bereits gespeicherte LLDP/CDP/MNDP-Hinweise werden regelmaessig
# erneut auf die Klassifikation gelegt. Das ist rein lokal (SQLite) und sorgt
# dafuer, dass ein spaeterer Nmap-/Heuristiklauf eine staerkere Topologie-
# Evidenz nicht dauerhaft ueberschreibt.
CLASSIFICATION_RECONCILE_INTERVAL_SECONDS = 60
INITIAL_RECONCILE_DELAY_SECONDS = 20

# Automatische RouterOS-Ergaenzung ist nur mit bereits funktionierender
# passwortfreier SSH-Authentifizierung erlaubt. Kein Passwortprompt im
# automatischen Betrieb.
ROUTEROS_DEFAULT_USER = "admin"
SSH_PREFLIGHT_TIMEOUT_SECONDS = 6


class NetCheckerLauncherError(RuntimeError):
    pass


def print_header(title: str) -> None:
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def ensure_required_files() -> None:
    missing: list[str] = []
    if not CORE_PATH.exists():
        missing.append(str(CORE_PATH))
    if not TOPOLOGY_PATH.exists():
        missing.append(str(TOPOLOGY_PATH))

    if missing:
        raise NetCheckerLauncherError(
            "Fehlende Datei(en): " + ", ".join(missing)
        )


def database_has_table(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        LIMIT 1
        """,
        (table,),
    ).fetchone()
    return row is not None


def scan_is_running() -> bool:
    """Prueft nur lesend, ob der Core gerade einen Scanlauf bearbeitet."""
    if not DATABASE_PATH.exists():
        return False

    try:
        connection = sqlite3.connect(
            f"file:{DATABASE_PATH}?mode=ro",
            uri=True,
            timeout=2,
        )
        try:
            if not database_has_table(connection, "scan_runs"):
                return False

            row = connection.execute(
                """
                SELECT 1
                FROM scan_runs
                WHERE status = 'running'
                LIMIT 1
                """
            ).fetchone()
            return row is not None
        finally:
            connection.close()
    except sqlite3.Error:
        # Bei einem kurzen SQLite-Lock lieber warten als einen Topologielauf
        # parallel zu erzwingen.
        return True


def discover_routeros_candidates() -> list[tuple[str, str]]:
    """
    Sucht bekannte MikroTik/RouterBOARD-Geraete ausschliesslich in der lokalen
    NetChecker-Datenbank. Es wird dabei noch kein Netzwerkgeraet kontaktiert.

    Rueckgabe: [(ip, user), ...]
    """
    if not DATABASE_PATH.exists():
        return []

    candidates: list[str] = []

    try:
        connection = sqlite3.connect(
            f"file:{DATABASE_PATH}?mode=ro",
            uri=True,
            timeout=2,
        )
        connection.row_factory = sqlite3.Row
        try:
            if not database_has_table(connection, "devices"):
                return []
            if not database_has_table(connection, "addresses"):
                return []

            has_classifications = database_has_table(
                connection,
                "device_classifications",
            )

            if has_classifications:
                rows = connection.execute(
                    """
                    SELECT DISTINCT
                        (
                            SELECT a.ip
                            FROM addresses a
                            WHERE a.device_id = d.id
                            ORDER BY a.last_seen DESC, a.id DESC
                            LIMIT 1
                        ) AS ip,
                        d.vendor,
                        d.hostname,
                        dc.subtype,
                        dc.category
                    FROM devices d
                    JOIN device_classifications dc
                      ON dc.device_id = d.id
                    WHERE
                        LOWER(COALESCE(d.vendor, '')) LIKE '%mikrotik%'
                        OR LOWER(COALESCE(d.vendor, '')) LIKE '%routerboard%'
                        OR LOWER(COALESCE(dc.subtype, '')) LIKE '%mikrotik%'
                        OR LOWER(COALESCE(dc.subtype, '')) LIKE '%routerboard%'
                    """
                ).fetchall()

                for row in rows:
                    if row["ip"]:
                        candidates.append(str(row["ip"]))

            # Bereits erfolgreich manuell ausgelesene RouterOS-Ziele ebenfalls
            # kennen. So bleibt das Ziel auch erhalten, falls die Klassifikation
            # spaeter anders formuliert wird.
            if database_has_table(connection, "topology_routeros_records"):
                rows = connection.execute(
                    """
                    SELECT DISTINCT router_ip
                    FROM topology_routeros_records
                    WHERE router_ip IS NOT NULL
                      AND TRIM(router_ip) <> ''
                    ORDER BY router_ip
                    """
                ).fetchall()
                for row in rows:
                    candidates.append(str(row["router_ip"]))
        finally:
            connection.close()
    except sqlite3.Error:
        return []

    unique = sorted(set(candidates))
    return [(ip, ROUTEROS_DEFAULT_USER) for ip in unique]


def ssh_identity_available() -> bool:
    """
    Prueft lokal, ob ueberhaupt eine SSH-Key-/Agent-Identitaet vorhanden ist.
    Ohne Identitaet wird RouterOS im Automatikmodus gar nicht erst kontaktiert.
    """
    ssh_dir = Path.home() / ".ssh"
    key_names = (
        "id_ed25519",
        "id_rsa",
        "id_ecdsa",
        "id_dsa",
    )

    if any((ssh_dir / name).exists() for name in key_names):
        return True

    try:
        result = subprocess.run(
            ["ssh-add", "-L"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def routeros_batch_auth_works(ip: str, user: str) -> bool:
    """
    Einmaliger READ-ONLY-Preflight fuer den aktuellen Launcher-Lauf.

    BatchMode verhindert garantiert einen Passwortprompt. Der Remote-Befehl
    schreibt nichts; :put gibt lediglich einen Text aus.
    """
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no",
                "-o", "ConnectTimeout=5",
                "-o", "ConnectionAttempts=1",
                "-o", "StrictHostKeyChecking=accept-new",
                f"{user}@{ip}",
                ':put "NETCHECKER_READONLY_OK"',
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=SSH_PREFLIGHT_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

    return (
        result.returncode == 0
        and "NETCHECKER_READONLY_OK" in result.stdout
    )


def resolve_automatic_routeros_targets() -> list[tuple[str, str]]:
    """
    Entscheidet einmal beim Start, welche RouterOS-Geraete automatisch
    ausgelesen werden duerfen.

    Wichtig: Ohne lokale SSH-Key-/Agent-Identitaet gibt es keinerlei
    Authentifizierungsversuch gegen das Produktionsgeraet.
    """
    candidates = discover_routeros_candidates()
    if not candidates:
        return []

    if not ssh_identity_available():
        print(
            "Topologie: RouterOS erkannt, aber keine passwortfreie SSH-Identitaet "
            "vorhanden. Automatische RouterOS-Abfrage bleibt deaktiviert."
        )
        print(
            "           Lokale/passive Topologie laeuft trotzdem automatisch; "
            "manuelle RouterOS-Abfragen bleiben weiterhin moeglich."
        )
        return []

    approved: list[tuple[str, str]] = []
    for ip, user in candidates:
        if routeros_batch_auth_works(ip, user):
            approved.append((ip, user))
            print(
                f"Topologie: {user}@{ip} fuer automatische READ-ONLY-"
                "RouterOS-Abfragen freigegeben (SSH-Key/Agent)."
            )
        else:
            print(
                f"Topologie: {user}@{ip} nicht automatisch abgefragt: "
                "keine passwortfreie SSH-Anmeldung."
            )

    return approved


def build_topology_command(
    automatic_routeros_targets: Iterable[tuple[str, str]],
) -> list[str]:
    command = [
        sys.executable,
        str(TOPOLOGY_PATH),
        "--json-out",
    ]

    # Die aktuelle topology.py verarbeitet ein RouterOS-Ziel pro Snapshot.
    # Deshalb nehmen wir fuer Phase 3 zunaechst genau ein automatisch
    # authentifizierbares Ziel. Weitere Router koennen spaeter ueber das
    # Quellenmodell ergaenzt werden.
    targets = list(automatic_routeros_targets)
    if targets:
        ip, user = targets[0]
        command.extend([
            "--routeros", ip,
            "--routeros-user", user,
        ])

    return command


def run_topology_cycle(
    automatic_routeros_targets: Iterable[tuple[str, str]],
) -> int:
    """Startet einen vollstaendigen Topologie-Snapshot als eigenen Prozess."""
    print_header("Automatischer Topologie-Lauf")
    print("Betriebsmodus.: PRODUKTION / READ-ONLY")
    print("Intervall.....: 30 Minuten")
    print("Startbedingung: kein laufender NetChecker-Scan")

    command = build_topology_command(automatic_routeros_targets)

    # stdin bleibt am Terminal. Ein RouterOS-Ziel wird hier aber nur dann
    # angehaengt, wenn der Batch-Preflight bereits passwortfrei funktioniert
    # hat; dadurch entsteht im Automatikbetrieb kein Passwortprompt.
    result = subprocess.run(command)

    if result.returncode == 0:
        print("Topologie.....: erfolgreich gespeichert")
    elif result.returncode == 2:
        print("Topologie.....: PARTIAL gespeichert")
    else:
        print(f"Topologie.....: Fehler, Exit-Code {result.returncode}")

    return result.returncode


def run_classification_reconcile() -> int:
    """Wendet nur lokal gespeicherte Topologie-Hinweise an; kein Netzwerkzugriff."""
    result = subprocess.run([
        sys.executable,
        str(TOPOLOGY_PATH),
        "--reconcile-only",
    ])
    return result.returncode


def run_serial_classification_reconcile(core: subprocess.Popen) -> bool:
    """Reconciled die Klassifikation nur in einem scanfreien SQLite-Fenster."""
    if scan_is_running() or core.poll() is not None:
        return False

    core.send_signal(signal.SIGSTOP)
    time.sleep(0.1)

    try:
        if scan_is_running():
            return False
        run_classification_reconcile()
        return True
    finally:
        if core.poll() is None:
            core.send_signal(signal.SIGCONT)


def run_serial_topology_cycle(
    core: subprocess.Popen,
    automatic_routeros_targets: Iterable[tuple[str, str]],
) -> bool:
    """
    Garantiert, dass der Core waehrend des Topologie-Laufs keinen neuen Scan
    beginnt. Der Core wird nur in einem bereits scanfreien Fenster kurz mit
    SIGSTOP angehalten und danach mit SIGCONT fortgesetzt.

    Rueckgabe:
        True  -> Topologie wurde gestartet.
        False -> Es lief doch noch ein Scan; Lauf wurde verschoben.
    """
    if scan_is_running():
        return False

    if core.poll() is not None:
        return False

    core.send_signal(signal.SIGSTOP)
    time.sleep(0.2)

    try:
        # Zweite Kontrolle nach dem Anhalten schliesst das kleine Zeitfenster
        # zwischen erster DB-Pruefung und SIGSTOP.
        if scan_is_running():
            return False

        run_topology_cycle(automatic_routeros_targets)
        return True
    finally:
        if core.poll() is None:
            core.send_signal(signal.SIGCONT)


def start_core() -> subprocess.Popen:
    command = [sys.executable, str(CORE_PATH), *sys.argv[1:]]
    return subprocess.Popen(command, cwd=BASE_DIR)


def stop_core(core: subprocess.Popen, timeout: float = 10.0) -> None:
    if core.poll() is not None:
        return

    core.send_signal(signal.SIGINT)

    try:
        core.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass

    core.terminate()
    try:
        core.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        core.kill()
        core.wait()


def main() -> int:
    ensure_required_files()

    print_header("NetChecker")
    print("Scanner.......: netchecker_core.py")
    print("Topologie.....: automatisch integriert")
    print("Topologie-Takt: 30 Minuten")
    print("Evidenz-Overlay: lokal alle 60 Sekunden")
    print("Produktionsnet: READ-ONLY fuer Infrastruktur")
    print("JSON..........: data/topology_latest.json")

    automatic_routeros_targets = resolve_automatic_routeros_targets()

    core = start_core()
    next_topology_at = time.monotonic() + INITIAL_TOPOLOGY_DELAY_SECONDS
    next_reconcile_at = time.monotonic() + INITIAL_RECONCILE_DELAY_SECONDS

    try:
        while True:
            return_code = core.poll()
            if return_code is not None:
                print()
                print(
                    f"NetChecker-Core wurde beendet (Exit-Code {return_code}). "
                    "Launcher wird ebenfalls beendet."
                )
                return return_code

            now = time.monotonic()

            if now >= next_topology_at:
                if run_serial_topology_cycle(
                    core,
                    automatic_routeros_targets,
                ):
                    next_topology_at = (
                        time.monotonic() + TOPOLOGY_INTERVAL_SECONDS
                    )
                    # Der volle Topologielauf reconciled bereits mit.
                    next_reconcile_at = (
                        time.monotonic() + CLASSIFICATION_RECONCILE_INTERVAL_SECONDS
                    )
                else:
                    # Core war doch noch beschaeftigt. Nur kurz verschieben,
                    # nicht einen parallelen Lauf erzwingen.
                    next_topology_at = now + IDLE_RECHECK_SECONDS

            elif now >= next_reconcile_at:
                if run_serial_classification_reconcile(core):
                    next_reconcile_at = (
                        time.monotonic() + CLASSIFICATION_RECONCILE_INTERVAL_SECONDS
                    )
                else:
                    next_reconcile_at = now + IDLE_RECHECK_SECONDS

            time.sleep(SUPERVISOR_TICK_SECONDS)

    except KeyboardInterrupt:
        print("\nNetChecker wird beendet ...")
        stop_core(core)
        return 130
    finally:
        if core.poll() is None:
            stop_core(core)


if __name__ == "__main__":
    raise SystemExit(main())
