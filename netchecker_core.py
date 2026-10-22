import ipaddress
import json
import logging
import time
from runtime_lock import exclusive_cycle, inventory_lock, single_scanner

from classification_store import (
    classify_and_store_inventory,
)

from database import (
    abort_scan_run,
    detect_detail_changes,
    detect_discovery_changes,
    detect_known_port_changes,
    fail_scan_run,
    finish_scan_run,
    get_connection,
    get_historically_open_tcp_ports,
    recover_interrupted_scan_runs,
    save_discovery_host,
    save_network,
    save_os_information,
    save_port_scan,
    start_scan_run,
)

from enrichment import (
    get_enrichment_targets,
    run_enrichment,
)

from network import (
    get_default_route,
    get_interface_info,
)

from output import print_device

from scanner import (
    scan_known_tcp_ports,
    scan_host_details,
    scan_network,
)

from vendor import get_vendor_from_mac
from local_host import enrich_local_host
from runtime_config import DATABASE_PATH
from netchecker_config import timing_value
from startup_migrations import migrate_connection_for_startup

logger = logging.getLogger(__name__)

# ==========================================================
# Dauerbetrieb
# ==========================================================

DISCOVERY_INTERVAL_SECONDS = 5 * 60
DETAIL_INTERVAL_SECONDS = 30 * 60

MAIN_LOOP_SLEEP_SECONDS = 1
DISCOVERY_RETRY_SECONDS = 30


# ==========================================================
# Hilfsfunktionen
# ==========================================================

def sort_hosts(hosts):
    """
    Sortiert Hosts numerisch nach ihrer IP-Adresse.
    """

    def sort_key(host):

        ip_address = host.get(
            "ip"
        )

        if not ip_address:

            return (
                1,
                0
            )

        try:

            return (
                0,
                int(
                    ipaddress.ip_address(
                        ip_address
                    )
                )
            )

        except ValueError:

            return (
                1,
                0
            )


    return sorted(
        hosts,
        key=sort_key
    )


def count_changes_for_run(
    connection,
    scan_run_id
):
    """
    Zählt Änderungen eines bestimmten Scan-Runs.
    """

    row = connection.execute(
        """
        SELECT COUNT(*) AS count

        FROM changes

        WHERE scan_run_id = ?
        """,
        (scan_run_id,)
    ).fetchone()


    if row is None:

        return 0


    return int(
        row["count"]
    )


# ==========================================================
# Klassifikation
# ==========================================================

@exclusive_cycle
def run_classification_cycle(
    connection,
    network_id,
    reason
):
    """
    Klassifiziert das aktuelle DB-Inventar.

    Dabei entsteht kein Netzwerkverkehr.
    """

    result = classify_and_store_inventory(
        connection,
        network_id
    )


    print()

    print(
        f"Klassifikation ({reason}): "
        f"{result['evaluated']} Geräte geprüft, "
        f"{result['changed']} geändert."
    )


    return result


# ==========================================================
# Discovery
# ==========================================================

@exclusive_cycle
def run_discovery_cycle(
    connection,
    network_id,
    interface_info
):
    """
    Führt einen Discovery-Lauf aus.

    Rückgabe:
        Hostliste bei Erfolg
        None bei Fehler
    """

    scan_run_id = start_scan_run(
        connection,
        network_id,
        "discovery"
    )

    known_device_ids = {row['device_id'] for row in connection.execute(
        'SELECT DISTINCT device_id FROM addresses WHERE network_id=?', (network_id,))}


    try:

        print()
        print("=" * 80)
        print("Discovery")
        print("=" * 80)

        print(
            f"Netz.........: "
            f"{interface_info['network']}"
        )

        print(
            f"Scan-Run-ID..: "
            f"{scan_run_id}"
        )

        print()


        hosts = scan_network(
            interface_info[
                "network"
            ]
        )

        # Eigene Schnittstelleninformationen ergänzen.
        # Keine zusätzlichen Netzwerkabfragen.
        hosts = enrich_local_host(
            hosts,
            interface_info["interface"]
        )


        # Ein Null-Treffer darf niemals bedeuten:
        # "Alle Geräte sind verschwunden".
        if not hosts:

            raise RuntimeError(
                "Discovery hat keine Geräte gefunden."
            )


        hosts = sort_hosts(
            hosts
        )


        total_hosts = len(
            hosts
        )

        processed_hosts = 0
        failed_hosts = 0


        print(
            f"Gefundene Geräte: "
            f"{total_hosts}"
        )

        print()


        for index, host in enumerate(
            hosts,
            start=1
        ):

            ip_address = host.get(
                "ip"
            )


            try:

                mac_address = host.get(
                    "mac"
                )


                # Lokale IEEE-OUI-Datenbank verwenden.
                if mac_address:

                    vendor = get_vendor_from_mac(
                        mac_address
                    )


                    if vendor:

                        host[
                            "vendor"
                        ] = vendor


                device_id = save_discovery_host(
                    connection,
                    network_id,
                    scan_run_id,
                    host
                )


                # Die folgenden Scan-Stufen arbeiten intern
                # mit device_id.
                host[
                    "device_id"
                ] = device_id
                host['new_device'] = device_id not in known_device_ids
                known_device_ids.add(device_id)


                processed_hosts += 1


                print(
                    f"[{index:02d}/{total_hosts:02d}] "
                    f"{ip_address or '-'}"
                )


            except Exception as error:

                failed_hosts += 1


                print(
                    f"[{index:02d}/{total_hosts:02d}] "
                    f"{ip_address or '-'} "
                    f"- Fehler: {error}"
                )


        # Confirm only ports that have at some point been observed open.
        # Discovery has already confirmed these devices are reachable. The
        # targeted checks are serial and each device failure is isolated.
        known_port_targets = []
        for host in hosts:
            device_id = host.get("device_id")
            if device_id is None or not host.get("ip"):
                continue
            ports = get_historically_open_tcp_ports(connection,network_id,device_id)
            if ports:
                known_port_targets.append((host,ports))

        port_check_started = time.monotonic()
        port_check_failures = 0
        for index, (host, ports) in enumerate(known_port_targets,start=1):
            try:
                result = scan_known_tcp_ports(host['ip'],ports)
                metadata = (result or {}).get('scan_metadata') or {}
                if result and metadata.get('complete'):
                    # This probe is state-only; Nmap's service table labels
                    # are not active service/version detection and must not
                    # replace richer enrichment data.
                    state_only_ports = [{key:port.get(key) for key in ('protocol','port','state')}
                                        for port in result.get('ports') or ()]
                    save_port_scan(connection,network_id,scan_run_id,
                        dict(result,device_id=host['device_id'],ip=host['ip'],ports=state_only_ports),
                        source='nmap_discovery_known_ports',
                        observation_type='known_tcp_port_scan',infer_os=False)
                    status = 'vollständig'
                else:
                    port_check_failures += 1
                    status = 'unvollständig'
                    connection.execute("""INSERT INTO observations(network_id,device_id,scan_run_id,
                        observation_type,source,data_json)
                        VALUES(?,?,?,'known_tcp_port_scan_attempt','nmap_discovery_known_ports',?)""",
                        (network_id,host['device_id'],scan_run_id,json.dumps({
                            'ip':host['ip'],'status':status,'requested_ports':ports,
                            'scan_metadata':metadata},ensure_ascii=False)))
            except Exception as error:
                port_check_failures += 1
                status = 'Fehler'
                logger.warning('Gezielte Portprüfung für %s fehlgeschlagen: %s',host['ip'],error)
                connection.execute("""INSERT INTO observations(network_id,device_id,scan_run_id,
                    observation_type,source,data_json)
                    VALUES(?,?,?,'known_tcp_port_scan_attempt','nmap_discovery_known_ports',?)""",
                    (network_id,host['device_id'],scan_run_id,json.dumps({
                        'ip':host['ip'],'status':status,'requested_ports':ports,
                        'error_type':type(error).__name__},ensure_ascii=False)))
            print(f"  Portprüfung [{index:02d}/{len(known_port_targets):02d}] "
                  f"{host['ip']}: {len(ports)} bekannte TCP-Ports, {status}")

        port_check_elapsed = time.monotonic() - port_check_started
        if known_port_targets:
            print(f"Gezielte Portprüfungen: {len(known_port_targets)} Geräte, "
                  f"{port_check_failures} Fehler/unvollständig, {port_check_elapsed:.1f}s")
            logger.info('Gezielte Portprüfungen: %s Geräte, %s Fehler/unvollständig, %.1fs',
                        len(known_port_targets),port_check_failures,port_check_elapsed)
        if port_check_elapsed > timing_value('discovery_interval_seconds'):
            logger.warning('Gezielte Portprüfungen dauerten %.1fs und überschritten das Discovery-Intervall.',
                           port_check_elapsed)


        finish_scan_run(
            connection,
            scan_run_id,
            hosts_found=total_hosts,
            hosts_processed=processed_hosts,
            hosts_failed=failed_hosts
        )


        # Erst abgeschlossene Discovery-Runs vergleichen.
        detect_discovery_changes(
            connection,
            network_id,
            scan_run_id
        )

        detect_known_port_changes(connection,network_id,scan_run_id)


        change_count = count_changes_for_run(
            connection,
            scan_run_id
        )


        print()

        print(
            f"Discovery abgeschlossen: "
            f"{processed_hosts}/{total_hosts} gespeichert, "
            f"{failed_hosts} Fehler, "
            f"{change_count} bestätigte Änderungen."
        )


        return [host for host in hosts if host.get("device_id") is not None]


    except KeyboardInterrupt:

        abort_scan_run(
            connection,
            scan_run_id
        )

        raise


    except Exception as error:

        fail_scan_run(
            connection,
            scan_run_id,
            error
        )


        print()

        print(
            f"Discovery fehlgeschlagen: "
            f"{error}"
        )


        return None


# ==========================================================
# Detail-Scan
# ==========================================================

@exclusive_cycle
def run_detail_cycle(
    connection,
    network_id,
    hosts,
    *,
    scan_type='detail',
    successful_device_ids=None,
):
    """
    Führt wiederkehrende Detail-Scans durch.

    Der Detail-Scan sammelt vor allem:

    - offene Ports
    - Services
    - Produkte
    - Versionen

    Ein vorhandenes OS darf dabei niemals durch
    einen Scan ohne OS-Ergebnis überschrieben werden.
    """

    if not hosts:

        return False


    scan_run_id = start_scan_run(
        connection,
        network_id,
        scan_type
    )


    total_hosts = len(
        hosts
    )

    processed_hosts = 0
    failed_hosts = 0


    try:

        print()
        print("=" * 80)
        print("Erstscan neuer Geräte" if scan_type == 'detail_initial' else "Detail-Scan")
        print("=" * 80)

        print(
            f"Geräte.......: "
            f"{total_hosts}"
        )

        print(
            f"Scan-Run-ID..: "
            f"{scan_run_id}"
        )

        print()


        for index, host in enumerate(
            hosts,
            start=1
        ):

            ip_address = host.get(
                "ip"
            )


            print()

            print(
                f"[{index:02d}/{total_hosts:02d}] "
                f"Untersuche "
                f"{ip_address or '-'}..."
            )


            try:

                details = scan_host_details(
                    ip_address
                )


                if details is None:

                    failed_hosts += 1

                    print(
                        "  Kein verwertbares "
                        "Detail-Ergebnis."
                    )

                    continue


                # ==================================================
                # Ports
                # ==================================================

                host[
                    "ports"
                ] = (
                    details.get(
                        "ports"
                    )
                    or []
                )


                host["scan_metadata"] = details.get("scan_metadata", {})

                save_port_scan(
                    connection,
                    network_id,
                    scan_run_id,
                    host
                )
                if successful_device_ids is not None:
                    successful_device_ids.add(host['device_id'])


                # ==================================================
                # OS
                #
                # WICHTIG:
                #
                # Der schnelle normale Detail-Scan macht
                # normalerweise keine OS-Erkennung.
                #
                # Ein fehlendes Ergebnis bedeutet daher NICHT:
                #
                #     "Das Gerät hat kein bekanntes OS."
                #
                # Es bedeutet lediglich:
                #
                #     "Dieser Scan hat kein neues OS geliefert."
                #
                # Deshalb speichern wir NUR ein echtes
                # OS-Ergebnis.
                #
                # Ein früher durch Enrichment erkanntes OS
                # bleibt dadurch dauerhaft erhalten.
                # ==================================================

                detected_os = details.get(
                    "os"
                )


                host[
                    "os"
                ] = detected_os


                if (
                    detected_os
                    and detected_os.get(
                        "name"
                    )
                ):

                    save_os_information(
                        connection,
                        network_id,
                        scan_run_id,
                        host
                    )


                processed_hosts += 1


                # print_device liest wieder aus SQLite.
                #
                # Dadurch erscheint hier auch ein früher
                # durch Enrichment erkanntes OS.
                print_device(
                    connection,
                    host[
                        "device_id"
                    ],
                    network_id=network_id,
                )


            except KeyboardInterrupt:

                raise


            except Exception as error:

                failed_hosts += 1


                print(
                    f"  Fehler bei "
                    f"{ip_address or '-'}: "
                    f"{error}"
                )


        # ==================================================
        # Scan abschließen
        # ==================================================

        finish_scan_run(
            connection,
            scan_run_id,
            hosts_found=total_hosts,
            hosts_processed=processed_hosts,
            hosts_failed=failed_hosts
        )


        # ==================================================
        # Port-/Service-Änderungen
        # ==================================================

        detect_detail_changes(
            connection,
            network_id,
            scan_run_id
        )


        change_count = count_changes_for_run(
            connection,
            scan_run_id
        )


        print()
        print("=" * 80)

        print(
            f"Detail-Scan abgeschlossen: "
            f"{processed_hosts}/{total_hosts} erfolgreich, "
            f"{failed_hosts} Fehler."
        )

        print(
            f"Port-/Service-Änderungen: "
            f"{change_count}"
        )

        print("=" * 80)


        return True


    except KeyboardInterrupt:

        abort_scan_run(
            connection,
            scan_run_id
        )

        raise


    except Exception as error:

        fail_scan_run(
            connection,
            scan_run_id,
            error
        )


        print()

        print(
            f"Detail-Scan fehlgeschlagen: "
            f"{error}"
        )


        return False


# ==========================================================
# Erstscan nach Discovery
# ==========================================================

def run_initial_detail_cycle(connection, network_id, discovered_hosts):
    """Scan newly created devices once, independently of the regular timer."""
    new_hosts = []
    seen_ids = set()
    for host in discovered_hosts:
        device_id = host.get('device_id')
        if (host.get('new_device') and device_id is not None and host.get('ip')
                and device_id not in seen_ids):
            new_hosts.append(host)
            seen_ids.add(device_id)
    if not new_hosts:
        return set()

    successful_device_ids = set()
    if run_detail_cycle(connection, network_id, new_hosts, scan_type='detail_initial',
                        successful_device_ids=successful_device_ids):
        run_classification_cycle(connection, network_id, 'nach Erstscan')
    return successful_device_ids


# ==========================================================
# Enrichment
# ==========================================================

@exclusive_cycle
def run_enrichment_cycle(
    connection,
    network_id
):
    """
    Prüft nach dem Detail-Scan, welche Geräte noch
    zusätzliche OS- oder Service-Erkennung benötigen.

    Bereits bekannte Betriebssysteme werden nicht erneut untersucht;
    fehlende Serviceinformationen werden unabhängig davon ausgewählt.
    """

    targets, stats = get_enrichment_targets(
        connection,
        network_id
    )


    print()

    print(
        "Enrichment-Prüfung: "
        f"{len(targets)} Kandidat(en)."
    )


    print(
        f"  OS bekannt............: "
        f"{stats['os_known']}"
    )

    print(
        f"  sicher klassifiziert..: "
        f"{stats['classified']}"
    )

    print(
        f"  OS erfolglos versucht.: "
        f"{stats['no_os_detected']}"
    )
    print(f"  Service-LIGHT..........: {stats['service_targets']}")
    print(f"  Service später (Budget): {stats['service_deferred']}")


    if not targets:

        return False


    run_enrichment(
        connection,
        network_id,
        targets
    )


    return True


# ==========================================================
# Hauptprogramm
# ==========================================================

@single_scanner
def main():

    connection = get_connection()


    try:

        # ==================================================
        # Datenbank
        # ==================================================

        with inventory_lock():
            migrate_connection_for_startup(
                connection, DATABASE_PATH, component='scanner'
            )
            recover_interrupted_scan_runs(connection)


        # ==================================================
        # Netzwerk
        # ==================================================

        route = get_default_route()


        if not route:

            print(
                "Keine Default-Route gefunden."
            )

            return


        interface_name = route.get(
            "interface"
        )


        gateway = route.get(
            "gateway"
        )


        if not interface_name:

            print(
                "Keine Netzwerkschnittstelle gefunden."
            )

            return


        interface_info = get_interface_info(
            interface_name
        )


        if not interface_info:

            print(
                "Netzwerkinformationen konnten "
                "nicht ermittelt werden."
            )

            return


        network_id = save_network(
            connection,
            interface_info[
                "network"
            ],
            interface_info[
                "interface"
            ],
            gateway
        )


        # ==================================================
        # Startinformationen
        # ==================================================

        print()
        print("=" * 80)
        print("NetChecker Dauerbetrieb")
        print("=" * 80)


        print(
            f"Interface....: "
            f"{interface_info['interface']}"
        )


        print(
            f"IP...........: "
            f"{interface_info['ip']}"
        )


        print(
            f"MAC..........: "
            f"{interface_info['mac']}"
        )


        print(
            f"Netz.........: "
            f"{interface_info['network']}"
        )


        print(
            f"Gateway......: "
            f"{gateway or '-'}"
        )


        print(
            f"Discovery....: alle "
            f"{int(timing_value('discovery_interval_seconds') // 60)} Minuten"
        )


        print(
            f"Detail.......: alle "
            f"{int(timing_value('detail_interval_seconds') // 60)} Minuten"
        )


        print(
            "Enrichment...: nach Detail, "
            "nur bei Bedarf"
        )


        print("=" * 80)


        # ==================================================
        # Bereits vorhandene Daten klassifizieren
        # ==================================================

        run_classification_cycle(
            connection,
            network_id,
            "Start"
        )


        # ==================================================
        # Scheduler
        # ==================================================

        latest_hosts = []


        next_discovery_at = 0.0
        next_detail_at = 0.0


        while True:

            now = time.monotonic()
            initially_scanned_ids = set()


            # ==================================================
            # Discovery
            # ==================================================

            if (
                now
                >= next_discovery_at
            ):

                discovered_hosts = (
                    run_discovery_cycle(
                        connection,
                        network_id,
                        interface_info
                    )
                )


                if (
                    discovered_hosts
                    is not None
                ):

                    latest_hosts = (
                        discovered_hosts
                    )


                    run_classification_cycle(
                        connection,
                        network_id,
                        "nach Discovery"
                    )

                    next_discovery_at = (
                        time.monotonic()
                        + timing_value("discovery_interval_seconds")
                    )

                    initially_scanned_ids = run_initial_detail_cycle(
                        connection, network_id, latest_hosts
                    )


                else:

                    next_discovery_at = (
                        time.monotonic()
                        + timing_value("discovery_retry_seconds")
                    )


            # ==================================================
            # Detail
            # ==================================================

            now = time.monotonic()


            if (
                latest_hosts
                and now
                >= next_detail_at
            ):

                regular_hosts = [host for host in latest_hosts
                                 if host['device_id'] not in initially_scanned_ids]
                detail_ok = (run_detail_cycle(connection, network_id, regular_hosts)
                             if regular_hosts else True)


                if detail_ok:

                    # Neue Ports und Services berücksichtigen.
                    run_classification_cycle(
                        connection,
                        network_id,
                        "nach Detail"
                    )


                    # Fehlende Informationen gezielt
                    # nachermitteln.
                    enrichment_ran = (
                        run_enrichment_cycle(
                            connection,
                            network_id
                        )
                    )


                    # Falls Enrichment OS-Informationen
                    # geliefert hat:
                    if enrichment_ran:

                        run_classification_cycle(
                            connection,
                            network_id,
                            "nach Enrichment"
                        )


                next_detail_at = (
                    time.monotonic()
                    + timing_value("detail_interval_seconds")
                )


            time.sleep(
                timing_value("main_loop_sleep_seconds")
            )


    except KeyboardInterrupt:

        print()
        print()

        print(
            "NetChecker wird beendet."
        )


    finally:

        connection.close()


if __name__ == "__main__":
    main()
