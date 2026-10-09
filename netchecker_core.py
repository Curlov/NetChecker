import ipaddress
import time

from classification_store import (
    classify_and_store_inventory,
    init_classification_tables,
)

from database import (
    abort_scan_run,
    detect_detail_changes,
    detect_discovery_changes,
    fail_scan_run,
    finish_scan_run,
    get_connection,
    init_database,
    recover_interrupted_scan_runs,
    save_discovery_host,
    save_network,
    save_os_information,
    save_port_scan,
    start_scan_run,
)

from enrichment import (
    get_enrichment_targets,
    init_enrichment_status_table,
    run_enrichment,
)

from network import (
    get_default_route,
    get_interface_info,
)

from output import print_device

from scanner import (
    scan_host_details,
    scan_network,
)

from vendor import get_vendor_from_mac
from local_host import enrich_local_host

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


        return hosts


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

def run_detail_cycle(
    connection,
    network_id,
    hosts
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
        "detail"
    )


    total_hosts = len(
        hosts
    )

    processed_hosts = 0
    failed_hosts = 0


    try:

        print()
        print("=" * 80)
        print("Detail-Scan")
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


                save_port_scan(
                    connection,
                    network_id,
                    scan_run_id,
                    host
                )


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
                    ]
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
# Enrichment
# ==========================================================

def run_enrichment_cycle(
    connection,
    network_id
):
    """
    Prüft nach dem Detail-Scan, welche Geräte noch
    zusätzliche OS-Erkennung benötigen.

    Bereits bekannte Betriebssysteme werden nicht
    erneut untersucht.
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

def main():

    connection = get_connection()


    try:

        # ==================================================
        # Datenbank
        # ==================================================

        init_database(
            connection
        )


        init_classification_tables(
            connection
        )


        init_enrichment_status_table(
            connection
        )


        recover_interrupted_scan_runs(
            connection
        )


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
            f"{DISCOVERY_INTERVAL_SECONDS // 60} Minuten"
        )


        print(
            f"Detail.......: alle "
            f"{DETAIL_INTERVAL_SECONDS // 60} Minuten"
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
                        + DISCOVERY_INTERVAL_SECONDS
                    )


                else:

                    next_discovery_at = (
                        time.monotonic()
                        + DISCOVERY_RETRY_SECONDS
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

                detail_ok = (
                    run_detail_cycle(
                        connection,
                        network_id,
                        latest_hosts
                    )
                )


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
                    + DETAIL_INTERVAL_SECONDS
                )


            time.sleep(
                MAIN_LOOP_SLEEP_SECONDS
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