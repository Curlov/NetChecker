# Entwicklungsstand

Alle acht vorgeschlagenen Entwicklungsschritte sind im Quellcode bearbeitet:

1. Reentrante kooperative Schreibsperren und Scanner-Lebenszeitsperre; kein SIGSTOP.
2. Wiederholbare Port-/Discovery-Vergleiche, konservative Missing-Erkennung und
   verschachtelte Transaktionen mit Savepoints.
3. Netzwerk-/Bereichsbezug in Topologiezuordnungen; optionaler API-Schlüssel und
   Bereichsfreigabe; eindeutig benannte Kundennetze in der Oberfläche.
4. Schema-Version 4, Migrationstagebuch, Trigger-/Indexerhalt und Wiederaufbau
   historischer Service-Metadaten ohne Überschreiben neuerer Projektionen.
5. Service-/Skript-/CPE-Auswertung, getrennte OS-Eigenschaften, Aktualität und
   Konflikte; ausreichend vorhandene Service-Evidenz verhindert unnötiges DEEP.
6. Unsichere MAC-lose Zuordnungen nachvollziehbar; keine Fusion aufgrund IP allein;
   Schnittstellen und lokale Identitätsanker für nachgewiesene MAC-Wechsel.
7. MAC-/OS-Evidenz und Service-/Identitätshistorie in der Weboberfläche;
   Detailaktualisierung bei erhaltener Auswahl.
8. Interaktiver SVG-Topologiegraph, Snapshotvergleich, lokale JSON-Ereignislogs
   sowie sichere SQLite-Backups und getrennte Bereichsarchive.

Validierung: Offline-Unittests, direkte ASGI-Aufrufe ohne Webserver,
synthetische Migrationen und Sperr-Testprozesse. Keine produktiven Scans,
SSH-Abfragen, Datenbankmigrationen oder Dienstneustarts wurden ausgeführt.

Die Übernahme in den laufenden Betrieb ist offen und erfordert eine eigene
Betriebsfreigabe. Einschränkungen: keine individuelle Benutzerverwaltung,
keine automatische Dublettenfusion ohne starke Evidenz, kein automatischer
Archivimport und keine Ableitung garantierter Erreichbarkeit aus Firewallregeln.
Die im Browser angezeigten Historien sind begrenzte Auszüge; vollständige Daten
bleiben in SQLite und in ausdrücklich erzeugten Archiven erhalten.
