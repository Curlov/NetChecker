# NetChecker

Lokales Python-System für Netzwerk-Inventarisierung, historische Beobachtungen,
evidenzbasierte Geräteklassifikation und Topologie. Python 3.10 oder neuer,
Linux, SQLite mit JSON-/Window-Funktionen und Nmap werden vorausgesetzt.
Die Python-Abhängigkeiten stehen in `requirements.txt`; die Versionsangaben
entsprechen der bei der Umsetzung vorhandenen virtuellen Umgebung.

## Architektur

`netchecker.py` startet den kontinuierlichen Core und koordiniert lokale
Topologie-/Klassifikationsarbeit. Discovery, Detail und Enrichment laufen seriell;
fünf bzw. 30 Minuten sind Wartezeiten nach Abschluss. Lange Scans verschieben
die nächste Discovery. Der schnelle Detail-Scan verwendet 100 häufige TCP-Ports.
Service-/OS-Erkennung erfolgt im LIGHT-/DEEP-Enrichment.

Service-LIGHT wird zusätzlich unabhängig vom gespeicherten Betriebssystem und
der Geräteklassifikation ausgewählt. Es untersucht ausschließlich bereits
bekannte offene TCP-Ports, ohne OS-Fingerprinting oder zusätzliche NSE-Skripte.
Standardmäßig werden maximal vier Geräte pro Enrichment-Zyklus ausgewählt.
Vollständige Serviceprüfungen bleiben sieben Tage gültig; neu erkannte Ports
werden separat nachgezogen. Technische Fehler werden frühestens nach einer
Stunde erneut versucht. Vorhandene Produkt-/Versionsdaten und OS-Entscheidungen
bleiben erhalten. Diese Auswahl tritt erst mit der Übernahme des geänderten
Python-Codes in den laufenden Betrieb in Kraft.

`schema.py` koordiniert Schema-Version 4 einschließlich rückwärtskompatibler
Migrationen. Wiederholte Initialisierung einer aktuellen Datenbank schreibt nicht.
`observations` bewahrt Rohbeobachtungen, `port_inventory` die netzwerkbezogene
Projektion. Die ältere Tabelle `ports` bleibt als Kompatibilitätstabelle erhalten.
`os_claims` trennt Familie, Kernel, Distribution und Distributionsversion.
Servicebanner sind Hinweise; lokal ausgelesene OS-Release-Daten sind bestätigt.
Ein Banner kann zu einem Container oder Dienst gehören und beweist deshalb
nicht zwingend das Betriebssystem des gesamten Rechners.

Ein bestätigtes Gerät ist nicht automatisch eine bestätigte Zuordnung jeder
späteren IP-Beobachtung. MAC-lose Beobachtungen bleiben als unsichere Evidenz
kenntlich. Eine neue MAC wird nicht allein aufgrund einer früheren IP/Hostname-
Übereinstimmung mit einer alten Identität zusammengeführt. MAC-Wechsel des
lokalen NetCheckers können über den lokalen Identitätsanker korreliert werden.
Ohne starke Evidenz bleiben mögliche Dubletten als Kandidaten bestehen.

## Offline prüfen

```bash
.venv/bin/python -B -m unittest discover -v
```

Die Tests nutzen ausschließlich temporäre oder In-Memory-Datenbanken,
synthetisches XML, direktes ASGI und lokale Sperr-Testprozesse. Sie starten
weder Nmap noch SSH, Uvicorn oder produktive Dienste. JavaScript kann mit
einem vorhandenen Node.js geprüft werden (`node --check web/static/app.js`).
Node.js ist keine Laufzeitabhängigkeit. Die Oberfläche benötigt einen modernen
Browser mit SVG, Pointer Events und DOMPoint.
Bei vorhandenem Node.js prüft `node tests/frontend_harness.js` Auswahl,
Filtererhalt und Detailaktualisierung gegen eine synthetische DOM-/API-Umgebung.

## Betriebsfreigabe und Migration

Beim normalen Start migrieren Scanner und API ein älteres Schema vor Beginn ihrer
Arbeit. Die API nimmt erst nach erfolgreicher Migration und Schema-Prüfung
Requests an; ein Update bleibt daher nicht allein wegen einer fehlenden Migration
bei 503. Beide Startpfade verwenden dieselbe dateibasierte Inventarsperre wie die
übrigen koordinierten Schreibvorgänge.

Vor einer Änderung an einer vorhandenen Datenbank erstellt NetChecker im selben
Verzeichnis eine eindeutige Sicherung über die SQLite-Backup-API. Die Sicherung
enthält bestätigte WAL-Daten, wird auf Integrität und Fremdschlüssel geprüft,
mit Modus 0600 angelegt und niemals überschrieben. Danach läuft die
Schemaänderung transaktional. Bei einem Fehler wird sie zurückgerollt, die
Sicherung bleibt erhalten und der Prozess startet nicht mit einem unvollständigen
Schema. Startprotokolle nennen Schema-Version, Komponente und Sicherungspfad.
Sicherungen bleiben lokal liegen und müssen nach betrieblicher Prüfung manuell
aufbewahrt oder entfernt werden.

Die API öffnet ihre Datenbank zur Startmigration nur im vorhandenen
Read-write-Modus (`mode=rw`): Ein fehlender oder falsch konfigurierter Pfad wird
nicht stillschweigend als leere Datenbank neu angelegt. Die Requests selbst
verwenden weiterhin schreibgeschützte Verbindungen, abgesehen von den
ausdrücklichen Layout-Schreibendpunkten. Die manuelle Wartungsmigration bleibt
für Offline- und Verwaltungsabläufe verfügbar:

```bash
.venv/bin/python -B maintenance.py backup --database data/netchecker.db --out /sicherer/lokaler/pfad/inventar.db
.venv/bin/python -B maintenance.py init --database data/netchecker.db --allow-production
```

Die Sicherung verwendet die SQLite-Backup-API und berücksichtigt committed WAL-
Inhalte. Archive werden mit Dateimodus 0600 erstellt; vorhandene Ziele werden
nicht überschrieben. Backups dürfen nicht nach GitHub oder an externe Dienste
übertragen werden. Produktive Rohdaten sind keine Testfixtures.

Neue synthetische Datenbank, ohne Produktionszugriff:

```bash
.venv/bin/python -B maintenance.py init --database /tmp/netchecker-test.db
```

## Konfiguration

| Variable | Verhalten |
|---|---|
| `NETCHECKER_DATABASE` | Absoluter oder projektbezogener Datenbankpfad |
| `NETCHECKER_SCOPE_ID` | Explizit angelegter Kunden-/Standortbereich, Standard 1 |
| `NETCHECKER_ROUTEROS_TARGETS` | Nur ausdrücklich freigegebene IPs, kommagetrennt; leer deaktiviert SSH |
| `NETCHECKER_API_KEY` | Optionaler gemeinsamer API-Schlüssel im Header `X-Netchecker-Key` |
| `NETCHECKER_ALLOWED_SCOPES` | Sichtbare Bereichs-IDs für diese API-Installation, kommagetrennt |
| `NETCHECKER_ENRICHMENT_RETRY_DAYS` | Standard 0: keine automatische Wiederholung endgültiger Negativentscheidungen; positive Werte nur nach Scanfreigabe |
| `NETCHECKER_SERVICE_MAX_HOSTS` | Service-LIGHT-Budget je Zyklus, Standard 4; 0 deaktiviert die zusätzliche Stufe |
| `NETCHECKER_SERVICE_RETRY_DAYS` | Gültigkeit vollständiger Serviceprüfungen, Standard 7 Tage, mindestens 1 |
| `NETCHECKER_LOG_FILE` | Optionales lokales JSON-Ereignislog mit Rotation; sonst stderr |

Ohne API-Schlüssel ist die Oberfläche für eine vertrauenswürdige lokale Umgebung
ausgelegt. Für Kundenzugriff Schlüssel und Bereichsbeschränkung konfigurieren
und HTTPS vorsehen. Der Schlüssel wird im Browser nur im Eingabefeld der Sitzung
gehalten, nicht in URLs oder persistentem Browser-Speicher. Es gibt noch keine
Benutzerverwaltung mit individuellen Rollen; getrennte API-Installationen können
mit unterschiedlichen Bereichen und Schlüsseln betrieben werden.

`network_scopes` trennt Kunden/Standorte auch bei gleichen CIDRs und MACs.
Neue Bereiche werden bewusst nicht beim Finden unbekannter Netze automatisch
erzeugt. Nach Betriebsfreigabe kann ein Bereich parametrisiert lokal angelegt
und über `NETCHECKER_SCOPE_ID` ausgewählt werden. Eine Scope-ID muss existieren.
Hierfür steht `maintenance.py create-scope` mit `--customer`, `--site`, `--name`
und `--database` zur Verfügung; bei der produktiven Datenbank ist zusätzlich
`--allow-production` erforderlich. Der Vorgang startet keine Netzwerkerkennung.

## Web und Topologie

Die Oberfläche aktualisiert Übersicht, Netzwerkauswahl und geöffnete Details.
Auswahl und Filter bleiben erhalten. Sie zeigt MAC-Fakten, OS-Quellen, Konflikte,
Service-Metadaten, Identitätskandidaten und begrenzte Historienauszüge.
Die Gerätetyp-Auswahl zeigt deutsche Bezeichnungen und lokale Lucide-Icons auf
dunklem Hintergrund. Übersicht und Topologie verwenden dieselben zwölf
Geräteklassen-Symbole. Grün und Rot kennzeichnen den zuletzt gespeicherten
Anwesenheitsstatus; unbekannte Zustände bleiben grau. Die Klassen und Farben
beschreiben den aktuellen Inventarstatus, auch bei historischen Snapshots.

Veränderungen werden als ein logisches Ereignis pro Tabellenzeile angezeigt.
Portnummer, Protokoll und Dienst stehen im Vordergrund; die unveränderten
gespeicherten JSON-Daten sind über „Details“ aufklappbar. SQLite-Zeitpunkte werden
als UTC gelesen und im deutschen Datumsformat für Europe/Berlin einschließlich
Sommerzeit angezeigt. „Port nicht mehr offen“ wird als unsicherer Negativbefund
von einem ausdrücklich geschlossenen Port unterschieden.

Status-/Ereignis-Icons verwenden ausschließlich lokal gespeicherte Lucide-SVGs
in `web/static/vendor/lucide/`. Größe und Linienstärke sind einheitlich; Text
ergänzt stets die Farbgebung (Grün positiv, Rot negativ, Blau Information,
Gelb Warnung). Quellen, Version und Lizenzen sind im Verzeichnis dokumentiert.
`scripts/vendor_lucide.py` aktualisiert den festgelegten SVG-Ausschnitt nur bei
ausdrücklichem Aufruf; die laufende Oberfläche nutzt weder CDN noch Icon-Fonts.

Die Topologie verwendet historische Snapshots. Durch Ziehen am freien Hintergrund
lassen sich alle Knoten und Verbindungen gemeinsam verschieben. Die Ansicht bleibt
beim Aktualisieren desselben Snapshots erhalten; „Ansicht zurücksetzen“ setzt Zoom
und Verschiebung zurück. Knoten lassen sich einzeln mit Maus
oder Pfeiltasten verschieben; das Mausrad zoomt.
Geräte rasten beim Loslassen auf einem in alle Richtungen fortgesetzten Raster
ein. Die Abstände entsprechen der ursprünglichen Anordnung; belegte Plätze
führen zum Positionstausch. Pfeiltasten bewegen um einen Rasterplatz.
Positionen außerhalb der Startanordnung bleiben beim Aktualisieren erhalten.
Eine angeklickte Verbindung
zeigt Quelle und Evidenz. Durchgezogene Linien sind gemeldete LLDP/CDP-Nachbarn,
gestrichelte Linien andere Beziehungen. Auch LLDP/CDP ist beobachtete Evidenz,
keine unabhängige Prüfung eines Kabels. Snapshotvergleiche zeigen zusätzliche,
fehlende oder veränderte Beobachtungen; Abwesenheit beweist keinen Ausfall.
Der Vergleich zeigt beide Zeitpunkte sowie verständliche Einträge mit
aufklappbaren vollständigen Belegen. Neue Beobachtungen werden grün, veränderte
Evidenz blau und nicht erneut beobachtete Beziehungen gelb gestrichelt markiert.
Ein aktivierter Vergleich fixiert den Ziel-Snapshot und bleibt einschließlich
aufgeklappter Details beim automatischen Aktualisieren erhalten. Die Auswahl
eines anderen Ausgangs- oder Ziel-Snapshots beendet den bisherigen Vergleich.
Die automatische Ansicht folgt dem neuesten abgeschlossenen Snapshot, bis ein
historischer Snapshot ausdrücklich ausgewählt wird.

Manuelle Topologieobjekte werden in Schema v6 getrennt vom Scannerinventar in
`topology_manual_nodes` gespeichert. Sie erzeugen keine Einträge in `devices`,
`networks` oder anderen Scan-Tabellen. `GET /api/topology/layout` liefert
erkannte Gerätepositionen und manuelle Nodes gemeinsam; angelegt, bearbeitet und
gelöscht werden manuelle Nodes über `POST /api/topology/manual-nodes`,
`PUT /api/topology/manual-nodes/{id}` und `DELETE /api/topology/manual-nodes/{id}`.
Positionsänderungen werden gemeinsam über `PUT /api/topology/layout` gespeichert.
Die Oberfläche speichert Änderungen an Typ, Bezeichnung, Geräteverknüpfung und
Eigenschaften automatisch. Ausgeblendete Nodes bleiben separat erhalten und
können wieder eingeblendet werden.

Netzwerkbezeichnungen werden als CIDR kanonisiert und mit einem passenden
Netzwerkdatensatz im selben Bereich verknüpft. Eine mehrdeutige Zuordnung wird
mit HTTP 409 abgewiesen. `topology_layout_links` enthält fremdschlüsselgesicherte
Endpunkte für spätere Verbindungen zwischen erkannten und manuellen Nodes; dieser
Arbeitsblock fügt noch keine Verbindungsbearbeitung hinzu.

Die lokale Routentabelle und der vorhandene Neighbor-Cache werden ohne neue
Netzwerkabfragen gelesen. RouterOS liest ausschließlich freigegebene Datensätze.
Firewall-/NAT-Einträge beschreiben Konfiguration; daraus wird keine garantierte
effektive Erreichbarkeit zwischen Segmenten abgeleitet.

## Historie und Archivierung

Es gibt keine automatische Löschung oder Historienbereinigung. Ein einzelner
Kunden-/Standortbereich kann mitsamt seiner gespeicherten Historie lokal als
JSON Lines archiviert werden:

```bash
.venv/bin/python -B maintenance.py export-scope --database data/netchecker.db --scope 1 --out /sicherer/lokaler/pfad/bereich.jsonl
```

Der Export filtert Geräte, Netzwerke, Beobachtungen und Topologie nach dem Bereich.
Widersprüchliche Verweise auf Geräte anderer Bereiche führen zum Abbruch.
Das Format enthält Tabellenname und Datensatz pro Zeile sowie die Schema-Version;
es ist ein Archivformat, kein automatischer Import. Vollständige SQLite-Backups
sind für eine identische Wiederherstellung vorgesehen. Aufbewahrungsfristen und
Wiederherstellungen müssen je Kunde festgelegt und freigegeben werden.
