# Gerätefingerprints

NetChecker verwendet zuerst die bereits gespeicherten Nmap-Ergebnisse. Die
Klassifikation liest Produkt, Version, Zusatztext, CPE, `service ostype`,
`service devicetype`, verfügbare Skriptausgaben sowie Nmap-`osclass` aus den
bestehenden Beobachtungen. Es gibt dafür keinen zusätzlichen Scan und keine
neue Datenbanktabelle. Ein Nmap-Portname aus einer Tabellenzuordnung allein
ist kein Produktfingerprint.

## Lokale Regeln

`fingerprints/rules-v1.json` enthält einen kleinen, versionierten Regelsatz.
Jede Regel nennt Kennung, Kategorie, Punkte im bestehenden Klassifikationsscore
und mindestens einen konkreten Treffer in gespeicherten Servicefeldern. Die
Klassifikation speichert Kennung, Revision, Quelle und Treffertext in ihrer
Evidenz. Nur offene Ports werden geprüft. Widersprüche senken über den
bestehenden Abstand zum zweitbesten Score die Konfidenz. Manuelle und stärkere
gespeicherte Klassifikationen bleiben durch `classification_store.py` geschützt.

Eine zusätzliche, manuell kuratierte Datei kann als
`fingerprints/local-rules.json` abgelegt werden. Sie verwendet dasselbe
JSON-Schema und wird beim Prozessstart eingelesen. Das Format begrenzt Datei,
Regelzahl und Trefferlänge; reguläre Ausdrücke und vollständige externe
Datenbanken werden nicht geladen. `source` und `revision` der Datei müssen
die Herkunft und den Stand der kuratierten Regeln bezeichnen. Eine Regel wird
erst ergänzt, wenn gespeicherte Nmap-Daten dafür tatsächlich einen zusätzlichen
Gerätehinweis enthalten. Ein Neustart lädt geänderte Regeln.

## Quellen und Lizenzprüfung

- [Nmap Service- und OS-Erkennung](https://nmap.org/book/vscan.html): NetChecker
  verwendet die Ergebnisse des installierten Nmap. Die Nmap-Datendateien
  werden nicht kopiert. Nmap nennt für die Datendateien die
  [Nmap Public Source License](https://nmap.org/npsl/npsl-annotated.html).
- [IANA Service Name and Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/):
  nicht importiert. IANA weist selbst darauf hin, dass eine Portregistrierung
  den tatsächlich laufenden Dienst nicht beweist. Daher dient sie nicht als
  Produktidentität.
- [Rapid7 Recog](https://github.com/rapid7/recog): XML-Fingerprints unter
  [BSD-2-Clause](https://github.com/rapid7/recog/blob/main/LICENSE). Das
  Projekt nennt Ruby-, Java- und Go-Implementierungen, aber keine offizielle
  Python-Implementierung. Ein vollständiger Import oder die Ausführung der
  regulären Ausdrücke wäre für die vorhandenen Nmap-Ergebnisse derzeit ohne
  nachgewiesenen Zusatznutzen. Geeignete Einzelregeln können mit Quellenangabe
  in das lokale JSON-Format übertragen werden.

## Grenzen

Ein Dienstprodukt kann einen Managementprozessor oder Container bezeichnen und
ist nicht immer das Modell des gesamten Geräts. Die Weboberfläche zeigt solche
Angaben daher als erkannte Produkte und Fingerprints als Vermutung. Bestätigte
Samsung-API-Antworten bleiben als eigene Identifikation mit Gerätetyp, Modell,
Name und Betriebssystem sichtbar. Firmware wird nur angezeigt, wenn eine Quelle
sie ausdrücklich liefert; eine Nmap-Dienstversion wird nicht als Firmware
ausgegeben. Weitere mDNS-, SSDP-, SNMP- und Herstellerabfragen sind nicht
aktiviert, solange keine passende, freigegebene Quelle und kein konkreter
Zusatznutzen vorliegen.
