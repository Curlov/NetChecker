
"use strict";

// ==========================================================
// NetChecker – Weboberfläche
// ==========================================================

const networkSelect = document.querySelector("#network-select");
const categorySelect = document.querySelector("#category-select");
const searchInput = document.querySelector("#search");
const deviceTable = document.querySelector("#device-table");

const detailPanel = document.querySelector("#detail-panel");
const detailTitle = document.querySelector("#detail-title");
const detailSubtitle = document.querySelector("#detail-subtitle");

const connectionStatus = document.querySelector("#connection-status");
const lastUpdate = document.querySelector("#last-update");

const deviceCount = document.querySelector("#device-count");
const presentCount = document.querySelector("#present-count");
const unknownCount = document.querySelector("#unknown-count");

const REFRESH_INTERVAL_MS = 30000;
const PAGE_SIZE = 1000;

let devices = [];
let deviceTotal = 0;
let deviceRequestId = 0;
let detailRequestId = 0;


// ==========================================================
// Feldnamen und Werte übersetzen
// ==========================================================

const fieldNames = {
    ip: "IP-Adresse",
    mac: "MAC-Adresse",
    hostname: "Hostname",
    vendor: "Hersteller",
    category: "Gerätetyp",
    subtype: "Untertyp",
    confidence: "Konfidenz",
    score: "Bewertung",
    state: "Status",
    presence: "Anwesenheit",
    port: "Port",
    protocol: "Protokoll",
    service: "Dienst",
    product: "Produkt",
    version: "Version",
    os: "Betriebssystem",
    os_name: "Betriebssystem",
    name: "Name",
    address: "Adresse",
    network: "Netzwerk",
    network_id: "Netzwerk-ID",
    device_id: "Geräte-ID",
    source: "Quelle",
    reason: "Grund",
    accuracy: "Genauigkeit",
    last_seen: "Zuletzt gesehen",
    first_seen: "Erstmals gesehen",
    open_ports: "Offene Ports",
    ports: "Ports",
    added: "Hinzugefügt",
    removed: "Entfernt",
    old: "Vorher",
    new: "Nachher"
};

const eventNames = {
    device_added: "Gerät neu erkannt",
    device_removed: "Gerät entfernt",
    device_new: "Neues Gerät",
    device_missing: "Gerät nicht erreichbar",
    device_returned: "Gerät wieder erreichbar",
    host_up: "Gerät erreichbar",
    host_down: "Gerät nicht erreichbar",
    appeared: "Neu erkannt",
    disappeared: "Nicht mehr erkannt",
    port_opened: "Port geöffnet",
    port_closed: "Port geschlossen",
    port_added: "Neuer Port",
    port_removed: "Port entfernt",
    ports_changed: "Ports verändert",
    hostname_changed: "Hostname geändert",
    mac_changed: "MAC-Adresse geändert",
    vendor_changed: "Hersteller geändert",
    os_changed: "Betriebssystem geändert",
    classification_changed: "Gerätetyp geändert",
    category_changed: "Gerätetyp geändert",
    status_changed: "Status geändert",
    state_changed: "Status geändert",
    service_changed: "Dienst geändert"
};

const valueNames = {
    present: "Erreichbar",
    missing: "Nicht erreichbar",
    up: "Aktiv",
    down: "Inaktiv",
    open: "Offen",
    closed: "Geschlossen",
    filtered: "Gefiltert",
    unknown: "Unbekannt",
    provisional: "Vorläufig",
    confirmed: "Bestätigt",
    true: "Ja",
    false: "Nein"
};

function translateField(value) {
    if (!value) return "Information";

    const key = String(value).toLowerCase();

    return fieldNames[key] ||
        String(value).replaceAll("_", " ");
}

function translateEvent(value) {
    if (!value) return "Veränderung";

    const key = String(value).toLowerCase();

    return eventNames[key] ||
        String(value).replaceAll("_", " ");
}

function displayValue(value) {
    if (value === null || value === undefined || value === "") {
        return "-";
    }

    if (typeof value === "boolean") {
        return value ? "Ja" : "Nein";
    }

    const text = String(value);
    return valueNames[text.toLowerCase()] || text;
}


// ==========================================================
// JSON-Daten für Menschen lesbar machen
// ==========================================================

function parseStoredValue(value) {
    if (value === null || value === undefined) {
        return null;
    }

    if (typeof value !== "string") {
        return value;
    }

    const trimmed = value.trim();

    if (!trimmed) return null;

    try {
        return JSON.parse(trimmed);
    } catch {
        return value;
    }
}

function flattenObject(value, prefix = "", result = {}) {
    if (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    ) {
        for (const [key, item] of Object.entries(value)) {
            const path = prefix ? `${prefix}.${key}` : key;

            if (
                item !== null &&
                typeof item === "object" &&
                !Array.isArray(item)
            ) {
                flattenObject(item, path, result);
            } else {
                result[path] = item;
            }
        }
    } else {
        result[prefix || "value"] = value;
    }

    return result;
}

function humanValue(value) {
    if (value === null || value === undefined) {
        return "-";
    }

    if (Array.isArray(value)) {
        if (value.length === 0) return "Keine";

        return value.map(item => {
            if (
                item !== null &&
                typeof item === "object"
            ) {
                return Object.entries(flattenObject(item))
                    .map(([key, val]) =>
                        `${translateField(key)}: ${humanValue(val)}`
                    )
                    .join(", ");
            }

            return displayValue(item);
        }).join("; ");
    }

    if (typeof value === "object") {
        return Object.entries(flattenObject(value))
            .map(([key, val]) =>
                `${translateField(key)}: ${humanValue(val)}`
            )
            .join("; ") || "-";
    }

    return displayValue(value);
}

function formatChange(change) {
    const before = parseStoredValue(change.old_value_json);
    const after = parseStoredValue(change.new_value_json);

    const beforeIsObject =
        before !== null &&
        typeof before === "object" &&
        !Array.isArray(before);

    const afterIsObject =
        after !== null &&
        typeof after === "object" &&
        !Array.isArray(after);

    if (beforeIsObject || afterIsObject) {
        const oldFields = beforeIsObject
            ? flattenObject(before)
            : {};

        const newFields = afterIsObject
            ? flattenObject(after)
            : {};

        const keys = [...new Set([
            ...Object.keys(oldFields),
            ...Object.keys(newFields)
        ])];

        return keys.filter(key => {
            return JSON.stringify(oldFields[key]) !==
                   JSON.stringify(newFields[key]);
        }).map(key => ({
            field: translateField(key),
            before: humanValue(oldFields[key]),
            after: humanValue(newFields[key])
        }));
    }

    return [{
        field: translateEvent(change.change_type),
        before: humanValue(before),
        after: humanValue(after)
    }];
}


// ==========================================================
// API-Hilfsfunktionen
// ==========================================================

async function fetchJson(url) {
    const response = await fetch(url, {
        cache: "no-store"
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
}

function setConnectionStatus(message) {
    connectionStatus.textContent = message;
}


// ==========================================================
// Netzwerke laden
// ==========================================================

async function loadNetworks() {
    const result = await fetchJson("/api/networks");

    networkSelect.replaceChildren(
        new Option("Netzwerk auswählen", "")
    );

    for (const network of result.networks) {
        networkSelect.add(
            new Option(
                `${network.cidr} (${network.device_count} Geräte)`,
                String(network.id)
            )
        );
    }

    if (result.networks.length > 0) {
        networkSelect.value = String(result.networks[0].id);
        await loadDevices();
    } else {
        setConnectionStatus("Keine Netzwerke gespeichert");
        renderDevices();
    }
}


// ==========================================================
// Geräte laden
// ==========================================================

async function loadDevices() {
    const requestId = ++deviceRequestId;
    const networkId = networkSelect.value;

    if (!networkId) {
        devices = [];
        deviceTotal = 0;
        updateCategories();
        renderDevices();
        return;
    }

    try {
        const allDevices = [];
        let offset = 0;
        let total = 0;

        do {
            const url = new URL(
                "/api/devices",
                location.origin
            );

            url.searchParams.set("network_id", networkId);
            url.searchParams.set("limit", PAGE_SIZE);
            url.searchParams.set("offset", offset);

            const result = await fetchJson(url);

            if (
                requestId !== deviceRequestId ||
                networkId !== networkSelect.value
            ) return;

            total = result.total ?? result.count;
            allDevices.push(...result.devices);

            offset += result.devices.length;

            if (result.devices.length === 0) break;

        } while (offset < total);

        if (
            requestId !== deviceRequestId ||
            networkId !== networkSelect.value
        ) return;

        devices = allDevices;
        deviceTotal = total;

        updateCategories();
        renderDevices();

        setConnectionStatus("API verbunden");

        lastUpdate.textContent =
            "Aktualisiert: " +
            new Date().toLocaleTimeString("de-DE");

    } catch (error) {
        if (requestId !== deviceRequestId) return;

        setConnectionStatus("API-Fehler");
        deviceTable.replaceChildren();

        addTableMessage(`Fehler: ${error.message}`);
    }
}


// ==========================================================
// Filter
// ==========================================================

function updateCategories() {
    const previous = categorySelect.value;

    const categories = [...new Set(
        devices.map(d => d.category || "unknown")
    )].sort();

    categorySelect.replaceChildren(
        new Option("Alle Gerätetypen", "")
    );

    for (const category of categories) {
        categorySelect.add(new Option(category, category));
    }

    if (categories.includes(previous)) {
        categorySelect.value = previous;
    }
}


// ==========================================================
// Geräteübersicht
// ==========================================================

function addTableMessage(message) {
    const row = deviceTable.insertRow();
    const cell = row.insertCell();

    cell.colSpan = 7;
    cell.textContent = message;
}

function renderDevices() {
    const search = searchInput.value.toLowerCase().trim();
    const category = categorySelect.value;

    // IP-Sortierung erfolgt bereits numerisch im Backend.
    const filtered = devices.filter(device => {
        if (
            category &&
            (device.category || "unknown") !== category
        ) return false;

        return [
            device.ip,
            device.mac,
            device.hostname,
            device.vendor,
            device.category,
            device.subtype,
            device.operating_system
        ].some(value =>
            String(value ?? "").toLowerCase().includes(search)
        );
    });

    deviceTable.replaceChildren();

    for (const device of filtered) {
        const row = deviceTable.insertRow();
        row.dataset.deviceId = device.id;

        const type =
            device.subtype && device.subtype !== "-"
                ? device.subtype
                : device.category;

        const values = [
            device.ip,
            device.hostname,
            device.vendor,
            type,
            device.mac,
            device.presence,
            device.confidence == null
                ? "-"
                : `${device.confidence}%`
        ];

        for (const value of values) {
            row.insertCell().textContent = displayValue(value);
        }

        row.cells[5].className =
            device.presence === "present"
                ? "status-present"
                : "status-other";

        row.addEventListener("click", () => {
            showDevice(device.id);
        });
    }

    if (filtered.length === 0) {
        addTableMessage("Keine passenden Geräte gefunden.");
    }

    deviceCount.textContent = filtered.length;

    presentCount.textContent = filtered.filter(
        d => d.presence === "present"
    ).length;

    unknownCount.textContent = filtered.filter(
        d => !d.category || d.category === "unknown"
    ).length;

    if (devices.length !== deviceTotal) {
        lastUpdate.textContent =
            `${devices.length} von ${deviceTotal} geladen`;
    }
}


// ==========================================================
// Detailansicht: Hilfsfunktionen
// ==========================================================

function addDetailLine(container, label, value) {
    const line = document.createElement("div");
    line.className = "detail-line";

    const key = document.createElement("span");
    key.textContent = label;

    const val = document.createElement("span");
    val.textContent = displayValue(value);

    line.append(key, val);
    container.appendChild(line);
}

function renderDetailTable(container, rows, columns) {
    container.replaceChildren();

    if (!rows || rows.length === 0) {
        const empty = document.createElement("p");
        empty.className = "detail-empty";
        empty.textContent = "Keine Informationen vorhanden.";

        container.appendChild(empty);
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "table-container";

    const table = document.createElement("table");
    table.className = "detail-table";

    const header = table.createTHead().insertRow();

    for (const [, label] of columns) {
        const th = document.createElement("th");
        th.textContent = label;
        header.appendChild(th);
    }

    const body = table.createTBody();

    for (const item of rows) {
        const row = body.insertRow();

        for (const [key] of columns) {
            row.insertCell().textContent =
                displayValue(item[key]);
        }
    }

    wrapper.appendChild(table);
    container.appendChild(wrapper);
}


// ==========================================================
// Veränderungen lesbar darstellen
// ==========================================================

function renderChanges(changes) {
    const container = document.querySelector("#detail-changes");
    container.replaceChildren();

    if (!changes || changes.length === 0) {
        const empty = document.createElement("p");
        empty.className = "detail-empty";
        empty.textContent = "Keine Veränderungen erfasst.";

        container.appendChild(empty);
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "table-container";

    const table = document.createElement("table");
    table.className = "detail-table";

    const heading = table.createTHead().insertRow();

    for (const label of [
        "Zeitpunkt",
        "Ereignis",
        "Eigenschaft",
        "Vorher",
        "Nachher"
    ]) {
        const th = document.createElement("th");
        th.textContent = label;
        heading.appendChild(th);
    }

    const body = table.createTBody();

    for (const change of changes) {
        const differences = formatChange(change);

        if (differences.length === 0) {
            differences.push({
                field: "Information",
                before: "-",
                after: "Keine Wertänderung erkennbar"
            });
        }

        for (const difference of differences) {
            const row = body.insertRow();

            const values = [
                change.detected_at,
                translateEvent(change.change_type),
                difference.field,
                difference.before,
                difference.after
            ];

            for (const value of values) {
                row.insertCell().textContent = displayValue(value);
            }
        }
    }

    wrapper.appendChild(table);
    container.appendChild(wrapper);
}


// ==========================================================
// Einzelnes Gerät laden
// ==========================================================

async function showDevice(deviceId) {
    const requestId = ++detailRequestId;
    const networkId = networkSelect.value;

    if (!networkId) return;

    detailPanel.hidden = false;
    detailTitle.textContent = `Gerät #${deviceId}`;
    detailSubtitle.textContent = "Lade Informationen ...";

    detailPanel.scrollIntoView({
        behavior: "smooth"
    });

    try {
        const url = new URL(
            `/api/devices/${deviceId}`,
            location.origin
        );

        url.searchParams.set("network_id", networkId);

        const data = await fetchJson(url);

        if (
            requestId !== detailRequestId ||
            networkId !== networkSelect.value
        ) return;

        const device = data.device;
        const classification = data.classification;
        const presence = data.presence;

        detailTitle.textContent =
            device.hostname ||
            data.addresses[0]?.ip ||
            `Gerät #${deviceId}`;

        detailSubtitle.textContent =
            `Geräte-ID: ${device.id} · Netzwerk-ID: ${networkId}`;

        // Stammdaten
        const general = document.querySelector("#detail-general");
        general.replaceChildren();

        addDetailLine(general, "MAC-Adresse", device.mac);
        addDetailLine(general, "Hersteller", device.vendor);
        addDetailLine(general, "Hostname", device.hostname);
        addDetailLine(general, "Identität", device.identity_status);
        addDetailLine(general, "Status", presence?.state);
        addDetailLine(general, "Erstmals gesehen", device.first_seen);
        addDetailLine(general, "Zuletzt gesehen", device.last_seen);

        // Klassifikation
        const cls = document.querySelector("#detail-classification");
        cls.replaceChildren();

        addDetailLine(cls, "Kategorie", classification?.category);
        addDetailLine(cls, "Untertyp", classification?.subtype);
        addDetailLine(
            cls,
            "Konfidenz",
            classification?.confidence == null
                ? "-"
                : `${classification.confidence}%`
        );
        addDetailLine(cls, "Quelle", classification?.source);
        addDetailLine(cls, "Score", classification?.score);

        // Betriebssystem
        renderDetailTable(
            document.querySelector("#detail-os"),
            data.os_information,
            [
                ["name", "Betriebssystem"],
                ["accuracy", "Genauigkeit"],
                ["observed_at", "Erfasst"]
            ]
        );

        // Adressen
        renderDetailTable(
            document.querySelector("#detail-addresses"),
            data.addresses,
            [
                ["ip", "IP-Adresse"],
                ["network", "Netzwerk"],
                ["last_seen", "Zuletzt gesehen"]
            ]
        );

        // Ports
        renderDetailTable(
            document.querySelector("#detail-ports"),
            data.ports,
            [
                ["port", "Port"],
                ["protocol", "Protokoll"],
                ["state", "Status"],
                ["service", "Dienst"],
                ["product", "Produkt"],
                ["version", "Version"]
            ]
        );

        // Klassifikationshistorie
        renderDetailTable(
            document.querySelector("#detail-history"),
            data.classification_history,
            [
                ["classified_at", "Zeitpunkt"],
                ["category", "Kategorie"],
                ["subtype", "Untertyp"],
                ["confidence", "Konfidenz"]
            ]
        );

        // Veränderungen: jetzt lesbar statt als JSON
        renderChanges(data.changes);

        // Topologie
        renderDetailTable(
            document.querySelector("#detail-topology"),
            data.topology_hints,
            [
                ["category", "Kategorie"],
                ["manufacturer", "Hersteller"],
                ["model", "Modell"],
                ["source", "Quelle"],
                ["confidence", "Konfidenz"]
            ]
        );

    } catch (error) {
        if (requestId !== detailRequestId) return;

        detailSubtitle.textContent =
            `Fehler beim Laden: ${error.message}`;
    }
}


// ==========================================================
// Interaktion
// ==========================================================

function closeDeviceDetails() {
    ++detailRequestId;
    detailPanel.hidden = true;
}

networkSelect.addEventListener("change", () => {
    ++deviceRequestId;
    closeDeviceDetails();

    devices = [];
    deviceTotal = 0;

    renderDevices();
    loadDevices();
});

searchInput.addEventListener("input", renderDevices);
categorySelect.addEventListener("change", renderDevices);

document.querySelector("#refresh-button")
    .addEventListener("click", loadDevices);

document.querySelector("#close-detail")
    .addEventListener("click", closeDeviceDetails);


// ==========================================================
// Automatische Aktualisierung
// ==========================================================

setInterval(loadDevices, REFRESH_INTERVAL_MS);


// ==========================================================
// Start
// ==========================================================

loadNetworks().catch(error => {
    setConnectionStatus(`API-Fehler: ${error.message}`);
});
