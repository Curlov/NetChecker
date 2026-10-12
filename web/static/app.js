
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
let topologyRequestId = 0;
let networkRequestId = 0;
let topologyPinned = false;
let topologyGraphContext = '';
const topologyPositions = new Map();
let topologyBaseViewBox = '0 0 1000 500';
let topologyPan = null;

let devices = [];
let deviceTotal = 0;
let deviceRequestId = 0;
let detailRequestId = 0;

// Aktuell ausgewähltes Gerät
let selectedDeviceId = null;


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
    new_device: "Gerät neu erkannt",
    ip_changed: "IP-Adresse geändert",
    port_not_open: "Port nicht mehr offen",
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
    suspected: "Vermutet",
    not_open: "Nicht mehr offen",
    true: "Ja",
    false: "Nein"
};

function translateField(value) {
    if (!value) return "Information";

    const key = String(value).toLowerCase();

    return Object.prototype.hasOwnProperty.call(fieldNames,key) ? fieldNames[key] :
        String(value).replaceAll("_", " ");
}

function translateEvent(value) {
    if (!value) return "Veränderung";

    const key = String(value).toLowerCase();

    return Object.prototype.hasOwnProperty.call(eventNames,key) ? eventNames[key] :
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
    const key = text.toLowerCase();
    return Object.prototype.hasOwnProperty.call(valueNames,key) ? valueNames[key] : text;
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

function flattenObject(value, prefix = "", result = Object.create(null)) {
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
    const type = String(change.change_type || '').toLowerCase();
    const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
    const portOf = value => {
        if (!record(value)) return null;
        if (record(value.port)) return value.port;
        return value.port !== undefined && value.protocol !== undefined ? value : null;
    };
    const oldPort = portOf(before);
    const newPort = portOf(after);
    const portEvents = ['port_opened','port_closed','port_not_open','port_added','port_removed','service_changed','ports_changed'];
    let field = 'Gerät';
    let oldText = humanValue(before);
    let newText = humanValue(after);
    let note = '';
    if (portEvents.includes(type) && (oldPort || newPort)) {
        const port = newPort || oldPort;
        const protocol = port.protocol || oldPort?.protocol;
        const service = port.service || oldPort?.service;
        field = `${protocol ? String(protocol).toUpperCase() : 'Port'} ${port.port ?? oldPort?.port ?? '?'}${service ? ` – ${service}` : ''}`;
        const serviceText = value => value ? [value.service,value.product,value.version,value.extrainfo]
            .filter(part => part !== null && part !== undefined && part !== '').join(' · ') || displayValue(value.state) : '-';
        oldText = oldPort ? displayValue(oldPort.state) : 'Nicht als offen erfasst';
        newText = newPort ? displayValue(newPort.state) : 'Nicht mehr erfasst';
        if (['port_opened','port_added'].includes(type)) newText = newPort?.state ? displayValue(newPort.state) : 'Offen';
        if (type === 'port_closed') newText = 'Geschlossen';
        if (['port_not_open','port_removed'].includes(type)) {
            newText = 'Nicht mehr offen';
            note = 'Im Scan nicht mehr als offen erfasst; der Port kann geschlossen oder gefiltert sein.';
        }
        if (type === 'service_changed') {oldText = serviceText(oldPort); newText = serviceText(newPort);}
    } else if (['new_device','device_new','device_added','appeared'].includes(type)) {
        field = record(after) ? after.hostname || after.ip || after.mac || 'Gerät' : 'Gerät';
        oldText = 'Nicht erfasst'; newText = 'Neu erkannt';
    } else if (['device_missing','device_removed','host_down','disappeared'].includes(type)) {
        field = record(before) ? before.hostname || before.ip || before.mac || 'Gerät' : 'Gerät';
        oldText = 'Erreichbar'; newText = 'Nicht mehr erkannt';
    } else if (['device_returned','host_up'].includes(type)) {
        field = record(after) ? after.hostname || after.ip || after.mac || 'Gerät' : 'Gerät';
        oldText = 'Nicht erreichbar'; newText = 'Wieder erreichbar';
    } else if (type === 'ip_changed') {
        field = 'IP-Adresse';
        oldText = humanValue(record(before) ? before.ip : before);
        newText = humanValue(record(after) ? after.ip : after);
    } else if (record(before) || record(after)) {
        const oldFields = record(before) ? before : {};
        const newFields = record(after) ? after : {};
        const keys = [...new Set([...Object.keys(oldFields),...Object.keys(newFields)])];
        const changed = keys.filter(key => JSON.stringify(oldFields[key]) !== JSON.stringify(newFields[key]));
        field = changed.length ? changed.map(translateField).join(', ') : 'Gerätezustand';
    } else {
        field = translateEvent(change.change_type);
    }
    const compact = text => String(text).length > 160 ? String(text).slice(0,157) + '…' : String(text);
    return {field:compact(field), before:compact(oldText), after:compact(newText), note,
            design:eventDesign(type)};
}

const lucideIconNames = new Set(['circle-plus','circle-minus','circle-check','circle-x','info',
    'triangle-alert','arrow-right-left','refresh-cw','chevron-down',
    'router','network','boxes','server','monitor','monitor-smartphone','phone',
    'printer','camera','battery-charging','cpu','circle-question-mark']);

const deviceClassDesigns = {
    firewall_router: {icon:'router',label:'Router / Firewall'},
    network_device: {icon:'network',label:'Netzwerkgerät'},
    virtualization: {icon:'boxes',label:'Virtualisierung'},
    server: {icon:'server',label:'Server'},
    workstation: {icon:'monitor',label:'PC / Workstation'},
    apple_device: {icon:'monitor-smartphone',label:'Apple-Gerät'},
    voip_phone: {icon:'phone',label:'VoIP-Telefon'},
    printer: {icon:'printer',label:'Drucker'},
    camera: {icon:'camera',label:'IP-Kamera'},
    power_device: {icon:'battery-charging',label:'USV / Stromversorgung'},
    single_board_computer: {icon:'cpu',label:'Single-Board-Computer'},
    unknown: {icon:'circle-question-mark',label:'Unbekannt'}
};

function deviceClassDesign(category) {
    const normalized = String(category || 'unknown').trim().toLowerCase();
    return Object.hasOwn(deviceClassDesigns,normalized) ? deviceClassDesigns[normalized] : deviceClassDesigns.unknown;
}

function topologyPresenceDesign(presence) {
    if (presence === 'present') return {tone:'present',label:'Erreichbar (zuletzt beobachtet)'};
    if (presence === 'missing') return {tone:'missing',label:'Nicht erreichbar (als fehlend erkannt)'};
    return {tone:'unknown',label:'Erreichbarkeit unbekannt'};
}

function createLucideIcon(name) {
    const icon = document.createElementNS('http://www.w3.org/2000/svg','svg');
    for (const [key,value] of Object.entries({class:'lucide-icon',viewBox:'0 0 24 24',
        fill:'none',stroke:'currentColor','stroke-width':2,'stroke-linecap':'round','stroke-linejoin':'round',
        'aria-hidden':'true',focusable:'false'})) icon.setAttribute(key,value);
    const use = document.createElementNS('http://www.w3.org/2000/svg','use');
    // Version the sprite so browsers cannot reuse the earlier subset without
    // device icons. Explicit dimensions also size referenced SVG symbols.
    use.setAttribute('href',`/static/vendor/lucide/sprite.svg?v=1.55.0-devices-1#${lucideIconNames.has(name) ? name : 'info'}`);
    use.setAttribute('width',24);
    use.setAttribute('height',24);
    icon.appendChild(use);
    return icon;
}

function eventDesign(type) {
    if (['new_device','device_new','device_added','appeared','port_opened','port_added'].includes(type))
        return {tone:'positive',icon:'circle-plus'};
    if (['device_returned','host_up','present','up','open','confirmed'].includes(type))
        return {tone:'positive',icon:'circle-check'};
    if (['port_closed','closed'].includes(type)) return {tone:'negative',icon:'circle-x'};
    if (['device_missing','device_removed','host_down','disappeared','port_removed','missing','down'].includes(type))
        return {tone:'negative',icon:'circle-minus'};
    if (['port_not_open','not_open','filtered','unknown','provisional','suspected','mac_changed'].includes(type))
        return {tone:'warning',icon:'triangle-alert'};
    if (type === 'ip_changed') return {tone:'info',icon:'arrow-right-left'};
    if (['service_changed','os_changed','classification_changed','category_changed','ports_changed'].includes(type))
        return {tone:'info',icon:'refresh-cw'};
    return {tone:'info',icon:'info'};
}

function iconText(label, design = eventDesign('info')) {
    const span = document.createElement('span');
    span.className = `icon-text event-${design.tone}`;
    const text = document.createElement('span'); text.textContent = label;
    span.append(createLucideIcon(design.icon),text);
    return span;
}

function formatEventTime(value) {
    if (value === null || value === undefined || value === '') return '-';
    const text = String(value).trim();
    // SQLite CURRENT_TIMESTAMP is UTC, even though its representation has no zone.
    const sqlite = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(text);
    const date = new Date(sqlite ? text.replace(' ','T') + 'Z' : text);
    if (Number.isNaN(date.getTime())) return String(value);
    if (sqlite && date.toISOString().slice(0,19) !== text.replace(' ','T').slice(0,19)) return String(value);
    return new Intl.DateTimeFormat('de-DE',{timeZone:'Europe/Berlin',day:'2-digit',month:'2-digit',
        year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).format(date);
}


// ==========================================================
// API-Hilfsfunktionen
// ==========================================================

async function fetchJson(url) {
    const response = await fetch(url, {
        cache: "no-store",
        headers: document.querySelector('#api-key').value
            ? {'X-Netchecker-Key': document.querySelector('#api-key').value} : {}
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

async function loadNetworks(preserveSelection = false) {
    const requestId = ++networkRequestId;
    const previous = networkSelect.value;
    const result = await fetchJson("/api/networks");
    if (requestId !== networkRequestId) return;
    const current = networkSelect.value;

    networkSelect.replaceChildren(
        new Option("Netzwerk auswählen", "")
    );

    for (const network of result.networks) {
        networkSelect.add(
            new Option(
                `${network.customer} / ${network.site} · ${network.cidr} (${network.device_count} Geräte)`,
                String(network.id)
            )
        );
    }

    if (result.networks.length > 0) {
        networkSelect.value = preserveSelection && result.networks.some(n => String(n.id) === current)
            ? current : String(result.networks[0].id);
        if (previous && networkSelect.value !== previous) closeDeviceDetails();
        await loadDevices();
        await loadTopology();
    } else {
        setConnectionStatus("Keine Netzwerke gespeichert");
        devices = []; deviceTotal = 0; closeDeviceDetails();
        renderDevices();
        await loadTopology();
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
        if (selectedDeviceId !== null) {
            if (devices.some(device => String(device.id) === selectedDeviceId)) {
                await showDevice(selectedDeviceId, false);
            } else {
                closeDeviceDetails();
            }
        }

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
        categorySelect.add(
            new Option(deviceClassDesign(category).label, category)
        );
    }

    if (categories.includes(previous)) {
        categorySelect.value = previous;
    } else categorySelect.value = '';
    renderCategoryMenu(categories);
}

function renderCategoryMenu(categories) {
    const menu = document.querySelector('#category-menu');
    const trigger = document.querySelector('#category-trigger');
    const options = document.querySelector('#category-options');
    const selected = categorySelect.value;
    const selectedDesign = selected ? deviceClassDesign(selected) : {label:'Alle Gerätetypen',icon:'network'};
    trigger.replaceChildren(iconText(selectedDesign.label,{tone:'info',icon:selectedDesign.icon}),createLucideIcon('chevron-down'));
    options.replaceChildren();
    for (const category of ['',...categories]) {
        const design = category ? deviceClassDesign(category) : {label:'Alle Gerätetypen',icon:'network'};
        const button = document.createElement('button');
        button.type = 'button';
        button.setAttribute('aria-pressed',String(category === selected));
        button.appendChild(iconText(design.label,{tone:'info',icon:design.icon}));
        button.addEventListener('click', () => {
            categorySelect.value = category;
            menu.open = false;
            renderDevices();
            renderCategoryMenu(categories);
            if (typeof trigger.focus === 'function') trigger.focus();
        });
        options.appendChild(button);
    }
}

function closeCategoryMenu(event) {
    if (event.key === 'Escape') {
        document.querySelector('#category-menu').open = false;
        const trigger = document.querySelector('#category-trigger');
        if (typeof trigger.focus === 'function') trigger.focus();
    }
}

document.querySelector('#category-menu').addEventListener('keydown',closeCategoryMenu);


// ==========================================================
// Geräteauswahl – dauerhafte Hervorhebung
// ==========================================================

function updateSelectedDevice() {
    const rows = deviceTable.querySelectorAll(
        "tr[data-device-id]"
    );

    for (const row of rows) {
        const isSelected =
            selectedDeviceId !== null &&
            row.dataset.deviceId === selectedDeviceId;

        row.classList.toggle(
            "device-selected",
            isSelected
        );

        if (isSelected) {
            row.setAttribute("aria-selected", "true");
        } else {
            row.removeAttribute("aria-selected");
        }
    }
}

function clearSelectedDevice() {
    selectedDeviceId = null;
    updateSelectedDevice();
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

    // IP-Sortierung erfolgt numerisch im Backend.
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

        row.dataset.deviceId = String(device.id);

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
        row.cells[3].replaceChildren(iconText(displayValue(type),
            {tone:'info',icon:deviceClassDesign(device.category).icon}));
        row.cells[5].replaceChildren(iconText(displayValue(device.presence),
            eventDesign(String(device.presence || 'unknown').toLowerCase())));

        // Markierung beim Neuaufbau wiederherstellen.
        if (String(device.id) === selectedDeviceId) {
            row.classList.add("device-selected");
            row.setAttribute("aria-selected", "true");
        }

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

function addDetailLine(container, label, value, design = null) {
    const line = document.createElement("div");
    line.className = "detail-line";

    const key = document.createElement("span");
    key.textContent = label;

    const val = document.createElement("span");
    if (design) val.appendChild(iconText(displayValue(value),design));
    else val.textContent = displayValue(value);

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
            const cell = row.insertCell();
            if (['state','status'].includes(key)) {
                cell.appendChild(iconText(displayValue(item[key]),eventDesign(String(item[key] || 'unknown').toLowerCase())));
            } else if (['observed_at','classified_at','detected_at','first_seen','last_seen','service_observed_at'].includes(key)) {
                cell.textContent = formatEventTime(item[key]);
            } else cell.textContent = displayValue(item[key]);
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
    const expanded = new Set([...container.querySelectorAll('details[data-change-key]')]
        .filter(details => details.open).map(details => details.dataset.changeKey));
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
    table.className = "detail-table changes-table";

    const heading = table.createTHead().insertRow();

    for (const label of [
        "Zeitpunkt",
        "Ereignis",
        "Betroffen",
        "Vorher",
        "Nachher",
        "Details"
    ]) {
        const th = document.createElement("th");
        th.textContent = label;
        heading.appendChild(th);
    }

    const body = table.createTBody();

    for (const change of changes) {
        const formatted = formatChange(change);
        const row = body.insertRow();
        row.className = `change-row change-${formatted.design.tone}`;
        const time = row.insertCell(); time.className = 'change-time';
        time.textContent = formatEventTime(change.detected_at);
        time.title = `Gespeicherter Zeitpunkt: ${change.detected_at ?? '-'}; Anzeige in Europe/Berlin`;
        row.insertCell().appendChild(iconText(translateEvent(change.change_type),formatted.design));
        const field = row.insertCell(); field.className = 'change-subject'; field.textContent = formatted.field;
        row.insertCell().textContent = formatted.before;
        row.insertCell().textContent = formatted.after;
        const detailsCell = row.insertCell();
        const details = document.createElement('details'); details.className = 'change-details';
        // The API does not always supply a change ID. Include the complete record
        // in the fallback key, so refreshes do not conflate simultaneous events.
        const key = JSON.stringify([change.id ?? null,change.change_type,change.detected_at,
            change.old_value_json,change.new_value_json]);
        details.dataset.changeKey = key;
        details.open = expanded.has(key);
        const summary = document.createElement('summary');
        summary.appendChild(iconText('Details',{tone:'info',icon:'chevron-down'}));
        details.appendChild(summary);
        if (formatted.note) {
            const note = document.createElement('p'); note.className = 'change-note';
            note.appendChild(iconText(formatted.note,eventDesign('unknown')));
            details.appendChild(note);
        }
        const event = document.createElement('p');
        event.appendChild(iconText(`${translateEvent(change.change_type)} · ${change.change_type || 'Unbekannter Typ'}`,formatted.design));
        details.appendChild(event);
        const timestamp = document.createElement('p');
        timestamp.textContent = `Gespeicherter Zeitpunkt (unverändert): ${change.detected_at ?? '-'}`;
        details.appendChild(timestamp);
        for (const [label,value] of [['Vorher',change.old_value_json],['Nachher',change.new_value_json]]) {
            const heading = document.createElement('h4'); heading.textContent = `${label} – vollständige gespeicherte Daten`;
            const pre = document.createElement('pre');
            // Keep original JSON strings verbatim, including unknown fields and
            // numbers that JSON.parse could round. Never interpret them as HTML.
            pre.textContent = typeof value === 'string' ? value : value === undefined
                ? 'Nicht gespeichert' : JSON.stringify(value,null,2);
            details.append(heading,pre);
        }
        detailsCell.appendChild(details);
    }

    wrapper.appendChild(table);
    container.appendChild(wrapper);
}


// ==========================================================
// Einzelnes Gerät laden
// ==========================================================

async function showDevice(deviceId, scroll = true) {
    const networkId = networkSelect.value;

    if (!networkId) return;

    // Gerät auswählen und Zeile dauerhaft markieren.
    selectedDeviceId = String(deviceId);
    updateSelectedDevice();

    const requestId = ++detailRequestId;

    detailPanel.hidden = false;
    detailTitle.textContent = `Gerät #${deviceId}`;
    detailSubtitle.textContent = "Lade Informationen ...";

    if (scroll) detailPanel.scrollIntoView({behavior: 'smooth'});

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
        const general =
            document.querySelector("#detail-general");

        general.replaceChildren();

        addDetailLine(general, "MAC-Adresse", device.mac);
        addDetailLine(general, "Hersteller", device.vendor);
        addDetailLine(general, "Hostname", device.hostname);
        addDetailLine(general, "Identität", device.identity_status,eventDesign(device.identity_status));
        addDetailLine(general, "Status", presence?.state,eventDesign(presence?.state));
        addDetailLine(general, "Erstmals gesehen", formatEventTime(device.first_seen));
        addDetailLine(general, "Zuletzt gesehen", formatEventTime(device.last_seen));

        const mac = document.querySelector('#detail-mac');
        mac.replaceChildren();
        const facts = data.mac_analysis || {};
        for (const [key, label] of [['valid','Gültig'], ['unicast','Unicast'], ['multicast','Multicast'],
            ['locally_administered','Lokal administriert'], ['universally_administered','Universell administriert']]) {
            addDetailLine(mac, label, facts[key]);
        }
        addDetailLine(mac, 'Hypothesen', (facts.hypotheses || []).join('; ') || 'Keine abgeleitet');

        const summary = document.querySelector('#detail-os-summary');
        summary.replaceChildren();
        for (const [kind, label] of [['family','Familie'], ['kernel','Kernel'], ['distribution','Distribution'],
            ['distribution_version','Distributionsversion']]) {
            const claim = data.os_summary?.[kind];
            addDetailLine(summary, label, claim ? `${claim.value} · ${displayValue(claim.status)} · ${claim.source}${claim.stale ? ' · veraltet' : ''}` : null);
            if (claim?.conflicting) addDetailLine(summary, 'Weitere Hinweise', claim.alternatives.join('; '));
        }
        renderDetailTable(document.querySelector('#detail-os-claims'), (data.os_claims || []).slice(0, 100).map(c =>
            ({...c, evidence_text: JSON.stringify(c.evidence)})), [['kind','Eigenschaft'], ['value','Wert'],
            ['status','Bewertung'], ['source','Quelle'], ['observed_at','Zeitpunkt'], ['evidence_text','Evidenz']]);
        const identity = document.querySelector('#detail-identity');
        identity.replaceChildren();
        const observation = parseStoredValue(data.last_identity_observation?.data_json) || {};
        addDetailLine(identity, 'Zuordnungsmethode', observation.match_method);
        addDetailLine(identity, 'Bewertung der Beobachtung', observation.identity_evidence_status,
            eventDesign(observation.identity_evidence_status));
        renderDetailTable(document.querySelector('#detail-interfaces'), data.interfaces,
            [['mac','MAC-Adresse'], ['source','Quelle'], ['first_seen','Erstmals'], ['last_seen','Zuletzt']]);
        renderDetailTable(document.querySelector('#detail-identity-candidates'), data.identity_candidates,
            [['candidate_device_id','Mögliche weitere Identität'], ['reason','Grund'], ['status','Status'], ['evidence_json','Evidenz']]);
        renderDetailTable(document.querySelector('#detail-port-history'), data.port_history,
            [['observed_at','Zeitpunkt'], ['source','Quelle'], ['scan_run_id','Scanlauf'], ['data_json','Gespeicherte Beobachtung']]);

        // Klassifikation
        const cls =
            document.querySelector("#detail-classification");

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
            data.ports.map(p => ({...p, cpe_text:(p.cpe || []).join('; ')})),
            [
                ["port", "Port"],
                ["protocol", "Protokoll"],
                ["state", "Status"],
                ["service", "Dienst"],
                ["product", "Produkt"],
                ["version", "Version"],
                ['extrainfo','Zusatzinformationen'], ['ostype','OS-Hinweis'], ['devicetype','Gerätehinweis'],
                ['tunnel','Tunnel'], ['cpe_text','CPE'], ['service_observed_at','Service erfasst']
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

        // Veränderungen lesbar statt als JSON
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

    // Auswahl beim Schließen entfernen.
    clearSelectedDevice();
}

networkSelect.addEventListener("change", () => {
    ++networkRequestId;
    ++deviceRequestId;

    closeDeviceDetails();

    devices = [];
    deviceTotal = 0;

    renderDevices();
    loadDevices();
    ++topologyRequestId;
    topologyPinned = false;
    document.querySelector('#topology-snapshot').replaceChildren();
    loadTopology();
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

setInterval(() => loadNetworks(true).catch(error => setConnectionStatus(`API-Fehler: ${error.message}`)), REFRESH_INTERVAL_MS);

document.querySelector('#api-key').addEventListener('change', () => {
    closeDeviceDetails();
    loadNetworks(true).catch(error => setConnectionStatus(`API-Fehler: ${error.message}`));
});

const svgNamespace = 'http://www.w3.org/2000/svg';
function svgElement(name, attributes) {
    const element = document.createElementNS(svgNamespace, name);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
    return element;
}

async function loadTopology() {
    const networkId = networkSelect.value;
    const requestId = ++topologyRequestId;
    const status = document.querySelector('#topology-status');
    const select = document.querySelector('#topology-snapshot');
    const beforeSelect = document.querySelector('#topology-before');
    if (!networkId) {
        select.replaceChildren(); beforeSelect.replaceChildren();
        document.querySelector('#topology-graph').replaceChildren();
        document.querySelector('#topology-segments').replaceChildren();
        document.querySelector('#topology-diff').replaceChildren();
        document.querySelector('#topology-evidence').textContent = '';
        status.textContent = 'Kein Netzwerk ausgewählt';
        return;
    }
    try {
        const result = await fetchJson(`/api/topology/snapshots?network_id=${encodeURIComponent(networkId)}`);
        if (requestId !== topologyRequestId || networkId !== networkSelect.value) return;
        const previous = select.value;
        const previousBefore = beforeSelect.value;
        select.replaceChildren(); beforeSelect.replaceChildren();
        const snapshots = result.snapshots.filter(s => ['complete','partial'].includes(s.status));
        for (const snapshot of snapshots) {
            const label = `#${snapshot.id} · ${formatEventTime(snapshot.created_at)} · ${snapshot.status}`;
            select.add(new Option(label, String(snapshot.id)));
            beforeSelect.add(new Option(label, String(snapshot.id)));
        }
        if (topologyPinned && snapshots.some(s => String(s.id) === previous)) select.value = previous;
        if (snapshots.some(s => String(s.id) === previousBefore)) beforeSelect.value = previousBefore;
        else if (snapshots.length > 1) beforeSelect.value = String(snapshots[1].id);
        if (!snapshots.length) {
            status.textContent = 'Noch keine abgeschlossenen Snapshots';
            document.querySelector('#topology-graph').replaceChildren();
            document.querySelector('#topology-segments').replaceChildren();
            document.querySelector('#topology-evidence').textContent = '';
            return;
        }
        await showTopology();
    } catch (error) {
        if (requestId !== topologyRequestId) return;
        status.textContent = `Topologie: ${error.message}`;
    }
}

let topologyDisplayedData = null;
let topologyActiveComparison = null;

function topologyComparisonMatches(networkId,snapshotId) {
    return topologyActiveComparison && topologyActiveComparison.networkId === String(networkId) &&
        String(topologyActiveComparison.data.after.id) === String(snapshotId) &&
        String(topologyActiveComparison.data.before.id) === document.querySelector('#topology-before').value;
}

async function showTopology() {
    const requestId = ++topologyRequestId;
    const networkId = networkSelect.value;
    const snapshotId = document.querySelector('#topology-snapshot').value;
    if (!networkId || !snapshotId) return;
    try {
        const data = await fetchJson(`/api/topology?network_id=${encodeURIComponent(networkId)}&snapshot_id=${encodeURIComponent(snapshotId)}`);
        if (requestId !== topologyRequestId || networkId !== networkSelect.value) return;
        document.querySelector('#topology-status').textContent = `Snapshot #${data.snapshot.id} · ${data.snapshot.status}`;
        document.querySelector('#topology-evidence').textContent = '';
        const preserveComparison = topologyComparisonMatches(networkId,snapshotId);
        if (!preserveComparison) {
            topologyActiveComparison = null;
            document.querySelector('#topology-diff').replaceChildren();
        }
        topologyDisplayedData = data;
        renderDetailTable(document.querySelector('#topology-segments'), data.segments,
            [['segment_name','Segment'], ['cidr','Netz'], ['segment_type','Art'], ['source','Quelle']]);
        if (preserveComparison) renderTopologyComparisonGraph(topologyActiveComparison.data,data);
        else renderTopologyGraph(data);
    } catch (error) {
        if (requestId === topologyRequestId) document.querySelector('#topology-status').textContent = error.message;
    }
}

function renderTopologyGraph(data) {
    const svg = document.querySelector('#topology-graph');
    svg.replaceChildren();
    const context = `${data.snapshot.network_id}:${data.snapshot.id}`;
    if (context !== topologyGraphContext) {
        stopTopologyPan();
        topologyGraphContext = context; topologyPositions.clear();
    }
    const nodes = new Map();
    // The selected snapshot describes connections; colors/classes describe the
    // current inventory of the selected network, never historical scan evidence.
    const currentDevices = new Map(devices.map(device => [String(device.id),device]));
    const normalizeMac = mac => String(mac || '').replace(/[:-]/g,'').toLowerCase();
    const deviceForNode = (id,mac) => {
        if (id != null && currentDevices.has(String(id))) return currentDevices.get(String(id));
        // Historical neighbor entries can lack a device ID. Only an unambiguous
        // MAC match may supply current inventory metadata; never guess from IP.
        const matches = mac ? devices.filter(device => normalizeMac(device.mac) === normalizeMac(mac)) : [];
        return matches.length === 1 ? matches[0] : null;
    };
    const getNode = (id, ip, mac) => {
        const key = id != null ? `device:${id}` : `endpoint:${mac || ip || 'unknown'}`;
        if (!nodes.has(key)) nodes.set(key, {key, device:deviceForNode(id,mac),
            label:ip || mac || `Gerät #${id}`});
        else if (ip) nodes.get(key).label = ip;
        if (!nodes.get(key).device) nodes.get(key).device = deviceForNode(id,mac);
        return nodes.get(key);
    };
    const links = data.links.map(link => ({link,
        a:getNode(link.source_device_id,link.source_ip,null),
        b:getNode(link.target_device_id,link.target_ip,link.target_mac)}));
    for (const neighbor of data.neighbors) getNode(neighbor.device_id,neighbor.ip,neighbor.mac);
    const entries = [...nodes.values()];
    const columns = Math.max(1, Math.ceil(Math.sqrt(entries.length * 2)));
    const rows = Math.max(1, Math.ceil(entries.length / columns));
    // Retain the compact original grid, with only a small spacing increment.
    const columnSpacing = 820/Math.max(1,columns-1) + 14;
    const rowSpacing = 380/Math.max(1,rows-1) + 8;
    const graphWidth = Math.max(1000,180+(columns-1)*columnSpacing);
    const graphHeight = Math.max(500,120+(rows-1)*rowSpacing);
    const previousBase = topologyBaseViewBox;
    topologyBaseViewBox = `0 0 ${graphWidth} ${graphHeight}`;
    if (previousBase !== topologyBaseViewBox || !svg.getAttribute('viewBox') || topologyPositions.size === 0)
        svg.setAttribute('viewBox',topologyBaseViewBox);
    svg.style.width = `${graphWidth}px`;
    svg.style.height = `${graphHeight}px`;
    const occupiedSlots = new Set();
    entries.forEach((node, index) => {
        node.x = 90 + (index % columns)*columnSpacing;
        node.y = 60 + Math.floor(index / columns)*rowSpacing;
        const stored = topologyPositions.get(node.key);
        if (stored) {node.x = stored.x; node.y = stored.y;}
        // The grid extends in every direction. Preserve positions outside the
        // initial layout on refresh instead of pulling devices back into it.
        node.gridColumn = Math.round((node.x-90)/columnSpacing);
        node.gridRow = Math.round((node.y-60)/rowSpacing);
    });
    // Existing positions take priority over newly added nodes.
    for (const node of [...entries].sort((a,b) => Number(topologyPositions.has(b.key))-Number(topologyPositions.has(a.key)))) {
        let slot = `${node.gridColumn}:${node.gridRow}`;
        while (occupiedSlots.has(slot)) {
            node.gridColumn++;
            slot = `${node.gridColumn}:${node.gridRow}`;
        }
        occupiedSlots.add(slot);
        node.x = 90+node.gridColumn*columnSpacing;
        node.y = 60+node.gridRow*rowSpacing;
    }
    for (const edge of links) {
        const line = svgElement('line', {class:`topology-link ${edge.link.relation === 'physical_neighbor' ? 'physical' : 'inferred'}${edge.link.comparison ? ` topology-comparison-${edge.link.comparison}` : ''}`, tabindex:0});
        const title = svgElement('title', {});
        title.textContent = `${edge.link.comparison ? topologyComparisonDesigns[edge.link.comparison].label + ' · ' : ''}${edge.link.relation} · ${edge.link.evidence_source} · ${edge.link.confidence}%`;
        line.appendChild(title);
        const inspect = () => {document.querySelector('#topology-evidence').textContent = JSON.stringify({...edge.link,
            evidence:parseStoredValue(edge.link.evidence_json)}, null, 2);};
        line.addEventListener('click', inspect);
        line.addEventListener('keydown', event => {if (event.key === 'Enter') inspect();});
        svg.appendChild(line); edge.element = line;
    }
    const redraw = () => {
        for (const edge of links) {
            for (const [key,value] of Object.entries({x1:edge.a.x,y1:edge.a.y,x2:edge.b.x,y2:edge.b.y})) edge.element.setAttribute(key,value);
        }
        for (const node of entries) {
            node.element.setAttribute('transform',`translate(${node.x},${node.y})`);
            topologyPositions.set(node.key,{x:node.x,y:node.y});
        }
    };
    const snapNode = (node,original) => {
        const column = Math.round((node.x-90)/columnSpacing);
        const row = Math.round((node.y-60)/rowSpacing);
        const x = 90+column*columnSpacing;
        const y = 60+row*rowSpacing;
        const occupant = entries.find(other => other !== node && Math.abs(other.x-x)<0.01 && Math.abs(other.y-y)<0.01);
        // Dropping onto an occupied slot swaps the two devices.
        if (occupant) {occupant.x=original.x; occupant.y=original.y;}
        node.x=x; node.y=y; redraw();
    };
    for (const node of entries) {
        const design = deviceClassDesign(node.device?.category);
        const presence = topologyPresenceDesign(node.device?.presence);
        const description = `${node.label} · ${design.label} · ${presence.label} · Aktueller Inventarstatus`;
        const group = svgElement('g',{class:`topology-node topology-status-${presence.tone}`,tabindex:0,
            'aria-label':description});
        group.appendChild(svgElement('circle',{r:16,class:'topology-node-background'}));
        const icon = createLucideIcon(design.icon);
        for (const [key,value] of Object.entries({x:-9,y:-9,width:18,height:18})) icon.setAttribute(key,value);
        group.appendChild(icon);
        const label = svgElement('text',{x:0,y:32,'text-anchor':'middle'});
        const fullLabel = String(node.label);
        label.textContent = fullLabel.length > 48 ? fullLabel.slice(0,45) + '…' : fullLabel;
        const title = svgElement('title',{}); title.textContent = description; group.appendChild(title);
        const statusLabel = svgElement('text',{x:0,y:47,'text-anchor':'middle',class:'topology-status-label'});
        statusLabel.textContent = presence.tone === 'present' ? 'Erreichbar' :
            presence.tone === 'missing' ? 'Nicht erreichbar' : 'Status unbekannt';
        group.appendChild(statusLabel);
        group.appendChild(label); svg.appendChild(group); node.element = group;
        let dragOrigin = null;
        group.addEventListener('pointerdown', event => {
            if (event.button !== 0) return;
            dragOrigin = {x:node.x,y:node.y};
            event.preventDefault(); event.stopPropagation(); group.setPointerCapture(event.pointerId);
        });
        group.addEventListener('pointermove', event => {
            if (!group.hasPointerCapture(event.pointerId)) return;
            const point = new DOMPoint(event.clientX,event.clientY).matrixTransform(svg.getScreenCTM().inverse());
            node.x = point.x; node.y = point.y; redraw();
        });
        const finishDrag = event => {
            if (!dragOrigin) return;
            snapNode(node,dragOrigin); dragOrigin=null;
            if (group.hasPointerCapture(event.pointerId)) group.releasePointerCapture(event.pointerId);
        };
        group.addEventListener('pointerup',finishDrag);
        group.addEventListener('pointercancel',finishDrag);
        group.addEventListener('lostpointercapture',finishDrag);
        group.addEventListener('keydown', event => {
            const movement = {ArrowLeft:[-columnSpacing,0],ArrowRight:[columnSpacing,0],ArrowUp:[0,-rowSpacing],ArrowDown:[0,rowSpacing]}[event.key];
            if (movement) {
                event.preventDefault(); const original={x:node.x,y:node.y};
                node.x += movement[0]; node.y += movement[1]; snapNode(node,original);
            }
        });
    }
    redraw();
}

document.querySelector('#topology-snapshot').addEventListener('change', () => {topologyActiveComparison = null; topologyPinned = true; showTopology();});
function stopTopologyPan() {
    if (!topologyPan) return;
    const svg = document.querySelector('#topology-graph');
    const pointerId = topologyPan.pointerId;
    topologyPan = null;
    svg.classList.remove('topology-panning');
    if (svg.hasPointerCapture(pointerId)) svg.releasePointerCapture(pointerId);
}

const topologyGraph = document.querySelector('#topology-graph');
topologyGraph.addEventListener('pointerdown', event => {
    if (event.target !== topologyGraph || event.button !== 0 || topologyPan) return;
    const matrix = topologyGraph.getScreenCTM();
    if (!matrix) return;
    event.preventDefault();
    const inverse = matrix.inverse();
    const start = new DOMPoint(event.clientX,event.clientY).matrixTransform(inverse);
    const box = topologyGraph.viewBox.baseVal;
    topologyPan = {pointerId:event.pointerId, inverse, start,
        box:{x:box.x,y:box.y,width:box.width,height:box.height}};
    topologyGraph.setPointerCapture(event.pointerId);
    topologyGraph.classList.add('topology-panning');
});
topologyGraph.addEventListener('pointermove', event => {
    if (!topologyPan || event.pointerId !== topologyPan.pointerId) return;
    event.preventDefault();
    const point = new DOMPoint(event.clientX,event.clientY).matrixTransform(topologyPan.inverse);
    const {box,start} = topologyPan;
    topologyGraph.setAttribute('viewBox',`${box.x-(point.x-start.x)} ${box.y-(point.y-start.y)} ${box.width} ${box.height}`);
});
for (const eventName of ['pointerup','pointercancel','lostpointercapture']) {
    topologyGraph.addEventListener(eventName, event => {
        if (topologyPan?.pointerId === event.pointerId) stopTopologyPan();
    });
}
document.querySelector('#topology-reset').addEventListener('click', () => {
    stopTopologyPan(); topologyGraph.setAttribute('viewBox',topologyBaseViewBox);
});
document.querySelector('#topology-graph').addEventListener('wheel', event => {
    event.preventDefault();
    if (topologyPan) return;
    const svg = event.currentTarget;
    const box = svg.viewBox.baseVal;
    const baseWidth = Number(topologyBaseViewBox.split(' ')[2]);
    const width = Math.min(baseWidth*4,Math.max(250,box.width * (event.deltaY > 0 ? 1.1 : 0.9)));
    const scale = width/box.width;
    const point = new DOMPoint(event.clientX,event.clientY).matrixTransform(svg.getScreenCTM().inverse());
    svg.setAttribute('viewBox',`${point.x-(point.x-box.x)*scale} ${point.y-(point.y-box.y)*scale} ${width} ${box.height*scale}`);
}, {passive:false});
const topologyComparisonDesigns = {
    added:{label:'Neue Beobachtung',tone:'positive',icon:'circle-plus'},
    removed:{label:'Nicht erneut beobachtet',tone:'warning',icon:'triangle-alert'},
    changed:{label:'Evidenz geändert',tone:'info',icon:'arrow-right-left'}
};

function topologyLinkKey(link) {
    return JSON.stringify(['source_device_id','source_ip','source_interface','target_device_id',
        'target_ip','target_mac','target_interface','relation','evidence_source'].map(key => link[key] ?? null));
}

function renderTopologyComparison(data,graphData) {
    const container = document.querySelector('#topology-diff');
    container.replaceChildren();
    addDetailLine(container,'Vergleich',`${formatEventTime(data.before.created_at)} (#${data.before.id}) → ${formatEventTime(data.after.created_at)} (#${data.after.id})`);
    addDetailLine(container,'Einordnung',data.interpretation);
    for (const kind of ['added','removed','changed']) {
        const design = topologyComparisonDesigns[kind];
        const section = document.createElement('section');
        section.className = 'topology-comparison-section';
        const heading = document.createElement('h4');
        heading.appendChild(iconText(`${design.label}: ${data[kind].length}`,design));
        section.appendChild(heading);
        for (const entry of data[kind]) {
            const link = kind === 'changed' ? entry.after : entry;
            const endpoint = side => {
                const ip = link[`${side}_ip`];
                const id = link[`${side}_device_id`];
                const iface = link[`${side}_interface`];
                return `${ip || (id != null ? `Gerät #${id}` : link[`${side}_mac`] || 'Unbekannt')}${iface ? ` (${iface})` : ''}`;
            };
            const details = document.createElement('details');
            const summary = document.createElement('summary');
            summary.appendChild(iconText(`${endpoint('source')} → ${endpoint('target')}`,design));
            details.appendChild(summary);
            const explanation = document.createElement('p');
            explanation.textContent = kind === 'added' ? 'Diese Verbindungsevidenz ist im Ziel-Snapshot neu enthalten.' :
                kind === 'removed' ? 'Diese Evidenz fehlt im Ziel-Snapshot. Das beweist keinen Verbindungsausfall.' :
                `Quelle: ${link.evidence_source || 'unbekannt'}. Bewertung: ${entry.before.confidence ?? '–'} % → ${entry.after.confidence ?? '–'} %. Die vollständigen Belege stehen unten.`;
            details.appendChild(explanation);
            const raw = document.createElement('pre');
            raw.textContent = JSON.stringify(entry,null,2);
            details.appendChild(raw); section.appendChild(details);
        }
        container.appendChild(section);
    }
    if (!data.added.length && !data.removed.length && !data.changed.length)
        addDetailLine(container,'Ergebnis','Keine Unterschiede in den gespeicherten Verbindungsbeobachtungen.');
    addDetailLine(container,'Grafik','Grün: neue Beobachtung; Gelb gestrichelt: nicht erneut beobachtet; Blau: veränderte Evidenz. Gerätefarben zeigen weiterhin den aktuellen Inventarstatus.');
    if (graphData) renderTopologyComparisonGraph(data,graphData);
}

function renderTopologyComparisonGraph(data,graphData) {
    const marks = new Map([
        ...data.added.map(link => [topologyLinkKey(link),'added']),
        ...data.changed.map(entry => [topologyLinkKey(entry.after),'changed'])
    ]);
    renderTopologyGraph({...graphData,links:[
        ...graphData.links.map(link => ({...link,comparison:marks.get(topologyLinkKey(link))})),
        ...data.removed.map(link => ({...link,comparison:'removed'}))
    ]});
}

function activateTopologyComparison(data,graphData) {
    topologyActiveComparison = {networkId:String(networkSelect.value),data};
    // A comparison concerns two fixed snapshots, so stop following newer ones.
    topologyPinned = true;
    renderTopologyComparison(data,graphData);
}

document.querySelector('#topology-before').addEventListener('change', () => {
    ++topologyRequestId;
    topologyActiveComparison = null;
    document.querySelector('#topology-diff').replaceChildren();
    if (topologyDisplayedData && String(topologyDisplayedData.snapshot.network_id) === networkSelect.value)
        renderTopologyGraph(topologyDisplayedData);
});

document.querySelector('#topology-compare').addEventListener('click', async () => {
    const networkId = networkSelect.value;
    const before = document.querySelector('#topology-before').value;
    const after = document.querySelector('#topology-snapshot').value;
    if (!networkId || !before || !after) return;
    if (before === after) {
        topologyActiveComparison = null;
        const container = document.querySelector('#topology-diff'); container.replaceChildren();
        addDetailLine(container,'Vergleich','Bitte zwei unterschiedliche Snapshots auswählen.');
        if (topologyDisplayedData && String(topologyDisplayedData.snapshot.network_id) === networkId)
            renderTopologyGraph(topologyDisplayedData);
        return;
    }
    const requestId = ++topologyRequestId;
    try {
        const data = await fetchJson(`/api/topology/compare?network_id=${encodeURIComponent(networkId)}&before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`);
        if (requestId !== topologyRequestId || networkId !== networkSelect.value) return;
        const graphData = topologyDisplayedData && String(topologyDisplayedData.snapshot.network_id) === networkId &&
            String(topologyDisplayedData.snapshot.id) === after ? topologyDisplayedData : null;
        activateTopologyComparison(data,graphData);
    } catch (error) {if (requestId === topologyRequestId) document.querySelector('#topology-status').textContent = error.message;}
});


// ==========================================================
// Start
// ==========================================================

loadNetworks().catch(error => {
    setConnectionStatus(`API-Fehler: ${error.message}`);
});
