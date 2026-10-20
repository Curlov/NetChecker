
"use strict";

// ==========================================================
// NetChecker – Weboberfläche
// ==========================================================

const activeView = document.body.dataset.view || "list";
const API_KEY_SESSION_STORAGE_KEY = "netchecker.api-key";
const apiKeyInput = document.querySelector("#api-key");
const apiKeyForm = document.querySelector("#api-key-form");
const apiKeyButton = document.querySelector("#api-key-toggle");
let activeApiKey = "";

try {
    activeApiKey = sessionStorage.getItem(API_KEY_SESSION_STORAGE_KEY) || "";
} catch (_) {}

function updateApiKeyControl() {
    if (apiKeyInput) {
        apiKeyInput.value = activeApiKey;
        apiKeyInput.disabled = Boolean(activeApiKey);
    }
    if (apiKeyButton) apiKeyButton.textContent = activeApiKey ? "Abmelden" : "Anmelden";
}

function setActiveApiKey(value) {
    activeApiKey = value;
    try {
        if (activeApiKey)
            sessionStorage.setItem(API_KEY_SESSION_STORAGE_KEY, activeApiKey);
        else
            sessionStorage.removeItem(API_KEY_SESSION_STORAGE_KEY);
    } catch (_) {}
    updateApiKeyControl();
}

updateApiKeyControl();
window.getNetCheckerApiKey = () => activeApiKey;

apiKeyForm?.addEventListener("submit", async event => {
    event.preventDefault();
    if (activeApiKey) {
        setActiveApiKey("");
        window.location.reload();
        return;
    }

    const candidate = apiKeyInput.value;
    if (!candidate) {
        apiKeyInput.focus();
        return;
    }

    apiKeyButton.disabled = true;
    try {
        const response = await fetch("/api/health", {
            cache: "no-store",
            headers: {"X-Netchecker-Key": candidate}
        });
        let result = {};
        try { result = await response.json(); } catch (_) {}
        if (!response.ok)
            throw new Error(result.detail || `HTTP ${response.status}`);
    } catch (error) {
        setConnectionStatus(`Anmeldung fehlgeschlagen: ${error.message}`, false);
        apiKeyButton.disabled = false;
        return;
    }

    setActiveApiKey(candidate);
    apiKeyButton.disabled = false;
    closeDeviceDetails();
    loadNetworks(true).catch(error => setConnectionStatus(`API-Fehler: ${error.message}`, false));
});

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
const UNASSIGNED_FILTER = "__unassigned__";
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

function devicePresenceDesign(presence) {
    if (presence === "present") return {tone:"positive", icon:"circle-check"};
    if (presence === "missing") return {tone:"negative", icon:"circle-x"};
    return {tone:"warning", icon:"triangle-alert"};
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

async function fetchJson(url, options = {}) {
    const headers = {...(options.headers || {})};
    const apiKey = window.getNetCheckerApiKey();
    if (apiKey) headers["X-Netchecker-Key"] = apiKey;
    const response = await fetch(url, {
        ...options,
        cache: "no-store",
        headers
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
}

function setConnectionStatus(message, connected = null) {
    const messageElement = document.querySelector("#connection-message");
    const iconContainer = document.querySelector("#connection-icon");
    const design = devicePresenceDesign(connected === true ? "present" :
        connected === false ? "missing" : "unknown");
    connectionStatus.dataset.state = connected === true ? "connected" :
        connected === false ? "error" : "loading";
    iconContainer.className = `icon-text event-${design.tone}`;
    iconContainer.replaceChildren(createLucideIcon(design.icon));
    messageElement.textContent = message;
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

    const options = [new Option("Netzwerk auswählen", ""),
        ...result.networks.map(network => new Option(
            `${network.customer} / ${network.site} · ${network.cidr} (${network.device_count} Geräte)`,
            String(network.id)
        ))];
    // Replacing an unchanged, possibly focused select can make the browser
    // scroll the page during an otherwise invisible background refresh.
    if (networkSelect.options.length !== options.length ||
        options.some((option, index) => networkSelect.options[index].value !== option.value ||
            networkSelect.options[index].text !== option.text))
        networkSelect.replaceChildren(...options);

    if (result.networks.length > 0) {
        networkSelect.value = preserveSelection && result.networks.some(n => String(n.id) === current)
            ? current : String(result.networks[0].id);
        if (previous && networkSelect.value !== previous) closeDeviceDetails();
        await loadCurrentView();
    } else {
        setConnectionStatus("Keine Netzwerke gespeichert", true);
        devices = []; deviceTotal = 0; closeDeviceDetails();
        if (activeView === "list") renderDevices();
        await loadCurrentView();
    }
}


// ==========================================================
// Geräte laden
// ==========================================================

async function loadCurrentView() {
    if (activeView === "topology") return loadTopology();
    if (activeView === "timeline") return loadTimeline();
    if (activeView === "configuration") return loadConfiguration();
    return loadDevices();
}

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

        if (activeView === 'topology') return;

        updateCategories();
        renderDevices();
        if (selectedDeviceId !== null) {
            if (devices.some(device => String(device.id) === selectedDeviceId)) {
                await showDevice(selectedDeviceId, false);
            } else {
                closeDeviceDetails();
            }
        }

        setConnectionStatus("API verbunden", true);

        lastUpdate.textContent =
            "Aktualisiert: " +
            new Date().toLocaleTimeString("de-DE");

    } catch (error) {
        if (requestId !== deviceRequestId) return;

        if (activeView === 'topology') throw error;
        setConnectionStatus("API-Fehler", false);
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
    categorySelect.add(new Option('Nicht zugeordnet', UNASSIGNED_FILTER));

    if (categories.includes(previous) || previous === UNASSIGNED_FILTER) {
        categorySelect.value = previous;
    } else categorySelect.value = '';
    renderCategoryMenu(categories);
}

function renderCategoryMenu(categories) {
    const menu = document.querySelector('#category-menu');
    const trigger = document.querySelector('#category-trigger');
    const options = document.querySelector('#category-options');
    const selected = categorySelect.value;
    const selectedDesign = selected === UNASSIGNED_FILTER
        ? {label:'Nicht zugeordnet',icon:'circle'}
        : selected ? deviceClassDesign(selected) : {label:'Alle Gerätetypen',icon:'network'};
    trigger.replaceChildren(iconText(selectedDesign.label,{tone:'info',icon:selectedDesign.icon}),createLucideIcon('chevron-down'));
    options.replaceChildren();
    for (const category of ['',...categories,UNASSIGNED_FILTER]) {
        const design = category === UNASSIGNED_FILTER
            ? {label:'Nicht zugeordnet',icon:'circle'}
            : category ? deviceClassDesign(category) : {label:'Alle Gerätetypen',icon:'network'};
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

document.querySelector('#category-menu')?.addEventListener('keydown',closeCategoryMenu);


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

function compactDeviceListValue(value, maxLength = 24) {
    const text = displayValue(value);
    return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function renderDevices() {
    const search = searchInput.value.toLowerCase().trim();
    const category = categorySelect.value;
    const portQuery = search.match(/^port\b\s*:?\s*(\d+)$/);
    const isExplicitPortQuery = /^port\b/.test(search);
    const requestedPort = portQuery ? Number(portQuery[1]) : null;

    // IP-Sortierung erfolgt numerisch im Backend.
    const filtered = devices.filter(device => {
        if (
            category && category !== UNASSIGNED_FILTER &&
            (device.category || "unknown") !== category
        ) return false;
        if (category === UNASSIGNED_FILTER && device.topology_placed) return false;

        // `port 22` searches only exact port numbers, independent of any
        // matching digits in hostnames, addresses, services, or descriptions.
        if (isExplicitPortQuery) {
            if (!portQuery || requestedPort < 1 || requestedPort > 65535) return false;
            return String(device.port_numbers || "").split(",").includes(String(requestedPort));
        }

        return [
            device.ip,
            device.mac,
            device.hostname,
            device.display_name,
            device.vendor,
            device.category,
            device.subtype,
            device.operating_system,
            device.port_search
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
            device.display_name || device.hostname,
            device.vendor,
            type,
            device.mac,
            device.presence,
            device.confidence == null
                ? "-"
                : `${device.confidence}%`
        ];

        for (const [index, value] of values.entries()) {
            const cell = row.insertCell();
            const fullText = displayValue(value);
            cell.textContent = index === 2 || index === 3
                ? compactDeviceListValue(value) : fullText;
            if (index === 2 || index === 3) cell.title = fullText;
        }

        row.cells[5].className =
            device.presence === "present"
                ? "status-present"
                : "status-other";
        row.cells[3].replaceChildren(iconText(compactDeviceListValue(type),
            {tone:'info',icon:deviceClassDesign(device.category).icon}));
        row.cells[3].title = displayValue(type);
        row.cells[5].replaceChildren(iconText(displayValue(device.presence),
            devicePresenceDesign(String(device.presence || 'unknown').toLowerCase())));

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

function renderLatestDetailTable(container, rows, columns, preferredId = null) {
    const wasExpanded = container.querySelector('.detail-older')?.open || false;
    const sorted = [...(rows || [])].sort((a,b) =>
        String(b.observed_at || '').localeCompare(String(a.observed_at || '')) ||
        Number(b.id || 0)-Number(a.id || 0));
    const preferred = preferredId == null ? null :
        sorted.find(item => String(item.id) === String(preferredId));
    const featured = preferred || sorted[0];
    renderDetailTable(container, featured ? [featured] : [], columns);
    if (preferred) {
        const label = document.createElement('p');
        label.className = 'detail-featured-label';
        label.textContent = 'Aussagekräftigste Evidenz';
        container.prepend(label);
    }
    if (sorted.length <= 1) return;
    const older = document.createElement('details');
    older.className = 'detail-older';
    older.open = wasExpanded;
    const summary = document.createElement('summary');
    summary.textContent = `${preferred ? 'Weitere Evidenzen' : 'Ältere Einträge'} anzeigen (${sorted.length-1})`;
    const content = document.createElement('div');
    renderDetailTable(content, sorted.filter(item => item !== featured), columns);
    older.append(summary,content);
    container.appendChild(older);
}

function preferredOsEvidenceId(summary) {
    const family = summary?.family;
    const kinds = family?.value === 'Linux' || !family
        ? ['distribution_version','distribution','kernel','family'] : ['family'];
    const candidates = kinds.map(kind => summary?.[kind]).filter(Boolean);
    return (candidates.find(claim => !claim.stale) || candidates[0])?.id ?? null;
}

function readableOsEvidence(claim) {
    const evidence = claim.evidence || {};
    const detail = [evidence.name,evidence.value].find(value =>
        typeof value === 'string' && value.trim());
    return {
        ...claim,
        detected_name: detail || claim.value,
        confidence_label: claim.confidence == null ? null : `${claim.confidence}%`,
        evidence_text: JSON.stringify(claim.evidence)
    };
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

    const nameInput = document.querySelector('#detail-name');
    const sameDevice = nameInput.dataset.deviceId === String(deviceId) &&
        nameInput.dataset.networkId === String(networkId);
    detailPanel.hidden = false;
    if (!sameDevice) {
        detailTitle.textContent = `Gerät #${deviceId}`;
        detailSubtitle.textContent = "Lade Informationen ...";
    }

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
            device.display_name || device.hostname ||
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
        const serverName = device.display_name || '';
        const hasDraft = sameDevice &&
            nameInput.value !== (nameInput.dataset.serverValue || '');
        if (!hasDraft && (!sameDevice || document.activeElement !== nameInput))
            nameInput.value = serverName;
        nameInput.dataset.deviceId = String(deviceId);
        nameInput.dataset.networkId = String(networkId);
        nameInput.dataset.serverValue = serverName;
        if (!hasDraft)
            document.querySelector('#detail-name-status').textContent = '';
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
        const allOsClaims = data.os_claims || [];
        const preferredOsId = preferredOsEvidenceId(data.os_summary);
        const shownOsClaims = allOsClaims.slice(0,100);
        const preferredOsClaim = allOsClaims.find(claim => String(claim.id) === String(preferredOsId));
        if (preferredOsClaim && !shownOsClaims.some(claim => claim.id === preferredOsClaim.id))
            shownOsClaims.push(preferredOsClaim);
        renderLatestDetailTable(document.querySelector('#detail-os-claims'),
            shownOsClaims.map(readableOsEvidence),
            [['kind','Eigenschaft'], ['value','Wert'], ['detected_name','Erkannter Treffer'],
                ['confidence_label','Konfidenz'], ['status','Bewertung'], ['source','Quelle'],
                ['observed_at','Zeitpunkt'], ['evidence_text','Evidenz']], preferredOsId);
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
        renderLatestDetailTable(document.querySelector('#detail-port-history'), data.port_history,
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

    if (!detailPanel) return;
    detailPanel.hidden = true;
    const nameInput = document.querySelector('#detail-name');
    delete nameInput.dataset.deviceId;
    delete nameInput.dataset.networkId;
    delete nameInput.dataset.serverValue;

    // Auswahl beim Schließen entfernen.
    clearSelectedDevice();
}

document.querySelector('#detail-name-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    if (!selectedDeviceId || !networkSelect.value) return;
    const deviceId = selectedDeviceId;
    const networkId = networkSelect.value;
    const input = document.querySelector('#detail-name');
    const status = document.querySelector('#detail-name-status');
    const button = event.currentTarget.querySelector('button');
    const submittedName = input.value;
    button.disabled = true;
    status.textContent = 'Speichere …';
    try {
        const headers = {'Content-Type':'application/json'};
        const apiKey = window.getNetCheckerApiKey();
        if (apiKey) headers['X-Netchecker-Key'] = apiKey;
        const response = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/name?network_id=${encodeURIComponent(networkId)}`,
            {method:'PUT',cache:'no-store',headers,body:JSON.stringify({display_name:submittedName})});
        const result = await response.json();
        if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `HTTP ${response.status}`);
        if (selectedDeviceId !== deviceId || networkSelect.value !== networkId) return;
        const newerDraft = input.value !== submittedName;
        if (!newerDraft) input.value = result.display_name || '';
        input.dataset.serverValue = result.display_name || '';
        for (const device of devices) if (String(device.id) === deviceId) device.display_name = result.display_name;
        renderDevices();
        const current = devices.find(device => String(device.id) === deviceId);
        detailTitle.textContent = result.display_name || current?.hostname || current?.ip || `Gerät #${deviceId}`;
        status.textContent = newerDraft ? 'Name gespeichert; neuer Entwurf noch offen.' : 'Name gespeichert.';
    } catch (error) {
        if (selectedDeviceId === deviceId && networkSelect.value === networkId)
            status.textContent = `Speichern fehlgeschlagen: ${error.message}`;
    } finally {
        button.disabled = false;
    }
});

networkSelect.addEventListener("change", () => {
    ++networkRequestId;
    ++deviceRequestId;

    closeDeviceDetails();

    devices = [];
    deviceTotal = 0;

    if (activeView === "list") renderDevices();
    topologyPinned = false;
    if (activeView !== "timeline") loadCurrentView();
});

searchInput?.addEventListener("input", renderDevices);
categorySelect?.addEventListener("change", renderDevices);

document.querySelector("#refresh-button")
    .addEventListener("click", loadCurrentView);

document.querySelector("#close-detail")
    ?.addEventListener("click", closeDeviceDetails);


// ==========================================================
// Automatische Aktualisierung
// ==========================================================

setInterval(() => {
    if (activeView === 'topology' && window.topologyRefreshShouldDefer?.()) return;
    loadNetworks(true).catch(error => setConnectionStatus(`API-Fehler: ${error.message}`, false));
}, REFRESH_INTERVAL_MS);

// ==========================================================
// Start
// ==========================================================

document.addEventListener("DOMContentLoaded", () => loadNetworks().catch(error => {
    setConnectionStatus(`API-Fehler: ${error.message}`, false);
}));
