"use strict";
let timelineRequestId = 0;
let timelineAbortController = null;
let timelineDays = [];
let timelineContext = null;
let timelineAxis = null;
let timelineEmptyMessage = null;
let timelineNoMatchesMessage = null;
const timelineDeviceRows = new Map();
let timelineExpandedDevices = new Set();
let timelineExpandedPorts = new Set();
let timelineSearchExpansionSnapshot = null;
const timelineDay = document.querySelector('#timeline-day');
const timelineSearch = document.querySelector('#timeline-search');
const timelineCategorySelect = document.querySelector('#timeline-category-select');
const timelineCategoryMenu = document.querySelector('#timeline-category-menu');
const timelineCategoryTrigger = document.querySelector('#timeline-category-trigger');
const timelineCategoryOptions = document.querySelector('#timeline-category-options');
const timelineExpandAll = document.querySelector('#timeline-expand-all');
const timelineContent = document.querySelector('#timeline-content');
const timelineStatus = document.querySelector('#timeline-status');
const timelineZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const TIMELINE_UNASSIGNED_FILTER = '__unassigned__';

function renderTimelineCategoryMenu(devices) {
    const previous = timelineCategorySelect.value;
    const categories = [...new Set(devices.map(device => device.category || 'unknown'))].sort();
    timelineCategorySelect.replaceChildren(new Option('Alle Gerätetypen', ''));
    for (const category of categories)
        timelineCategorySelect.add(new Option(deviceClassDesign(category).label, category));
    timelineCategorySelect.add(new Option('Nicht zugeordnet', TIMELINE_UNASSIGNED_FILTER));
    timelineCategorySelect.value = categories.includes(previous) || previous === TIMELINE_UNASSIGNED_FILTER
        ? previous : '';

    const selected = timelineCategorySelect.value;
    const selectedDesign = selected === TIMELINE_UNASSIGNED_FILTER
        ? {label:'Nicht zugeordnet',icon:'circle'}
        : selected ? deviceClassDesign(selected) : {label:'Alle Gerätetypen',icon:'network'};
    timelineCategoryTrigger.replaceChildren(
        iconText(selectedDesign.label, {tone:'info',icon:selectedDesign.icon}),
        createLucideIcon('chevron-down'),
    );
    timelineCategoryOptions.replaceChildren();
    for (const category of ['', ...categories, TIMELINE_UNASSIGNED_FILTER]) {
        const design = category === TIMELINE_UNASSIGNED_FILTER
            ? {label:'Nicht zugeordnet',icon:'circle'}
            : category ? deviceClassDesign(category) : {label:'Alle Gerätetypen',icon:'network'};
        const button = document.createElement('button');
        button.type = 'button';
        button.setAttribute('aria-pressed', String(category === selected));
        button.appendChild(iconText(design.label, {tone:'info',icon:design.icon}));
        button.addEventListener('click', () => {
            timelineCategorySelect.value = category;
            timelineCategoryMenu.open = false;
            renderTimelineCategoryMenu(devices);
            applyTimelineSearch();
            timelineCategoryTrigger.focus();
        });
        timelineCategoryOptions.appendChild(button);
    }
}

function makeTimelineTrack() {
    const track = document.createElement('span');
    track.className = 'timeline-track';
    return track;
}
function updateTimelineTrack(track, intervals) {
    const bars = [...track.children];
    intervals.forEach((interval, index) => {
        const bar = bars[index] || document.createElement('span');
        const state = interval.state || 'online';
        bar.className = `timeline-bar timeline-bar-${state}`;
        bar.style.left = `${interval.start / 14.4}%`;
        bar.style.width = `${Math.max(0, interval.end - interval.start) / 14.4}%`;
        const format = value => new Date(value).toLocaleString('de-DE');
        const labels = {online:'Erreichbar', inactive:'Nicht mehr erreichbar', open:'Offen', closed:'Geschlossen', not_open:'Nicht mehr offen', filtered:'Gefiltert (nicht als offen erkannt)', unreachable:'Nicht erreichbar (Gerät offline)'};
        bar.title = `${labels[state] || 'Status'}: ${format(interval.from)} – ${format(interval.to)} (abgeleitet)`;
        if (!bars[index]) track.appendChild(bar);
    });
    while (track.children.length > intervals.length) track.lastElementChild.remove();
}
function resetTimeline() {
    // A user-selected day/network starts a fresh view; periodic refreshes keep
    // the existing details nodes so their open state and scroll anchor survive.
    timelineContent.replaceChildren();
    timelineAxis = null;
    timelineEmptyMessage = null;
    timelineNoMatchesMessage = null;
    timelineDeviceRows.clear();
    updateTimelineExpandButton();
}
function captureTimelineExpansion() {
    timelineExpandedDevices = new Set();
    timelineExpandedPorts = new Set();
    for (const [deviceId, row] of timelineDeviceRows) {
        if (row.details.open) timelineExpandedDevices.add(deviceId);
        for (const [portKey, portRow] of row.portRows) {
            if (portRow.details.open) timelineExpandedPorts.add(`${deviceId}:${portKey}`);
        }
    }
}
function ensureTimelineAxis() {
    if (timelineAxis) return;
    timelineAxis = document.createElement('div');
    timelineAxis.className = 'timeline-axis';
    const label = document.createElement('span');
    label.className = 'timeline-axis-label';
    const track = document.createElement('div');
    track.className = 'timeline-axis-track';
    for (const hour of ['00:00','06:00','12:00','18:00','24:00']) {
        const tick = document.createElement('span');
        tick.textContent = hour;
        track.appendChild(tick);
    }
    timelineAxis.append(label, track);
    timelineContent.appendChild(timelineAxis);
}
function createTimelineDeviceRow(device) {
    const details = document.createElement('details');
    details.className = 'timeline-device';
    details.dataset.deviceId = String(device.id);
    details.open = timelineExpandedDevices.has(String(device.id));
    details.addEventListener('toggle', () => {
        if (details.open) timelineExpandedDevices.add(String(device.id));
        else timelineExpandedDevices.delete(String(device.id));
        updateTimelineExpandButton();
    });
    const summary = document.createElement('summary');
    summary.className = 'timeline-row timeline-device-summary';
    const labelBox = document.createElement('span');
    labelBox.className = 'timeline-device-label';
    const chevron = document.createElement('span');
    chevron.className = 'timeline-chevron';
    chevron.setAttribute('aria-hidden', 'true');
    chevron.textContent = '›';
    const label = document.createElement('span');
    label.className = 'timeline-device-name';
    const track = makeTimelineTrack();
    labelBox.append(chevron, label);
    summary.append(labelBox, track);
    const empty = document.createElement('p');
    empty.className = 'timeline-service-empty';
    empty.textContent = 'Keine Port-/Service-Beobachtungen für diesen Zeitraum.';
    const services = document.createElement('div');
    services.className = 'timeline-service-list';
    details.append(summary, empty, services);
    const row = {details, label, track, empty, services, portRows:new Map()};
    timelineDeviceRows.set(String(device.id), row);
    timelineContent.appendChild(details);
    return row;
}
function formatPortObservationTime(value) {
    return new Date(value).toLocaleString('de-DE');
}
function observationValue(value) {
    if (value === null || value === undefined || value === '') return '';
    return Array.isArray(value) ? value.join(', ') :
        typeof value === 'object' ? JSON.stringify(value) : String(value);
}
function timelineStateLabel(state) {
    return ({open:'Offen', closed:'Geschlossen', filtered:'Gefiltert',
        not_open:'Nicht offen', unfiltered:'Nicht gefiltert'})[String(state || '').toLowerCase()] || observationValue(state);
}
function createPortObservation(item) {
    const entry = document.createElement('article');
    entry.className = 'timeline-observation';
    entry.dataset.observationId = item.id;
    const heading = document.createElement('time');
    heading.dateTime = item.observed_at;
    heading.textContent = formatPortObservationTime(item.observed_at);
    entry.appendChild(heading);
    const portData = item.port_data || {};
    const facts = document.createElement('div');
    facts.className = 'timeline-observation-facts';
    for (const [key, title] of [
        ['state','Status'], ['service','Dienst'], ['product','Software / Produkt'],
        ['version','Version'], ['extrainfo','Zusatzinformation'], ['ostype','Betriebssystem'],
        ['devicetype','Gerätetyp'], ['tunnel','Tunnel']
    ]) {
        const value = key === 'state' ? timelineStateLabel(portData[key]) : observationValue(portData[key]);
        if (!value) continue;
        const fact = document.createElement('span');
        const label = document.createElement('strong');
        label.textContent = `${title}: `;
        fact.append(label, document.createTextNode(value));
        facts.appendChild(fact);
    }
    if (item.source) {
        const source = document.createElement('span');
        source.textContent = `Quelle: ${item.source}`;
        facts.appendChild(source);
    }
    if (item.observation_type) {
        const type = document.createElement('span');
        type.textContent = `Beobachtung: ${item.observation_type}`;
        facts.appendChild(type);
    }
    if (item.scan_run_id !== null && item.scan_run_id !== undefined) {
        const run = document.createElement('span');
        run.textContent = `Scan #${item.scan_run_id}`;
        facts.appendChild(run);
    }
    entry.appendChild(facts);
    const raw = document.createElement('details');
    raw.className = 'timeline-observation-raw';
    const rawSummary = document.createElement('summary');
    rawSummary.textContent = 'Alle gespeicherten Portdaten';
    const rawData = document.createElement('pre');
    rawData.textContent = JSON.stringify(portData, null, 2);
    raw.append(rawSummary, rawData);
    entry.appendChild(raw);
    return entry;
}
function createTimelinePortRow(deviceId, port) {
    const details = document.createElement('details');
    details.className = 'timeline-port';
    details.open = timelineExpandedPorts.has(`${deviceId}:${port.key}`);
    details.addEventListener('toggle', () => {
        const key = `${deviceId}:${port.key}`;
        if (details.open) timelineExpandedPorts.add(key);
        else timelineExpandedPorts.delete(key);
        updateTimelineExpandButton();
        if (details.open) loadTimelinePortObservations(deviceId, row);
    });
    const summary = document.createElement('summary');
    summary.className = 'timeline-row timeline-port-summary';
    const label = document.createElement('span');
    label.className = 'timeline-port-label';
    const track = makeTimelineTrack();
    summary.append(label, track);
    const observations = document.createElement('div');
    observations.className = 'timeline-port-observations';
    const status = document.createElement('p');
    status.className = 'timeline-service-empty';
    status.setAttribute('role', 'status');
    const more = document.createElement('button');
    more.type = 'button';
    more.textContent = 'Weitere Beobachtungen laden';
    more.hidden = true;
    const row = {details, label, track, observations, status, more, key:port.key,
        observationRows:new Map(), loaded:false, loading:false, nextOffset:0, requestId:0};
    more.addEventListener('click', () => loadTimelinePortObservations(deviceId, row, true));
    details.append(summary, status, observations, more);
    return row;
}
async function loadTimelinePortObservations(deviceId, row, more = false) {
    if (row.loading || (row.loaded && !more) || !row.port) return;
    const requestId = ++row.requestId;
    const context = timelineContext;
    const networkId = networkSelect.value;
    const day = timelineDay.value;
    const offset = more ? row.nextOffset : 0;
    row.loading = true;
    row.more.disabled = true;
    row.status.textContent = 'Lade Beobachtungen …';
    const current = () => row.requestId === requestId && timelineContext === context &&
        networkSelect.value === networkId && timelineDay.value === day &&
        timelineDeviceRows.get(String(deviceId))?.portRows.get(row.key) === row;
    try {
        const url = `/api/timeline/${encodeURIComponent(deviceId)}/ports/` +
            `${encodeURIComponent(row.port.protocol)}/${encodeURIComponent(row.port.port)}` +
            `?network_id=${encodeURIComponent(networkId)}&day=${encodeURIComponent(day)}` +
            `&tz=${encodeURIComponent(timelineZone)}&offset=${offset}&limit=100`;
        const data = await fetchJson(url);
        if (!current()) return;
        if (offset === 0) {
            const present = new Set(data.observations.map(item => item.id));
            for (const [id, element] of row.observationRows) {
                if (!present.has(id)) {
                    element.remove();
                    row.observationRows.delete(id);
                }
            }
        }
        for (const item of data.observations) {
            if (row.observationRows.has(item.id)) continue;
            const observation = createPortObservation(item);
            row.observations.appendChild(observation);
            row.observationRows.set(item.id, observation);
        }
        row.loaded = true;
        row.nextOffset = data.next_offset;
        row.more.hidden = !data.has_more;
        row.more.textContent = 'Weitere Beobachtungen laden';
        row.status.textContent = row.observationRows.size
            ? `${row.observationRows.size} von ${row.port.observation_count} Beobachtungen`
            : 'Keine Beobachtungen für diesen Zeitraum.';
    } catch (error) {
        if (!current()) return;
        row.status.textContent = `Beobachtungen konnten nicht geladen werden: ${error.message}`;
        row.nextOffset = offset;
        row.more.hidden = false;
        row.more.textContent = 'Erneut versuchen';
    } finally {
        if (row.requestId === requestId) {
            row.loading = false;
            row.more.disabled = false;
        }
    }
}
function updateTimelinePortRow(deviceId, deviceRow, port, deviceActive) {
    let row = deviceRow.portRows.get(port.key);
    if (!row) {
        row = createTimelinePortRow(deviceId, port);
        deviceRow.portRows.set(port.key, row);
        deviceRow.services.appendChild(row.details);
    }
    if (row.port?.observation_revision !== port.observation_revision) {
        ++row.requestId;
        row.loaded = false;
        row.loading = false;
        row.nextOffset = 0;
        row.more.hidden = true;
    }
    row.port = port;
    row.label.textContent = `${port.protocol.toUpperCase()} ${port.port}${port.service ? ` – ${port.service}` : ''}`;
    row.portNumber = String(port.port);
    row.searchText = [port.protocol, port.port, port.status, port.label,
        port.service, port.product, port.version, port.search_text]
        .filter(value => value !== null && value !== undefined)
        .map(value => typeof value === 'object' ? JSON.stringify(value) : String(value))
        .join(' ').toLowerCase();
    const state = deviceActive === false ? 'unreachable' :
        port.status === 'filtered' || port.status === 'unfiltered' ? 'filtered' :
        port.status === 'not_open' ? 'not_open' : port.closed ? 'closed' : 'open';
    updateTimelineTrack(row.track, port.intervals.map(interval => ({...interval, state})));
    if (row.details.open && deviceRow.details.open) loadTimelinePortObservations(deviceId, row);
}
function updateTimelineDevice(device) {
    const key = String(device.id);
    const row = timelineDeviceRows.get(key) || createTimelineDeviceRow(device);
    row.label.textContent = [device.ip, device.display_name || device.hostname].filter(Boolean).join(' · ') || `Gerät #${device.id}`;
    row.searchText = [device.ip, device.display_name, device.hostname, device.mac]
        .filter(Boolean).join(' ').toLowerCase();
    row.category = device.category || 'unknown';
    row.topologyPlaced = Boolean(device.topology_placed);
    updateTimelineTrack(row.track, device.intervals.map(interval => ({
        ...interval, state:device.active === false ? 'inactive' : 'online',
    })));
    for (const port of device.ports) updateTimelinePortRow(key, row, port, device.active);
    row.empty.hidden = row.portRows.size > 0;
}
function updateTimelineExpandButton() {
    const deviceDetails = [...timelineDeviceRows.values()].map(row => row.details);
    const allOpen = deviceDetails.length > 0 && deviceDetails.every(item => item.open);
    timelineExpandAll.disabled = deviceDetails.length === 0;
    timelineExpandAll.textContent = allOpen ? 'Alle einklappen' : 'Alle ausklappen';
}
function applyTimelineSearch() {
    const query = timelineSearch.value.toLowerCase().trim();
    const selectedCategory = timelineCategorySelect.value;
    const portMatch = query.match(/^port\b\s*:?\s*(\d+)$/);
    const isPortQuery = /^port\b/.test(query);
    let visibleDevices = 0;

    for (const row of timelineDeviceRows.values()) {
        const categoryMatches = !selectedCategory || (selectedCategory === TIMELINE_UNASSIGNED_FILTER
            ? !row.topologyPlaced : row.category === selectedCategory);
        const deviceMatches = categoryMatches && (!query || (!isPortQuery && row.searchText.includes(query)));
        let matchingPorts = 0;
        for (const portRow of row.portRows.values()) {
            const matches = !query || (isPortQuery
                ? Boolean(portMatch && Number(portMatch[1]) >= 1 && Number(portMatch[1]) <= 65535 &&
                    portRow.portNumber === String(Number(portMatch[1])))
                : portRow.searchText.includes(query));
            portRow.details.hidden = Boolean(query && !deviceMatches && !matches);
            if (query && matches) matchingPorts++;
        }
        const visible = categoryMatches && (deviceMatches || matchingPorts > 0);
        row.details.hidden = !visible;
        if (visible) visibleDevices++;
        // Reveal matching port rows when the match came from a port field.
        if (query && matchingPorts > 0) row.details.open = true;
    }

    if (!timelineNoMatchesMessage) {
        timelineNoMatchesMessage = document.createElement('p');
        timelineNoMatchesMessage.className = 'timeline-service-empty';
        timelineNoMatchesMessage.textContent = 'Keine passenden Timeline-Einträge gefunden.';
        timelineContent.appendChild(timelineNoMatchesMessage);
    }
    timelineNoMatchesMessage.hidden = !query || visibleDevices > 0;
    updateTimelineExpandButton();
}
function setAllTimelineDevices(open) {
    for (const [deviceId, row] of timelineDeviceRows) {
        row.details.open = open;
        if (open) timelineExpandedDevices.add(deviceId);
        else timelineExpandedDevices.delete(deviceId);
    }
    updateTimelineExpandButton();
}
async function loadTimeline() {
    const requestId = ++timelineRequestId;
    timelineAbortController?.abort();
    timelineAbortController = new AbortController();
    const networkId = networkSelect.value;
    if (!networkId) {
        resetTimeline();
        timelineContext = null;
        timelineSearchExpansionSnapshot = null;
        renderTimelineCategoryMenu([]);
        document.querySelector('#timeline-prev').disabled = true;
        document.querySelector('#timeline-next').disabled = true;
        timelineStatus.textContent = 'Bitte Netzwerk auswählen.';
        return;
    }
    if (!timelineContent.children.length) timelineStatus.textContent = 'Lade Verlauf …';
    try {
        const url = `/api/timeline?network_id=${encodeURIComponent(networkId)}&tz=${encodeURIComponent(timelineZone)}${timelineDay.value ? '&day=' + encodeURIComponent(timelineDay.value) : ''}`;
        const data = await fetchJson(url, {signal:timelineAbortController.signal});
        if (requestId !== timelineRequestId || networkId !== networkSelect.value) return;
        const context = `${networkId}:${data.day}`;
        if (context !== timelineContext) {
            if (timelineContext && timelineContext.startsWith(`${networkId}:`)) captureTimelineExpansion();
            else {
                timelineExpandedDevices = new Set();
                timelineExpandedPorts = new Set();
            }
            resetTimeline();
            timelineSearchExpansionSnapshot = null;
            timelineContext = context;
        }
        timelineDays = data.days; timelineDay.value = data.day;
        timelineStatus.textContent = `${new Date(data.day + 'T12:00:00').toLocaleDateString('de-DE')} · 00:00–24:00 · ${data.timezone}`;
        document.querySelector('#timeline-prev').disabled = !timelineDays.some(day => day < data.day);
        document.querySelector('#timeline-next').disabled = !timelineDays.some(day => day > data.day);
        ensureTimelineAxis();
        if (!data.has_day_observations) {
            if (!timelineEmptyMessage) {
                timelineEmptyMessage = document.createElement('p');
                timelineEmptyMessage.className = 'timeline-service-empty';
                timelineEmptyMessage.textContent = 'Für diesen Tag liegen keine neuen Scanbeobachtungen vor. Angezeigte Geräte und Ports zeigen den zuletzt gespeicherten Stand.';
                timelineAxis.after(timelineEmptyMessage);
            }
        } else {
            timelineEmptyMessage?.remove();
            timelineEmptyMessage = null;
        }
        for (const device of data.devices) updateTimelineDevice(device);
        renderTimelineCategoryMenu(data.devices);
        const presentDeviceIds = new Set(data.devices.map(device => String(device.id)));
        timelineExpandedDevices = new Set([...timelineExpandedDevices].filter(id => presentDeviceIds.has(id)));
        const presentPortIds = new Set(data.devices.flatMap(device =>
            device.ports.map(port => `${device.id}:${port.key}`)));
        timelineExpandedPorts = new Set([...timelineExpandedPorts].filter(key => presentPortIds.has(key)));
        applyTimelineSearch();
        updateTimelineExpandButton();
        setConnectionStatus('API verbunden', true);
    } catch (error) {
        if (error.name === 'AbortError') return;
        if (requestId === timelineRequestId) {
            timelineStatus.textContent = `Timeline: ${error.message}`;
            setConnectionStatus(`API-Fehler: ${error.message}`, false);
        }
    }
}
timelineDay.addEventListener('change', loadTimeline);
timelineCategorySelect.addEventListener('change', applyTimelineSearch);
timelineSearch.addEventListener('input', () => {
    const active = Boolean(timelineSearch.value.trim());
    if (active && !timelineSearchExpansionSnapshot) {
        timelineSearchExpansionSnapshot = {
            devices: new Set(timelineExpandedDevices),
            ports: new Set(timelineExpandedPorts),
        };
    } else if (!active && timelineSearchExpansionSnapshot) {
        timelineExpandedDevices = new Set(timelineSearchExpansionSnapshot.devices);
        timelineExpandedPorts = new Set(timelineSearchExpansionSnapshot.ports);
        for (const [deviceId, row] of timelineDeviceRows) {
            row.details.open = timelineExpandedDevices.has(deviceId);
            for (const [portKey, portRow] of row.portRows)
                portRow.details.open = timelineExpandedPorts.has(`${deviceId}:${portKey}`);
        }
        timelineSearchExpansionSnapshot = null;
    }
    applyTimelineSearch();
});
timelineExpandAll.addEventListener('click', () => {
    const devices = [...timelineDeviceRows.values()].map(row => row.details);
    setAllTimelineDevices(!(devices.length > 0 && devices.every(item => item.open)));
});
networkSelect.addEventListener('change', () => {timelineDay.value = ''; loadTimeline();});
for (const [id, direction] of [['timeline-prev', -1], ['timeline-next', 1]]) {
    document.getElementById(id).addEventListener('click', () => {
        const candidates = timelineDays.filter(day => direction < 0 ? day < timelineDay.value : day > timelineDay.value);
        timelineDay.value = direction < 0 ? candidates.at(-1) : candidates[0]; loadTimeline();
    });
}
