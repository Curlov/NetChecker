"use strict";
let timelineRequestId = 0;
let timelineDays = [];
let timelineContext = null;
let timelineAxis = null;
let timelineEmptyMessage = null;
const timelineDeviceRows = new Map();
let timelineExpandedDevices = new Set();
let timelineExpandedPorts = new Set();
const timelineDay = document.querySelector('#timeline-day');
const timelineContent = document.querySelector('#timeline-content');
const timelineStatus = document.querySelector('#timeline-status');
const timelineZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
function makeTimelineTrack() {
    const track = document.createElement('span');
    track.className = 'timeline-track';
    return track;
}
function updateTimelineTrack(track, intervals) {
    const bars = [...track.children];
    intervals.forEach((interval, index) => {
        const bar = bars[index] || document.createElement('span');
        bar.className = 'timeline-bar';
        bar.style.left = `${interval.start / 14.4}%`;
        bar.style.width = `${Math.max(0, interval.end - interval.start) / 14.4}%`;
        const format = value => new Date(value).toLocaleString('de-DE');
        bar.title = `${format(interval.from)} – ${format(interval.to)} (abgeleitet)`;
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
    timelineDeviceRows.clear();
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
    });
    const summary = document.createElement('summary');
    summary.className = 'timeline-row timeline-port-summary';
    const label = document.createElement('span');
    label.className = 'timeline-port-label';
    const track = makeTimelineTrack();
    summary.append(label, track);
    const observations = document.createElement('div');
    observations.className = 'timeline-port-observations';
    details.append(summary, observations);
    return {details, label, track, observations, observationRows:new Map()};
}
function updateTimelinePortRow(deviceId, deviceRow, port) {
    let row = deviceRow.portRows.get(port.key);
    if (!row) {
        row = createTimelinePortRow(deviceId, port);
        deviceRow.portRows.set(port.key, row);
        deviceRow.services.appendChild(row.details);
    }
    const latest = port.observations.at(-1)?.port_data || {};
    row.label.textContent = `${port.protocol.toUpperCase()} ${port.port}${latest.service ? ` – ${latest.service}` : ''}`;
    updateTimelineTrack(row.track, port.intervals);
    for (const item of port.observations) {
        if (row.observationRows.has(item.id)) continue;
        const observation = createPortObservation(item);
        row.observations.appendChild(observation);
        row.observationRows.set(item.id, observation);
    }
}
function updateTimelineDevice(device) {
    const key = String(device.id);
    const row = timelineDeviceRows.get(key) || createTimelineDeviceRow(device);
    row.label.textContent = [device.ip, device.display_name || device.hostname].filter(Boolean).join(' · ') || `Gerät #${device.id}`;
    updateTimelineTrack(row.track, device.intervals);
    for (const port of device.ports) updateTimelinePortRow(key, row, port);
    row.empty.hidden = row.portRows.size > 0;
}
async function loadTimeline() {
    const requestId = ++timelineRequestId;
    const networkId = networkSelect.value;
    if (!networkId) {
        resetTimeline();
        timelineContext = null;
        document.querySelector('#timeline-prev').disabled = true;
        document.querySelector('#timeline-next').disabled = true;
        timelineStatus.textContent = 'Bitte Netzwerk auswählen.';
        return;
    }
    if (!timelineContent.children.length) timelineStatus.textContent = 'Lade Verlauf …';
    try {
        const url = `/api/timeline?network_id=${encodeURIComponent(networkId)}&tz=${encodeURIComponent(timelineZone)}${timelineDay.value ? '&day=' + encodeURIComponent(timelineDay.value) : ''}`;
        const data = await fetchJson(url);
        if (requestId !== timelineRequestId || networkId !== networkSelect.value) return;
        const context = `${networkId}:${data.day}`;
        if (context !== timelineContext) {
            if (timelineContext && timelineContext.startsWith(`${networkId}:`)) captureTimelineExpansion();
            else {
                timelineExpandedDevices = new Set();
                timelineExpandedPorts = new Set();
            }
            resetTimeline();
            timelineContext = context;
        }
        timelineDays = data.days; timelineDay.value = data.day;
        timelineStatus.textContent = `${new Date(data.day + 'T12:00:00').toLocaleDateString('de-DE')} · 00:00–24:00 · ${data.timezone}`;
        document.querySelector('#timeline-prev').disabled = !timelineDays.some(day => day < data.day);
        document.querySelector('#timeline-next').disabled = !timelineDays.some(day => day > data.day);
        ensureTimelineAxis();
        if (!data.devices.length && timelineDeviceRows.size === 0) {
            if (!timelineEmptyMessage) {
                timelineEmptyMessage = document.createElement('p');
                timelineEmptyMessage.textContent = 'Keine Verlaufsdaten für diesen Tag vorhanden.';
            }
            timelineContent.appendChild(timelineEmptyMessage);
        } else {
            timelineEmptyMessage?.remove();
            timelineEmptyMessage = null;
            for (const device of data.devices) updateTimelineDevice(device);
        }
        const presentDeviceIds = new Set(data.devices.map(device => String(device.id)));
        timelineExpandedDevices = new Set([...timelineExpandedDevices].filter(id => presentDeviceIds.has(id)));
        const presentPortIds = new Set(data.devices.flatMap(device =>
            device.ports.map(port => `${device.id}:${port.key}`)));
        timelineExpandedPorts = new Set([...timelineExpandedPorts].filter(key => presentPortIds.has(key)));
        setConnectionStatus('API verbunden', true);
    } catch (error) {
        if (requestId === timelineRequestId) {
            timelineStatus.textContent = `Timeline: ${error.message}`;
            setConnectionStatus(`API-Fehler: ${error.message}`, false);
        }
    }
}
timelineDay.addEventListener('change', loadTimeline);
networkSelect.addEventListener('change', () => {timelineDay.value = ''; loadTimeline();});
for (const [id, direction] of [['timeline-prev', -1], ['timeline-next', 1]]) {
    document.getElementById(id).addEventListener('click', () => {
        const candidates = timelineDays.filter(day => direction < 0 ? day < timelineDay.value : day > timelineDay.value);
        timelineDay.value = direction < 0 ? candidates.at(-1) : candidates[0]; loadTimeline();
    });
}
