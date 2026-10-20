"use strict";

const CONFIG_TIMING_LABELS = {
    discovery_interval_seconds: "Discovery-Intervall",
    detail_interval_seconds: "Detail- und Enrichment-Intervall",
    discovery_retry_seconds: "Wiederholung nach fehlgeschlagener Discovery",
    main_loop_sleep_seconds: "Wartezeit der Scan-Schleife",
    topology_interval_seconds: "Topologie-Intervall",
    initial_topology_delay_seconds: "Verzögerung des ersten Topologie-Laufs",
    idle_recheck_seconds: "Wiederprüfung während eines laufenden Scans",
    supervisor_tick_seconds: "Prüfintervall des Launchers",
    classification_reconcile_interval_seconds: "Klassifikationsabgleich",
    initial_reconcile_delay_seconds: "Verzögerung des ersten Klassifikationsabgleichs"
};

const CONFIG_PROFILE_LABELS = {
    discovery: "Geräte suchen",
    detail: "Detail-Scan",
    reachability: "Erreichbarkeit prüfen",
    os_light: "Betriebssystem und Dienste (leicht)",
    os_deep: "Betriebssystem und Dienste (gründlich)",
    services: "Dienste auf bekannten Ports"
};

let currentNetCheckerConfiguration = null;
let configurationHasUnsavedChanges = false;
const configForm = document.querySelector("#configuration-form");
const configFields = document.querySelector("#configuration-fields");
const configStatus = document.querySelector("#configuration-status");

function configField(labelText, control, hint) {
    const wrapper = document.createElement("div");
    wrapper.className = "configuration-field";
    const label = document.createElement("label");
    label.textContent = labelText;
    label.title = labelText;
    label.htmlFor = control.id;
    wrapper.append(label, control);
    if (hint) {
        const note = document.createElement("small");
        note.textContent = hint;
        wrapper.append(note);
    }
    return wrapper;
}

function configNumberInput(id, value) {
    const input = document.createElement("input");
    input.id = id;
    input.type = "number";
    input.min = "1";
    input.max = "86400";
    input.step = "1";
    input.required = true;
    input.value = String(value);
    return input;
}

function renderNetCheckerConfiguration(data) {
    currentNetCheckerConfiguration = data;
    configFields.replaceChildren();
    const effective = data.effective;
    const defaults = data.defaults;

    const timings = document.createElement("section");
    timings.className = "configuration-section";
    const timingHeading = document.createElement("h3");
    timingHeading.textContent = "Zeitpläne und Wartezeiten";
    timingHeading.title = timingHeading.textContent;
    timings.append(timingHeading);
    const timingGrid = document.createElement("div");
    timingGrid.className = "configuration-grid";
    for (const [key, labelText] of Object.entries(CONFIG_TIMING_LABELS)) {
        const input = configNumberInput(`config-timing-${key}`, effective.timings[key]);
        input.dataset.configTiming = key;
        timingGrid.append(configField(labelText, input,
            `Default: ${defaults.timings[key]} Sekunden`));
    }
    timings.append(timingGrid);
    configFields.append(timings);

    const nmap = document.createElement("section");
    nmap.className = "configuration-section";
    const nmapHeading = document.createElement("h3");
    nmapHeading.textContent = "Nmap-Abfragen";
    nmapHeading.title = nmapHeading.textContent;
    const nmapHelp = document.createElement("p");
    nmapHelp.textContent = "Jede Zeile ist ein einzelnes Nmap-Argument. Ausgabeziel und Zielgeräte verwaltet NetChecker selbst.";
    nmap.append(nmapHeading, nmapHelp);
    const profileGrid = document.createElement("div");
    profileGrid.className = "configuration-profile-grid";
    for (const [name, labelText] of Object.entries(CONFIG_PROFILE_LABELS)) {
        const card = document.createElement("article");
        card.className = "configuration-profile";
        const heading = document.createElement("h4");
        heading.textContent = labelText;
        heading.title = labelText;
        const argumentsInput = document.createElement("textarea");
        argumentsInput.id = `config-nmap-${name}-arguments`;
        argumentsInput.rows = 7;
        argumentsInput.spellcheck = false;
        argumentsInput.dataset.configProfile = name;
        argumentsInput.dataset.configProperty = "arguments";
        argumentsInput.value = effective.nmap[name].arguments.join("\n");
        const timeoutInput = configNumberInput(`config-nmap-${name}-timeout`,
            effective.nmap[name].timeout_seconds);
        timeoutInput.dataset.configProfile = name;
        timeoutInput.dataset.configProperty = "timeout_seconds";
        const timeoutField = configField("Prozess-Timeout (Sekunden)", timeoutInput,
            `Default: ${defaults.nmap[name].timeout_seconds} Sekunden`);
        card.append(heading,
            configField("Argumente", argumentsInput,
                `Default: ${defaults.nmap[name].arguments.join(" ")}`), timeoutField);
        profileGrid.append(card);
    }
    nmap.append(profileGrid);
    configFields.append(nmap);
    configStatus.textContent = Object.keys(data.overrides).length
        ? "Nutzerüberschreibungen aktiv" : "Standardwerte aktiv";
}

async function configurationRequest(method, body) {
    const apiKey = document.querySelector("#api-key")?.value || "";
    const headers = {"Content-Type": "application/json"};
    if (apiKey) headers["X-Netchecker-Key"] = apiKey;
    const response = await fetch("/api/configuration", {
        method,
        cache: "no-store",
        headers,
        ...(body === undefined ? {} : {body: JSON.stringify(body)})
    });
    let result = {};
    try { result = await response.json(); } catch (_) {}
    if (!response.ok)
        throw new Error(result.detail || `HTTP ${response.status}`);
    return result;
}

async function loadConfiguration() {
    try {
        const configuration = await configurationRequest("GET");
        if (!configurationHasUnsavedChanges || !currentNetCheckerConfiguration)
            renderNetCheckerConfiguration(configuration);
        setConnectionStatus("Konfiguration verfügbar", true);
    } catch (error) {
        configStatus.textContent = `Konfiguration konnte nicht geladen werden: ${error.message}`;
        setConnectionStatus("Konfiguration nicht verfügbar", false);
    }
}

configForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (!currentNetCheckerConfiguration) return;
    const defaults = currentNetCheckerConfiguration.defaults;
    const overrides = {timings: {}, nmap: {}};
    for (const input of configForm.querySelectorAll("[data-config-timing]")) {
        const key = input.dataset.configTiming;
        const value = Number(input.value);
        if (value !== Number(defaults.timings[key])) overrides.timings[key] = value;
    }
    for (const name of Object.keys(CONFIG_PROFILE_LABELS)) {
        const argumentsInput = configForm.querySelector(`[data-config-profile="${name}"][data-config-property="arguments"]`);
        const timeoutInput = configForm.querySelector(`[data-config-profile="${name}"][data-config-property="timeout_seconds"]`);
        const args = argumentsInput.value.split(/\r?\n/).map(argument => argument.trim()).filter(Boolean);
        const profile = {};
        if (JSON.stringify(args) !== JSON.stringify(defaults.nmap[name].arguments))
            profile.arguments = args;
        const timeout = Number(timeoutInput.value);
        if (timeout !== Number(defaults.nmap[name].timeout_seconds))
            profile.timeout_seconds = timeout;
        if (Object.keys(profile).length) overrides.nmap[name] = profile;
    }
    try {
        configStatus.textContent = "Speichere …";
        const saved = await configurationRequest("PUT", overrides);
        configurationHasUnsavedChanges = false;
        renderNetCheckerConfiguration(saved);
        configStatus.textContent = "Gespeichert. Scanner verwenden die Werte beim nächsten Lauf.";
        setConnectionStatus("Konfiguration gespeichert", true);
    } catch (error) {
        configStatus.textContent = `Speichern fehlgeschlagen: ${error.message}`;
        setConnectionStatus("Speichern fehlgeschlagen", false);
    }
});

document.querySelector("#configuration-reset").addEventListener("click", async () => {
    try {
        configStatus.textContent = "Lösche Nutzerüberschreibungen …";
        const reset = await configurationRequest("DELETE");
        configurationHasUnsavedChanges = false;
        renderNetCheckerConfiguration(reset);
        configStatus.textContent = "Überschreibungen gelöscht. Die Defaults sind aktiv.";
        setConnectionStatus("Defaults aktiv", true);
    } catch (error) {
        configStatus.textContent = `Zurücksetzen fehlgeschlagen: ${error.message}`;
        setConnectionStatus("Zurücksetzen fehlgeschlagen", false);
    }
});

configForm.addEventListener("input", () => {
    configurationHasUnsavedChanges = true;
    configStatus.textContent = "Ungespeicherte Änderungen";
});
