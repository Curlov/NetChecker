const svgNamespace = 'http://www.w3.org/2000/svg';
const TOPOLOGY_LABEL_REFERENCE = '333.333.333.333';
const TOPOLOGY_HORIZONTAL_GAP = 5;
const TOPOLOGY_VERTICAL_GAP = 17;
const TOPOLOGY_GRID_ORIGIN = {x:90,y:60};
const TOPOLOGY_ROOM_TITLE_GAP = 8;
const TOPOLOGY_ROOM_TITLE_HEIGHT = 26;
let topologyLayoutId = null;
let topologySaveQueue = Promise.resolve();
let topologyManualSaveQueue = Promise.resolve();
let topologyPendingWrites = 0;
let topologyMutationVersion = 0;
let topologyManualNodes = [];
let topologyManualLinks = [];
let topologyCurrentRenderData = null;
let topologyLinkRedrawFrame = null;
let topologyLinkRedrawTimer = null;
let selectedManualNodeId = null;
let selectedTopologyNodeKey = null;
let selectedTopologyLinkId = null;
let topologyGridSpacing = {column: 0, row: 0};
let topologyLabelMaxWidth = 0;
let topologyMeasuredNodeBounds = null;
let topologyNodeYOffset = 0;
let topologyPaletteDrag = null;
let topologyTrayDrag = null;
let topologyUnplacedDevices = [];
let topologyUnplacedCollapsed = false;
let topologyPendingDrop = null;
let topologyContextAnchor = {x:24,y:24};
let topologyRooms = [];
let topologyRenderedNodes = [];
let topologyRoomShapeUpdates = new Map();
let topologyDropPreviewRoomId = null;
let selectedRoomId = null;
let topologyToolMode = 'select';
let topologyEditorGesture = null;
let topologyLinkDrag = null;
let topologyConnectionArmed = null;
let topologyRoomDraw = null;
let topologyCameraInitialized = false;
let topologyRoomBoundaryCycle = {key:'',index:0,time:0,roomId:null};
let topologyLinkPreviewElement = null;
const TOPOLOGY_CONNECTION_SIDES = ['top','right','bottom','left'];
const TOPOLOGY_LINK_TYPES = [
    ['ethernet','Ethernet'],['fiber','Glasfaser'],['wifi','WLAN'],
    ['logical','Logische Verbindung'],['unknown','Unbekannt']
];
const TOPOLOGY_EVIDENCE_LABELS = {
    manual_documented:'Manuell dokumentiert',
    scanner_derived:'Technisch abgeleitet',
    observed:'Tatsächlich beobachtet'
};

function topologyGridToPixel(gridColumn,gridRow,{nodeAnchor=false}={}) {
    return {
        x:TOPOLOGY_GRID_ORIGIN.x+gridColumn*topologyGridSpacing.column,
        y:TOPOLOGY_GRID_ORIGIN.y+gridRow*topologyGridSpacing.row+
            (nodeAnchor ? topologyNodeYOffset : 0)
    };
}

function topologyPixelToGrid(x,y,{nodeAnchor=false}={}) {
    return {
        gridColumn:Math.round((x-TOPOLOGY_GRID_ORIGIN.x)/topologyGridSpacing.column),
        gridRow:Math.round((y-TOPOLOGY_GRID_ORIGIN.y-
            (nodeAnchor ? topologyNodeYOffset : 0))/topologyGridSpacing.row)
    };
}

function topologyGridDeltaFromPixels(dx,dy) {
    return {
        gridColumn:Math.round(dx/topologyGridSpacing.column),
        gridRow:Math.round(dy/topologyGridSpacing.row)
    };
}

function topologyGridVectorToPixel(gridColumns,gridRows) {
    return {x:gridColumns*topologyGridSpacing.column,y:gridRows*topologyGridSpacing.row};
}

function topologyGridSizeToPixel(gridWidth,gridHeight) {
    return {width:gridWidth*topologyGridSpacing.column,height:gridHeight*topologyGridSpacing.row};
}

function topologyGridBoundaryToPixel(gridX,gridY) {
    return {
        x:TOPOLOGY_GRID_ORIGIN.x+(gridX-0.5)*topologyGridSpacing.column,
        y:TOPOLOGY_GRID_ORIGIN.y+(gridY-0.5)*topologyGridSpacing.row
    };
}

function topologyPixelToGridBoundary(point) {
    return {
        x:Math.round((point.x-TOPOLOGY_GRID_ORIGIN.x)/topologyGridSpacing.column+0.5),
        y:Math.round((point.y-TOPOLOGY_GRID_ORIGIN.y)/topologyGridSpacing.row+0.5)
    };
}

function topologyRoomPixelBounds(room) {
    const topLeft=topologyGridBoundaryToPixel(Number(room.grid_x),Number(room.grid_y));
    const {width,height}=topologyGridSizeToPixel(Number(room.grid_width),Number(room.grid_height));
    return {x:topLeft.x,y:topLeft.y,width,height,right:topLeft.x+width,bottom:topLeft.y+height};
}

function topologyConnectionNormal(anchor) {
    return {
        top:{x:0,y:-1},right:{x:1,y:0},bottom:{x:0,y:1},left:{x:-1,y:0}
    }[anchor];
}

function topologyNodeEndpoint(node,anchor) {
    const endpoint=node.device?.id != null
        ? {device_id:Number(node.device.id),anchor}
        : {manual_node_id:Number(node.manual.id),anchor};
    return endpoint;
}

function topologyEndpointIdentity(endpoint) {
    if (endpoint.manual_node_id != null) {
        const node=topologyRenderedNodes.find(item=>Number(item.manual?.id)===Number(endpoint.manual_node_id));
        if (node?.manual?.linked_device_id != null) return `device:${Number(node.manual.linked_device_id)}`;
    }
    const kind=endpoint.device_id != null ? 'device' : endpoint.manual_node_id != null ? 'manual' : 'room';
    const id=endpoint.device_id ?? endpoint.manual_node_id ?? endpoint.room_id;
    return `${kind}:${Number(id)}`;
}

function topologyPathData(points) {
    return points.map((point,index) => `${index ? 'L' : 'M'}${point.x},${point.y}`).join(' ');
}

function topologyDistanceToSegment(point,x1,y1,x2,y2) {
    const dx=x2-x1, dy=y2-y1;
    const lengthSquared=dx*dx+dy*dy;
    const progress=lengthSquared
        ? Math.max(0,Math.min(1,((point.x-x1)*dx+(point.y-y1)*dy)/lengthSquared)) : 0;
    return Math.hypot(point.x-(x1+progress*dx),point.y-(y1+progress*dy));
}

function topologyRoomAtBoundary(event) {
    const point=topologySvgPoint(event.clientX,event.clientY);
    const matrix=topologyGraph.getScreenCTM();
    if (!point || !matrix) return null;
    const screenScale=Math.hypot(matrix.a,matrix.b) || 1;
    const tolerance=8/screenScale;
    const roomOrder=new Map([...topologyGraph.children].map((item,index) =>
        [Number(item.dataset.roomId),index]));
    const candidates=topologyRooms.map(room => {
        const box=topologyRoomPixelBounds(room);
        const distance=Math.min(
            topologyDistanceToSegment(point,box.x,box.y,box.right,box.y),
            topologyDistanceToSegment(point,box.right,box.y,box.right,box.bottom),
            topologyDistanceToSegment(point,box.right,box.bottom,box.x,box.bottom),
            topologyDistanceToSegment(point,box.x,box.bottom,box.x,box.y)
        );
        return {room,distance};
    }).filter(item => item.distance <= tolerance)
        .sort((a,b) => a.distance-b.distance ||
            (roomOrder.get(Number(b.room.id)) ?? -1)-(roomOrder.get(Number(a.room.id)) ?? -1) ||
            topologyRoomDepth(b.room)-topologyRoomDepth(a.room) ||
            Number(b.room.id)-Number(a.room.id));
    if (!candidates.length) {
        topologyRoomBoundaryCycle={key:'',index:0,time:0,roomId:null};
        return null;
    }
    const roomIds=candidates.map(item => Number(item.room.id)).sort((a,b) => a-b);
    const key=`${roomIds.join(',')}:${Math.round(event.clientX/8)}:${Math.round(event.clientY/8)}`;
    const now=performance.now();
    const previousIndex=candidates.findIndex(item => Number(item.room.id) ===
        Number(topologyRoomBoundaryCycle.roomId));
    const index=key === topologyRoomBoundaryCycle.key && now-topologyRoomBoundaryCycle.time < 1200 &&
        previousIndex >= 0 ? (previousIndex+1)%candidates.length : 0;
    topologyRoomBoundaryCycle={key,index,time:now,roomId:Number(candidates[index].room.id)};
    return candidates[index].room;
}

function topologyRoomDepth(room) {
    let depth=0;
    let parentId=room.parent_room_id == null ? null : Number(room.parent_room_id);
    const visited=new Set([Number(room.id)]);
    while (parentId !== null && !visited.has(parentId)) {
        visited.add(parentId); depth++;
        const parent=topologyRooms.find(item => Number(item.id) === parentId);
        parentId=parent?.parent_room_id == null ? null : Number(parent.parent_room_id);
    }
    return depth;
}

function topologyRoomDescendantIds(roomId) {
    const descendants=new Set();
    let changed=true;
    while (changed) {
        changed=false;
        for (const room of topologyRooms) {
            const id=Number(room.id);
            const parentId=room.parent_room_id == null ? null : Number(room.parent_room_id);
            if (id !== Number(roomId) && parentId !== null &&
                (parentId === Number(roomId) || descendants.has(parentId)) && !descendants.has(id)) {
                descendants.add(id); changed=true;
            }
        }
    }
    return descendants;
}

function topologyRoomParentForGridBounds(bounds,excludedRoomIds=new Set()) {
    const excluded=new Set([...excludedRoomIds].map(Number));
    return topologyRooms.filter(room => !excluded.has(Number(room.id)) &&
        bounds.grid_x >= Number(room.grid_x) && bounds.grid_y >= Number(room.grid_y) &&
        bounds.grid_x+bounds.grid_width <= Number(room.grid_x)+Number(room.grid_width) &&
        bounds.grid_y+bounds.grid_height <= Number(room.grid_y)+Number(room.grid_height))
        .sort((a,b) => Number(a.grid_width)*Number(a.grid_height)-Number(b.grid_width)*Number(b.grid_height) ||
            Number(a.id)-Number(b.id))[0] || null;
}

function readTopologyCamera(networkId) {
    try {
        const stored=sessionStorage.getItem(`netchecker.topology.camera.${networkId}`);
        if (!stored) return null;
        const values=stored.trim().split(/\s+/).map(Number);
        if (values.length !== 4 || !values.every(Number.isFinite) || values[2] <= 0 || values[3] <= 0)
            return null;
        return values.join(' ');
    } catch (_) { return null; }
}

function saveTopologyCamera(svg) {
    const networkId=topologyGraphContext;
    const viewBox=svg?.getAttribute('viewBox');
    if (networkId == null || !viewBox) return;
    try { sessionStorage.setItem(`netchecker.topology.camera.${networkId}`,viewBox); }
    catch (_) {}
}

const topologyManualTypes = {
    switch: {label:'Switch',icon:'network'},
    router: {label:'Router',icon:'router'},
    firewall: {label:'Firewall',icon:'router'},
    gateway: {label:'Gateway',icon:'router'},
    access_point: {label:'Access Point',icon:'monitor-smartphone'},
    patchpanel: {label:'Patchpanel',icon:'network'},
    network: {label:'Netzwerk',icon:'network'},
    internet: {label:'Internet',icon:'circle-question-mark'},
    generic: {label:'Generischer Knoten',icon:'info'}
};

function setTopologySaveStatus(message, state = '') {
    const element = document.querySelector('#topology-save-status');
    if (!element) return;
    element.textContent = message;
    element.dataset.state = state;
}

function topologyApiError(result,status) {
    const detail = result?.detail;
    if (Array.isArray(detail)) {
        const messages = detail.map(issue => {
            const location = (issue.loc || []).filter(part => part !== 'body').join('.');
            const message = issue.type === 'extra_forbidden' ? 'unerwartetes Feld' :
                issue.msg === 'Field required' ? 'Pflichtfeld fehlt' :
                issue.msg === 'Input should be a valid integer' ? 'muss eine ganze Zahl sein' :
                issue.msg === 'Input should be greater than or equal to 2' ? 'muss mindestens 2 sein' :
                issue.msg || 'ungültiger Wert';
            return location ? `${location}: ${message}` : message;
        });
        if (messages.length) return `Ungültige Eingabe: ${messages.join('; ')}`;
    }
    if (typeof detail === 'string' && detail) return detail;
    return `HTTP ${status}`;
}

function syncTopologyRooms(updatedRooms) {
    if (!Array.isArray(updatedRooms)) return;
    const currentRooms = topologyRooms;
    topologyRooms = updatedRooms.map(updated => {
        const current = currentRooms.find(room => Number(room.id) === Number(updated.id));
        return current ? Object.assign(current,updated) : updated;
    });
    refreshTopologyRoomShapes();
}

function refreshTopologyRoomShapes() {
    for (const updateShape of topologyRoomShapeUpdates.values()) updateShape();
}

function applyTopologyRoomAssignments(assignments) {
    for (const assignment of assignments) {
        const manual = assignment.manual_node_id != null;
        const memberId = Number(manual ? assignment.manual_node_id : assignment.device_id);
        if (!Number.isFinite(memberId)) continue;
        const memberKey = manual ? 'manual_node_ids' : 'device_ids';
        for (const room of topologyRooms)
            room[memberKey] = (room[memberKey] || []).filter(id => Number(id) !== memberId);
        if (assignment.room_id != null) {
            const room = topologyRooms.find(item => Number(item.id) === Number(assignment.room_id));
            if (room) room[memberKey] = [...(room[memberKey] || []),memberId];
        }
    }
    refreshTopologyRoomShapes();
}

async function saveTopologyLayout(networkId, layoutId, positions, manualPositions = [], roomAssignments = []) {
    topologyPendingWrites++;
    const operation = topologySaveQueue.then(async () => {
        if (String(networkId) === topologyGraphContext)
            setTopologySaveStatus('Speichere Layout …', 'saving');
        const headers = {'Content-Type': 'application/json'};
        const apiKey = document.querySelector('#api-key').value;
        if (apiKey) headers['X-Netchecker-Key'] = apiKey;
        const response = await fetch(
            `/api/topology/layout?network_id=${encodeURIComponent(networkId)}`,
            {
                method: 'PUT',
                cache: 'no-store',
                headers,
                body: JSON.stringify({layout_id: layoutId, positions, manual_positions: manualPositions,
                    room_assignments: roomAssignments})
            }
        );
        let result = {};
        try { result = await response.json(); } catch (_) {}
        if (!response.ok)
            throw new Error(topologyApiError(result,response.status));
        if (String(networkId) === topologyGraphContext) {
            topologyLayoutId = result.layout?.id ?? null;
            syncTopologyRooms(result.rooms);
            setTopologySaveStatus('Layout gespeichert', 'saved');
        }
        return {saved:true,error:null};
    });
    topologySaveQueue = operation.catch(() => {});
    try {
        return await operation;
    } catch (error) {
        if (String(networkId) === topologyGraphContext)
            setTopologySaveStatus(`Nicht dauerhaft gespeichert: ${error.message}`, 'error');
        return {saved:false,error:error.message};
    } finally {
        topologyPendingWrites--;
        topologyMutationVersion++;
    }
}

function svgElement(name, attributes) {
    const element = document.createElementNS(svgNamespace, name);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
    return element;
}

function measureTopologyCellGeometry(svg) {
    const sample = svgElement('g',{class:'topology-node topology-measurement',transform:'translate(32,32)'});
    sample.appendChild(svgElement('circle',{r:16,class:'topology-node-background'}));
    const icon = createLucideIcon('info');
    for (const [key,value] of Object.entries({x:-9,y:-9,width:18,height:18})) icon.setAttribute(key,value);
    sample.appendChild(icon);
    const label = svgElement('text',{x:0,y:32,'text-anchor':'middle',class:'topology-node-label'});
    label.textContent = TOPOLOGY_LABEL_REFERENCE;
    sample.appendChild(label);
    const status = svgElement('text',{x:0,y:47,'text-anchor':'middle',class:'topology-status-label'});
    sample.appendChild(status);
    svg.appendChild(sample);

    try {
        const labelWidth = label.getBBox().width;
        let nodeBounds = null;
        for (const text of ['Erreichbar','Nicht erreichbar','Status unbekannt','Manuell']) {
            status.textContent = text;
            const bounds = sample.getBBox();
            nodeBounds = nodeBounds ? {
                x:Math.min(nodeBounds.x,bounds.x), y:Math.min(nodeBounds.y,bounds.y),
                width:Math.max(nodeBounds.x+nodeBounds.width,bounds.x+bounds.width)-Math.min(nodeBounds.x,bounds.x),
                height:Math.max(nodeBounds.y+nodeBounds.height,bounds.y+bounds.height)-Math.min(nodeBounds.y,bounds.y)
            } : bounds;
        }
        if (!(labelWidth > 0) || !nodeBounds)
            throw new Error('SVG-Textmaße für das Topologie-Raster konnten nicht ermittelt werden.');
        return {
            labelWidth,
            column:labelWidth+TOPOLOGY_HORIZONTAL_GAP,
            row:nodeBounds.height+TOPOLOGY_VERTICAL_GAP,
            nodeBounds,
            nodeYOffset:-(nodeBounds.y+nodeBounds.height/2)
        };
    } finally {
        sample.remove();
    }
}

function fitTopologyNodeLabel(element,fullText,maxWidth) {
    const text = String(fullText);
    element.textContent = text;
    if (element.getBBox().width <= maxWidth) return;
    const characters = [...text];
    let low = 0;
    let high = characters.length;
    while (low < high) {
        const middle = Math.ceil((low+high)/2);
        element.textContent = `${characters.slice(0,middle).join('')}…`;
        if (element.getBBox().width <= maxWidth) low = middle;
        else high = middle-1;
    }
    element.textContent = `${characters.slice(0,low).join('')}…`;
}

function createTopologyNodeVisual(node) {
    const design = node.manual ? topologyManualTypes[node.manual.node_type] : deviceClassDesign(node.device?.category);
    const presence = node.device ? topologyPresenceDesign(node.device.presence) :
        {tone:'unknown',label:'Status unbekannt'};
    const origin = node.manual ? (node.device ? 'Manuell angelegt · mit erkanntem Gerät verknüpft' :
        'Manuell angelegt · nicht vom Scanner erkannt') : 'Vom Scanner erkannt';
    const description = `${node.label} · ${design.label} · ${origin} · ${presence.label}`;
    const selectedClass = node.key === selectedTopologyNodeKey ? ' topology-node-selected' : '';
    const group = svgElement('g',{class:`topology-node topology-status-${presence.tone}${node.manual ? ' topology-node-manual' : ''}${selectedClass}`,tabindex:0,
        'aria-label':description,
        'data-topology-key':node.key,
        'data-device-id':node.device ? Number(node.device.id) : '',
        'data-manual-node-id':node.manual ? Number(node.manual.id) : ''});
    group.appendChild(svgElement('circle',{r:16,class:'topology-node-background'}));
    const icon = createLucideIcon(design.icon);
    for (const [key,value] of Object.entries({x:-9,y:-9,width:18,height:18})) icon.setAttribute(key,value);
    group.appendChild(icon);
    const label = svgElement('text',{x:0,y:32,'text-anchor':'middle',class:'topology-node-label'});
    const fullLabel = String(node.label);
    label.textContent = fullLabel;
    const title = svgElement('title',{}); title.textContent = description; group.appendChild(title);
    const statusLabel = svgElement('text',{x:0,y:47,'text-anchor':'middle',class:'topology-status-label'});
    statusLabel.textContent = node.manual && !node.device ? 'Manuell' : presence.tone === 'present' ? 'Erreichbar' :
        presence.tone === 'missing' ? 'Nicht erreichbar' : 'Status unbekannt';
    group.appendChild(statusLabel);
    group.appendChild(label);
    const labelTitle = svgElement('title',{}); labelTitle.textContent = fullLabel; label.appendChild(labelTitle);
    group.topologyLabelElement=label;
    return group;
}

function topologyDeviceSearchText(device) {
    const design=deviceClassDesign(device.category);
    return [device.ip,device.hostname,device.category,design.label].filter(Boolean).join(' ').toLocaleLowerCase('de');
}

function renderTopologyUnplacedDevices() {
    const section=document.querySelector('#topology-unplaced');
    const toggle=document.querySelector('#topology-unplaced-toggle');
    const content=document.querySelector('#topology-unplaced-content');
    const list=document.querySelector('#topology-unplaced-list');
    const empty=document.querySelector('#topology-unplaced-empty');
    const search=document.querySelector('#topology-unplaced-search');
    if (!section || !toggle || !content || !list || !empty || !search) return;
    toggle.replaceChildren();
    toggle.appendChild(createLucideIcon('chevron-down'));
    const heading=document.createElement('span');
    heading.textContent=`Nicht platzierte Geräte (${topologyUnplacedDevices.length})`;
    toggle.appendChild(heading);
    toggle.setAttribute('aria-expanded',String(!topologyUnplacedCollapsed));
    content.hidden=topologyUnplacedCollapsed;
    const query=search.value.trim().toLocaleLowerCase('de');
    const matching=topologyUnplacedDevices.filter(device => !query || topologyDeviceSearchText(device).includes(query));
    list.replaceChildren();
    for (const device of matching) {
        const node={key:`device:${device.id}`,device,label:device.ip || device.hostname || `Gerät #${device.id}`};
        const item=svgElement('svg',{class:'topology-unplaced-device',role:'listitem',tabindex:0,
            'aria-label':`${node.label} · ${device.hostname || ''} · ${deviceClassDesign(device.category).label}`,
            'data-device-id':Number(device.id),viewBox:`0 0 ${topologyGridSpacing.column} ${topologyGridSpacing.row}`,
            width:topologyGridSpacing.column,height:topologyGridSpacing.row});
        const visual=createTopologyNodeVisual(node);
        visual.setAttribute('transform',`translate(${topologyGridSpacing.column/2},${topologyGridSpacing.row/2+topologyNodeYOffset})`);
        item.appendChild(visual);
        item.addEventListener('pointerdown',event => {
            if (event.button !== 0 || topologyTrayDrag || topologyEditorGesture) return;
            closeTopologyContextMenu();
            event.preventDefault();
            topologyTrayDrag={pointerId:event.pointerId,node,startX:event.clientX,startY:event.clientY,
                moved:false,cell:null,target:item,sourceLayoutId:topologyLayoutId};
            topologyEditorGesture={type:'device-tray-drag',pointerId:event.pointerId,target:item};
            item.setPointerCapture(event.pointerId);
        });
        item.addEventListener('lostpointercapture',event => finishTopologyTrayDrag(event,true));
        list.appendChild(item);
        fitTopologyNodeLabel(visual.topologyLabelElement,String(node.label),topologyLabelMaxWidth);
    }
    empty.hidden=matching.length > 0;
    empty.textContent=topologyUnplacedDevices.length === 0
        ? 'Alle Geräte sind platziert.' : 'Keine Geräte entsprechen der Suche.';
}

async function loadTopology() {
    return loadInventoryTopology();
}

async function loadInventoryTopology({preserveGraphOnError=false} = {}) {
    const networkId = networkSelect.value;
    const mutationVersion = topologyMutationVersion;
    let loadPhase = 'Geräte laden';
    if (topologyEditorGesture && String(networkId) !== topologyGraphContext)
        cancelTopologyGesture();
    const requestId = ++topologyRequestId;
    const status = document.querySelector('#topology-status');
    const graph = document.querySelector('#topology-graph');
    document.querySelector('#topology-evidence').textContent = '';
    if (!networkId) {
        if (!preserveGraphOnError) {
            if (topologyEditorGesture) cancelTopologyGesture();
            graph.replaceChildren();
        }
        status.textContent = 'Kein Netzwerk ausgewählt';
        topologyLayoutId = null;
        topologyManualNodes = [];
        topologyManualLinks = [];
        topologyRooms = [];
        selectedManualNodeId = null;
        selectedRoomId = null;
        selectedTopologyNodeKey = null;
        selectedTopologyLinkId = null;
        setTopologySaveStatus('Kein Netzwerk ausgewählt');
        return;
    }
    status.textContent = 'Lade Geräte …';
    try {
        await loadDevices();
        if (requestId !== topologyRequestId || networkId !== networkSelect.value ||
            mutationVersion !== topologyMutationVersion) return;
        let data = {links: [], neighbors: [], segments: []};
        try {
            loadPhase = 'Scanner-Topologie laden';
            data = await fetchJson(`/api/topology?network_id=${encodeURIComponent(networkId)}`);
        } catch (error) {
            if (error.message !== 'HTTP 404') throw error;
        }
        loadPhase = 'Layout laden';
        const layout = await fetchJson(`/api/topology/layout?network_id=${encodeURIComponent(networkId)}`);
        if (requestId !== topologyRequestId || networkId !== networkSelect.value ||
            mutationVersion !== topologyMutationVersion) return;
        if (topologyEditorGesture?.target && !topologyEditorGesture.target.isConnected)
            cancelTopologyGesture();
        if ((topologyEditorGesture || topologyPendingWrites > 0) &&
            String(networkId) === topologyGraphContext) {
            status.textContent = `${devices.length} Geräte · aktueller Inventarstatus`;
            setConnectionStatus('API verbunden', true);
            return;
        }
        if (topologyEditorGesture) cancelTopologyGesture();
        loadPhase = 'Topologie darstellen';
        setConnectionStatus('API verbunden', true);
        topologyManualNodes = layout.manual_nodes || [];
        topologyRooms = layout.rooms || [];
        renderTopologyGraph({...data, networkId, layout});
        setTopologySaveStatus(layout.layout ? 'Layout geladen' : 'Noch keine Positionen gespeichert',
            layout.layout ? 'saved' : '');
        status.textContent = `${devices.length} Geräte · aktueller Inventarstatus`;
        setConnectionStatus('API verbunden', true);
    } catch (error) {
        if (requestId !== topologyRequestId) return;
        console.error(`Topologiefehler während „${loadPhase}“`,error);
        const apiFailure = loadPhase !== 'Topologie darstellen';
        if (preserveGraphOnError || (topologyGraphContext === String(networkId) && graph.childElementCount)) {
            status.textContent = apiFailure
                ? `Topologie: ${error.message}` : `Darstellungsfehler: ${error.message}`;
            setConnectionStatus(apiFailure ? `API-Fehler: ${error.message}` : 'API verbunden',!apiFailure);
            return;
        }
        if (topologyEditorGesture) cancelTopologyGesture();
        graph.replaceChildren();
        status.textContent = apiFailure
            ? `Topologie: ${error.message}` : `Darstellungsfehler: ${error.message}`;
        setConnectionStatus(apiFailure ? `API-Fehler: ${error.message}` : 'API verbunden',!apiFailure);
    }
}


function renderTopologyGraph(data) {
    const svg = document.querySelector('#topology-graph');
    if (topologyEditorGesture) cancelTopologyGesture();
    if (topologyLinkRedrawFrame !== null) {
        cancelAnimationFrame(topologyLinkRedrawFrame);
        topologyLinkRedrawFrame = null;
    }
    if (topologyLinkRedrawTimer !== null) {
        clearTimeout(topologyLinkRedrawTimer);
        topologyLinkRedrawTimer = null;
    }
    topologyCurrentRenderData=data;
    topologyLinkPreviewElement=null;
    topologyDropPreviewRoomId=null;
    topologyRoomBoundaryCycle={key:'',index:0,time:0,roomId:null};
    svg.replaceChildren();
    topologyRoomShapeUpdates = new Map();
    const measured = measureTopologyCellGeometry(svg);
    topologyLabelMaxWidth = measured.labelWidth;
    topologyMeasuredNodeBounds = measured.nodeBounds;
    topologyNodeYOffset = measured.nodeYOffset;
    topologyGridSpacing = {column:measured.column,row:measured.row};
    const context = String(data.networkId);
    const contextChanged = context !== topologyGraphContext;
    if (contextChanged) {
        stopTopologyPan();
        topologyEditorGesture = null;
        topologyGraphContext = context; topologyPositions.clear();
        topologyLayoutId = null;
        selectedManualNodeId = null;
        selectedRoomId = null;
        selectedTopologyNodeKey = null;
    }
    topologyLayoutId = data.layout?.layout?.id ?? null;
    topologyRooms = data.layout?.rooms || [];
    topologyManualLinks = data.layout?.links || [];
    topologyPositions.clear();
    const layoutPositions=data.layout?.positions || [];
    const manualNodes=data.layout?.manual_nodes || [];
    const currentDevices = new Map(devices.map(device => [String(device.id),device]));
    const placedDeviceIds = new Set(layoutPositions.map(position => String(position.device_id)));
    for (const manual of manualNodes) {
        if (manual.linked_device_id != null && currentDevices.has(String(manual.linked_device_id)))
            placedDeviceIds.add(String(manual.linked_device_id));
    }
    for (const position of layoutPositions) {
        topologyPositions.set(`device:${position.device_id}`, {
            gridColumn: position.grid_x,
            gridRow: position.grid_y
        });
    }
    for (const manual of data.layout?.manual_nodes || []) {
        topologyPositions.set(`manual:${manual.id}`, {
            gridColumn: manual.grid_x,
            gridRow: manual.grid_y
        });
    }
    const nodes = new Map();
    // The selected snapshot describes connections; colors/classes describe the
    // current inventory of the selected network, never historical scan evidence.
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
        else if (ip && !nodes.get(key).manual) nodes.get(key).label = ip;
        if (!nodes.get(key).device) nodes.get(key).device = deviceForNode(id,mac);
        return nodes.get(key);
    };
    for (const device of devices) {
        if (placedDeviceIds.has(String(device.id))) getNode(device.id, device.ip, device.mac);
    }
    for (const manual of manualNodes) {
        let node;
        const linkedDevice = manual.linked_device_id == null
            ? null : currentDevices.get(String(manual.linked_device_id));
        if (linkedDevice) {
            node = getNode(linkedDevice.id, linkedDevice.ip, linkedDevice.mac);
            node.positionKey = `manual:${manual.id}`;
            node.manual = manual;
            node.label = manual.label;
        } else {
            node = {
                key:`manual:${manual.id}`,
                positionKey:`manual:${manual.id}`,
                manual,
                device:null,
                label:manual.label
            };
            nodes.set(node.key,node);
        }
    }
    const links = (data.links || []).filter(link =>
        currentDevices.has(String(link.source_device_id)) &&
        currentDevices.has(String(link.target_device_id)) &&
        placedDeviceIds.has(String(link.source_device_id)) &&
        placedDeviceIds.has(String(link.target_device_id))).map(link => ({link,
        a:getNode(link.source_device_id,link.source_ip,null),
        b:getNode(link.target_device_id,link.target_ip,link.target_mac)}));
    const entries = [...nodes.values()];
    // Keep saved integer cell coordinates and derive compact visual spacing
    // from the rendered reference label and status/icon bounds.
    const columnSpacing = measured.column;
    const rowSpacing = measured.row;
    const occupiedSlots = new Set();
    const reservedSlots = new Set();
    for (const manual of manualNodes.filter(node => node.linked_device_id != null)) {
        const restoredDevicePosition = topologyPositions.get(`device:${manual.linked_device_id}`);
        if (restoredDevicePosition && Number.isInteger(restoredDevicePosition.gridColumn) &&
            Number.isInteger(restoredDevicePosition.gridRow)) {
            reservedSlots.add(`${restoredDevicePosition.gridColumn}:${restoredDevicePosition.gridRow}`);
        }
    }
    entries.forEach(node => {
        const stored = topologyPositions.get(node.positionKey || node.key) || topologyPositions.get(node.key);
        if (stored && Number.isInteger(stored.gridColumn) && Number.isInteger(stored.gridRow)) {
            const storedPoint=topologyGridToPixel(stored.gridColumn,stored.gridRow,{nodeAnchor:true});
            node.x = storedPoint.x;
            node.y = storedPoint.y;
        } else if (node.manual && Number.isInteger(Number(node.manual.grid_x)) &&
            Number.isInteger(Number(node.manual.grid_y))) {
            node.gridColumn=Number(node.manual.grid_x);
            node.gridRow=Number(node.manual.grid_y);
            const manualPoint=topologyGridToPixel(node.gridColumn,node.gridRow,{nodeAnchor:true});
            node.x=manualPoint.x; node.y=manualPoint.y;
        } else if (stored) {
            node.x = stored.x; node.y = stored.y;
        } else {
            return;
        }
        // The grid extends in every direction. Preserve positions outside the
        // initial layout on refresh instead of pulling devices back into it.
        Object.assign(node,topologyPixelToGrid(node.x,node.y,{nodeAnchor:true}));
    });
    topologyUnplacedDevices=devices.filter(device => !placedDeviceIds.has(String(device.id)));
    renderTopologyUnplacedDevices();
    // Existing positions take priority over newly added nodes.
    for (const node of [...entries].sort((a,b) =>
        Number(topologyPositions.has(b.positionKey || b.key) || topologyPositions.has(b.key)) -
        Number(topologyPositions.has(a.positionKey || a.key) || topologyPositions.has(a.key)))) {
        let slot = `${node.gridColumn}:${node.gridRow}`;
        while (occupiedSlots.has(slot) || reservedSlots.has(slot)) {
            node.gridColumn++;
            slot = `${node.gridColumn}:${node.gridRow}`;
        }
        occupiedSlots.add(slot);
        const point=topologyGridToPixel(node.gridColumn,node.gridRow,{nodeAnchor:true});
        node.x = point.x; node.y = point.y;
    }
    topologyBaseViewBox = topologyFitViewBox(entries,topologyRooms);
    const savedCamera=contextChanged ? readTopologyCamera(context) : null;
    if (savedCamera) svg.setAttribute('viewBox',savedCamera);
    else if (contextChanged || !topologyCameraInitialized || !svg.getAttribute('viewBox'))
        svg.setAttribute('viewBox',topologyBaseViewBox);
    topologyCameraInitialized=true;
    saveTopologyCamera(svg);

    let redrawConnections=() => {};
    const roomVisuals=new Map();
    const setRoomShape = (group,room,rect,label,roomPorts=null) => {
        roomPorts ||= roomVisuals.get(Number(room.id))?.ports || new Map();
        const oldBounds = {x:Number(rect.getAttribute('x')),y:Number(rect.getAttribute('y')),
            width:Number(rect.getAttribute('width')),height:Number(rect.getAttribute('height'))};
        const bounds = topologyRoomPixelBounds(room);
        const box = bounds;
        rect.setAttribute('x',box.x); rect.setAttribute('y',box.y);
        rect.setAttribute('width',box.width); rect.setAttribute('height',box.height);
        label.setAttribute('x',box.x); label.setAttribute('y',box.y-TOPOLOGY_ROOM_TITLE_GAP);
        fitTopologyNodeLabel(label,room.name,Math.max(1,box.width-10));
        const points = {
            nw:[box.x,box.y],n:[box.x+box.width/2,box.y],ne:[box.x+box.width,box.y],
            e:[box.x+box.width,box.y+box.height/2],se:[box.x+box.width,box.y+box.height],
            s:[box.x+box.width/2,box.y+box.height],sw:[box.x,box.y+box.height],
            w:[box.x,box.y+box.height/2]
        };
        for (const handle of group.querySelectorAll('.topology-room-handle')) {
            const [x,y] = points[handle.dataset.grip];
            handle.setAttribute('cx',x); handle.setAttribute('cy',y);
        }
        const connectionPoints={top:points.n,right:points.e,bottom:points.s,left:points.w};
        for (const [side,port] of roomPorts) {
            const [x,y]=connectionPoints[side];
            // Keep edge anchors local so translated rooms stay aligned.
            port.localAnchorPoint={x,y};
            port.anchorPoint={x,y}; port.hitPoint={x,y};
        }
        if (roomVisuals.has(Number(room.id))) {
            const changedBounds = {x:box.x,y:box.y,width:box.width,height:box.height};
            const moved = oldBounds.x !== changedBounds.x || oldBounds.y !== changedBounds.y ||
                oldBounds.width !== changedBounds.width || oldBounds.height !== changedBounds.height;
            if (moved) redrawConnections({rooms:[Number(room.id)],rects:[changedBounds]});
        }
    };
    for (const room of [...topologyRooms].sort((a,b) => topologyRoomDepth(a)-topologyRoomDepth(b) ||
        Number(a.id)-Number(b.id))) {
        const group = svgElement('g',{class:`topology-room${Number(room.id) === selectedRoomId ? ' topology-room-selected' : ''}`,
            'data-room-id':room.id,'aria-label':`Raum ${room.name}`});
        const rect = svgElement('rect',{class:'topology-room-shape',rx:2});
        const label = svgElement('text',{class:'topology-room-label'});
        group.appendChild(rect);
        const gripNames = ['nw','n','ne','e','se','s','sw','w'];
        for (const grip of gripNames) {
            const handle = svgElement('circle',{class:`topology-room-handle topology-room-grip-${grip}`,r:5,'data-grip':grip,
                tabindex:0,'aria-label':`Raumgröße an ${grip} ändern`});
            group.appendChild(handle);
            let resizeState = null;
            const finishResize = event => {
                if (!resizeState || event.pointerId !== resizeState.pointerId) return;
                const state = resizeState; resizeState = null; topologyEditorGesture = null;
                if (handle.hasPointerCapture(event.pointerId)) handle.releasePointerCapture(event.pointerId);
                group.removeAttribute('transform');
                if (event.type !== 'pointerup') setRoomShape(group,room,rect,label);
                redrawConnections({rooms:[Number(room.id)],rects:[roomVisualBounds(room.id)]});
                if (event.type !== 'pointerup') return;
                const next = state.next;
                if (next && (next.grid_x !== room.grid_x || next.grid_y !== room.grid_y ||
                    next.grid_width !== room.grid_width || next.grid_height !== room.grid_height)) {
                    const geometry = {
                        grid_x:next.grid_x, grid_y:next.grid_y,
                        grid_width:next.grid_width, grid_height:next.grid_height
                    };
                    void runTopologyAction(() => saveTopologyRoomGeometry(room,geometry,'Raumgröße gespeichert',
                        () => setRoomShape(group,room,rect,label),
                        () => setRoomShape(group,room,rect,label)));
                }
            };
            handle.addEventListener('pointerdown',event => {
                if (event.button !== 0 || topologyEditorGesture) return;
                event.preventDefault(); event.stopPropagation(); closeTopologyContextMenu();
                selectTopologyRoom(room);
                const point = topologySvgPoint(event.clientX,event.clientY);
                if (!point) return;
                resizeState = {pointerId:event.pointerId,start:{...room},startPoint:point,next:null,
                    limits:topologyRoomResizeLimits(room)};
                topologyEditorGesture = {type:'room-resize',pointerId:event.pointerId,roomId:Number(room.id),target:handle};
                handle.setPointerCapture(event.pointerId);
            });
            handle.addEventListener('pointermove',event => {
                if (!resizeState || resizeState.pointerId !== event.pointerId) return;
                const point = topologySvgPoint(event.clientX,event.clientY); if (!point) return;
                const start = resizeState.start; const next = {...start};
                const delta=topologyGridDeltaFromPixels(point.x-resizeState.startPoint.x,
                    point.y-resizeState.startPoint.y);
                const dx=delta.gridColumn, dy=delta.gridRow;
                const limits=resizeState.limits;
                if (grip.includes('w')) {
                    next.grid_width=Math.max(2,start.grid_width-dx);
                    next.grid_x=start.grid_x+start.grid_width-next.grid_width;
                    if (next.grid_x > start.grid_x && limits.left !== null) {
                        next.grid_x=Math.min(next.grid_x,Math.max(start.grid_x,
                            Math.min(limits.left,start.grid_x+start.grid_width-2)));
                        next.grid_width=start.grid_x+start.grid_width-next.grid_x;
                    }
                }
                if (grip.includes('e')) {
                    next.grid_width=Math.max(2,start.grid_width+dx);
                    const candidateRight=start.grid_x+next.grid_width;
                    const startRight=start.grid_x+start.grid_width;
                    if (candidateRight < startRight && limits.right !== null) {
                        const minRight=Math.min(startRight,Math.max(start.grid_x+2,limits.right));
                        next.grid_width=Math.max(candidateRight,minRight)-start.grid_x;
                    }
                }
                if (grip.includes('n')) {
                    next.grid_height=Math.max(1,start.grid_height-dy);
                    next.grid_y=start.grid_y+start.grid_height-next.grid_height;
                    if (next.grid_y > start.grid_y && limits.top !== null) {
                        next.grid_y=Math.min(next.grid_y,Math.max(start.grid_y,
                            Math.min(limits.top,start.grid_y+start.grid_height-1)));
                        next.grid_height=start.grid_y+start.grid_height-next.grid_y;
                    }
                }
                if (grip.includes('s')) {
                    next.grid_height=Math.max(1,start.grid_height+dy);
                    const candidateBottom=start.grid_y+next.grid_height;
                    const startBottom=start.grid_y+start.grid_height;
                    if (candidateBottom < startBottom && limits.bottom !== null) {
                        const minBottom=Math.min(startBottom,Math.max(start.grid_y+1,limits.bottom));
                        next.grid_height=Math.max(candidateBottom,minBottom)-start.grid_y;
                    }
                }
                resizeState.next=next; setRoomShape(group,next,rect,label);
            });
            for (const name of ['pointerup','pointercancel','lostpointercapture']) handle.addEventListener(name,finishResize);
        }
        const roomPorts=new Map();
        for (const side of TOPOLOGY_CONNECTION_SIDES) {
            roomPorts.set(side,{endpoint:{room_id:Number(room.id),anchor:side},
                localAnchorPoint:{x:0,y:0},anchorPoint:{x:0,y:0},hitPoint:{x:0,y:0}});
        }
        group.appendChild(label);
        roomVisuals.set(Number(room.id),{group,rect,label,ports:roomPorts});
        setRoomShape(group,room,rect,label,roomPorts);
        topologyRoomShapeUpdates.set(Number(room.id),() => setRoomShape(group,room,rect,label));
        const title = svgElement('title',{}); title.textContent = room.description ? `${room.name} · ${room.description}` : room.name;
        group.appendChild(title); svg.appendChild(group);
        let moveState = null;
        const finishMove = event => {
            if (!moveState || event.pointerId !== moveState.pointerId) return;
            const state=moveState; moveState=null; topologyEditorGesture=null;
            if (group.hasPointerCapture(event.pointerId)) group.releasePointerCapture(event.pointerId);
            const restorePreview = () => {
                group.removeAttribute('transform');
                for (const child of state.descendantRooms) child.element?.removeAttribute('transform');
                for (const previous of state.nodePositions) {
                    previous.node.x=previous.x; previous.node.y=previous.y;
                    previous.node.gridColumn=previous.gridColumn; previous.node.gridRow=previous.gridRow;
                }
                redraw(state.nodes,roomMoveInvalidation(state));
                clearTopologyRoomDropPreview();
            };
            if (event.type !== 'pointerup') {restorePreview(); return;}
            const point=topologySvgPoint(event.clientX,event.clientY);
            if (!point) {restorePreview(); return;}
            const delta=topologyGridDeltaFromPixels(point.x-state.startPoint.x,
                point.y-state.startPoint.y);
            const dx=delta.gridColumn, dy=delta.gridRow;
            const movedRoom=state.room;
            const nextGeometry={grid_x:movedRoom.grid_x+dx,grid_y:movedRoom.grid_y+dy,
                grid_width:movedRoom.grid_width,grid_height:movedRoom.grid_height};
            const targetParent=topologyRoomParentForGridBounds(nextGeometry,state.subtreeIds);
            const targetParentId=targetParent ? Number(targetParent.id) : null;
            const parentChanged=targetParentId !== (movedRoom.parent_room_id == null
                ? null : Number(movedRoom.parent_room_id));
            if (!dx && !dy && !parentChanged) {restorePreview(); return;}
            const shift=topologyGridVectorToPixel(dx,dy);
            group.setAttribute('transform',`translate(${shift.x},${shift.y})`);
            for (const child of state.descendantRooms)
                child.element?.setAttribute('transform',`translate(${shift.x},${shift.y})`);
            redraw(state.nodes,roomMoveInvalidation(state));
            clearTopologyRoomDropPreview();
            void runTopologyAction(() => saveTopologyRoomGeometry(movedRoom,
                {...nextGeometry,parent_room_id:targetParentId,move_contents:true},
                state.nodes.length || state.descendantRooms.length
                    ? 'Raum und Inhalt verschoben' : 'Raum verschoben',restorePreview,() => {
                    group.removeAttribute('transform');
                    for (const child of state.descendantRooms) child.element?.removeAttribute('transform');
                    for (const previous of state.nodePositions) {
                        const node=previous.node;
                        node.gridColumn=previous.gridColumn+dx; node.gridRow=previous.gridRow+dy;
                        const point=topologyGridToPixel(node.gridColumn,node.gridRow,{nodeAnchor:true});
                        node.x = point.x; node.y = point.y;
                    }
                    redraw(state.nodes,roomMoveInvalidation(state));
                    setRoomShape(group,movedRoom,rect,label);
                }));
        };
        group.addEventListener('pointerdown',event => {
            if (event.button !== 0 || event.target.classList.contains('topology-room-handle') || topologyEditorGesture) return;
            event.preventDefault(); event.stopPropagation(); closeTopologyContextMenu();
            const currentRoom=topologyRooms.find(item => Number(item.id) === Number(room.id)) || room;
            selectTopologyRoom(currentRoom);
            const point=topologySvgPoint(event.clientX,event.clientY); if (!point) return;
            const descendantIds=topologyRoomDescendantIds(currentRoom.id);
            const subtreeIds=new Set([Number(currentRoom.id),...descendantIds]);
            const subtreeRooms=topologyRooms.filter(item => descendantIds.has(Number(item.id)));
            const descendants=subtreeRooms.map(item => ({
                room:item,element:document.querySelector(`[data-room-id="${item.id}"]`)
            }));
            const deviceIds=new Set(topologyRooms.filter(item => subtreeIds.has(Number(item.id)))
                .flatMap(item => item.device_ids || []).map(Number));
            const manualIds=new Set(topologyRooms.filter(item => subtreeIds.has(Number(item.id)))
                .flatMap(item => item.manual_node_ids || []).map(Number));
            const nodes=topologyRenderedNodes.filter(node => node.manual
                ? manualIds.has(Number(node.manual.id))
                : deviceIds.has(Number(node.device?.id)));
            moveState={pointerId:event.pointerId,startPoint:point,nodes,
                nodePositions:nodes.map(node=>({node,x:node.x,y:node.y,
                    gridColumn:node.gridColumn,gridRow:node.gridRow})),room:currentRoom,
                descendantRooms:descendants,subtreeIds};
            topologyEditorGesture={type:'room-move',pointerId:event.pointerId,roomId:Number(room.id),target:group};
            group.setPointerCapture(event.pointerId);
        });
        group.addEventListener('pointermove',event => {
            if (!moveState || moveState.pointerId !== event.pointerId) return;
            const point=topologySvgPoint(event.clientX,event.clientY); if (!point) return;
            const dx=point.x-moveState.startPoint.x, dy=point.y-moveState.startPoint.y;
            group.setAttribute('transform',`translate(${dx},${dy})`);
            for (const child of moveState.descendantRooms)
                child.element?.setAttribute('transform',`translate(${dx},${dy})`);
            for (const previous of moveState.nodePositions) {
                previous.node.x=previous.x+dx; previous.node.y=previous.y+dy;
            }
            const roomBounds=[...moveState.subtreeIds].map(roomVisualBounds).filter(Boolean);
            const nodeBounds=moveState.nodePositions.map(previous=>nodeBoundsAt(previous.node));
            redraw(moveState.nodes,{nodes:moveState.nodes,rooms:moveState.subtreeIds,
                rects:[...roomBounds,...nodeBounds]});
            const delta=topologyGridDeltaFromPixels(dx,dy);
            const nextGeometry={grid_x:moveState.room.grid_x+delta.gridColumn,
                grid_y:moveState.room.grid_y+delta.gridRow,grid_width:moveState.room.grid_width,
                grid_height:moveState.room.grid_height};
            const targetParent=topologyRoomParentForGridBounds(nextGeometry,moveState.subtreeIds);
            setTopologyRoomDropPreview(targetParent?.id ?? null);
        });
        for (const name of ['pointerup','pointercancel','lostpointercapture']) group.addEventListener(name,finishMove);
        group.addEventListener('contextmenu',event => {
            event.preventDefault(); event.stopPropagation(); selectTopologyRoom(room);
            openTopologyRoomContextMenu(event.clientX,event.clientY,room);
        });
    }
    for (const edge of links) {
        const line = svgElement('line', {class:`topology-link ${edge.link.relation === 'physical_neighbor' ? 'physical' : 'inferred'}`, tabindex:0});
        const title = svgElement('title', {});
        title.textContent = `${edge.link.relation} · ${edge.link.evidence_source} · ${edge.link.confidence}%`;
        line.appendChild(title);
        const inspect = () => {document.querySelector('#topology-evidence').textContent = JSON.stringify({...edge.link,
            evidence:parseStoredValue(edge.link.evidence_json)}, null, 2);};
        line.addEventListener('click', inspect);
        line.addEventListener('keydown', event => {if (event.key === 'Enter') inspect();});
        svg.appendChild(line); edge.element = line;
    }
    const resolveManualLinkEndpoint = endpoint => {
        if (endpoint.room_id != null) {
            const room=topologyRooms.find(item=>Number(item.id)===Number(endpoint.room_id));
            return room ? {kind:'room',room} : null;
        }
        const node=entries.find(item=>endpoint.device_id != null
            ? Number(item.device?.id)===Number(endpoint.device_id)
            : Number(item.manual?.id)===Number(endpoint.manual_node_id));
        return node ? {kind:'node',node} : null;
    };
    const manualEdges=topologyManualLinks.map(link=>({
        link,a:resolveManualLinkEndpoint(link.source),b:resolveManualLinkEndpoint(link.target)
    })).filter(edge=>edge.a && edge.b).sort((a,b)=>Number(a.link.id)-Number(b.link.id));
    for (const edge of manualEdges) {
        const group=svgElement('g',{class:`topology-manual-link topology-link-evidence-${edge.link.evidence_status || 'manual_documented'}${
            Number(edge.link.id)===selectedTopologyLinkId ? ' topology-manual-link-selected' : ''}`,
            'data-link-id':Number(edge.link.id),tabindex:0,
            'aria-label':`${edge.link.label || 'Verbindung'} · ${TOPOLOGY_LINK_TYPES.find(item=>item[0]===edge.link.link_type)?.[1] || 'Unbekannt'}`});
        const hitPath=svgElement('polyline',{class:'topology-manual-link-hit',points:''});
        group.appendChild(hitPath);
        const line=svgElement('polyline',{class:'topology-manual-link-path',points:''});
        const title=svgElement('title',{});
        title.textContent=`${edge.link.label || 'Verbindung'} · ${TOPOLOGY_EVIDENCE_LABELS[edge.link.evidence_status] || edge.link.evidence_status}`;
        line.appendChild(title); group.appendChild(line);
        const label=svgElement('text',{class:'topology-manual-link-label','text-anchor':'middle'});
        if (edge.link.label) {label.textContent=edge.link.label; group.appendChild(label);}
        group.addEventListener('pointerdown',event=>{
            if (event.button!==0) return;
            event.preventDefault(); event.stopPropagation();
            selectTopologyLink(edge.link);
            closeTopologyContextMenu();
        });
        group.addEventListener('click',event=>{event.stopPropagation();selectTopologyLink(edge.link);});
        group.addEventListener('keydown',event=>{
            if (event.key==='Enter') {event.preventDefault();selectTopologyLink(edge.link);}
        });
        group.addEventListener('contextmenu',event=>{
            event.preventDefault();event.stopPropagation();selectTopologyLink(edge.link);
            openTopologyLinkContextMenu(event.clientX,event.clientY,edge.link,edge.a,edge.b);
        });
        svg.appendChild(group); edge.element=group; edge.hitPathElement=hitPath;
        edge.pathElement=line; edge.labelElement=edge.link.label ? label : null;
    }
    const roomTransformOffset=group=>{
        const match=/translate\(([-\d.]+)[, ]+([-\d.]+)\)/.exec(group?.getAttribute('transform') || '');
        return match ? {x:Number(match[1]),y:Number(match[2])} : {x:0,y:0};
    };
    const roomVisualBounds=roomId=>{
        const visual=roomVisuals.get(Number(roomId));
        if (!visual) return null;
        const offset=roomTransformOffset(visual.group);
        return {x:Number(visual.rect.getAttribute('x'))+offset.x,
            y:Number(visual.rect.getAttribute('y'))+offset.y,
            width:Number(visual.rect.getAttribute('width')),
            height:Number(visual.rect.getAttribute('height'))};
    };
    const nodeBoundsAt=(node,x=node.x,y=node.y)=>({
        x:x+topologyMeasuredNodeBounds.x-2,y:y+topologyMeasuredNodeBounds.y-2,
        width:topologyMeasuredNodeBounds.width+4,height:topologyMeasuredNodeBounds.height+4
    });
    const roomMoveInvalidation=state=>({
        nodes:state.nodes,rooms:state.subtreeIds,
        rects:[...[...state.subtreeIds].map(roomVisualBounds).filter(Boolean),
            ...state.nodePositions.map(previous=>nodeBoundsAt(previous.node))]
    });
    const manualLinkAnchor=(object,side)=>{
        const normal=topologyConnectionNormal(side);
        if (object.kind==='node') return {
            x:object.node.x+normal.x*16,y:object.node.y+normal.y*16,normal
        };
        const visual=roomVisuals.get(Number(object.room.id));
        if (!visual) return null;
        const offset=roomTransformOffset(visual.group);
        const portAnchor=visual.ports.get(side)?.localAnchorPoint;
        if (portAnchor) return {x:portAnchor.x+offset.x,y:portAnchor.y+offset.y,normal};
        const x=Number(visual.rect.getAttribute('x'))+offset.x;
        const y=Number(visual.rect.getAttribute('y'))+offset.y;
        const width=Number(visual.rect.getAttribute('width'));
        const height=Number(visual.rect.getAttribute('height'));
        const anchor={
            top:{x:x+width/2,y},right:{x:x+width,y:y+height/2},
            bottom:{x:x+width/2,y:y+height},left:{x,y:y+height/2}
        }[side];
        return {...anchor,normal};
    };
    const roomIdsForEndpoint=object=>{
        const ids=new Set();
        const includeAncestors=roomId=>{
            const visited=new Set();
            let room=topologyRooms.find(item=>Number(item.id)===Number(roomId));
            while (room && !visited.has(Number(room.id))) {
                const id=Number(room.id); visited.add(id); ids.add(id);
                room=room.parent_room_id == null ? null :
                    topologyRooms.find(item=>Number(item.id)===Number(room.parent_room_id));
            }
        };
        if (object.kind==='room') includeAncestors(object.room.id);
        else {
            const deviceId=object.node.device?.id;
            const manualId=object.node.manual?.id;
            for (const room of topologyRooms) {
                const containsDevice=deviceId != null && (room.device_ids || []).some(id=>Number(id)===Number(deviceId));
                const containsManual=manualId != null && (room.manual_node_ids || []).some(id=>Number(id)===Number(manualId));
                if (containsDevice || containsManual) includeAncestors(room.id);
            }
        }
        return [...ids];
    };
    const routeIntersectsRect=(points,rect)=>{
        if (!points?.length || !rect || !Number.isFinite(rect.x) || !Number.isFinite(rect.y)) return false;
        const left=rect.x,right=rect.x+rect.width,top=rect.y,bottom=rect.y+rect.height;
        for (let index=1;index<points.length;index++) {
            const a=points[index-1],b=points[index];
            if (Math.abs(a.y-b.y)<0.01) {
                if (a.y>=top && a.y<=bottom && Math.max(Math.min(a.x,b.x),left)<=Math.min(Math.max(a.x,b.x),right)) return true;
            } else if (Math.abs(a.x-b.x)<0.01) {
                if (a.x>=left && a.x<=right && Math.max(Math.min(a.y,b.y),top)<=Math.min(Math.max(a.y,b.y),bottom)) return true;
            } else return true;
        }
        return false;
    };
    const anchorRouteForEdge=(edge,sourceSides,targetSides,geometry,maxTurns,preview,roomClearance)=>{
        const candidates=[];
        const nodeRects=preview ? [] : geometry.nodes.filter(({node})=>
            (edge.a.kind!=='node' || edge.a.node!==node) &&
            (edge.b.kind!=='node' || edge.b.node!==node));
        const startIds=preview ? new Set() : new Set(roomIdsForEndpoint(edge.a));
        const endIds=preview ? new Set() : new Set(roomIdsForEndpoint(edge.b));
        const axes={x:[],y:[]};
        if (!preview && maxTurns>1) for (const {rect} of nodeRects) {
            axes.x.push(rect.x-1,rect.x-6,rect.x+rect.width+1,rect.x+rect.width+6);
            axes.y.push(rect.y-1,rect.y-6,rect.y+rect.height+1,rect.y+rect.height+6);
        }
        if (!preview && maxTurns>1) for (const {rect} of geometry.rooms) {
            axes.x.push(rect.x-roomClearance.x,rect.x+roomClearance.x,
                rect.x+rect.width-roomClearance.x,rect.x+rect.width+roomClearance.x);
            axes.y.push(rect.y-roomClearance.y,rect.y+roomClearance.y,
                rect.y+rect.height-roomClearance.y,rect.y+rect.height+roomClearance.y);
        }
        for (const sourceSide of sourceSides) for (const targetSide of targetSides) {
            const source=manualLinkAnchor(edge.a,sourceSide);
            const target=manualLinkAnchor(edge.b,targetSide);
            if (!source || !target) continue;
            const preferredAxis=Math.abs(target.x-source.x)>=Math.abs(target.y-source.y) ? 'x' : 'y';
            for (const candidate of window.TopologyRouting.anchorRouteCandidates(
                source,target,{maxTurns,axes,preferredAxis})) {
                if (!preview && !window.TopologyRouting.validAnchorRoute(
                    candidate.points,nodeRects,geometry.rooms,startIds,endIds,roomClearance)) continue;
                candidates.push({...candidate,sourceSide,targetSide,preview});
                break;
            }
        }
        return window.TopologyRouting.chooseOrthogonalRoute(candidates);
    };
    const redrawManualLinks=(invalidation={all:true,nodes:new Set(),rooms:new Set(),rects:[]})=>{
        const changedRooms=invalidation.rooms instanceof Set ? invalidation.rooms : new Set(invalidation.rooms || []);
        for (const [roomId,visual] of roomVisuals) {
            if (!invalidation.all && !changedRooms.has(roomId)) continue;
            const room=topologyRooms.find(item=>Number(item.id)===roomId);
            if (!room) continue;
            for (const [side,port] of visual.ports) {
                const point=manualLinkAnchor({kind:'room',room},side);
                if (!point) continue;
                port.anchorPoint={x:point.x,y:point.y}; port.hitPoint={x:point.x,y:point.y};
            }
        }
        if (!manualEdges.length || !window.TopologyRouting) return;
        const liveMove=['node-move','room-move','room-resize'].includes(topologyEditorGesture?.type);
        const changedNodes=invalidation.nodes instanceof Set ? invalidation.nodes : new Set(invalidation.nodes || []);
        const changedRects=invalidation.rects || [];
        const isDirty=edge=>invalidation.all || (!liveMove && !edge.routePoints) ||
            (edge.a.kind==='node' && changedNodes.has(edge.a.node)) ||
            (edge.b.kind==='node' && changedNodes.has(edge.b.node)) ||
            (edge.a.kind==='room' && changedRooms.has(Number(edge.a.room.id))) ||
            (edge.b.kind==='room' && changedRooms.has(Number(edge.b.room.id))) ||
            (!liveMove && changedRects.some(rect=>routeIntersectsRect(edge.routePoints,rect)));
        const dirtyEdges=manualEdges.filter(isDirty);
        if (!dirtyEdges.length) return;
        const anchorGeometry=liveMove ? {nodes:[],rooms:[]} : {
            nodes:entries.map(node=>({node,rect:nodeBoundsAt(node)})),
            rooms:[...roomVisuals].map(([id])=>({id,rect:roomVisualBounds(id)})).filter(item=>item.rect)
        };
        const roomClearance={x:topologyGridSpacing.column/2,y:topologyGridSpacing.row/2};
        for (const edge of dirtyEdges) {
            const sourceSides=edge.a.kind==='node' && edge.link.source.anchor==='auto'
                ? TOPOLOGY_CONNECTION_SIDES : [edge.link.source.anchor];
            const targetSides=edge.b.kind==='node' && edge.link.target.anchor==='auto'
                ? TOPOLOGY_CONNECTION_SIDES : [edge.link.target.anchor];
            let best=anchorRouteForEdge(edge,sourceSides,targetSides,anchorGeometry,1,liveMove,roomClearance);
            if (!best) best=anchorRouteForEdge(edge,sourceSides,targetSides,anchorGeometry,2,liveMove,roomClearance);
            if (!best) {
                const nodeRects=anchorGeometry.nodes.filter(({node})=>
                    (edge.a.kind!=='node' || edge.a.node!==node) &&
                    (edge.b.kind!=='node' || edge.b.node!==node));
                const startIds=liveMove ? new Set() : new Set(roomIdsForEndpoint(edge.a));
                const endIds=liveMove ? new Set() : new Set(roomIdsForEndpoint(edge.b));
                const candidates=[];
                for (const sourceSide of sourceSides) for (const targetSide of targetSides) {
                    const source=manualLinkAnchor(edge.a,sourceSide);
                    const target=manualLinkAnchor(edge.b,targetSide);
                    if (!source || !target) continue;
                    const points=window.TopologyRouting.routeOrthogonalPixels(source,target,{
                        nodeRects,roomRects:anchorGeometry.rooms,startIds,endIds,roomClearance
                    });
                    if (points) candidates.push({sourceSide,targetSide,points,preview:liveMove});
                }
                best=window.TopologyRouting.chooseOrthogonalRoute(candidates);
            }
            if (!best) {
                edge.hitPathElement.setAttribute('points','');
                edge.pathElement.setAttribute('points','');
                edge.routePoints=null;
                edge.element.classList.remove('topology-manual-link-drag-preview');
                if (edge.labelElement) edge.labelElement.setAttribute('display','none');
                continue;
            }
            const points=best.points;
            edge.routePoints=points;
            edge.element.classList.toggle('topology-manual-link-drag-preview',best.preview);
            const path=points.map(point=>`${point.x},${point.y}`).join(' ');
            edge.hitPathElement.setAttribute('points',path);
            edge.pathElement.setAttribute('points',path);
            if (edge.labelElement) {
                edge.labelElement.removeAttribute('display');
                let longest=null;
                for (let index=1;index<points.length;index++) {
                    const from=points[index-1],to=points[index];
                    const length=Math.hypot(to.x-from.x,to.y-from.y);
                    if (!longest || length>longest.length) longest={from,to,length};
                }
                if (longest) {
                    edge.labelElement.setAttribute('x',(longest.from.x+longest.to.x)/2);
                    edge.labelElement.setAttribute('y',(longest.from.y+longest.to.y)/2-5);
                }
            }
        }
    };
    let pendingLinkInvalidation={all:false,nodes:new Set(),rooms:new Set(),rects:[]};
    const scheduleManualLinkRedraw=(change={all:true})=>{
        if (change.all) pendingLinkInvalidation.all=true;
        for (const node of change.nodes || []) pendingLinkInvalidation.nodes.add(node);
        for (const room of change.rooms || []) pendingLinkInvalidation.rooms.add(Number(room));
        if (change.rects) pendingLinkInvalidation.rects=change.rects.slice();
        if (topologyLinkRedrawFrame!==null || topologyLinkRedrawTimer!==null) return;
        topologyLinkRedrawFrame=requestAnimationFrame(()=>{
            topologyLinkRedrawFrame=null;
            topologyLinkRedrawTimer=setTimeout(()=>{
                topologyLinkRedrawTimer=null;
                const invalidation=pendingLinkInvalidation;
                pendingLinkInvalidation={all:false,nodes:new Set(),rooms:new Set(),rects:[]};
                redrawManualLinks(invalidation);
            },0);
        });
    };
    redrawConnections=scheduleManualLinkRedraw;
    const redraw = (changedNodes=null,invalidation={all:true}) => {
        const changed=changedNodes ? new Set(changedNodes) : null;
        for (const edge of links) {
            if (changed && !changed.has(edge.a) && !changed.has(edge.b)) continue;
            for (const [key,value] of Object.entries({x1:edge.a.x,y1:edge.a.y,x2:edge.b.x,y2:edge.b.y})) edge.element.setAttribute(key,value);
        }
        for (const node of changed || entries) {
            if (!node?.element) continue;
            node.element.setAttribute('transform',`translate(${node.x},${node.y})`);
            Object.assign(node,topologyPixelToGrid(node.x,node.y,{nodeAnchor:true}));
            topologyPositions.set(node.positionKey || node.key,{
                x:node.x, y:node.y,
                gridColumn:node.gridColumn, gridRow:node.gridRow
            });
        }
        redrawConnections(invalidation);
    };
    const redrawNode = node => {
        redraw([node],{nodes:[node],rects:[nodeBoundsAt(node)]});
    };
    const snapNode = (node,original,forceRoomAssignment=false) => {
        const target = topologyDropTargetAtPoint(node.x,node.y,reservedSlots);
        if (!target.valid) {
            node.x=original.x; node.y=original.y;
            redraw([node],{nodes:[node],rects:[nodeBoundsAt(node)]});
            clearTopologyRoomDropPreview();
            setTopologySaveStatus('Rasterplatz ist bereits belegt','error');
            return;
        }
        const column=target.gridColumn, row=target.gridRow;
        const targetPoint=topologyGridToPixel(column,row,{nodeAnchor:true});
        const x = targetPoint.x, y = targetPoint.y;
        const occupant = entries.find(other => other !== node && Math.abs(other.x-x)<0.01 && Math.abs(other.y-y)<0.01);
        const occupantOrigin=occupant ? {x:occupant.x,y:occupant.y} : null;
        if (!occupant && Math.abs(node.x-x)<0.01 && Math.abs(node.y-y)<0.01 && !forceRoomAssignment) {
            clearTopologyRoomDropPreview();
            return;
        }
        // Dropping onto an occupied slot swaps the two nodes.
        const changedNodes=[node,...(occupant ? [occupant] : [])];
        if (occupant) {occupant.x=original.x; occupant.y=original.y;}
        node.x=x; node.y=y;
        redraw(changedNodes,{nodes:changedNodes,rects:changedNodes.map(item=>nodeBoundsAt(item))});
        const positions = entries.filter(item => item.device?.id != null && !item.manual).map(item => ({
            device_id:Number(item.device.id), grid_x:item.gridColumn, grid_y:item.gridRow
        }));
        const manualPositions = entries.filter(item => item.manual).map(item => ({
            manual_node_id:Number(item.manual.id), grid_x:item.gridColumn, grid_y:item.gridRow
        }));
        const roomAssignments = [node,...(occupant ? [occupant] : [])].filter(item =>
            item.manual || item.device?.id != null).map(item => {
            const itemPoint=topologyGridToPixel(item.gridColumn,item.gridRow,{nodeAnchor:true});
            const dropTarget = item === node ? target : topologyDropTargetAtPoint(
                itemPoint.x,itemPoint.y,reservedSlots);
            const room = dropTarget.valid ? dropTarget.room : null;
            return item.manual
                ? {room_id:room ? Number(room.id) : null,manual_node_id:Number(item.manual.id)}
                : {room_id:room ? Number(room.id) : null,device_id:Number(item.device.id)};
        });
        applyTopologyRoomAssignments(roomAssignments);
        clearTopologyRoomDropPreview();
        void saveTopologyLayout(context, topologyLayoutId, positions, manualPositions, roomAssignments)
            .then(async result => {
                if (result.saved || String(context) !== topologyGraphContext) return;
                node.x=original.x; node.y=original.y;
                if (occupant && occupantOrigin) {
                    occupant.x=occupantOrigin.x; occupant.y=occupantOrigin.y;
                }
                redraw(changedNodes,{nodes:changedNodes,rects:changedNodes.map(item=>nodeBoundsAt(item))});
                await loadInventoryTopology({preserveGraphOnError:true});
                setTopologySaveStatus(`Nicht dauerhaft gespeichert: ${result.error}`,'error');
            });
    };
    for (const node of entries) {
        const group=createTopologyNodeVisual(node);
        svg.appendChild(group); node.element = group;
        fitTopologyNodeLabel(group.topologyLabelElement,String(node.label),topologyLabelMaxWidth);
        let dragOrigin = null;
        let dragStartPoint = null;
        let dragPreviewCell = null;
        let dragMoved = false;
        group.addEventListener('pointerdown', event => {
            if (event.button !== 0 || topologyEditorGesture) return;
            const point=topologySvgPoint(event.clientX,event.clientY);
            if (!point) return;
            selectTopologyNode(node);
            closeTopologyContextMenu();
            dragOrigin = {x:node.x,y:node.y};
            dragStartPoint = point;
            dragPreviewCell = null;
            dragMoved = false;
            topologyEditorGesture = {type:'node-move',pointerId:event.pointerId,key:node.key,target:group};
            event.preventDefault(); event.stopPropagation(); group.setPointerCapture(event.pointerId);
        });
        group.addEventListener('contextmenu', event => {
            event.preventDefault();
            event.stopPropagation();
            selectTopologyNode(node);
            openTopologyContextMenu(event.clientX,event.clientY,node);
        });
        group.addEventListener('pointermove', event => {
            if (!dragOrigin || !dragStartPoint || !group.hasPointerCapture(event.pointerId)) return;
            const point=topologySvgPoint(event.clientX,event.clientY);
            if (!point) return;
            const dx=point.x-dragStartPoint.x,dy=point.y-dragStartPoint.y;
            if (Math.hypot(dx,dy)>=1) dragMoved=true;
            node.x=dragOrigin.x+dx; node.y=dragOrigin.y+dy; redrawNode(node);
            const cell=topologyPixelToGrid(node.x,node.y,{nodeAnchor:true});
            const cellKey=`${cell.gridColumn}:${cell.gridRow}`;
            if (cellKey!==dragPreviewCell) {
                dragPreviewCell=cellKey;
                const target=topologyDropTargetAtPoint(node.x,node.y,reservedSlots);
                setTopologyRoomDropPreview(target.valid ? target.room?.id ?? null : null);
            }
        });
        const finishDrag = event => {
            if (!dragOrigin || event.pointerId !== topologyEditorGesture?.pointerId) return;
            const original=dragOrigin; dragOrigin=null; dragStartPoint=null; dragPreviewCell=null;
            const moved=dragMoved; dragMoved=false;
            topologyEditorGesture = null;
            if (group.hasPointerCapture(event.pointerId)) group.releasePointerCapture(event.pointerId);
            clearTopologyRoomDropPreview();
            if (event.type !== 'pointerup') {
                node.x=original.x; node.y=original.y; redrawNode(node);
                return;
            }
            if (!moved) {node.x=original.x;node.y=original.y;redrawNode(node);return;}
            snapNode(node,original,true);
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
    topologyRenderedNodes = entries;
    refreshTopologyRoomShapes();
    if (selectedRoomId !== null) raiseTopologyRoomToFront(selectedRoomId);
}

function topologyRenderWithAddedLink(link) {
    const current=topologyCurrentRenderData;
    if (!link || !current || String(current.networkId)!==String(topologyGraphContext)) return false;
    const positions=topologyRenderedNodes.filter(node=>node.device?.id!=null && !node.manual)
        .map(node=>({device_id:Number(node.device.id),grid_x:node.gridColumn,grid_y:node.gridRow}));
    const manualNodes=(current.layout?.manual_nodes || []).map(manual=>{
        const node=topologyRenderedNodes.find(item=>Number(item.manual?.id)===Number(manual.id));
        return node ? {...manual,grid_x:node.gridColumn,grid_y:node.gridRow} : manual;
    });
    const links=[...topologyManualLinks,link];
    const layout={...current.layout,positions,manual_nodes:manualNodes,rooms:topologyRooms,links};
    topologyManualNodes=manualNodes;
    topologyManualLinks=links;
    topologyCurrentRenderData={...current,layout};
    renderTopologyGraph(topologyCurrentRenderData);
    return true;
}

async function topologyManualRequest(path, method, payload) {
    const headers = {};
    const apiKey = document.querySelector('#api-key').value;
    if (apiKey) headers['X-Netchecker-Key'] = apiKey;
    if (payload !== undefined) headers['Content-Type'] = 'application/json';
    topologyPendingWrites++;
    try {
        const response = await fetch(path, {
            method,
            cache:'no-store',
            headers,
            body:payload === undefined ? undefined : JSON.stringify(payload)
        });
        let result = {};
        try { result = await response.json(); } catch (_) {}
        if (!response.ok) throw new Error(topologyApiError(result,response.status));
        return result;
    } finally {
        topologyPendingWrites--;
        topologyMutationVersion++;
    }
}

function topologyDeviceOptionLabel(device) {
    return [device.hostname,device.ip,device.mac].filter(Boolean).join(' · ') || `Gerät #${device.id}`;
}

function selectTopologyNode(node) {
    selectedTopologyNodeKey = node.key;
    selectedManualNodeId = node.manual ? Number(node.manual.id) : null;
    selectedRoomId = null;
    selectedTopologyLinkId = null;
    document.querySelectorAll('.topology-room-selected').forEach(group => group.classList.remove('topology-room-selected'));
    document.querySelectorAll('.topology-manual-link-selected').forEach(group => group.classList.remove('topology-manual-link-selected'));
    document.querySelectorAll('.topology-node').forEach(group => {
        group.classList.toggle('topology-node-selected',group.dataset.topologyKey === node.key);
    });
}

function selectTopologyRoom(room) {
    selectedRoomId = Number(room.id);
    selectedTopologyNodeKey = null;
    selectedManualNodeId = null;
    selectedTopologyLinkId = null;
    document.querySelectorAll('.topology-manual-link-selected').forEach(group => group.classList.remove('topology-manual-link-selected'));
    document.querySelectorAll('.topology-node-selected').forEach(group => group.classList.remove('topology-node-selected'));
    document.querySelectorAll('.topology-room').forEach(group => {
        group.classList.toggle('topology-room-selected',Number(group.dataset.roomId) === selectedRoomId);
    });
    raiseTopologyRoomToFront(selectedRoomId);
}

function selectTopologyLink(link) {
    selectedTopologyLinkId=Number(link.id);
    selectedRoomId=null; selectedTopologyNodeKey=null; selectedManualNodeId=null;
    document.querySelectorAll('.topology-room-selected,.topology-node-selected').forEach(group =>
        group.classList.remove('topology-room-selected','topology-node-selected'));
    document.querySelectorAll('.topology-manual-link').forEach(group =>
        group.classList.toggle('topology-manual-link-selected',Number(group.dataset.linkId)===selectedTopologyLinkId));
}

function raiseTopologyRoomToFront(roomId) {
    const graph=document.querySelector('#topology-graph');
    const selectedGroup=[...graph.children].find(item => item.classList.contains('topology-room') &&
        Number(item.dataset.roomId) === Number(roomId));
    const nextLayer=[...graph.children].find(item => !item.classList.contains('topology-room'));
    if (selectedGroup) {
        if (nextLayer) graph.insertBefore(selectedGroup,nextLayer);
        else graph.appendChild(selectedGroup);
    }
}

function clearTopologySelection() {
    selectedRoomId = null;
    selectedTopologyNodeKey = null;
    selectedManualNodeId = null;
    selectedTopologyLinkId = null;
    document.querySelectorAll('.topology-room-selected,.topology-node-selected,.topology-manual-link-selected').forEach(group => {
        group.classList.remove('topology-room-selected','topology-node-selected','topology-manual-link-selected');
    });
    closeTopologyContextMenu();
}

function selectManualTopologyNode(nodeId) {
    const node = topologyManualNodes.find(item => Number(item.id) === Number(nodeId));
    if (node) selectTopologyNode({key:`manual:${node.id}`,manual:node});
}

function topologyOccupiedCells() {
    const occupied = new Set();
    for (const position of topologyPositions.values()) {
        if (Number.isInteger(position.gridColumn) && Number.isInteger(position.gridRow))
            occupied.add(`${position.gridColumn}:${position.gridRow}`);
    }
    for (const node of topologyManualNodes) {
        if (Number.isInteger(node.grid_x) && Number.isInteger(node.grid_y))
            occupied.add(`${node.grid_x}:${node.grid_y}`);
    }
    return occupied;
}

function topologyFreeCellNear(gridX,gridY) {
    const occupied = topologyOccupiedCells();
    for (let radius=0; radius<100; radius++) {
        const candidates = [];
        for (let x=-radius; x<=radius; x++) {
            for (let y=-radius; y<=radius; y++) {
                if (Math.max(Math.abs(x),Math.abs(y)) === radius) candidates.push({x:gridX+x,y:gridY+y});
            }
        }
        candidates.sort((a,b) => (a.x-gridX)**2+(a.y-gridY)**2 - ((b.x-gridX)**2+(b.y-gridY)**2));
        const free = candidates.find(cell => !occupied.has(`${cell.x}:${cell.y}`));
        if (free) return {grid_x:free.x,grid_y:free.y};
    }
    throw new Error('Kein freier Rasterplatz verfügbar');
}

async function updateManualTopologyNode(nodeId, changes) {
    const networkId = networkSelect.value;
    const operation = topologyManualSaveQueue.then(async () => {
        setTopologySaveStatus('Speichere manuelles Objekt …','saving');
        await topologyManualRequest(
            `/api/topology/manual-nodes/${encodeURIComponent(nodeId)}?network_id=${encodeURIComponent(networkId)}`,
            'PUT',changes
        );
        setTopologySaveStatus('Manuelles Objekt gespeichert','saved');
        await loadInventoryTopology();
    });
    topologyManualSaveQueue = operation.catch(() => {});
    return operation;
}

function topologyMenu() { return document.querySelector('#topology-context-menu'); }

function closeTopologyContextMenu() {
    const menu = topologyMenu();
    menu.hidden = true;
    menu.replaceChildren();
    topologyPendingDrop = null;
}

function placeTopologyMenu(x,y) {
    const menu = topologyMenu();
    menu.hidden = false;
    menu.style.visibility = 'hidden';
    menu.style.left = `${x}px`;
    menu.style.top = `${y}px`;
    requestAnimationFrame(() => {
        const rect = menu.getBoundingClientRect();
        menu.style.left = `${Math.max(8,Math.min(x,innerWidth-rect.width-8))}px`;
        menu.style.top = `${Math.max(8,Math.min(y,innerHeight-rect.height-8))}px`;
        menu.style.visibility = 'visible';
    });
}

function topologyMenuHeading(text) {
    const heading = document.createElement('h3');
    heading.textContent = text;
    topologyMenu().appendChild(heading);
    return heading;
}

function topologyMenuStatus(message,state='') {
    const menu = topologyMenu();
    let status = menu.querySelector('.topology-menu-status');
    if (!status) {
        status = document.createElement('div');
        status.className = 'topology-menu-status';
        status.setAttribute('role','status');
        menu.appendChild(status);
    }
    status.textContent = message;
    status.dataset.state = state;
}

async function runTopologyAction(action,close=true) {
    try {
        await action();
        if (close) closeTopologyContextMenu();
    } catch (error) {
        setTopologySaveStatus(`Nicht gespeichert: ${error.message}`,'error');
        if (!topologyMenu().hidden) topologyMenuStatus(error.message,'error');
    }
}

function topologyMenuButton(label,action,{secondary=false,danger=false}={}) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `topology-menu-action${secondary ? ' secondary' : ''}${danger ? ' danger' : ''}`;
    button.textContent = label;
    button.addEventListener('click',action);
    topologyMenu().appendChild(button);
    return button;
}

function menuBackButton(node) {
    topologyMenuButton('Zurück',() => openTopologyContextMenu(innerWidth/2,innerHeight/2,node),{secondary:true});
}

function topologyNodePixelBounds(node) {
    let box = null;
    if (node.element?.getBBox) {
        try {
            for (const child of node.element.children) {
                if (!child.getBBox) continue;
                const measured=child.getBBox();
                if (!(measured.width > 0 && measured.height > 0)) continue;
                const left=box ? Math.min(box.x,measured.x) : measured.x;
                const top=box ? Math.min(box.y,measured.y) : measured.y;
                const right=Math.max(box ? box.x+box.width : -Infinity,measured.x+measured.width);
                const bottom=Math.max(box ? box.y+box.height : -Infinity,measured.y+measured.height);
                box={x:left,y:top,width:right-left,height:bottom-top};
            }
        } catch (_) {}
    }
    box ||= topologyMeasuredNodeBounds;
    if (!box) throw new Error('Node-Maße sind für die Raumgeometrie nicht verfügbar.');
    return {left:node.x+box.x,right:node.x+box.x+box.width,
        top:node.y+box.y,bottom:node.y+box.y+box.height};
}

function topologyRoomResizeLimits(room) {
    const roomBounds=topologyRoomPixelBounds(room);
    const descendantIds=topologyRoomDescendantIds(room.id);
    const subtreeIds=new Set([Number(room.id),...descendantIds]);
    const deviceRoomAssignments=new Map();
    const manualNodeRoomAssignments=new Map();
    for (const item of topologyRooms) {
        const roomId=Number(item.id);
        for (const id of item.device_ids || []) {
            const deviceId=Number(id);
            if (!deviceRoomAssignments.has(deviceId)) deviceRoomAssignments.set(deviceId,new Set());
            deviceRoomAssignments.get(deviceId).add(roomId);
        }
        for (const id of item.manual_node_ids || []) {
            const nodeId=Number(id);
            if (!manualNodeRoomAssignments.has(nodeId)) manualNodeRoomAssignments.set(nodeId,new Set());
            manualNodeRoomAssignments.get(nodeId).add(roomId);
        }
    }

    const objects=topologyRenderedNodes.map(node => ({node,bounds:topologyNodePixelBounds(node)}))
        .filter(({node,bounds}) => {
            const assignedRooms=node.manual
                ? manualNodeRoomAssignments.get(Number(node.manual.id))
                : deviceRoomAssignments.get(Number(node.device?.id));
            const assignedToSubtree=assignedRooms
                ? [...assignedRooms].some(id => subtreeIds.has(id)) : false;
            const overlaps=bounds.right >= roomBounds.x && bounds.left <= roomBounds.right &&
                bounds.bottom >= roomBounds.y && bounds.top <= roomBounds.bottom;
            return assignedToSubtree || (!assignedRooms?.size && overlaps);
        }).map(({node}) => {
            const cell=Number.isInteger(node.gridColumn) && Number.isInteger(node.gridRow)
                ? {gridColumn:node.gridColumn,gridRow:node.gridRow}
                : topologyPixelToGrid(node.x,node.y,{nodeAnchor:true});
            // Text glyph bounds vary slightly. A ceil on pixels can otherwise
            // jump the resize limit one whole cell beyond the device.
            return {left:cell.gridColumn,right:cell.gridColumn+1,
                top:cell.gridRow,bottom:cell.gridRow+1};
        });
    for (const child of topologyRooms) {
        if (!descendantIds.has(Number(child.id))) continue;
        const left=Number(child.grid_x),top=Number(child.grid_y);
        objects.push({left:left-1,right:left+Number(child.grid_width)+1,
            top:top-1,bottom:top+Number(child.grid_height)+1});
    }

    if (!objects.length) return {left:null,right:null,top:null,bottom:null};
    return {
        left:Math.min(...objects.map(bounds => bounds.left)),
        right:Math.max(...objects.map(bounds => bounds.right)),
        top:Math.min(...objects.map(bounds => bounds.top)),
        bottom:Math.max(...objects.map(bounds => bounds.bottom))
    };
}

function topologyFitViewBox(nodes=topologyRenderedNodes,rooms=topologyRooms) {
    const contentBounds = [
        ...nodes.map(node => topologyNodePixelBounds(node)),
        ...rooms.map(room => {
            const box=topologyRoomPixelBounds(room);
            return {left:box.x,right:box.right,top:box.y-TOPOLOGY_ROOM_TITLE_HEIGHT,bottom:box.bottom};
        })
    ];
    const contentLeft=contentBounds.length ? Math.min(...contentBounds.map(box => box.left)) : 0;
    const contentRight=contentBounds.length ? Math.max(...contentBounds.map(box => box.right)) : 1000;
    const contentTop=contentBounds.length ? Math.min(...contentBounds.map(box => box.top)) : 0;
    const contentBottom=contentBounds.length ? Math.max(...contentBounds.map(box => box.bottom)) : 500;
    const padding=28;
    const paddedWidth=Math.max(1,contentRight-contentLeft+padding*2);
    const paddedHeight=Math.max(1,contentBottom-contentTop+padding*2);
    const viewport=document.querySelector('.topology-viewport');
    const aspect=viewport?.clientWidth > 0 && viewport?.clientHeight > 0
        ? viewport.clientWidth/viewport.clientHeight : 2;
    const graphWidth=Math.max(paddedWidth,paddedHeight*aspect);
    const graphHeight=Math.max(paddedHeight,paddedWidth/aspect);
    const centerX=(contentLeft+contentRight)/2, centerY=(contentTop+contentBottom)/2;
    return `${centerX-graphWidth/2} ${centerY-graphHeight/2} ${graphWidth} ${graphHeight}`;
}

function topologyRoomAtCell(gridX,gridY) {
    const point=topologyGridToPixel(gridX,gridY);
    return topologyRooms.map(room => ({room,bounds:topologyRoomPixelBounds(room)}))
        .filter(({bounds}) => point.x >= bounds.x && point.x <= bounds.right &&
            point.y >= bounds.y && point.y <= bounds.bottom)
        .sort((a,b) => a.bounds.width*a.bounds.height-b.bounds.width*b.bounds.height ||
            Number(a.room.id)-Number(b.room.id))[0]?.room || null;
}

function topologyDropTargetAtPoint(x,y,blockedCells = new Set()) {
    const {gridColumn,gridRow}=topologyPixelToGrid(x,y,{nodeAnchor:true});
    const valid = !blockedCells.has(`${gridColumn}:${gridRow}`);
    return {valid,gridColumn,gridRow,room:valid ? topologyRoomAtCell(gridColumn,gridRow) : null};
}

function setTopologyRoomDropPreview(roomId) {
    const normalizedId = roomId == null ? null : Number(roomId);
    if (normalizedId === topologyDropPreviewRoomId) return;
    const graph=document.querySelector('#topology-graph');
    if (topologyDropPreviewRoomId !== null)
        graph?.querySelector(`.topology-room[data-room-id="${topologyDropPreviewRoomId}"]`)
            ?.classList.remove('topology-room-drop-target');
    if (normalizedId !== null)
        graph?.querySelector(`.topology-room[data-room-id="${normalizedId}"]`)
            ?.classList.add('topology-room-drop-target');
    topologyDropPreviewRoomId=normalizedId;
}

function clearTopologyRoomDropPreview() {
    setTopologyRoomDropPreview(null);
}

async function saveTopologyRoomGeometry(room,geometry,message,rollback=() => {},onSaved=() => {}) {
    try {
        const result = await topologyManualRequest(
            `/api/topology/rooms/${room.id}/geometry?network_id=${encodeURIComponent(networkSelect.value)}`,
            'PUT',geometry);
        syncTopologyRooms(result.rooms);
        Object.assign(room,result.room || geometry);
        onSaved(result);
        setTopologySaveStatus(message,'saved');
    } catch (error) {
        rollback();
        throw error;
    }
}

function showTopologyRoomPrompt(rect,origin,parentRoomId=null) {
    const menu = topologyMenu();
    menu.replaceChildren();
    topologyMenuHeading('Raum anlegen');
    const name = document.createElement('input');
    name.type = 'text'; name.maxLength = 120; name.placeholder = 'Raumname'; name.value = 'Neuer Raum';
    name.setAttribute('aria-label','Raumname'); menu.appendChild(name);
    const description = document.createElement('input');
    description.type = 'text'; description.maxLength = 2000; description.placeholder = 'Beschreibung (optional)';
    description.setAttribute('aria-label','Raumbeschreibung'); menu.appendChild(description);
    const save = topologyMenuButton('Raum speichern',() => void runTopologyAction(async () => {
        if (!name.value.trim()) {name.focus(); topologyMenuStatus('Bitte einen Raumnamen eingeben.','error'); return;}
        const result = await topologyManualRequest(
            `/api/topology/rooms?network_id=${encodeURIComponent(networkSelect.value)}`,'POST',{
                layout_id:topologyLayoutId,parent_room_id:parentRoomId,
                name:name.value.trim(),description:description.value.trim(),
                ...rect,grid_cell_width:Math.round(topologyGridSpacing.column),
                grid_cell_height:Math.round(topologyGridSpacing.row),move_contents:true
            }
        );
        selectedRoomId = Number(result.room.id); topologyToolMode = 'select';
        updateTopologyRoomTool();
        setTopologySaveStatus('Raum dauerhaft gespeichert','saved');
        await loadInventoryTopology();
    }));
    topologyMenuButton('Abbrechen',closeTopologyContextMenu,{secondary:true});
    placeTopologyMenu(origin.x,origin.y); requestAnimationFrame(() => name.focus());
    name.addEventListener('keydown',event => {if (event.key === 'Enter') {event.preventDefault();save.click();}});
}

function editTopologyRoom(room) {
    const menu = topologyMenu(); menu.replaceChildren();
    topologyMenuHeading('Raum bearbeiten');
    const name = document.createElement('input'); name.value = room.name; name.maxLength = 120;
    name.setAttribute('aria-label','Raumname'); menu.appendChild(name);
    const description = document.createElement('textarea'); description.value = room.description || '';
    description.rows = 3; description.maxLength = 2000;
    description.setAttribute('aria-label','Raumbeschreibung'); menu.appendChild(description);
    const save = topologyMenuButton('Speichern',() => void runTopologyAction(async () => {
        await topologyManualRequest(`/api/topology/rooms/${room.id}?network_id=${encodeURIComponent(networkSelect.value)}`,
            'PUT',{name:name.value.trim(),description:description.value});
        setTopologySaveStatus('Raumdetails gespeichert','saved'); await loadInventoryTopology();
    }));
    topologyMenuButton('Abbrechen',() => openTopologyRoomContextMenu(topologyContextAnchor.x,topologyContextAnchor.y,room),{secondary:true});
    placeTopologyMenu(topologyContextAnchor.x,topologyContextAnchor.y); requestAnimationFrame(() => name.focus());
    name.addEventListener('keydown',event => {if (event.key === 'Enter') {event.preventDefault();save.click();}});
}

function openTopologyRoomContextMenu(x,y,room) {
    topologyContextAnchor = {x,y};
    const menu = topologyMenu(); menu.replaceChildren(); topologyMenuHeading(room.name);
    const details = document.createElement('p');
    details.textContent = `${room.grid_width} × ${room.grid_height} Rasterfelder · ${(room.device_ids || []).length + (room.manual_node_ids || []).length} Objekte`;
    menu.appendChild(details);
    topologyMenuButton('Verbindung ziehen',() => topologyArmConnection({kind:'room',room}));
    topologyMenuButton('Raum umbenennen / Beschreibung',() => editTopologyRoom(room));
    topologyMenuButton('Raum verschieben',() => {
        selectTopologyRoom(room); closeTopologyContextMenu();
        setTopologySaveStatus('Raum auf der Fläche mit der linken Maustaste ziehen','saved');
        document.querySelector(`[data-room-id="${room.id}"]`)?.classList.add('topology-room-selected');
    },{secondary:true});
    topologyMenuButton('Raum duplizieren',() => void runTopologyAction(async () => {
        const result = await topologyManualRequest(`/api/topology/rooms/${room.id}/duplicate?network_id=${encodeURIComponent(networkSelect.value)}`,'POST');
        selectedRoomId = Number(result.room.id); setTopologySaveStatus('Raum dupliziert','saved'); await loadInventoryTopology();
    }),{secondary:true});
    const deleteHint=document.createElement('p');
    deleteHint.textContent='Unterräume und manuelle Objekte werden gelöscht; enthaltene Geräte erscheinen wieder unter „Nicht platzierte Geräte“.';
    menu.appendChild(deleteHint);
    topologyMenuButton('Raum löschen',() => void runTopologyAction(async () => {
        await topologyManualRequest(`/api/topology/rooms/${room.id}?network_id=${encodeURIComponent(networkSelect.value)}`,'DELETE');
        selectedRoomId = null;
        setTopologySaveStatus('Raum und Unterräume gelöscht · Geräte nicht platziert','saved');
        await loadInventoryTopology();
    }),{danger:true});
    topologyMenuButton('Schließen',closeTopologyContextMenu,{secondary:true});
    placeTopologyMenu(x,y);
}

function updateTopologyRoomTool() {
    const button = document.querySelector('#topology-room-tool');
    if (!button) return;
    const active = topologyToolMode === 'draw-room';
    button.setAttribute('aria-pressed',String(active));
    button.classList.toggle('topology-tool-active',active);
    document.querySelector('#topology-graph')?.classList.toggle('topology-room-tool-active',active);
}

async function createManualTopologyNode(nodeType,label,cell,properties={},roomId=null) {
    const networkId = networkSelect.value;
    if (!networkId) throw new Error('Bitte zuerst ein Netzwerk auswählen.');
    const point=topologyGridToPixel(cell.grid_x,cell.grid_y,{nodeAnchor:true});
    const dropTarget=topologyDropTargetAtPoint(point.x,point.y);
    const automaticRoomId = roomId ?? dropTarget.room?.id ?? null;
    const result = await topologyManualRequest(
        `/api/topology/manual-nodes?network_id=${encodeURIComponent(networkId)}`,
        'POST',{
            layout_id:topologyLayoutId,
            node_type:nodeType,
            label,
            properties,
            linked_device_id:null,
            ...(automaticRoomId == null ? {} : {room_id:automaticRoomId}),
            ...cell
        }
    );
    topologyLayoutId = result.node.layout_id;
    selectedManualNodeId = Number(result.node.id);
    selectedTopologyNodeKey = `manual:${result.node.id}`;
    setTopologySaveStatus('Manuelles Objekt dauerhaft gespeichert','saved');
    await loadInventoryTopology();
}

function showTopologyNetworkPrompt(cell,origin,{duplicate=false,properties={}}={}) {
    topologyContextAnchor = {x:origin.x,y:origin.y};
    const menu = topologyMenu();
    menu.replaceChildren();
    topologyMenuHeading(duplicate ? 'Netzwerkobjekt kopieren' : 'Netzwerkobjekt anlegen');
    const note = document.createElement('p');
    note.textContent = duplicate
        ? 'Gib ein anderes CIDR-Netz an. Bestehende Netzwerkdefinitionen werden nicht dupliziert.'
        : 'Gib ein CIDR an. Vorhandene Netzwerke werden automatisch verknüpft.';
    menu.appendChild(note);
    const input = document.createElement('input');
    input.type = 'text'; input.maxLength = 120; input.placeholder = '192.168.10.0/24';
    input.setAttribute('aria-label','Netzwerk in CIDR-Notation');
    menu.appendChild(input);
    const save = topologyMenuButton(duplicate ? 'Kopie anlegen' : 'Netzwerk anlegen',() => {
        const label = input.value.trim();
        if (!label) {input.focus(); topologyMenuStatus('Bitte ein CIDR-Netz eingeben.','error'); return;}
        void runTopologyAction(() => createManualTopologyNode('network',label,cell,properties));
    });
    topologyMenuButton('Abbrechen',closeTopologyContextMenu,{secondary:true});
    topologyPendingDrop = {cell,origin};
    placeTopologyMenu(origin.x,origin.y);
    requestAnimationFrame(() => input.focus());
    input.addEventListener('keydown',event => {
        if (event.key === 'Enter') {event.preventDefault(); save.click();}
    });
}

function editManualLabel(node) {
    const menu = topologyMenu();
    menu.replaceChildren();
    topologyMenuHeading('Bezeichnung ändern');
    const input = document.createElement('input');
    input.type = 'text'; input.maxLength = 120; input.value = node.manual.label;
    input.setAttribute('aria-label',node.manual.node_type === 'network' ? 'CIDR-Netzwerk' : 'Bezeichnung');
    menu.appendChild(input);
    const save = topologyMenuButton('Speichern',() => void runTopologyAction(async () => {
        await updateManualTopologyNode(node.manual.id,{label:input.value.trim()});
    }));
    topologyMenuButton('Abbrechen',() => openTopologyContextMenu(topologyContextAnchor.x,topologyContextAnchor.y,node),{secondary:true});
    placeTopologyMenu(topologyContextAnchor.x,topologyContextAnchor.y);
    requestAnimationFrame(() => input.focus());
    input.addEventListener('keydown',event => {
        if (event.key === 'Enter') {event.preventDefault(); save.click();}
    });
}

function editManualType(node) {
    const menu = topologyMenu();
    menu.replaceChildren();
    topologyMenuHeading('Objekttyp ändern');
    const select = document.createElement('select');
    for (const [type,design] of Object.entries(topologyManualTypes))
        select.add(new Option(design.label,type));
    select.value = node.manual.node_type;
    menu.appendChild(select);
    const label = document.createElement('input');
    label.type = 'text'; label.maxLength = 120; label.value = node.manual.label;
    label.setAttribute('aria-label','Bezeichnung beziehungsweise CIDR');
    menu.appendChild(label);
    const help = document.createElement('small');
    help.textContent = 'Für den Typ Netzwerk muss die Bezeichnung ein CIDR-Netz sein.';
    menu.appendChild(help);
    topologyMenuButton('Speichern',() => void runTopologyAction(async () => {
        await updateManualTopologyNode(node.manual.id,{node_type:select.value,label:label.value.trim()});
    }));
    topologyMenuButton('Abbrechen',() => openTopologyContextMenu(topologyContextAnchor.x,topologyContextAnchor.y,node),{secondary:true});
    placeTopologyMenu(topologyContextAnchor.x,topologyContextAnchor.y);
    select.focus();
}

function editManualLink(node) {
    const menu = topologyMenu();
    menu.replaceChildren();
    topologyMenuHeading('Erkanntes Gerät verknüpfen');
    const select = document.createElement('select');
    select.add(new Option('Nicht verknüpft',''));
    for (const device of devices) select.add(new Option(topologyDeviceOptionLabel(device),String(device.id)));
    select.value = node.manual.linked_device_id == null ? '' : String(node.manual.linked_device_id);
    menu.appendChild(select);
    const save = () => void runTopologyAction(async () => {
        await updateManualTopologyNode(node.manual.id,{linked_device_id:select.value ? Number(select.value) : null});
    });
    topologyMenuButton('Speichern',save);
    topologyMenuButton('Verknüpfung entfernen',() => {
        select.value = ''; save();
    },{secondary:true});
    topologyMenuButton('Abbrechen',() => openTopologyContextMenu(topologyContextAnchor.x,topologyContextAnchor.y,node),{secondary:true});
    placeTopologyMenu(topologyContextAnchor.x,topologyContextAnchor.y);
    select.focus();
}

function editManualProperties(node) {
    const menu = topologyMenu();
    menu.replaceChildren();
    topologyMenuHeading('Eigenschaften');
    const original = node.manual.properties && typeof node.manual.properties === 'object'
        ? node.manual.properties : {};
    const rows = new Map();
    const removed = new Set();
    const list = document.createElement('div');
    list.className = 'topology-property-list';
    menu.appendChild(list);
    const addRow = (key,value,isNew=false) => {
        const row = document.createElement('div'); row.className = 'topology-property-row';
        const keyInput = document.createElement('input'); keyInput.value = key;
        keyInput.placeholder = 'Eigenschaft'; keyInput.setAttribute('aria-label','Eigenschaftsname');
        if (!isNew) keyInput.readOnly = true;
        row.appendChild(keyInput);
        let valueControl;
        const primitive = ['string','number','boolean'].includes(typeof value);
        if (typeof value === 'boolean') {
            valueControl = document.createElement('input'); valueControl.type = 'checkbox'; valueControl.checked = value;
            valueControl.setAttribute('aria-label',`${key} Wert`);
        } else if (primitive) {
            valueControl = document.createElement('input');
            valueControl.type = typeof value === 'number' ? 'number' : 'text';
            if (typeof value === 'number') valueControl.step = 'any';
            valueControl.value = value == null ? '' : String(value);
            valueControl.setAttribute('aria-label',`${key || 'Neue Eigenschaft'} Wert`);
        } else {
            valueControl = document.createElement('span');
            valueControl.className = 'topology-property-preserved';
            valueControl.textContent = 'Komplexer Wert bleibt unverändert';
            valueControl.title = JSON.stringify(value);
        }
        row.appendChild(valueControl);
        const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Entfernen';
        remove.setAttribute('aria-label',`${key || 'Eigenschaft'} entfernen`);
        remove.addEventListener('click',() => {
            if (!isNew) removed.add(key);
            rows.delete(row);
            row.remove();
        });
        row.appendChild(remove);
        rows.set(row,{keyInput,valueControl,original:value,isNew,primitive});
        list.appendChild(row);
    };
    for (const [key,value] of Object.entries(original)) addRow(key,value);
    const add = document.createElement('button'); add.type='button'; add.textContent='Eigenschaft hinzufügen';
    add.addEventListener('click',() => addRow('', '',true));
    menu.appendChild(add);
    topologyMenuButton('Speichern',() => void runTopologyAction(async () => {
        const next = {...original};
        for (const key of removed) delete next[key];
        for (const rowData of rows.values()) {
            const key = rowData.keyInput.value.trim();
            if (!key) throw new Error('Eigenschaftsnamen dürfen nicht leer sein.');
            if (rowData.isNew && Object.hasOwn(next,key)) {
                throw new Error(`„${key}“ existiert bereits.`);
            }
            let value = rowData.original;
            if (rowData.isNew) value = rowData.valueControl.type === 'checkbox'
                ? rowData.valueControl.checked : rowData.valueControl.value;
            else if (rowData.primitive) {
                if (typeof rowData.original === 'boolean') value = rowData.valueControl.checked;
                else if (typeof rowData.original === 'number') {
                    value = Number(rowData.valueControl.value);
                    if (!Number.isFinite(value)) throw new Error(`„${key}“ muss eine Zahl sein.`);
                } else value = rowData.valueControl.value;
            }
            Object.defineProperty(next,key,{value,enumerable:true,writable:true,configurable:true});
        }
        await updateManualTopologyNode(node.manual.id,{properties:next});
    }));
    topologyMenuButton('Abbrechen',() => openTopologyContextMenu(topologyContextAnchor.x,topologyContextAnchor.y,node),{secondary:true});
    placeTopologyMenu(topologyContextAnchor.x,topologyContextAnchor.y);
}

function openTopologyContextMenu(x,y,node) {
    topologyContextAnchor = {x,y};
    const menu = topologyMenu();
    menu.replaceChildren();
    topologyMenuHeading(node.manual ? node.manual.label : node.label);
    const description = document.createElement('p');
    description.textContent = node.manual
        ? node.manual.linked_device_id
            ? `Manuelles Objekt · verknüpft mit ${node.manual.linked_device_hostname || `Gerät #${node.manual.linked_device_id}`}`
            : 'Manuell angelegt · nicht vom Scanner erkannt'
        : 'Vom Scanner erkannt';
    menu.appendChild(description);
    topologyMenuButton('Verbindung ziehen',() => topologyArmConnection({kind:'node',node}));
    if (node.device) {
        topologyMenuButton('Gerätedetails öffnen',() => {
            closeTopologyContextMenu(); void showDevice(node.device.id,true);
        });
        topologyMenuButton('Geräte- und Scaninformationen anzeigen',() => {
            closeTopologyContextMenu(); void showDevice(node.device.id,false);
        },{secondary:true});
    }
    if (node.device) {
        topologyMenuButton(node.manual
            ? 'Geräteverknüpfung lösen und in Ablage verschieben' : 'In Ablage verschieben',() => void runTopologyAction(async () => {
            const networkId=networkSelect.value;
            const layoutQuery=topologyLayoutId == null ? '' : `&layout_id=${encodeURIComponent(topologyLayoutId)}`;
            await topologyManualRequest(
                `/api/topology/layout/positions/${encodeURIComponent(node.device.id)}?network_id=${encodeURIComponent(networkId)}${layoutQuery}`,
                'DELETE'
            );
            selectedTopologyNodeKey=null; selectedManualNodeId=null;
            await loadInventoryTopology();
            setTopologySaveStatus('Gerät in die Ablage verschoben','saved');
        }));
    }
    if (node.manual) {
        const manual = node.manual;
        topologyMenuButton('Umbenennen',() => editManualLabel(node),{secondary:true});
        topologyMenuButton('Typ ändern',() => editManualType(node),{secondary:true});
        topologyMenuButton('Eigenschaften',() => editManualProperties(node),{secondary:true});
        topologyMenuButton(manual.linked_device_id ? 'Geräteverknüpfung ändern' : 'Mit Gerät verknüpfen',
            () => editManualLink(node),{secondary:true});
        topologyMenuButton('Duplizieren',() => {
            try {
                const cell = topologyFreeCellNear(manual.grid_x,manual.grid_y);
                if (manual.node_type === 'network') showTopologyNetworkPrompt(cell,{x,y},{duplicate:true,properties:manual.properties || {}});
                else void runTopologyAction(() => createManualTopologyNode(manual.node_type,
                    `${manual.label.slice(0,110)} (Kopie)`,cell,manual.properties || {}));
            } catch (error) { topologyMenuStatus(error.message,'error'); }
        },{secondary:true});
        topologyMenuButton('Löschen',() => void runTopologyAction(async () => {
            const networkId = networkSelect.value;
            await topologyManualRequest(
                `/api/topology/manual-nodes/${encodeURIComponent(manual.id)}?network_id=${encodeURIComponent(networkId)}`,
                'DELETE'
            );
            selectedManualNodeId = null; selectedTopologyNodeKey = null;
            setTopologySaveStatus('Manuelles Objekt gelöscht','saved');
            await loadInventoryTopology();
        }),{danger:true});
    }
    topologyMenuButton('Schließen',closeTopologyContextMenu,{secondary:true});
    placeTopologyMenu(x,y);
    requestAnimationFrame(() => menu.querySelector('button')?.focus());
}

function openTopologyLinkContextMenu(x,y,link,source,target) {
    topologyContextAnchor={x,y};
    const menu=topologyMenu(); menu.replaceChildren();
    topologyMenuHeading(link.label || 'Verbindung');
    const endpointName=object=>object.kind==='room' ? `Raum ${object.room.name}` :
        object.node.manual?.label || object.node.device?.ip || `Gerät #${object.node.device?.id}`;
    const endpoints=document.createElement('p');
    endpoints.textContent=`${endpointName(source)} → ${endpointName(target)}`;
    menu.appendChild(endpoints);
    const evidence=document.createElement('p');
    evidence.textContent=`Evidenzstatus: ${TOPOLOGY_EVIDENCE_LABELS[link.evidence_status] || link.evidence_status}`;
    menu.appendChild(evidence);

    const typeLabel=document.createElement('label'); typeLabel.textContent='Verbindungstyp';
    const type=document.createElement('select'); type.setAttribute('aria-label','Verbindungstyp');
    for (const [value,label] of TOPOLOGY_LINK_TYPES) {
        const option=document.createElement('option'); option.value=value; option.textContent=label;
        type.appendChild(option);
    }
    type.value=link.link_type || 'unknown'; typeLabel.appendChild(type); menu.appendChild(typeLabel);

    const labelLabel=document.createElement('label'); labelLabel.textContent='Bezeichnung';
    const label=document.createElement('input'); label.type='text'; label.maxLength=120;
    label.value=link.label || ''; label.setAttribute('aria-label','Verbindungsbezeichnung');
    labelLabel.appendChild(label); menu.appendChild(labelLabel);

    const descriptionLabel=document.createElement('label'); descriptionLabel.textContent='Beschreibung';
    const description=document.createElement('textarea'); description.maxLength=2000;
    description.value=link.description || ''; description.setAttribute('aria-label','Verbindungsbeschreibung');
    descriptionLabel.appendChild(description); menu.appendChild(descriptionLabel);
    topologyMenuButton('Änderungen speichern',()=>void runTopologyAction(async()=>{
        await topologyManualRequest(
            `/api/topology/links/${encodeURIComponent(link.id)}?network_id=${encodeURIComponent(networkSelect.value)}`,
            'PUT',{link_type:type.value,label:label.value,description:description.value}
        );
        selectedTopologyLinkId=Number(link.id);
        setTopologySaveStatus('Verbindung aktualisiert','saved');
        await loadInventoryTopology({preserveGraphOnError:true});
    }));
    topologyMenuButton('Verbindung löschen',()=>void runTopologyAction(async()=>{
        await topologyManualRequest(
            `/api/topology/links/${encodeURIComponent(link.id)}?network_id=${encodeURIComponent(networkSelect.value)}`,
            'DELETE'
        );
        selectedTopologyLinkId=null;
        setTopologySaveStatus('Verbindung gelöscht','saved');
        await loadInventoryTopology({preserveGraphOnError:true});
    }),{danger:true});
    topologyMenuButton('Schließen',closeTopologyContextMenu,{secondary:true});
    placeTopologyMenu(x,y);
    requestAnimationFrame(()=>type.focus());
}

function topologySvgPoint(clientX,clientY) {
    const matrix = topologyGraph.getScreenCTM();
    return matrix ? new DOMPoint(clientX,clientY).matrixTransform(matrix.inverse()) : null;
}

function topologyArmConnection(source) {
    if (!topologyLayoutId) {
        setTopologySaveStatus('Zuerst ein Layout anlegen, um Verbindungen zu speichern','error');
        return;
    }
    topologyConnectionArmed=source;
    closeTopologyContextMenu();
    topologyGraph.classList.add('topology-connection-armed');
    setTopologySaveStatus(source.kind==='room'
        ? 'Verbindung aktiv: an einem vorhandenen Raumgriff ziehen und am Ziel loslassen'
        : 'Verbindung aktiv: am Gerät ziehen und auf einem Ziel loslassen','saved');
}

function topologyCancelArmedConnection() {
    if (!topologyConnectionArmed) return false;
    topologyConnectionArmed=null;
    topologyGraph.classList.remove('topology-connection-armed');
    setTopologySaveStatus('Verbindungserstellung abgebrochen');
    return true;
}

function topologyRoomAnchorForGrip(grip) {
    return {n:'top',e:'right',s:'bottom',w:'left'}[grip] || null;
}

function topologyRoomAnchorPoint(room,side,handle=null) {
    if (handle) {
        const matrix=handle.getScreenCTM();
        if (matrix) {
            const screenPoint=new DOMPoint(Number(handle.getAttribute('cx')),
                Number(handle.getAttribute('cy'))).matrixTransform(matrix);
            const point=topologySvgPoint(screenPoint.x,screenPoint.y);
            if (point) return {x:point.x,y:point.y};
        }
    }
    const bounds=topologyRoomPixelBounds(room);
    return {
        top:{x:bounds.x+bounds.width/2,y:bounds.y},
        right:{x:bounds.right,y:bounds.y+bounds.height/2},
        bottom:{x:bounds.x+bounds.width/2,y:bounds.bottom},
        left:{x:bounds.x,y:bounds.y+bounds.height/2}
    }[side];
}

function topologyRoomHandleNearPoint(clientX,clientY,roomId=null) {
    const graphMatrix=topologyGraph.getScreenCTM();
    if (!graphMatrix) return null;
    let nearest=null;
    for (const room of topologyRooms) {
        if (roomId!==null && Number(room.id)!==Number(roomId)) continue;
        const group=topologyGraph.querySelector(`.topology-room[data-room-id="${Number(room.id)}"]`);
        const translation=/translate\(([-\d.]+)[, ]+([-\d.]+)\)/.exec(group?.getAttribute('transform') || '');
        const offset=translation ? {x:Number(translation[1]),y:Number(translation[2])} : {x:0,y:0};
        for (const handle of group?.querySelectorAll('.topology-room-handle') || []) {
            const side=topologyRoomAnchorForGrip(handle.dataset.grip);
            if (!side) continue;
            const screenPoint=new DOMPoint(Number(handle.getAttribute('cx'))+offset.x,
                Number(handle.getAttribute('cy'))+offset.y).matrixTransform(graphMatrix);
            const distance=Math.hypot(clientX-screenPoint.x,clientY-screenPoint.y);
            if (distance<=12 && (!nearest || distance<nearest.distance))
                nearest={room,handle,side,distance};
        }
    }
    return nearest;
}

function topologyStartConnection(event,endpoint,anchorPoint) {
    event.preventDefault(); event.stopPropagation();
    topologyConnectionArmed=null;
    topologyGraph.classList.remove('topology-connection-armed');
    topologyLinkDrag={pointerId:event.pointerId,source:{...endpoint},
        sourcePoint:{...anchorPoint},point:{...anchorPoint},target:null,targetElement:null};
    topologyEditorGesture={type:'link-create',pointerId:event.pointerId,target:topologyGraph};
    topologyGraph.classList.add('topology-connection-active');
    topologyLinkPreviewElement=svgElement('polyline',{class:'topology-connection-preview',points:''});
    topologyGraph.appendChild(topologyLinkPreviewElement);
    topologyGraph.setPointerCapture(event.pointerId);
    topologyDrawConnectionPreview(topologyLinkDrag);
}

function topologyDrawConnectionPreview(drag) {
    if (!topologyLinkPreviewElement || !drag) return;
    const start=drag.sourcePoint, end=drag.point;
    const dx=end.x-start.x,dy=end.y-start.y;
    const normal=topologyConnectionNormal(drag.source.anchor);
    let points;
    if (!normal) {
        const elbow=Math.abs(dx)>=Math.abs(dy)
            ? {x:end.x,y:start.y} : {x:start.x,y:end.y};
        points=[start,elbow,end];
    } else if (normal.x) {
        const axis=dx*normal.x>0 ? end.x : start.x+normal.x*8;
        points=dx*normal.x>0
            ? [start,{x:axis,y:start.y},end]
            : [start,{x:axis,y:start.y},{x:axis,y:end.y},end];
    } else {
        const axis=dy*normal.y>0 ? end.y : start.y+normal.y*8;
        points=dy*normal.y>0
            ? [start,{x:start.x,y:axis},end]
            : [start,{x:start.x,y:axis},{x:end.x,y:axis},end];
    }
    points=points.filter((point,index)=>index===0 ||
        point.x!==points[index-1].x || point.y!==points[index-1].y);
    topologyLinkPreviewElement.setAttribute('points',points.map(point=>`${point.x},${point.y}`).join(' '));
}

function topologyConnectionTargetAt(clientX,clientY) {
    const hit=document.elementFromPoint(clientX,clientY);
    const handle=hit?.closest?.('.topology-room-handle');
    if (handle) {
        const roomGroup=handle.closest('.topology-room');
        const room=topologyRooms.find(item=>Number(item.id)===Number(roomGroup?.dataset.roomId));
        const anchor=topologyRoomAnchorForGrip(handle.dataset.grip);
        if (room && anchor) return {endpoint:{room_id:Number(room.id),anchor},element:handle};
    }
    const nodeElement=hit?.closest?.('.topology-node');
    const node=topologyRenderedNodes.find(item=>item.element===nodeElement);
    if (node) return {endpoint:topologyNodeEndpoint(node,'auto'),element:node.element};
    if (hit===topologyGraph || hit?.closest?.('.topology-room')) {
        const nearby=topologyRoomHandleNearPoint(clientX,clientY);
        if (nearby) return {endpoint:{room_id:Number(nearby.room.id),anchor:nearby.side},
            element:nearby.handle};
    }
    return null;
}

function topologyClearConnectionTarget(drag) {
    drag?.targetElement?.classList.remove('topology-connection-target-valid',
        'topology-connection-target-invalid');
    if (drag) {drag.target=null;drag.targetElement=null;}
}

function topologyUpdateConnectionDrag(event) {
    const drag=topologyLinkDrag;
    if (!drag || event.pointerId !== drag.pointerId) return false;
    const point=topologySvgPoint(event.clientX,event.clientY);
    if (!point) return true;
    drag.point=point;
    topologyClearConnectionTarget(drag);
    const candidate=topologyConnectionTargetAt(event.clientX,event.clientY);
    if (candidate) {
        const valid=topologyEndpointIdentity(candidate.endpoint)!==topologyEndpointIdentity(drag.source);
        candidate.element.classList.add(valid
            ? 'topology-connection-target-valid' : 'topology-connection-target-invalid');
        drag.targetElement=candidate.element;
        if (valid) drag.target=candidate.endpoint;
    }
    topologyDrawConnectionPreview(drag);
    event.preventDefault();
    return true;
}

function topologyFinishConnection(event,cancelled=false) {
    const drag=topologyLinkDrag;
    if (!drag || event && event.pointerId !== drag.pointerId) return;
    const target=drag.target;
    const preview=topologyLinkPreviewElement;
    topologyLinkDrag=null;
    topologyEditorGesture=null;
    topologyGraph.classList.remove('topology-connection-active');
    topologyClearConnectionTarget(drag);
    if (topologyGraph.hasPointerCapture(drag.pointerId)) topologyGraph.releasePointerCapture(drag.pointerId);
    if (cancelled || event?.type!=='pointerup') {
        preview?.remove();
        if (topologyLinkPreviewElement===preview) topologyLinkPreviewElement=null;
        setTopologySaveStatus('Verbindungserstellung abgebrochen');
        return;
    }
    if (!target) {
        preview?.remove();
        if (topologyLinkPreviewElement===preview) topologyLinkPreviewElement=null;
        setTopologySaveStatus('Kein gültiges Ziel – es wurde nichts gespeichert','error');
        return;
    }
    void (async () => {
        const networkId=networkSelect.value;
        let result;
        try {
            result=await topologyManualRequest(
                `/api/topology/links?network_id=${encodeURIComponent(networkId)}`,
                'POST',{
                    layout_id:topologyLayoutId,
                    source:drag.source,target,
                    link_type:'unknown',label:'',description:''
                }
            );
        } catch (error) {
            preview?.remove();
            if (topologyLinkPreviewElement===preview) topologyLinkPreviewElement=null;
            setTopologySaveStatus(`Verbindung nicht gespeichert: ${error.message}`,'error');
            return;
        }
        try {
            let rendered=false;
            try { rendered=topologyRenderWithAddedLink(result.link); }
            catch (error) { console.error('Verbindung gespeichert, Darstellung wird neu geladen',error); }
            if (!rendered && String(networkId)===String(networkSelect.value)) {
                preview?.remove();
                if (topologyLinkPreviewElement===preview) topologyLinkPreviewElement=null;
                await loadInventoryTopology({preserveGraphOnError:true});
            }
            setTopologySaveStatus('Verbindung gespeichert','saved');
        } catch (error) {
            preview?.remove();
            if (topologyLinkPreviewElement===preview) topologyLinkPreviewElement=null;
            setTopologySaveStatus(`Verbindung gespeichert, Darstellung konnte nicht aktualisiert werden: ${error.message}`,'error');
        }
    })();
}

function topologyBeginArmedConnection(event) {
    const armed=topologyConnectionArmed;
    if (!armed || event.button!==0 || topologyEditorGesture) return false;
    let endpoint=null,anchorPoint=null;
    if (armed.kind==='node') {
        const nodeElement=event.target.closest?.('.topology-node');
        if (nodeElement!==armed.node.element) return false;
        endpoint=topologyNodeEndpoint(armed.node,'auto');
        anchorPoint={x:armed.node.x,y:armed.node.y};
    } else {
        let handle=event.target.closest?.('.topology-room-handle');
        let roomGroup=handle?.closest('.topology-room');
        if (!handle || Number(roomGroup?.dataset.roomId)!==Number(armed.room.id)) {
            const nearby=topologyRoomHandleNearPoint(event.clientX,event.clientY,armed.room.id);
            handle=nearby?.handle || null;
            roomGroup=handle?.closest('.topology-room');
        }
        if (!handle || Number(roomGroup?.dataset.roomId)!==Number(armed.room.id)) return false;
        const side=topologyRoomAnchorForGrip(handle.dataset.grip);
        if (!side) return false;
        endpoint={room_id:Number(armed.room.id),anchor:side};
        anchorPoint=topologyRoomAnchorPoint(armed.room,side,handle);
    }
    topologyStartConnection(event,endpoint,anchorPoint);
    return true;
}

function clearTopologyPreview() {
    topologyGraph.querySelector('.topology-drop-preview')?.remove();
}

function drawTopologyPreview(drag,point) {
    clearTopologyPreview();
    const {gridColumn:gridX,gridRow:gridY}=topologyPixelToGrid(point.x,point.y,{nodeAnchor:true});
    const occupied = topologyOccupiedCells().has(`${gridX}:${gridY}`);
    const center=topologyGridToPixel(gridX,gridY,{nodeAnchor:true});
    const centerX=center.x, centerY=center.y;
    const target=topologyDropTargetAtPoint(centerX,centerY,
        occupied ? new Set([`${gridX}:${gridY}`]) : new Set());
    setTopologyRoomDropPreview(target.valid ? target.room?.id ?? null : null);
    const group = svgElement('g',{class:`topology-drop-preview${occupied ? ' topology-drop-invalid' : ''}`,
        transform:`translate(${centerX},${centerY})`});
    group.appendChild(svgElement('circle',{r:18,class:'topology-node-background'}));
    const icon = createLucideIcon(topologyManualTypes[drag.nodeType].icon);
    for (const [key,value] of Object.entries({x:-9,y:-9,width:18,height:18})) icon.setAttribute(key,value);
    group.appendChild(icon);
    const label = svgElement('text',{x:0,y:34,'text-anchor':'middle'}); label.textContent = topologyManualTypes[drag.nodeType].label;
    group.appendChild(label); topologyGraph.appendChild(group);
    drag.cell = {grid_x:gridX,grid_y:gridY};
}

function finishTopologyPaletteDrag(event,cancelled=false) {
    const drag = topologyPaletteDrag;
    if (!drag || event && event.pointerId !== drag.pointerId) return;
    topologyPaletteDrag = null;
    topologyEditorGesture = null;
    clearTopologyRoomDropPreview();
    clearTopologyPreview();
    if (drag.button.hasPointerCapture?.(drag.pointerId)) drag.button.releasePointerCapture(drag.pointerId);
    if (cancelled || !drag.moved) return;
    const rect = document.querySelector('.topology-viewport').getBoundingClientRect();
    const inside = event && event.clientX >= rect.left && event.clientX <= rect.right &&
        event.clientY >= rect.top && event.clientY <= rect.bottom;
    if (!inside || !drag.cell) {
        setTopologySaveStatus('Objekt wurde außerhalb der Zeichenfläche abgelegt','error');
        return;
    }
    const dropPoint = topologySvgPoint(event.clientX,event.clientY);
    if (!dropPoint) {
        setTopologySaveStatus('Zeichenfläche nicht verfügbar – Objekt wurde nicht erstellt','error');
        return;
    }
    const dropCell=topologyPixelToGrid(dropPoint.x,dropPoint.y,{nodeAnchor:true});
    drag.cell = {grid_x:dropCell.gridColumn,grid_y:dropCell.gridRow};
    if (topologyOccupiedCells().has(`${drag.cell.grid_x}:${drag.cell.grid_y}`)) {
        setTopologySaveStatus('Rasterplatz belegt – Objekt wurde nicht erstellt','error');
        return;
    }
    if (drag.nodeType === 'network') {
        showTopologyNetworkPrompt(drag.cell,{x:event.clientX,y:event.clientY});
        return;
    }
    const room = topologyRoomAtCell(drag.cell.grid_x,drag.cell.grid_y);
    void runTopologyAction(() => createManualTopologyNode(drag.nodeType,
        topologyManualTypes[drag.nodeType].label,drag.cell,{},room?.id ?? null));
}

function clearTopologyTrayPreview() {
    topologyGraph.querySelector('.topology-tray-drop-preview')?.remove();
}

function drawTopologyTrayPreview(drag,point) {
    clearTopologyTrayPreview();
    const cell=topologyPixelToGrid(point.x,point.y,{nodeAnchor:true});
    const blocked=topologyOccupiedCells().has(`${cell.gridColumn}:${cell.gridRow}`);
    const center=topologyGridToPixel(cell.gridColumn,cell.gridRow,{nodeAnchor:true});
    const target=topologyDropTargetAtPoint(center.x,center.y,
        blocked ? new Set([`${cell.gridColumn}:${cell.gridRow}`]) : new Set());
    setTopologyRoomDropPreview(target.valid ? target.room?.id ?? null : null);
    const visual=createTopologyNodeVisual(drag.node);
    visual.setAttribute('class',`${visual.getAttribute('class')} topology-drop-preview topology-tray-drop-preview${blocked ? ' topology-drop-invalid' : ''}`);
    visual.setAttribute('transform',`translate(${center.x},${center.y})`);
    topologyGraph.appendChild(visual);
    drag.cell={grid_x:cell.gridColumn,grid_y:cell.gridRow};
    drag.valid=!blocked;
}

function finishTopologyTrayDrag(event,cancelled=false) {
    const drag=topologyTrayDrag;
    if (!drag || event && event.pointerId !== drag.pointerId) return;
    topologyTrayDrag=null;
    topologyEditorGesture=null;
    clearTopologyRoomDropPreview();
    clearTopologyTrayPreview();
    if (drag.target.hasPointerCapture?.(drag.pointerId)) drag.target.releasePointerCapture(drag.pointerId);
    if (cancelled || !drag.moved) return;
    const rect=document.querySelector('.topology-viewport').getBoundingClientRect();
    const inside=event && event.clientX >= rect.left && event.clientX <= rect.right &&
        event.clientY >= rect.top && event.clientY <= rect.bottom;
    if (!inside) {
        setTopologySaveStatus('Gerät außerhalb der Zeichenfläche abgelegt','error');
        return;
    }
    const point=topologySvgPoint(event.clientX,event.clientY);
    if (!point) {
        setTopologySaveStatus('Zeichenfläche nicht verfügbar – Gerät wurde nicht platziert','error');
        return;
    }
    const cell=topologyPixelToGrid(point.x,point.y,{nodeAnchor:true});
    const slot=`${cell.gridColumn}:${cell.gridRow}`;
    if (topologyOccupiedCells().has(slot)) {
        setTopologySaveStatus('Rasterplatz belegt – Gerät wurde nicht platziert','error');
        return;
    }
    const room=topologyRoomAtCell(cell.gridColumn,cell.gridRow);
    const networkId=topologyGraphContext;
    void saveTopologyLayout(networkId,drag.sourceLayoutId,[{
        device_id:Number(drag.node.device.id),grid_x:cell.gridColumn,grid_y:cell.gridRow
    }],[],[{
        device_id:Number(drag.node.device.id),room_id:room ? Number(room.id) : null
    }]).then(async result => {
        if (!result.saved) return;
        await loadInventoryTopology({preserveGraphOnError:true});
    });
}

const topologyPalette = document.querySelector('#topology-palette');
const topologyUnplacedToggle = document.querySelector('#topology-unplaced-toggle');
const topologyUnplacedSearch = document.querySelector('#topology-unplaced-search');
topologyUnplacedToggle.addEventListener('click',() => {
    topologyUnplacedCollapsed=!topologyUnplacedCollapsed;
    renderTopologyUnplacedDevices();
});
topologyUnplacedSearch.addEventListener('input',renderTopologyUnplacedDevices);
for (const [nodeType,design] of Object.entries(topologyManualTypes)) {
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'topology-palette-item'; button.title = `${design.label} auf die Zeichenfläche ziehen`;
    button.setAttribute('aria-label',button.title); button.dataset.nodeType = nodeType;
    button.appendChild(createLucideIcon(design.icon));
    const label = document.createElement('span'); label.textContent = design.label; button.appendChild(label);
    button.addEventListener('pointerdown',event => {
        if (event.button !== 0 || topologyPaletteDrag || topologyEditorGesture) return;
        closeTopologyContextMenu();
        event.preventDefault();
        topologyPaletteDrag = {pointerId:event.pointerId,nodeType,button,startX:event.clientX,startY:event.clientY,moved:false,cell:null};
        topologyEditorGesture = {type:'palette-drag',pointerId:event.pointerId,nodeType,target:button};
        button.setPointerCapture(event.pointerId);
    });
    topologyPalette.appendChild(button);
}

document.addEventListener('pointermove',event => {
    if (topologyUpdateConnectionDrag(event)) return;
    const trayDrag=topologyTrayDrag;
    if (trayDrag && event.pointerId === trayDrag.pointerId) {
        if (!trayDrag.moved && Math.hypot(event.clientX-trayDrag.startX,event.clientY-trayDrag.startY) >= 5)
            trayDrag.moved=true;
        if (!trayDrag.moved) return;
        const rect=document.querySelector('.topology-viewport').getBoundingClientRect();
        if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) {
            clearTopologyTrayPreview(); clearTopologyRoomDropPreview(); trayDrag.cell=null; trayDrag.valid=false; return;
        }
        const point=topologySvgPoint(event.clientX,event.clientY);
        if (point) drawTopologyTrayPreview(trayDrag,point);
        return;
    }
    const drag = topologyPaletteDrag;
    if (!drag || event.pointerId !== drag.pointerId) return;
    if (!drag.moved && Math.hypot(event.clientX-drag.startX,event.clientY-drag.startY) >= 5) drag.moved = true;
    if (!drag.moved) return;
    const rect = document.querySelector('.topology-viewport').getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) {
        clearTopologyPreview(); clearTopologyRoomDropPreview(); drag.cell = null; return;
    }
    const point = topologySvgPoint(event.clientX,event.clientY);
    if (point) drawTopologyPreview(drag,point);
});
document.addEventListener('pointerup',event=>{
    if (!topologyLinkDrag || event.pointerId!==topologyLinkDrag.pointerId) return;
    topologyUpdateConnectionDrag(event);
    topologyFinishConnection(event);
});
document.addEventListener('pointercancel',event=>{
    if (topologyLinkDrag && event.pointerId===topologyLinkDrag.pointerId)
        topologyFinishConnection(event,true);
});
document.addEventListener('pointerup',event => finishTopologyPaletteDrag(event));
document.addEventListener('pointercancel',event => finishTopologyPaletteDrag(event,true));
document.addEventListener('pointerup',event => finishTopologyTrayDrag(event));
document.addEventListener('pointercancel',event => finishTopologyTrayDrag(event,true));
document.addEventListener('pointerdown',event => {
    if (!topologyMenu().hidden && !topologyMenu().contains(event.target)) closeTopologyContextMenu();
});

function cancelTopologyGesture() {
    const gesture=topologyEditorGesture;
    if (!gesture) {
        let cancelled=topologyCancelArmedConnection();
        if (topologyPaletteDrag) {finishTopologyPaletteDrag(null,true); cancelled=true;}
        if (topologyTrayDrag) {finishTopologyTrayDrag(null,true); cancelled=true;}
        if (topologyRoomDraw) {
            const pointerId=topologyRoomDraw.pointerId;
            topologyRoomDraw.preview.remove(); topologyRoomDraw=null;
            clearTopologyRoomDropPreview(); cancelled=true;
            if (topologyGraph.hasPointerCapture(pointerId)) topologyGraph.releasePointerCapture(pointerId);
        }
        if (topologyPan) {stopTopologyPan(); cancelled=true;}
        return cancelled;
    }
    if (gesture.type === 'palette-drag' && topologyPaletteDrag) {
        finishTopologyPaletteDrag(null,true);
        return true;
    }
    if (gesture.type === 'device-tray-drag' && topologyTrayDrag) {
        finishTopologyTrayDrag(null,true);
        return true;
    }
    if (gesture.type === 'link-create' && topologyLinkDrag) {
        topologyFinishConnection({pointerId:gesture.pointerId,type:'pointercancel'},true);
        return true;
    }
    if (gesture.target && typeof PointerEvent !== 'undefined') {
        gesture.target.dispatchEvent(new PointerEvent('pointercancel',{
            bubbles:true,pointerId:gesture.pointerId,pointerType:'mouse'
        }));
    }
    if (topologyEditorGesture === gesture) topologyEditorGesture=null;
    if (topologyRoomDraw?.pointerId === gesture.pointerId) {
        topologyRoomDraw.preview.remove(); topologyRoomDraw=null;
        clearTopologyRoomDropPreview(); clearTopologySelection();
    }
    if (topologyPan?.pointerId === gesture.pointerId) stopTopologyPan();
    if (topologyPaletteDrag?.pointerId === gesture.pointerId) finishTopologyPaletteDrag(null,true);
    if (topologyTrayDrag?.pointerId === gesture.pointerId) finishTopologyTrayDrag(null,true);
    if (gesture.target?.hasPointerCapture?.(gesture.pointerId))
        gesture.target.releasePointerCapture(gesture.pointerId);
    return true;
}

window.addEventListener('blur',cancelTopologyGesture);
document.addEventListener('visibilitychange',() => {
    if (document.hidden) cancelTopologyGesture();
});
const releaseUnfinishedTopologyGesture=event => {
    const gesture=topologyEditorGesture;
    if (!gesture || event.pointerId !== gesture.pointerId) return;
    setTimeout(() => {
        if (topologyEditorGesture === gesture) cancelTopologyGesture();
    },0);
};
for (const eventName of ['pointerup','pointercancel','lostpointercapture'])
    document.addEventListener(eventName,releaseUnfinishedTopologyGesture,true);

document.addEventListener('keydown',event => {
    if (event.key === 'Escape') {
        if (topologyRoomDraw) {
            const pointerId = topologyRoomDraw.pointerId;
            topologyRoomDraw.preview.remove(); topologyRoomDraw = null; topologyEditorGesture = null;
            clearTopologyRoomDropPreview();
            if (topologyGraph.hasPointerCapture(pointerId)) topologyGraph.releasePointerCapture(pointerId);
            topologyToolMode = 'select'; updateTopologyRoomTool();
            setTopologySaveStatus('Raumzeichnung abgebrochen');
        } else if (topologyToolMode === 'draw-room') {
            topologyToolMode = 'select'; updateTopologyRoomTool();
        } else if (topologyConnectionArmed) topologyCancelArmedConnection();
        else if (topologyEditorGesture) cancelTopologyGesture();
        else clearTopologySelection();
        return;
    }
    const typing = event.target.matches('input,textarea,select,[contenteditable="true"]');
    if (event.key === 'Delete' && !typing && selectedManualNodeId !== null) {
        const manual = topologyManualNodes.find(node => Number(node.id) === selectedManualNodeId);
        if (!manual) return;
        event.preventDefault();
        void runTopologyAction(async () => {
            await topologyManualRequest(`/api/topology/manual-nodes/${encodeURIComponent(manual.id)}?network_id=${encodeURIComponent(networkSelect.value)}`,'DELETE');
            selectedManualNodeId = null; selectedTopologyNodeKey = null;
            setTopologySaveStatus('Manuelles Objekt gelöscht','saved');
            await loadInventoryTopology();
        });
    } else if (event.key === 'Delete' && !typing && selectedRoomId !== null) {
        const room = topologyRooms.find(item => Number(item.id) === selectedRoomId);
        if (!room) return;
        event.preventDefault();
        void runTopologyAction(async () => {
            await topologyManualRequest(`/api/topology/rooms/${room.id}?network_id=${encodeURIComponent(networkSelect.value)}`,'DELETE');
            selectedRoomId = null; setTopologySaveStatus('Raum gelöscht','saved'); await loadInventoryTopology();
        });
    }
});

function stopTopologyPan() {
    if (!topologyPan) return;
    const svg = document.querySelector('#topology-graph');
    const pointerId = topologyPan.pointerId;
    topologyPan = null;
    if (topologyEditorGesture?.type === 'pan') topologyEditorGesture = null;
    svg.classList.remove('topology-panning');
    if (svg.hasPointerCapture(pointerId)) svg.releasePointerCapture(pointerId);
}

const topologyGraph = document.querySelector('#topology-graph');
topologyGraph.addEventListener('pointerdown',event=>{
    if (!topologyConnectionArmed || event.button!==0) return;
    if (topologyBeginArmedConnection(event)) return;
    // While the menu command is armed, no canvas object may begin a move or resize.
    event.preventDefault(); event.stopPropagation();
},true);
document.querySelector('#topology-room-tool').addEventListener('click',() => {
    if (topologyRoomDraw) return;
    topologyToolMode = topologyToolMode === 'draw-room' ? 'select' : 'draw-room';
    closeTopologyContextMenu(); updateTopologyRoomTool();
    setTopologySaveStatus(topologyToolMode === 'draw-room'
        ? 'Im freien Bereich ziehen, um einen Raum anzulegen' : 'Raumwerkzeug beendet');
});
const boundaryGridPoint = topologyPixelToGridBoundary;
topologyGraph.addEventListener('contextmenu',event => event.preventDefault());
topologyGraph.addEventListener('pointerdown', event => {
    const drawingRoom=topologyToolMode === 'draw-room';
    if (event.button !== 0 || topologyEditorGesture) return;
    if (!drawingRoom && !event.target.closest?.('.topology-room-handle')) {
        const room=topologyRoomAtBoundary(event);
        const targetRoom=event.target.closest?.('.topology-room');
        if (room && (!targetRoom || Number(targetRoom.dataset.roomId) !== Number(room.id))) {
            event.preventDefault(); event.stopImmediatePropagation(); closeTopologyContextMenu();
            selectTopologyRoom(room); return;
        }
    }
    if (!drawingRoom && event.target !== topologyGraph) return;
    if (drawingRoom && event.target !== topologyGraph &&
        !event.target.closest?.('.topology-room')) {
        event.preventDefault(); event.stopPropagation(); return;
    }
    if (drawingRoom && event.target.closest?.('.topology-room-handle')) {
        event.preventDefault(); event.stopPropagation(); return;
    }
    const matrix = topologyGraph.getScreenCTM();
    if (!matrix) return;
    event.preventDefault();
    if (drawingRoom) event.stopPropagation();
    const inverse = matrix.inverse();
    const start = new DOMPoint(event.clientX,event.clientY).matrixTransform(inverse);
    clearTopologySelection();
    if (drawingRoom) {
        const preview = svgElement('rect',{class:'topology-room-draw-preview',rx:2});
        topologyGraph.appendChild(preview);
        topologyRoomDraw={pointerId:event.pointerId,start:start,preview,gridStart:boundaryGridPoint(start),gridEnd:null};
        topologyEditorGesture={type:'room-draw',pointerId:event.pointerId,target:topologyGraph};
        topologyGraph.setPointerCapture(event.pointerId);
        return;
    }
    if (topologyPan) return;
    const box = topologyGraph.viewBox.baseVal;
    topologyPan = {pointerId:event.pointerId, inverse, start,
        box:{x:box.x,y:box.y,width:box.width,height:box.height}};
    topologyEditorGesture={type:'pan',pointerId:event.pointerId,target:topologyGraph};
    topologyGraph.setPointerCapture(event.pointerId);
    topologyGraph.classList.add('topology-panning');
},true);
topologyGraph.addEventListener('pointermove', event => {
    if (topologyRoomDraw?.pointerId === event.pointerId) {
        const point=topologySvgPoint(event.clientX,event.clientY); if (!point) return;
        const end=boundaryGridPoint(point); topologyRoomDraw.gridEnd=end;
        const left=Math.min(topologyRoomDraw.gridStart.x,end.x);
        const top=Math.min(topologyRoomDraw.gridStart.y,end.y);
        const width=Math.abs(end.x-topologyRoomDraw.gridStart.x);
        const height=Math.abs(end.y-topologyRoomDraw.gridStart.y);
        const roomOrigin=topologyGridBoundaryToPixel(left,top);
        topologyRoomDraw.preview.setAttribute('x',roomOrigin.x);
        topologyRoomDraw.preview.setAttribute('y',roomOrigin.y);
        const roomSize=topologyGridSizeToPixel(width,height);
        topologyRoomDraw.preview.setAttribute('width',roomSize.width);
        topologyRoomDraw.preview.setAttribute('height',roomSize.height);
        topologyRoomDraw.preview.classList.toggle('topology-room-draw-invalid',width<2 || height<1);
        const parent=width>=2 && height>=1
            ? topologyRoomParentForGridBounds({grid_x:left,grid_y:top,grid_width:width,grid_height:height})
            : null;
        topologyRoomDraw.parentRoomId=parent ? Number(parent.id) : null;
        setTopologyRoomDropPreview(topologyRoomDraw.parentRoomId);
        event.preventDefault(); return;
    }
    if (!topologyPan || event.pointerId !== topologyPan.pointerId) return;
    event.preventDefault();
    const point = new DOMPoint(event.clientX,event.clientY).matrixTransform(topologyPan.inverse);
    const {box,start} = topologyPan;
    topologyGraph.setAttribute('viewBox',`${box.x-(point.x-start.x)} ${box.y-(point.y-start.y)} ${box.width} ${box.height}`);
});
for (const eventName of ['pointerup','pointercancel','lostpointercapture']) {
    topologyGraph.addEventListener(eventName, event => {
        if (topologyRoomDraw?.pointerId === event.pointerId) {
            const state=topologyRoomDraw; topologyRoomDraw=null; topologyEditorGesture=null;
            state.preview.remove();
            clearTopologyRoomDropPreview();
            if (eventName !== 'pointerup') return;
            const rect=document.querySelector('.topology-viewport').getBoundingClientRect();
            if (event.clientX<rect.left || event.clientX>rect.right || event.clientY<rect.top || event.clientY>rect.bottom) {
                setTopologySaveStatus('Raum außerhalb der Zeichenfläche verworfen','error'); return;
            }
            const point=topologySvgPoint(event.clientX,event.clientY); if (!point) return;
            const end=boundaryGridPoint(point); const left=Math.min(state.gridStart.x,end.x);
            const top=Math.min(state.gridStart.y,end.y);
            const width=Math.abs(end.x-state.gridStart.x),height=Math.abs(end.y-state.gridStart.y);
            if (width<2 || height<1) {
                setTopologySaveStatus('Raum zu klein – es wurde nichts gespeichert','error'); return;
            }
            const parent=topologyRoomParentForGridBounds({
                grid_x:left,grid_y:top,grid_width:width,grid_height:height
            });
            topologyToolMode='select'; updateTopologyRoomTool();
            showTopologyRoomPrompt({grid_x:left,grid_y:top,grid_width:width,grid_height:height},
                {x:event.clientX,y:event.clientY},parent ? Number(parent.id) : null);
            return;
        }
        if (topologyPan?.pointerId === event.pointerId) {
            if (eventName !== 'pointerup') {
                const {x,y,width,height}=topologyPan.box;
                topologyGraph.setAttribute('viewBox',`${x} ${y} ${width} ${height}`);
            }
            stopTopologyPan();
            saveTopologyCamera(topologyGraph);
        }
    });
}
document.querySelector('#topology-reset').addEventListener('click', () => {
    stopTopologyPan();
    topologyBaseViewBox=topologyFitViewBox(topologyRenderedNodes,topologyRooms);
    topologyGraph.setAttribute('viewBox',topologyBaseViewBox);
    saveTopologyCamera(topologyGraph);
});
document.querySelector('#topology-graph').addEventListener('wheel', event => {
    event.preventDefault();
    if (topologyEditorGesture) return;
    const svg = event.currentTarget;
    const box = svg.viewBox.baseVal;
    const baseWidth = Number(topologyBaseViewBox.split(' ')[2]);
    const width = Math.min(baseWidth*4,Math.max(baseWidth/20,box.width * (event.deltaY > 0 ? 1.1 : 0.9)));
    const scale = width/box.width;
    const point = new DOMPoint(event.clientX,event.clientY).matrixTransform(svg.getScreenCTM().inverse());
    svg.setAttribute('viewBox',`${point.x-(point.x-box.x)*scale} ${point.y-(point.y-box.y)*scale} ${width} ${box.height*scale}`);
    saveTopologyCamera(svg);
}, {passive:false});
