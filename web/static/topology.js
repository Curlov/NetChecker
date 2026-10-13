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
let topologyManualNodes = [];
let selectedManualNodeId = null;
let selectedTopologyNodeKey = null;
let topologyGridSpacing = {column: 0, row: 0};
let topologyLabelMaxWidth = 0;
let topologyMeasuredNodeBounds = null;
let topologyNodeYOffset = 0;
let topologyPaletteDrag = null;
let topologyPendingDrop = null;
let topologyContextAnchor = {x:24,y:24};
let topologyRooms = [];
let topologyRenderedNodes = [];
let topologyRoomShapeUpdates = new Map();
let selectedRoomId = null;
let topologyToolMode = 'select';
let topologyEditorGesture = null;
let topologyRoomDraw = null;
let topologyCameraInitialized = false;

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

async function loadTopology() {
    return loadInventoryTopology();
}

async function loadInventoryTopology({preserveGraphOnError=false} = {}) {
    const networkId = networkSelect.value;
    const requestId = ++topologyRequestId;
    const status = document.querySelector('#topology-status');
    const graph = document.querySelector('#topology-graph');
    document.querySelector('#topology-evidence').textContent = '';
    if (!networkId) {
        if (!preserveGraphOnError) graph.replaceChildren();
        status.textContent = 'Kein Netzwerk ausgewählt';
        topologyLayoutId = null;
        topologyManualNodes = [];
        topologyRooms = [];
        selectedManualNodeId = null;
        selectedRoomId = null;
        selectedTopologyNodeKey = null;
        setTopologySaveStatus('Kein Netzwerk ausgewählt');
        return;
    }
    status.textContent = 'Lade Geräte …';
    try {
        await loadDevices();
        if (requestId !== topologyRequestId || networkId !== networkSelect.value) return;
        let data = {links: [], neighbors: [], segments: []};
        try {
            data = await fetchJson(`/api/topology?network_id=${encodeURIComponent(networkId)}`);
        } catch (error) {
            if (error.message !== 'HTTP 404') throw error;
        }
        const layout = await fetchJson(`/api/topology/layout?network_id=${encodeURIComponent(networkId)}`);
        if (requestId !== topologyRequestId || networkId !== networkSelect.value) return;
        topologyManualNodes = layout.manual_nodes || [];
        topologyRooms = layout.rooms || [];
        renderTopologyGraph({...data, networkId, layout});
        setTopologySaveStatus(layout.layout ? 'Layout geladen' : 'Noch keine Positionen gespeichert',
            layout.layout ? 'saved' : '');
        status.textContent = `${devices.length} Geräte · aktueller Inventarstatus`;
        setConnectionStatus('API verbunden', true);
    } catch (error) {
        if (requestId !== topologyRequestId) return;
        graph.replaceChildren();
        status.textContent = `Topologie: ${error.message}`;
        setConnectionStatus(`API-Fehler: ${error.message}`, false);
    }
}


function renderTopologyGraph(data) {
    const svg = document.querySelector('#topology-graph');
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
    for (const position of data.layout?.positions || []) {
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
        else if (ip && !nodes.get(key).manual) nodes.get(key).label = ip;
        if (!nodes.get(key).device) nodes.get(key).device = deviceForNode(id,mac);
        return nodes.get(key);
    };
    for (const device of devices) getNode(device.id, device.ip, device.mac);
    for (const manual of (data.layout?.manual_nodes || [])) {
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
    const links = data.links.filter(link =>
        currentDevices.has(String(link.source_device_id)) &&
        currentDevices.has(String(link.target_device_id))).map(link => ({link,
        a:getNode(link.source_device_id,link.source_ip,null),
        b:getNode(link.target_device_id,link.target_ip,link.target_mac)}));
    const entries = [...nodes.values()];
    const columns = Math.max(1, Math.ceil(Math.sqrt(entries.length * 2)));
    const rows = Math.max(1, Math.ceil(entries.length / columns));
    // Keep saved integer cell coordinates and derive compact visual spacing
    // from the rendered reference label and status/icon bounds.
    const columnSpacing = measured.column;
    const rowSpacing = measured.row;
    const occupiedSlots = new Set();
    const reservedSlots = new Set();
    for (const manual of (data.layout?.manual_nodes || []).filter(node => node.linked_device_id != null)) {
        const restoredDevicePosition = topologyPositions.get(`device:${manual.linked_device_id}`);
        if (restoredDevicePosition && Number.isInteger(restoredDevicePosition.gridColumn) &&
            Number.isInteger(restoredDevicePosition.gridRow)) {
            reservedSlots.add(`${restoredDevicePosition.gridColumn}:${restoredDevicePosition.gridRow}`);
        }
    }
    entries.forEach((node, index) => {
        const defaultPoint=topologyGridToPixel(index % columns,Math.floor(index / columns),{nodeAnchor:true});
        node.x = defaultPoint.x;
        node.y = defaultPoint.y;
        const stored = topologyPositions.get(node.positionKey || node.key) || topologyPositions.get(node.key);
        if (stored && Number.isInteger(stored.gridColumn) && Number.isInteger(stored.gridRow)) {
            const storedPoint=topologyGridToPixel(stored.gridColumn,stored.gridRow,{nodeAnchor:true});
            node.x = storedPoint.x;
            node.y = storedPoint.y;
        } else if (stored) {
            node.x = stored.x; node.y = stored.y;
        }
        // The grid extends in every direction. Preserve positions outside the
        // initial layout on refresh instead of pulling devices back into it.
        Object.assign(node,topologyPixelToGrid(node.x,node.y,{nodeAnchor:true}));
    });
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
    const nodeExtents = entries.map(node => topologyNodePixelBounds(node));
    const roomExtents = topologyRooms.map(topologyRoomPixelBounds);
    const contentBounds = [
        ...nodeExtents.map(box => ({left:box.left,right:box.right,top:box.top,bottom:box.bottom})),
        ...roomExtents.map(box => ({left:box.x,right:box.right,top:box.y-TOPOLOGY_ROOM_TITLE_HEIGHT,bottom:box.bottom}))
    ];
    const contentLeft=contentBounds.length ? Math.min(...contentBounds.map(box => box.left)) : 0;
    const contentRight=contentBounds.length ? Math.max(...contentBounds.map(box => box.right)) : 1000;
    const contentTop=contentBounds.length ? Math.min(...contentBounds.map(box => box.top)) : 0;
    const contentBottom=contentBounds.length ? Math.max(...contentBounds.map(box => box.bottom)) : 500;
    const padding=28;
    const paddedWidth=Math.max(1,contentRight-contentLeft+padding*2);
    const paddedHeight=Math.max(1,contentBottom-contentTop+padding*2);
    const viewport=document.querySelector('.topology-viewport');
    const aspect=viewport.clientWidth > 0 && viewport.clientHeight > 0
        ? viewport.clientWidth/viewport.clientHeight : 2;
    const graphWidth=Math.max(paddedWidth,paddedHeight*aspect);
    const graphHeight=Math.max(paddedHeight,paddedWidth/aspect);
    const centerX=(contentLeft+contentRight)/2, centerY=(contentTop+contentBottom)/2;
    const viewX=centerX-graphWidth/2, viewY=centerY-graphHeight/2;
    topologyBaseViewBox = `${viewX} ${viewY} ${graphWidth} ${graphHeight}`;
    const savedCamera=contextChanged ? readTopologyCamera(context) : null;
    if (savedCamera) svg.setAttribute('viewBox',savedCamera);
    else if (!topologyCameraInitialized || !svg.getAttribute('viewBox'))
        svg.setAttribute('viewBox',topologyBaseViewBox);
    topologyCameraInitialized=true;
    saveTopologyCamera(svg);

    const setRoomShape = (group,room,rect,label) => {
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
    };
    for (const room of [...topologyRooms].sort((a,b) => topologyRoomDepth(a)-topologyRoomDepth(b) ||
        Number(a.id)-Number(b.id))) {
        const group = svgElement('g',{class:`topology-room${Number(room.id) === selectedRoomId ? ' topology-room-selected' : ''}`,
            'data-room-id':room.id,'aria-label':`Raum ${room.name}`});
        const rect = svgElement('rect',{class:'topology-room-shape',rx:2});
        const label = svgElement('text',{class:'topology-room-label'});
        group.append(rect,label);
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
                if (event.type !== 'pointerup') { setRoomShape(group,room,rect,label); return; }
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
                resizeState = {pointerId:event.pointerId,start:{...room},startPoint:point,next:null};
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
                if (grip.includes('w')) {
                    next.grid_width=Math.max(2,start.grid_width-dx);
                    next.grid_x=start.grid_x+start.grid_width-next.grid_width;
                }
                if (grip.includes('e')) next.grid_width=Math.max(2,start.grid_width+dx);
                if (grip.includes('n')) {
                    next.grid_height=Math.max(2,start.grid_height-dy);
                    next.grid_y=start.grid_y+start.grid_height-next.grid_height;
                }
                if (grip.includes('s')) next.grid_height=Math.max(2,start.grid_height+dy);
                resizeState.next=next; setRoomShape(group,next,rect,label);
            });
            for (const name of ['pointerup','pointercancel','lostpointercapture']) handle.addEventListener(name,finishResize);
        }
        setRoomShape(group,room,rect,label);
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
                for (const node of state.nodes)
                    node.element?.setAttribute('transform',`translate(${node.x},${node.y})`);
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
            for (const node of state.nodes)
                node.element?.setAttribute('transform',`translate(${shift.x},${shift.y}) translate(${node.x},${node.y})`);
            clearTopologyRoomDropPreview();
            void runTopologyAction(() => saveTopologyRoomGeometry(movedRoom,
                {...nextGeometry,parent_room_id:targetParentId,move_contents:true},
                state.nodes.length || state.descendantRooms.length
                    ? 'Raum und Inhalt verschoben' : 'Raum verschoben',restorePreview,() => {
                    group.removeAttribute('transform');
                    for (const child of state.descendantRooms) child.element?.removeAttribute('transform');
                    for (const node of state.nodes) {
                        node.gridColumn += dx; node.gridRow += dy;
                        const point=topologyGridToPixel(node.gridColumn,node.gridRow,{nodeAnchor:true});
                        node.x = point.x; node.y = point.y;
                    }
                    redraw();
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
            moveState={pointerId:event.pointerId,startPoint:point,nodes,room:currentRoom,
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
            for (const node of moveState.nodes)
                node.element?.setAttribute('transform',`translate(${dx},${dy}) translate(${node.x},${node.y})`);
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
    const redraw = () => {
        for (const edge of links) {
            for (const [key,value] of Object.entries({x1:edge.a.x,y1:edge.a.y,x2:edge.b.x,y2:edge.b.y})) edge.element.setAttribute(key,value);
        }
        for (const node of entries) {
            node.element.setAttribute('transform',`translate(${node.x},${node.y})`);
            Object.assign(node,topologyPixelToGrid(node.x,node.y,{nodeAnchor:true}));
            topologyPositions.set(node.positionKey || node.key,{
                x:node.x, y:node.y,
                gridColumn:node.gridColumn, gridRow:node.gridRow
            });
        }
    };
    const snapNode = (node,original,forceRoomAssignment=false) => {
        const target = topologyDropTargetAtPoint(node.x,node.y,reservedSlots);
        if (!target.valid) {
            node.x=original.x; node.y=original.y; redraw();
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
        if (occupant) {occupant.x=original.x; occupant.y=original.y;}
        node.x=x; node.y=y; redraw();
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
                redraw();
                await loadInventoryTopology({preserveGraphOnError:true});
                setTopologySaveStatus(`Nicht dauerhaft gespeichert: ${result.error}`,'error');
            });
    };
    for (const node of entries) {
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
        group.appendChild(label); svg.appendChild(group); node.element = group;
        fitTopologyNodeLabel(label,fullLabel,topologyLabelMaxWidth);
        const labelTitle = svgElement('title',{}); labelTitle.textContent = fullLabel; label.appendChild(labelTitle);
        let dragOrigin = null;
        let dragMoved = false;
        group.addEventListener('pointerdown', event => {
            if (event.button !== 0 || topologyEditorGesture) return;
            selectTopologyNode(node);
            closeTopologyContextMenu();
            dragOrigin = {x:node.x,y:node.y};
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
            if (!group.hasPointerCapture(event.pointerId)) return;
            const point = new DOMPoint(event.clientX,event.clientY).matrixTransform(svg.getScreenCTM().inverse());
            if (dragOrigin && Math.hypot(point.x-dragOrigin.x,point.y-dragOrigin.y) >= 1) dragMoved = true;
            node.x = point.x; node.y = point.y; redraw();
            const target = topologyDropTargetAtPoint(node.x,node.y,reservedSlots);
            setTopologyRoomDropPreview(target.valid ? target.room?.id ?? null : null);
        });
        const finishDrag = event => {
            if (!dragOrigin || event.pointerId !== topologyEditorGesture?.pointerId) return;
            const original=dragOrigin; dragOrigin=null;
            const moved=dragMoved; dragMoved=false;
            topologyEditorGesture = null;
            if (group.hasPointerCapture(event.pointerId)) group.releasePointerCapture(event.pointerId);
            clearTopologyRoomDropPreview();
            if (event.type !== 'pointerup') {
                node.x=original.x; node.y=original.y; redraw();
                return;
            }
            if (!moved) {node.x=original.x;node.y=original.y;redraw();return;}
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
}

async function topologyManualRequest(path, method, payload) {
    const headers = {};
    const apiKey = document.querySelector('#api-key').value;
    if (apiKey) headers['X-Netchecker-Key'] = apiKey;
    if (payload !== undefined) headers['Content-Type'] = 'application/json';
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
}

function topologyDeviceOptionLabel(device) {
    return [device.hostname,device.ip,device.mac].filter(Boolean).join(' · ') || `Gerät #${device.id}`;
}

function selectTopologyNode(node) {
    selectedTopologyNodeKey = node.key;
    selectedManualNodeId = node.manual ? Number(node.manual.id) : null;
    selectedRoomId = null;
    document.querySelectorAll('.topology-room-selected').forEach(group => group.classList.remove('topology-room-selected'));
    document.querySelectorAll('.topology-node').forEach(group => {
        group.classList.toggle('topology-node-selected',group.dataset.topologyKey === node.key);
    });
}

function selectTopologyRoom(room) {
    selectedRoomId = Number(room.id);
    selectedTopologyNodeKey = null;
    selectedManualNodeId = null;
    document.querySelectorAll('.topology-node-selected').forEach(group => group.classList.remove('topology-node-selected'));
    document.querySelectorAll('.topology-room').forEach(group => {
        group.classList.toggle('topology-room-selected',Number(group.dataset.roomId) === selectedRoomId);
    });
}

function clearTopologySelection() {
    selectedRoomId = null;
    selectedTopologyNodeKey = null;
    selectedManualNodeId = null;
    document.querySelectorAll('.topology-room-selected,.topology-node-selected').forEach(group => {
        group.classList.remove('topology-room-selected','topology-node-selected');
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
            const measured=node.element.getBBox();
            if (measured.width > 0 && measured.height > 0) box=measured;
        } catch (_) {}
    }
    box ||= topologyMeasuredNodeBounds;
    if (!box) throw new Error('Node-Maße sind für die Raumgeometrie nicht verfügbar.');
    return {left:node.x+box.x,right:node.x+box.x+box.width,
        top:node.y+box.y,bottom:node.y+box.y+box.height};
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
    document.querySelectorAll('.topology-room[data-room-id]').forEach(group => {
        group.classList.toggle('topology-room-drop-target',
            normalizedId !== null && Number(group.dataset.roomId) === normalizedId);
    });
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
    topologyMenuButton('Raum löschen',() => void runTopologyAction(async () => {
        await topologyManualRequest(`/api/topology/rooms/${room.id}?network_id=${encodeURIComponent(networkSelect.value)}`,'DELETE');
        if (selectedRoomId === Number(room.id)) selectedRoomId = null;
        setTopologySaveStatus('Raum gelöscht','saved'); await loadInventoryTopology();
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
    if (node.device) {
        topologyMenuButton('Gerätedetails öffnen',() => {
            closeTopologyContextMenu(); void showDevice(node.device.id,true);
        });
        topologyMenuButton('Geräte- und Scaninformationen anzeigen',() => {
            closeTopologyContextMenu(); void showDevice(node.device.id,false);
        },{secondary:true});
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

function topologySvgPoint(clientX,clientY) {
    const matrix = topologyGraph.getScreenCTM();
    return matrix ? new DOMPoint(clientX,clientY).matrixTransform(matrix.inverse()) : null;
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

const topologyPalette = document.querySelector('#topology-palette');
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
document.addEventListener('pointerup',event => finishTopologyPaletteDrag(event));
document.addEventListener('pointercancel',event => finishTopologyPaletteDrag(event,true));
document.addEventListener('pointerdown',event => {
    if (!topologyMenu().hidden && !topologyMenu().contains(event.target)) closeTopologyContextMenu();
});

function cancelTopologyGesture() {
    const gesture=topologyEditorGesture;
    if (!gesture) return false;
    if (gesture.type === 'palette-drag' && topologyPaletteDrag) {
        finishTopologyPaletteDrag(null,true);
        return true;
    }
    if (gesture.target && typeof PointerEvent !== 'undefined') {
        gesture.target.dispatchEvent(new PointerEvent('pointercancel',{
            bubbles:true,pointerId:gesture.pointerId,pointerType:'mouse'
        }));
    }
    return true;
}

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
        } else if (topologyEditorGesture) cancelTopologyGesture();
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
        topologyRoomDraw.preview.classList.toggle('topology-room-draw-invalid',width<2 || height<2);
        const parent=width>=2 && height>=2
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
            if (width<2 || height<2) {
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
    stopTopologyPan(); topologyGraph.setAttribute('viewBox',topologyBaseViewBox);
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
