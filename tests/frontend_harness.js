/* DOM behaviour checks with synthetic API responses. No sockets or browser. */
async function checkFrontend(source) {
    class Element {
        constructor(tagName = 'div') {
            this.tagName = tagName; this.style = {};
            this.children = []; this.dataset = {}; this.attributes = {}; this.value = '';
            this.textContent = ''; this.hidden = false; this.scrolls = 0;
            this.listeners = {}; this.captured = new Set();
            const classes = new Set();
            this.classList = {add:name => classes.add(name), remove:name => classes.delete(name),
                toggle:(name,yes) => yes ? classes.add(name) : classes.delete(name),
                contains:name => classes.has(name)};
        }
        replaceChildren(...items) {this.children = items;}
        append(...items) {this.children.push(...items);}
        appendChild(item) {this.children.push(item); return item;}
        add(item) {this.children.push(item); if (!this.value) this.value = item.value;}
        insertRow() {const row = new Element('tr'); row.cells = row.children; this.children.push(row); return row;}
        insertCell() {const cell = new Element('td'); this.children.push(cell); return cell;}
        createTHead() {const result = new Element('thead'); this.children.push(result); return result;}
        createTBody() {const result = new Element('tbody'); this.children.push(result); return result;}
        addEventListener(name,callback) {(this.listeners[name] ||= []).push(callback);}
        dispatch(name,properties={}) {
            const event = {target:this,currentTarget:this,button:0,pointerId:1,clientX:0,clientY:0,
                preventDefault(){},stopPropagation(){},...properties};
            for (const callback of this.listeners[name] || []) callback(event);
        }
        setPointerCapture(id) {this.captured.add(id);}
        hasPointerCapture(id) {return this.captured.has(id);}
        releasePointerCapture(id) {this.captured.delete(id); this.dispatch('lostpointercapture',{pointerId:id});}
        get viewBox() {
            const [x,y,width,height] = (this.attributes.viewBox || '0 0 1000 500').split(' ').map(Number);
            return {baseVal:{x,y,width,height}};
        }
        getScreenCTM() {
            const box = this.viewBox.baseVal;
            const scaleX = box.width/(parseFloat(this.style.width) || 1000);
            const scaleY = box.height/(parseFloat(this.style.height) || 500);
            return {inverse:() => ({transformPoint:point => ({x:box.x+point.x*scaleX,y:box.y+point.y*scaleY})})};
        }
        setAttribute(key,value) {this.attributes[key] = value;}
        getAttribute(key) {return this.attributes[key] ?? null;}
        removeAttribute(key) {delete this.attributes[key];}
        querySelectorAll(selector) {
            const descendants = this.children.flatMap(child => [child,...child.querySelectorAll('*')]);
            if (selector==='*') return descendants;
            if (selector==='details[data-change-key]') return descendants.filter(child => child.tagName==='details' && child.dataset.changeKey);
            return descendants.filter(child => child.dataset.deviceId);
        }
        scrollIntoView() {this.scrolls++;}
    }
    class Option extends Element {
        constructor(label,value) {super(); this.textContent = label; this.value = value;}
    }
    class URL {
        constructor(path) {this.path = path; this.params = {}; this.searchParams = {set:(key,value) => {this.params[key] = value;}};}
        toString() {return this.path + '?' + Object.entries(this.params).map(([key,value]) => `${key}=${value}`).join('&');}
    }
    class DOMPoint {
        constructor(x,y) {this.x=x; this.y=y;}
        matrixTransform(matrix) {return matrix.transformPoint(this);}
    }
    const elements = new Map();
    const document = {querySelector:selector => {
        if (!elements.has(selector)) elements.set(selector,new Element());
        return elements.get(selector);
    }, createElement:name => new Element(name), createElementNS:(_,name) => new Element(name)};
    document.querySelector('#network-select').value = '1';
    let detailRequests = 0;
    let topologyResponse = null;
    const device = {id:1,ip:'192.0.2.2',hostname:'synthetic',category:'unknown',presence:'present'};
    const fetch = async url => {
        let data;
        if (String(url).startsWith('/api/devices/1?')) {
            detailRequests++;
            data = {device, addresses:[{ip:device.ip}],ports:[],os_information:[],
                mac_analysis:{valid:true,unicast:true,locally_administered:false,hypotheses:[]},
                os_summary:{family:{value:'Linux',status:'suspected',source:'synthetic'}},
                os_claims:[],identity_candidates:[],interfaces:[],port_history:[],classification_history:[],changes:[],topology_hints:[],
                classification:{category:'apple_device',subtype:'iPhone / iPad / iOS-Gerät',confidence:70,score:60,
                    evidence_json:JSON.stringify([{reason:'TCP-Port 62078 ist offen; Apple-Mobilgerät möglich'}])}};
        } else if (String(url).startsWith('/api/devices?')) {
            data = {total:1,count:1,devices:[device]};
        } else if (String(url).startsWith('/api/topology?') && topologyResponse) {
            data = topologyResponse;
        } else {
            throw new Error('Unexpected synthetic request: '+String(url));
        }
        return {ok:true,json:async () => data};
    };
    const boot = 'loadNetworks().catch(error => {\n    setConnectionStatus(`API-Fehler: ${error.message}`);\n});';
    if (!source.includes(boot)) throw new Error('Frontend bootstrap changed; update harness');
    const api = new Function('document','fetch','setInterval','Option','URL','location','DOMPoint',
        source.replace(boot,'') + '\nreturn {renderDevices,showDevice,loadDevices,closeDeviceDetails,formatChange,renderChanges,formatEventTime,createLucideIcon,renderTopologyGraph,renderTopologyComparison,activateTopologyComparison,showTopology, setDevices(value){devices=value; deviceTotal=value.length;}, selected(){return selectedDeviceId;}};')
        (document,fetch,() => {},Option,URL,{origin:'http://synthetic'},DOMPoint);
    api.setDevices([device]); api.renderDevices();
    await api.showDevice(1);
    const assert = (condition,message) => {if (!condition) throw new Error(message);};
    assert(api.selected()==='1','Selection was not stored');
    api.renderDevices();
    assert(document.querySelector('#device-table').children[0].classList.contains('device-selected'),'Selection lost on rebuild');
    document.querySelector('#search').value = 'synthetic';
    await api.loadDevices();
    const categoryOptions = document.querySelector('#category-options');
    assert(categoryOptions.children.length===2,'Category menu did not preserve available types');
    assert(categoryOptions.children.every(button => button.children[0].children.some(child => child.tagName==='svg')),
        'Category menu choices lack Lucide icons');
    document.querySelector('#category-menu').open = true;
    categoryOptions.children[1].dispatch('click');
    assert(document.querySelector('#category-select').value==='unknown' &&
        !document.querySelector('#category-menu').open,'Category choice did not filter and close');
    document.querySelector('#category-options').children[0].dispatch('click');
    document.querySelector('#category-menu').open = true;
    document.querySelector('#category-menu').dispatch('keydown',{key:'Tab'});
    document.querySelector('#category-menu').dispatch('keydown',{key:'Escape'});
    assert(!document.querySelector('#category-menu').open,'Category menu does not close with Escape');
    assert(detailRequests===2,'Open details were not refreshed');
    assert(document.querySelector('#detail-panel').scrolls===1,'Automatic refresh scrolled the page');
    assert(document.querySelector('#search').value==='synthetic','Search filter lost');
    assert(document.querySelector('#detail-mac').children.length > 0,'MAC facts missing');
    assert(document.querySelector('#detail-os-summary').children.length > 0,'OS summary missing');
    const classificationReason = document.querySelector('#detail-classification').children.find(line =>
        line.children[0]?.textContent === 'Erkennungsgrund');
    assert(classificationReason?.children[1]?.textContent.includes('TCP-Port 62078'),
        'Classification evidence reason was not shown');
    api.closeDeviceDetails();
    assert(api.selected()===null && document.querySelector('#detail-panel').hidden,'Close did not reset selection');

    const port = {port:8000,protocol:'tcp',state:'open',service:'http-alt',product:null,version:null};
    const opened = {change_type:'PORT_OPENED',detected_at:'2026-01-15 10:00:00',old_value_json:null,
        new_value_json:JSON.stringify({ip:'192.0.2.2',port})};
    const closed = {...opened,change_type:'PORT_CLOSED',old_value_json:opened.new_value_json,new_value_json:null};
    const notOpen = {...closed,change_type:'PORT_NOT_OPEN'};
    assert(api.formatChange(opened).field==='TCP 8000 – http-alt','Port subject not readable');
    assert(api.formatChange(opened).design.tone==='positive','Opened port not positive');
    assert(api.formatChange(closed).after==='Geschlossen' && api.formatChange(closed).design.tone==='negative','Closed port not distinct');
    assert(api.formatChange(notOpen).after==='Nicht mehr offen' && api.formatChange(notOpen).design.tone==='warning','Filtered port incorrectly claimed closed');
    const service = {...opened,change_type:'SERVICE_CHANGED',old_value_json:JSON.stringify({port:{...port,version:'1'}}),
        new_value_json:JSON.stringify({port:{...port,version:'2'}})};
    assert(api.formatChange(service).before.includes('1') && api.formatChange(service).after.includes('2'),'Service changes lost');
    const ip = {...opened,change_type:'IP_CHANGED',old_value_json:'{"ip":"192.0.2.2"}',new_value_json:'{"ip":"192.0.2.3"}'};
    assert(api.formatChange(ip).before==='192.0.2.2' && api.formatChange(ip).after==='192.0.2.3','IP changes lost');
    assert(api.formatChange({...opened,change_type:'NEW_DEVICE'}).after==='Neu erkannt','NEW_DEVICE not recognized');
    const winter = api.formatEventTime(opened.detected_at);
    assert(winter.includes('15.01.2026') && winter.includes('11:00:00'),'SQLite UTC winter time not converted to German time');
    assert(api.formatEventTime('2026-07-15 10:00:00').includes('12:00:00'),'Summer time incorrect');
    assert(api.formatEventTime('not a date')==='not a date','Invalid time lost');
    assert(api.formatEventTime('2026-02-31 10:00:00')==='2026-02-31 10:00:00','Invalid calendar date normalized');
    const raw = '{"number":9007199254740993,"unknown":[{},null,false],"text":"<script>literal</script>"}';
    const generic = {...opened,change_type:'CUSTOM_EVENT',old_value_json:'broken JSON',new_value_json:raw};
    const changes = [opened,closed,notOpen,service,ip,generic];
    api.renderChanges(changes);
    const container = document.querySelector('#detail-changes');
    const table = container.children[0].children[0];
    const body = table.children[1];
    assert(body.children.length===changes.length,'One logical event produced multiple rows');
    const detailNodes = container.querySelectorAll('details[data-change-key]');
    assert(detailNodes.length===changes.length,'Expandable details missing');
    const rawPres = detailNodes[5].children.filter(child => child.tagName==='pre');
    assert(rawPres[0].textContent==='broken JSON' && rawPres[1].textContent===raw,'Stored JSON was altered, rounded or dropped');
    detailNodes[0].open = true; api.renderChanges(changes);
    assert(container.querySelectorAll('details[data-change-key]')[0].open,'Expanded details lost after refresh');
    const icon = api.createLucideIcon('circle-plus');
    assert(icon.getAttribute('stroke-width')===2 && icon.getAttribute('aria-hidden')==='true','Icon style/accessibility inconsistent');
    assert(icon.children[0].getAttribute('href')==='/static/vendor/lucide/sprite.svg?v=1.55.0-devices-1#circle-plus','Icon is not local Lucide');
    assert(icon.children[0].getAttribute('width')===24 && icon.children[0].getAttribute('height')===24,
        'Referenced symbol has no explicit dimensions');
    api.renderChanges([]);
    assert(container.children[0].textContent==='Keine Veränderungen erfasst.','Empty history broken');

    const neighbors = Array.from({length:64},(_,index) => ({device_id:index+1,ip:`192.0.2.${index+1}`,mac:null}));
    const classes = ['firewall_router','network_device','virtualization','server','workstation','apple_device',
        'voip_phone','printer','camera','power_device','single_board_computer','unknown'];
    const icons = ['router','network','boxes','server','monitor','monitor-smartphone','phone','printer',
        'camera','battery-charging','cpu','circle-question-mark'];
    api.setDevices(classes.map((category,index) => ({id:index+1,category,
        presence:index===0 ? 'present' : index===1 ? 'missing' : null})));
    api.renderTopologyGraph({snapshot:{network_id:1,id:1},links:[],neighbors});
    const graph = document.querySelector('#topology-graph');
    const classNodes = graph.children.filter(child => child.tagName==='g');
    for (let index=0;index<icons.length;index++) {
        const glyph = classNodes[index].children.find(child => child.tagName==='svg');
        assert(glyph.children[0].getAttribute('href')===`/static/vendor/lucide/sprite.svg?v=1.55.0-devices-1#${icons[index]}`,
            'Device category icon missing or incorrect');
        assert(glyph.getAttribute('width')===18 && glyph.getAttribute('stroke-width')===2,
            'Device icons have inconsistent dimensions');
    }
    assert(classNodes[0].getAttribute('class').includes('topology-status-present'),'Present device not green');
    assert(classNodes[1].getAttribute('class').includes('topology-status-missing'),'Missing device not red');
    assert(classNodes[2].getAttribute('class').includes('topology-status-unknown'),'Unknown status falsely claims reachability');
    assert(classNodes[0].getAttribute('aria-label').includes('Aktueller Inventarstatus'),'Current metadata confused with snapshot');
    const positions = graph.children.filter(child => child.tagName==='g').map(child => {
        const match = /translate\(([^,]+),([^)]+)\)/.exec(child.getAttribute('transform'));
        return {x:Number(match[1]),y:Number(match[2])};
    });
    assert(positions.length===64,'Topology nodes lost');
    const originalGap = 820/(Math.ceil(Math.sqrt(64*2))-1);
    for (let index=1;index<positions.length;index++) {
        if (positions[index].y===positions[index-1].y)
            assert(Math.abs(positions[index].x-positions[index-1].x-originalGap-14)<0.001,
                'Topology spacing does not retain the original grid with a small increment');
    }
    assert(parseFloat(graph.style.width)>1000 && parseFloat(graph.style.width)<1200,
        'Topology area became unnecessarily large');
    const initialBox = graph.viewBox.baseVal;
    const node = graph.children.find(child => child.tagName==='g');
    const initialNode = node.getAttribute('transform');
    graph.dispatch('pointerdown',{clientX:100,clientY:100});
    graph.dispatch('pointermove',{clientX:120,clientY:130});
    assert(graph.viewBox.baseVal.x===-20 && graph.viewBox.baseVal.y===-30,'Whole graph did not pan with background');
    graph.dispatch('pointermove',{clientX:130,clientY:150});
    assert(graph.viewBox.baseVal.x===-30 && graph.viewBox.baseVal.y===-50,'Panning drifted as viewBox changed');
    assert(node.getAttribute('transform')===initialNode,'Panning changed individual node positions');
    graph.dispatch('pointerup');
    assert(!graph.classList.contains('topology-panning'),'Drag cursor stuck');
    const movedBox = graph.getAttribute('viewBox');
    graph.dispatch('pointermove',{clientX:300,clientY:300});
    assert(graph.getAttribute('viewBox')===movedBox,'Pan continued after pointer release');
    api.renderTopologyGraph({snapshot:{network_id:1,id:1},links:[],neighbors});
    assert(graph.getAttribute('viewBox')===movedBox,'Refresh reset the panned view');
    const refreshedNode = graph.children.find(child => child.tagName==='g');
    graph.dispatch('pointerdown',{target:refreshedNode,clientX:100,clientY:100});
    graph.dispatch('pointermove',{clientX:150,clientY:150});
    assert(graph.getAttribute('viewBox')===movedBox,'Dragging a node also panned background');
    const beforeZoom = graph.viewBox.baseVal.width;
    graph.dispatch('wheel',{deltaY:-1,clientX:200,clientY:200});
    assert(graph.viewBox.baseVal.width<beforeZoom,'Zoom no longer works after pan');
    const separateNode = graph.children.find(child => child.tagName==='g');
    const positionBefore = separateNode.getAttribute('transform');
    separateNode.dispatch('pointerdown',{clientX:100,clientY:100});
    separateNode.dispatch('pointermove',{clientX:220,clientY:220});
    separateNode.dispatch('pointerup');
    assert(separateNode.getAttribute('transform')!==positionBefore,'Individual node drag broken');
    const checkGrid = () => {
        const slots = new Set();
        for (const child of graph.children.filter(child => child.tagName==='g')) {
            const match = /translate\(([^,]+),([^)]+)\)/.exec(child.getAttribute('transform'));
            const column = (Number(match[1])-90)/(originalGap+14);
            const row = (Number(match[2])-60)/(380/(Math.ceil(64/Math.ceil(Math.sqrt(64*2)))-1)+8);
            assert(Math.abs(column-Math.round(column))<0.000001 && Math.abs(row-Math.round(row))<0.000001,
                'Device did not snap to the original grid');
            const slot = `${Math.round(column)}:${Math.round(row)}`;
            assert(!slots.has(slot),'Snapping overlapped two devices'); slots.add(slot);
        }
    };
    checkGrid();
    separateNode.dispatch('keydown',{key:'ArrowRight'}); checkGrid();
    api.renderTopologyGraph({snapshot:{network_id:1,id:1},links:[],neighbors}); checkGrid();
    const freeNode = graph.children.find(child => child.tagName==='g');
    for (let step=0;step<20;step++) freeNode.dispatch('keydown',{key:'ArrowRight'});
    for (let step=0;step<10;step++) freeNode.dispatch('keydown',{key:'ArrowUp'});
    checkGrid();
    const freePosition = freeNode.getAttribute('transform');
    const freeMatch = /translate\(([^,]+),([^)]+)\)/.exec(freePosition);
    assert(Number(freeMatch[1])>parseFloat(graph.style.width) && Number(freeMatch[2])<0,
        'Devices are still confined to the original grid');
    api.renderTopologyGraph({snapshot:{network_id:1,id:1},links:[],neighbors}); checkGrid();
    assert(graph.children.find(child => child.tagName==='g').getAttribute('transform')===freePosition,
        'Refresh pulled a freely positioned device back into the initial layout');
    graph.dispatch('pointerdown',{clientX:100,clientY:100});
    graph.dispatch('pointercancel');
    assert(!graph.classList.contains('topology-panning'),'Cancelled pan retained cursor');
    document.querySelector('#topology-reset').dispatch('click');
    assert(graph.viewBox.baseVal.x===initialBox.x && graph.viewBox.baseVal.width===initialBox.width,'View reset broken');
    const link = {source_device_id:1,source_ip:'192.0.2.1',target_device_id:2,target_ip:'192.0.2.2',
        relation:'physical_neighbor',evidence_source:'synthetic',confidence:80,evidence_json:'{"test":true}'};
    const added = {...link,target_device_id:3,target_ip:'192.0.2.3'};
    const removed = {...link,target_device_id:4,target_ip:'192.0.2.4'};
    const changed = {before:link,after:{...link,confidence:90}};
    api.renderTopologyComparison({before:{id:1,created_at:'2026-01-15 10:00:00'},
        after:{id:2,created_at:'2026-01-15 11:00:00'},added:[added],removed:[removed],changed:[changed],
        interpretation:'Fehlende Beobachtung beweist keinen Ausfall'},
        {snapshot:{id:2,network_id:1},links:[added,changed.after],neighbors:[]});
    const comparison = document.querySelector('#topology-diff');
    const sections = comparison.children.filter(child => child.tagName==='section');
    assert(sections.length===3,'Comparison categories missing');
    for (const section of sections) {
        const details = section.children.find(child => child.tagName==='details');
        assert(details && details.children.some(child => child.tagName==='pre'),'Comparison evidence not expandable');
    }
    const lines = graph.children.filter(child => child.tagName==='line');
    for (const kind of ['added','removed','changed'])
        assert(lines.some(line => line.getAttribute('class').includes(`topology-comparison-${kind}`)),
            'Comparison marking missing: '+kind);
    topologyResponse = {snapshot:{id:2,network_id:1,status:'complete'},links:[added,changed.after],neighbors:[],segments:[]};
    document.querySelector('#topology-before').value = '1';
    document.querySelector('#topology-snapshot').value = '2';
    api.activateTopologyComparison({before:{id:1,created_at:'2026-01-15 10:00:00'},
        after:{id:2,created_at:'2026-01-15 11:00:00'},added:[added],removed:[removed],changed:[changed],
        interpretation:'Kein Ausfallnachweis'},topologyResponse);
    const retainedSection = comparison.children.find(child => child.tagName==='section');
    const retainedDetails = retainedSection.children.find(child => child.tagName==='details');
    retainedDetails.open = true;
    await api.showTopology();
    assert(comparison.children.includes(retainedSection) && retainedDetails.open,
        'Automatic topology refresh discarded comparison or expanded evidence');
    assert(graph.children.some(child => child.tagName==='line' && child.getAttribute('class').includes('topology-comparison-removed')),
        'Automatic refresh removed comparison markings');
    document.querySelector('#topology-before').value = '2';
    document.querySelector('#topology-before').dispatch('change');
    assert(comparison.children.length===0 && !graph.children.some(child => child.tagName==='line' &&
        child.getAttribute('class').includes('topology-comparison-')),'New snapshot choice kept obsolete comparison');
    api.setDevices([{id:99,category:'single_board_computer',mac:'88:A2:9E:90:EB:3D',presence:'present'}]);
    api.renderTopologyGraph({snapshot:{network_id:1,id:3},links:[],
        neighbors:[{device_id:null,ip:'192.0.2.99',mac:'88-a2-9e-90-eb-3d'}]});
    const pi = graph.children.find(child => child.tagName==='g');
    assert(pi.children.find(child => child.tagName==='svg').children[0].getAttribute('href').endsWith('#cpu'),
        'Raspberry Pi without historical device ID did not receive its class icon');
    return 'Frontend: Ereignisse, Lucide, Refresh, Verschieben, Zoom, Snapshot-Vergleich und Raspberry-Pi-Zuordnung OK';
}

if (typeof module !== 'undefined') module.exports = {checkFrontend};
if (typeof require !== 'undefined' && require.main === module) {
    const source = require('fs').readFileSync('web/static/app.js','utf8');
    checkFrontend(source).then(result => console.log(result)).catch(error => {console.error(error); process.exitCode = 1;});
}
