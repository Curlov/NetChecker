'use strict';

const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const source=fs.readFileSync(path.join(__dirname,'../web/static/topology.js'),'utf8');
const start=source.indexOf('function selectTopologyLink(link) {');
const end=source.indexOf('\nfunction clearTopologySelection()',start);
assert.ok(start>=0 && end>start,'Connection selection functions are available');

function element(classes,linkId) {
    const names=new Set(classes);
    return {dataset:{linkId:String(linkId ?? '')},
        classList:{contains:name=>names.has(name),
            add:name=>names.add(name),remove:name=>names.delete(name),
            toggle:(name,enabled)=>enabled ? names.add(name) : names.delete(name)}};
}
const bent=element(['topology-manual-link'],1);
const straight=element(['topology-manual-link'],2);
const device=element(['topology-node']);
const graph={children:[bent,straight,device],
    insertBefore(item,before) {
        this.children.splice(this.children.indexOf(item),1);
        this.children.splice(this.children.indexOf(before),0,item);
    },
    appendChild(item) {
        this.children.splice(this.children.indexOf(item),1);
        this.children.push(item);
    }};
const document={querySelector:selector=>selector==='#topology-graph' ? graph : null,
    querySelectorAll:selector=>selector==='.topology-manual-link' ? [bent,straight] : []};
const context={document,selectedTopologyLinkId:null,selectedRoomId:null,
    selectedTopologyNodeKey:null,selectedManualNodeId:null,
    TOPOLOGY_LINK_TYPES:[['ethernet','Ethernet']],
    TOPOLOGY_EVIDENCE_LABELS:{manual_documented:'Manuell dokumentiert'},
    setTopologySaveStatus(){}};
const api=vm.runInNewContext(source.slice(start,end)+
    '\n({selectTopologyLink,raiseTopologyLinkToFront})',context);

api.selectTopologyLink({id:1,link_type:'ethernet',evidence_status:'manual_documented'});
assert.deepEqual(graph.children,[straight,bent,device],
    'The selected bent connection must paint above the overlapping connection');
assert.ok(bent.classList.contains('topology-manual-link-selected'));
assert.ok(!straight.classList.contains('topology-manual-link-selected'));

api.selectTopologyLink({id:2,link_type:'ethernet',evidence_status:'manual_documented'});
assert.deepEqual(graph.children,[bent,straight,device],
    'Changing selection moves the newly selected connection to the front');

graph.children=[straight,bent,device];
api.raiseTopologyLinkToFront(2);
assert.deepEqual(graph.children,[bent,straight,device],
    'Redrawing preserves the selected connection above other hit areas');

console.log('Topology connection selection: overlapping hit areas follow the selected link OK');
