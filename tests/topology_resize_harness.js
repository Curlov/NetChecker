'use strict';

const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const script=fs.readFileSync(path.join(__dirname,'../web/static/topology.js'),'utf8');
const start=script.indexOf('function topologyRoomResizeLimits(room) {');
const end=script.indexOf('\nfunction topologyFitViewBox(',start);
assert.ok(start>=0 && end>start,'Room resize limits are available');

const roomBounds=room=>({x:room.grid_x*100,y:room.grid_y*100,
    width:room.grid_width*100,height:room.grid_height*100});
const context={
    topologyRooms:[],topologyRenderedNodes:[],
    topologyRoomPixelBounds:roomBounds,
    topologyRoomDescendantIds:()=>new Set(),
    topologyNodePixelBounds:node=>({left:node.x-20,right:node.x+20,
        top:node.y-20,bottom:node.y+65}),
    topologyPixelToGrid:(x,y)=>({gridColumn:Math.round(x/100),gridRow:Math.round(y/100)})
};
const limitsFor=vm.runInNewContext(script.slice(start,end)+'\ntopologyRoomResizeLimits',context);

const outer={id:6,grid_x:-86,grid_y:-10,grid_width:8,grid_height:6,
    device_ids:[22],manual_node_ids:[]};
const inner={id:7,parent_room_id:6,grid_x:-85,grid_y:-9,grid_width:6,grid_height:1,
    device_ids:[],manual_node_ids:[]};
context.topologyRooms=[outer,inner];
context.topologyRenderedNodes=[{x:-8500,y:-600,gridColumn:-85,gridRow:-6,device:{id:22}}];
context.topologyRoomDescendantIds=()=>new Set([7]);
const nestedLimits=limitsFor(outer);
assert.equal(nestedLimits.bottom,-5,
    'Neuer Raum can shrink to the cell boundary immediately below its last device');
assert.equal(nestedLimits.top,-10);
assert.equal(nestedLimits.left,-86);
assert.equal(nestedLimits.right,-78);
assert.equal(inner.grid_y+inner.grid_height+1,-7,
    'The inner room still reserves one whole grid cell of clearance');

context.topologyRenderedNodes=[];
const childOnlyLimits=limitsFor(outer);
assert.equal(childOnlyLimits.bottom,-7,
    'A child room reserves one grid cell when there is no lower device');

const deviceRoom={id:16,grid_x:-75,grid_y:-6,grid_width:3,grid_height:2,
    device_ids:[],manual_node_ids:[13]};
context.topologyRooms=[deviceRoom];
context.topologyRoomDescendantIds=()=>new Set();
context.topologyRenderedNodes=[{x:-7400,y:-600,gridColumn:-74,gridRow:-6,manual:{id:13}}];
assert.equal(limitsFor(deviceRoom).bottom,-5,
    'A manual node also allows the lower room edge directly at its cell boundary');

console.log('Room resizing: direct device and manual-node bounds, one-cell child-room clearance OK');
