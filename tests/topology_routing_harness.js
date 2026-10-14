'use strict';

const assert=require('node:assert/strict');
const {routeOrthogonalGrid}=require('../web/static/topology-routing.js');
const {isOrthogonalPath,orthogonalAnchorLead,joinOrthogonalRoute,anchorRouteCandidates,validAnchorRoute,chooseOrthogonalRoute,
    orthogonalPathMetrics,routeOrthogonalPixels}=
    require('../web/static/topology-routing.js');

const route=(start,end,options)=>routeOrthogonalGrid(start,end,options);
const turns=points=>points.slice(2).reduce((count,point,index)=>{
    const previous=points[index+1],before=points[index];
    return count+Number((previous.x===before.x)!==(previous.x===point.x));
},0);
const visitedCells=points=>{
    const cells=new Set();
    for (let index=1;index<points.length;index++) {
        const from=points[index-1],to=points[index];
        const distance=Math.max(Math.abs(to.x-from.x),Math.abs(to.y-from.y));
        for (let step=0;step<=distance;step++) {
            const x=from.x+Math.sign(to.x-from.x)*step;
            const y=from.y+Math.sign(to.y-from.y)*step;
            cells.add(`${x}:${y}`);
        }
    }
    return cells;
};
const assertOrthogonal=(points,message)=>assert.ok(isOrthogonalPath(points),message);
const cellsInRect=(left,top,right,bottom)=>{
    const cells=[];
    for (let x=left;x<=right;x++) for (let y=top;y<=bottom;y++) cells.push([x,y]);
    return cells;
};
const blockOneTurnElbows=(start,end)=>{
    const blocked=[];
    if (start.y===end.y || start.x===end.x) return blocked;
    for (let y=Math.min(start.y,end.y)+1;y<Math.max(start.y,end.y);y++) blocked.push([end.x,y]);
    const midpoint=Math.round((start.x+end.x)/2),direction=Math.sign(end.x-start.x);
    for (let x=start.x+direction;x!==midpoint;x+=direction) blocked.push([x,end.y]);
    return blocked;
};

const direct=route({x:0,y:0},{x:10,y:0});
assert.deepEqual(direct,[{x:0,y:0},{x:10,y:0}]);
assert.equal(turns(direct),0);
assertOrthogonal(direct,'Direct route is orthogonal');

const blockedElbows=new Set(['4:1','4:2','4:3','1:4','2:4','3:4']);
assert.equal(route({x:0,y:0},{x:4,y:4},{blockedCells:blockedElbows,maxTurns:1}),null,
    'The fast pass stops after checking direct and one-bend paths');
const midpointFallback=route({x:0,y:0},{x:4,y:4},{blockedCells:blockedElbows});
assert.equal(turns(midpointFallback),2,
    'The full router still finds the centered two-bend fallback when one bend is blocked');
assertOrthogonal(midpointFallback,'The midpoint fallback remains orthogonal');

const chosenAutoSide=chooseOrthogonalRoute([
    {sourceSide:'top',targetSide:'left',points:[{x:0,y:0},{x:2,y:0},{x:2,y:2},{x:4,y:2}]},
    {sourceSide:'right',targetSide:'left',points:[{x:0,y:0},{x:9,y:0},{x:9,y:1},{x:9,y:7}]}
]);
assert.equal(chosenAutoSide.sourceSide,'right',
    'Automatic device anchors prefer a longer route when it removes an unnecessary bend');
assert.deepEqual(orthogonalPathMetrics(chosenAutoSide.points),{turns:1,length:16});
assert.equal(chooseOrthogonalRoute([{points:[{x:0,y:0},{x:1,y:1}]}]),null,
    'Automatic anchor selection refuses candidate routes containing diagonal segments');

const exactSource={x:17.25,y:31.5,normal:{x:1,y:0}};
const cornerTarget={x:86.75,y:72.25,normal:{x:0,y:-1}};
const exactOneBend=chooseOrthogonalRoute(anchorRouteCandidates(exactSource,cornerTarget));
assert.deepEqual(orthogonalPathMetrics(exactOneBend.points),{turns:1,length:110.25},
    'Fractional room anchors use one full-size bend instead of raster adapter hooks');
assert.deepEqual(exactOneBend.points[0],{x:exactSource.x,y:exactSource.y});
assert.deepEqual(exactOneBend.points.at(-1),{x:cornerTarget.x,y:cornerTarget.y});
const facingTarget={...cornerTarget,normal:{x:-1,y:0}};
const exactTwoBends=chooseOrthogonalRoute(anchorRouteCandidates(exactSource,facingTarget));
assert.equal(orthogonalPathMetrics(exactTwoBends.points).turns,2,
    'Facing room ports require exactly two bends, without short anchor hooks');
assertOrthogonal(exactTwoBends.points,'Exact room-anchor route has no diagonal transition');
const pixelObstacle=[{rect:{x:25,y:5,width:10,height:10}}];
assert.equal(validAnchorRoute([{x:10,y:10},{x:60,y:10}],pixelObstacle),false,
    'An exact-anchor shortcut cannot cross a device or its label');
assert.equal(validAnchorRoute([{x:10,y:10},{x:10,y:0},{x:60,y:0},{x:60,y:10}],pixelObstacle),true,
    'A two-bend exact-anchor detour remains available around a device');
const pixelRooms=[{id:1,rect:{x:0,y:0,width:20,height:20}},
    {id:2,rect:{x:30,y:0,width:20,height:20}}];
assert.equal(validAnchorRoute([{x:10,y:10},{x:40,y:10}],[],pixelRooms,new Set([1]),new Set()),false,
    'The exact-anchor shortcut cannot cut through a foreign room');
assert.equal(validAnchorRoute([{x:10,y:10},{x:10,y:-5},{x:40,y:-5},{x:40,y:10}],
    [],pixelRooms,new Set([1]),new Set([2])),true,
    'An exact-anchor route can leave its source room and enter its target room');
assert.deepEqual(chooseOrthogonalRoute([
    {points:[{x:0,y:0},{x:4,y:0},{x:4,y:4},{x:8,y:4}]},
    {points:[{x:0,y:0},{x:0,y:10},{x:8,y:10},{x:8,y:4}]}
]).points,[{x:0,y:0},{x:4,y:0},{x:4,y:4},{x:8,y:4}],
    'Among equally bent routes, the shorter complete path wins');

const obstacle=new Set(Array.from({length:7},(_,index)=>`${index+2}:0`));
const detour=route({x:0,y:0},{x:10,y:0},{blockedCells:obstacle});
assert.deepEqual(detour[0],{x:0,y:0});
assert.deepEqual(detour.at(-1),{x:10,y:0});
assert.equal(turns(detour),2,'A* selects the two-bend obstacle bypass before any longer zigzag');
for (let index=1;index<detour.length;index++)
    assert.ok(detour[index-1].x===detour[index].x || detour[index-1].y===detour[index].y,
        'Every segment is orthogonal');
for (const cell of visitedCells(detour)) assert.ok(!obstacle.has(cell),'Route avoids blocked cells');
assertOrthogonal(detour,'Obstacle detour has no diagonal steps');

const clearDirect=route({x:0,y:0},{x:10,y:0});
assert.deepEqual(clearDirect,[{x:0,y:0},{x:10,y:0}],
    'A clear connection takes the shortest direct route');

const anchored=route({x:0,y:0},{x:8,y:5},{initialDirection:{x:1,y:0}});
assert.ok(anchored[1].x>anchored[0].x && anchored[1].y===anchored[0].y,
    'An anchor lead continues outward without an immediate hook');
assertOrthogonal(anchored,'Anchor-constrained route is orthogonal');

const directed=route({x:0,y:0},{x:8,y:5},{
    initialDirection:{x:1,y:0},finalDirection:{x:-1,y:0}
});
assert.ok(directed[1].x>directed[0].x && directed[1].y===directed[0].y,
    'The source adapter does not reverse into its anchor');
const lastStep={x:Math.sign(directed.at(-1).x-directed.at(-2).x),
    y:Math.sign(directed.at(-1).y-directed.at(-2).y)};
assert.ok(!(lastStep.x===1 && lastStep.y===0),
    'The target adapter does not create a short reverse hook');
assert.ok(turns(directed)<=3,'Directed-anchor A* routing avoids unnecessary turns');
assertOrthogonal(directed,'Both directed anchor transitions remain orthogonal');

for (const normal of [{x:0,y:-1},{x:1,y:0},{x:0,y:1},{x:-1,y:0}]) {
    const gridPoint={x:normal.x ? normal.x*3 : 2,y:normal.y ? normal.y*3 : 2};
    const lead=orthogonalAnchorLead({x:0,y:0},gridPoint,normal);
    const first=lead[1];
    assert.ok((first.x*normal.x+first.y*normal.y)>0,
        `The ${normal.x},${normal.y} port lead initially exits in its defined direction`);
    assertOrthogonal(lead,'Each cardinal port lead is orthogonal');
}

const centered=route({x:0,y:0},{x:9,y:4},{preferredAxis:{axis:'x',value:5}});
assert.deepEqual(centered,[{x:0,y:0},{x:9,y:0},{x:9,y:4}],
    'A one-bend orthogonal route takes priority over the midpoint axis');
assert.equal(turns(centered),1,'A clear one-bend route avoids an unnecessary midpoint bend');

const verticalCentered=route({x:2,y:0},{x:5,y:9},{preferredAxis:{axis:'y',value:5}});
assert.deepEqual(verticalCentered,[{x:2,y:0},{x:5,y:0},{x:5,y:9}],
    'A one-bend vertical connection takes priority over the midpoint axis');
assert.equal(turns(verticalCentered),1,'A clear vertical route avoids an unnecessary midpoint bend');

const costlyBoundary=route({x:0,y:0},{x:8,y:0},{boundaryCells:[[4,0]],boundaryCost:1000});
assert.equal(turns(costlyBoundary),0,'A boundary proximity penalty cannot add a needless bend');

const misplacedAxis=route({x:0,y:0},{x:10,y:4},{preferredAxis:{axis:'x',value:20},
    blockedCells:blockOneTurnElbows({x:0,y:0},{x:10,y:4})});
assert.equal(turns(misplacedAxis),2,'A blocked one-bend route still needs only two bends');
assert.equal(orthogonalPathMetrics(misplacedAxis).length,14,
    'The router chooses the shortest two-bend path before a supplied visual midpoint');

const midpointBlocked=blockOneTurnElbows({x:0,y:0},{x:10,y:4});
const twoBendFallback=route({x:0,y:0},{x:10,y:4},{preferredAxis:{axis:'x',value:5},
    blockedCells:midpointBlocked});
assert.deepEqual(twoBendFallback,[{x:0,y:0},{x:5,y:0},{x:5,y:4},{x:10,y:4}],
    'The midpoint is used when both one-bend routes are obstructed');
assert.equal(turns(twoBendFallback),2,'The midpoint fallback uses exactly two turns');

const blockedElbowsAndAxis=[...blockOneTurnElbows({x:0,y:0},{x:10,y:4}),[5,2]];
const symmetricShifted=route({x:0,y:0},{x:10,y:4},{
    preferredAxis:{axis:'x',value:5},blockedCells:blockedElbowsAndAxis
});
const symmetricAxis=symmetricShifted.find((point,index)=>index>0 &&
    index<symmetricShifted.length-1 && symmetricShifted[index-1].x===point.x &&
    point.x!==0 && point.x!==10);
assert.ok(symmetricAxis && Math.abs(symmetricAxis.x-5)===1,
    'A blocked midpoint shifts by one grid cell to the nearest free axis');

const shifted=route({x:0,y:0},{x:10,y:4},{
    preferredAxis:{axis:'x',value:5},
    blockedCells:[...blockOneTurnElbows({x:0,y:0},{x:10,y:4}),[5,2]]
});
assert.ok(shifted.some(point=>point.x===4 || point.x===6),
    'A blocked midpoint moves to the nearest free grid axis');
assert.ok(turns(shifted)<=2,'The shifted midpoint route keeps a minimal number of turns');
assertOrthogonal(shifted,'Shifted midpoint route has no diagonal steps');

const sourceLead=orthogonalAnchorLead({x:0,y:0},{x:3,y:2},{x:1,y:0});
const targetLead=orthogonalAnchorLead({x:10,y:5},{x:8,y:3},{x:-1,y:0});
assert.deepEqual(sourceLead,[{x:0,y:0},{x:3,y:0},{x:3,y:2}],
    'A room-style anchor-to-grid adapter is orthogonal');
const joined=joinOrthogonalRoute(sourceLead,[{x:3,y:2},{x:8,y:2},{x:8,y:3}],targetLead);
assert.ok(joined,'Aligned anchor leads join the computed route');
assertOrthogonal(joined,'Complete anchor-to-anchor SVG route is orthogonal');
const pannedAndZoomed=joined.map(point=>({x:point.x*2+17,y:point.y*2-9}));
assertOrthogonal(pannedAndZoomed,'Uniform zoom and pan preserve orthogonal rendering');
assert.equal(isOrthogonalPath([{x:0,y:0},{x:1,y:1}]),false,
    'Diagonal pixel segments are rejected');
assert.equal(joinOrthogonalRoute(sourceLead,[{x:3,y:2},{x:4,y:3}],targetLead),null,
    'A diagonal computed segment is rejected instead of being drawn');

// A one-row room edge is half a placement cell away from an offset device icon.
// Connection routing must use the exact anchor coordinates without snapping.
const roomGrid={origin:{x:17,y:29},column:91,row:73,yOffset:11};
const oneRowTop=roomGrid.origin.y+1.5*roomGrid.row;
const oneRowRoomPort={x:roomGrid.origin.x+2.5*roomGrid.column,
    y:oneRowTop+roomGrid.row/2,normal:{x:1,y:0}};
const oneRowDevicePort={x:roomGrid.origin.x+4*roomGrid.column-16,
    y:roomGrid.origin.y+2*roomGrid.row+roomGrid.yOffset,normal:{x:-1,y:0}};
const oneRowRoute=chooseOrthogonalRoute(anchorRouteCandidates(oneRowRoomPort,oneRowDevicePort));
const oneRowMiddle=(oneRowRoomPort.x+oneRowDevicePort.x)/2;
assert.deepEqual(oneRowRoute.points,[
    {x:oneRowRoomPort.x,y:oneRowRoomPort.y},
    {x:oneRowMiddle,y:oneRowRoomPort.y},
    {x:oneRowMiddle,y:oneRowDevicePort.y},
    {x:oneRowDevicePort.x,y:oneRowDevicePort.y}
],'A one-grid-row room meets an offset device port with only two centered bends');
assert.equal(turns(oneRowRoute.points),2,'The half-grid room offset adds no extra turns');
const oneRowBounds={x:roomGrid.origin.x+roomGrid.column/2,y:oneRowTop,
    width:2*roomGrid.column,height:roomGrid.row};
const oneRowClearance={x:roomGrid.column/2,y:roomGrid.row/2};
const pixelOneRow=routeOrthogonalPixels(oneRowRoomPort,oneRowDevicePort,{
    roomRects:[{id:1,rect:oneRowBounds}],startIds:new Set([1]),
    roomClearance:oneRowClearance});
assert.deepEqual(pixelOneRow[0],{x:oneRowRoomPort.x,y:oneRowRoomPort.y},
    'Exact fractional anchors are routed without grid conversion');
assert.deepEqual(pixelOneRow.at(-1),{x:oneRowDevicePort.x,y:oneRowDevicePort.y});
assert.equal(turns(pixelOneRow),2,'A one-row room creates no extra raster-sized hook');
assert.ok(validAnchorRoute(pixelOneRow,[],[{id:1,rect:oneRowBounds}],new Set([1]),
    new Set(),oneRowClearance),
    'The exact-anchor route leaves its one-row room without following a room edge');
assertOrthogonal(pixelOneRow,'The pixel fallback remains orthogonal at fractional room ports');
const aroundDevice=routeOrthogonalPixels(
    {x:0,y:0,normal:{x:1,y:0}},
    {x:30,y:10,normal:{x:-1,y:0}},
    {nodeRects:[{rect:{x:10,y:-5,width:10,height:10}}]});
assert.ok(aroundDevice,'The pixel fallback finds a route around a device');
assert.equal(turns(aroundDevice),2,'The pixel fallback keeps two bends around a device obstacle');
assert.ok(validAnchorRoute(aroundDevice,[{rect:{x:10,y:-5,width:10,height:10}}]),
    'The pixel fallback does not cross a device obstacle');
assertOrthogonal(aroundDevice,'Every segment of the pixel obstacle detour is orthogonal');
const foreignRoom={id:2,rect:{x:24,y:0,width:20,height:20}};
const sourceRoom={id:1,rect:{x:0,y:0,width:20,height:20}};
const halfCellClearance={x:5,y:5};
assert.equal(validAnchorRoute([{x:22,y:-2},{x:46,y:-2}],[],[foreignRoom],
    new Set(),new Set(),halfCellClearance),false,
    'A parallel route two pixels from the room frame violates the half-cell clearance');
assert.equal(validAnchorRoute([{x:22,y:-5},{x:46,y:-5}],[],[foreignRoom],
    new Set(),new Set(),halfCellClearance),true,
    'A parallel route exactly half a cell from the room frame is allowed');
const nestedExitPixels=routeOrthogonalPixels(
    {x:10,y:10,normal:{x:1,y:0}},
    {x:55,y:10,normal:{x:-1,y:0}},
    {roomRects:[sourceRoom,foreignRoom],startIds:new Set([1]),
        roomClearance:halfCellClearance});
assert.ok(nestedExitPixels,'The pixel fallback can leave a source room around a foreign room');
assert.ok(validAnchorRoute(nestedExitPixels,[],[sourceRoom,foreignRoom],new Set([1]),
    new Set(),halfCellClearance),
    'The pixel fallback never cuts through or follows the foreign room');
assertOrthogonal(nestedExitPixels,'The nested room exit uses orthogonal segments');
const roomBounds=[{x:103.25,y:81.75,width:247.5,height:168.25},
    {x:477.5,y:279.25,width:207.25,height:149.5}];
const roomAnchor=(bounds,side)=>({
    top:{x:bounds.x+bounds.width/2,y:bounds.y},
    right:{x:bounds.x+bounds.width,y:bounds.y+bounds.height/2},
    bottom:{x:bounds.x+bounds.width/2,y:bounds.y+bounds.height},
    left:{x:bounds.x,y:bounds.y+bounds.height/2}
}[side]);
const roomNormal={top:{x:0,y:-1},right:{x:1,y:0},bottom:{x:0,y:1},left:{x:-1,y:0}};
for (const side of ['top','right','bottom','left']) {
    const anchor=roomAnchor(roomBounds[0],side),normal=roomNormal[side];
    const targetSide=({top:'bottom',right:'left',bottom:'top',left:'right'})[side];
    const targetAnchor=roomAnchor(roomBounds[1],targetSide),targetNormal=roomNormal[targetSide];
    const complete=routeOrthogonalPixels({...anchor,normal},{...targetAnchor,normal:targetNormal});
    assert.ok(complete,`The ${side} room connection has an exact-anchor route`);
    assert.deepEqual(complete[0],anchor);
    assert.deepEqual(complete.at(-1),targetAnchor);
    assertOrthogonal(complete,`The complete ${side} room-to-room pixel route is orthogonal`);
}

const enclosed=route({x:0,y:0},{x:2,y:2},{margin:0,
    blockedCells:[[1,0],[0,1],[1,1],[2,1],[1,2]]});
assert.equal(enclosed,null,
    'An impossible bounded route is omitted instead of crossing an obstacle');

const boundaryAvoided=route({x:0,y:0},{x:8,y:0},{
    boundaryCells:Array.from({length:9},(_,index)=>[index,0]),boundaryCost:1.25
});
assert.ok(boundaryAvoided.some(point=>point.y!==0),'A route can cross and then leave a room boundary');

const foreignCells=cellsInRect(4,-2,8,2);
const outsideRoute=route({x:0,y:0},{x:12,y:0},{
    roomCells:[{id:9,cells:foreignCells}],preferredAxis:{axis:'x',value:6}
});
assert.ok(outsideRoute,'A connection can route around a foreign room');
for (const cell of visitedCells(outsideRoute))
    assert.ok(!new Set(foreignCells.map(([x,y])=>`${x}:${y}`)).has(cell),
        'A connection never cuts through a foreign room when an outer route exists');
assertOrthogonal(outsideRoute,'The outer route around a foreign room remains orthogonal');

const tallForeignRoom=cellsInRect(4,-60,8,60);
const tallRoomRoute=route({x:0,y:0},{x:12,y:0},{
    roomCells:[{id:10,cells:tallForeignRoom}],preferredAxis:{axis:'x',value:6}
});
assert.ok(tallRoomRoute,'The search range expands past a large room to find an outer route');
const tallSet=new Set(tallForeignRoom.map(([x,y])=>`${x}:${y}`));
assert.ok([...visitedCells(tallRoomRoute)].every(cell=>!tallSet.has(cell)),
    'A large room cannot trap an otherwise routable connection inside the local search bounds');

const sourceRoomCells=cellsInRect(0,0,4,4);
const lowerRoomCells=cellsInRect(6,0,9,4);
const leaveSource=route({x:2,y:2},{x:12,y:2},{
    roomCells:[{id:1,cells:sourceRoomCells},{id:2,cells:lowerRoomCells}],
    startRoomIds:[1],preferredAxis:{axis:'x',value:7}
});
assert.ok(leaveSource,'A route can leave its endpoint room and pass around a lower foreign room');
const sourceSet=new Set(sourceRoomCells.map(([x,y])=>`${x}:${y}`));
const leaveCells=[...visitedCells(leaveSource)];
const firstOutside=leaveCells.findIndex(cell=>!sourceSet.has(cell));
assert.ok(firstOutside>=0,'The route exits its source room');
assert.ok(leaveCells.slice(firstOutside).every(cell=>!sourceSet.has(cell)),
    'After leaving the source room, the route does not re-enter it before the target');
const lowerSet=new Set(lowerRoomCells.map(([x,y])=>`${x}:${y}`));
assert.ok(leaveCells.every(cell=>!lowerSet.has(cell)),
    'The path avoids the lower room while leaving the upper room');

const parentCells=cellsInRect(0,0,10,8);
const nestedSourceCells=cellsInRect(2,2,4,4);
const siblingRoomCells=cellsInRect(6,1,9,6);
const nestedExit=route({x:3,y:3},{x:15,y:3},{
    roomCells:[{id:1,cells:parentCells},{id:2,cells:nestedSourceCells},
        {id:3,cells:siblingRoomCells}],
    startRoomIds:[1,2],preferredAxis:{axis:'x',value:9}
});
assert.ok(nestedExit,'An endpoint in a nested room can exit its room hierarchy');
const nestedCells=[...visitedCells(nestedExit)];
const parentSet=new Set(parentCells.map(([x,y])=>`${x}:${y}`));
const siblingSet=new Set(siblingRoomCells.map(([x,y])=>`${x}:${y}`));
assert.ok(nestedCells.every(cell=>!siblingSet.has(cell)),
    'Nested routing avoids sibling rooms that are not endpoint rooms');
const parentExit=nestedCells.findIndex(cell=>!parentSet.has(cell));
assert.ok(parentExit>=0 && nestedCells.slice(parentExit).every(cell=>!parentSet.has(cell)),
    'After leaving the outer source room, the route remains outside it');

const targetRoomCells=cellsInRect(8,0,12,4);
const enterTarget=route({x:0,y:2},{x:10,y:2},{
    roomCells:[{id:4,cells:targetRoomCells}],endRoomIds:[4]
});
assert.ok(enterTarget,'A route can enter a room containing its target');
const targetSet=new Set(targetRoomCells.map(([x,y])=>`${x}:${y}`));
const targetCells=[...visitedCells(enterTarget)];
const firstTarget=targetCells.findIndex(cell=>targetSet.has(cell));
assert.ok(firstTarget>=0 && targetCells.slice(firstTarget).every(cell=>targetSet.has(cell)),
    'After entering the target room, the route stays there until it reaches the target');
assertOrthogonal(enterTarget,'Room-constrained target approach remains orthogonal');

console.log('Orthogonal routing: exact anchors, minimal bends, obstacle and room avoidance OK');
