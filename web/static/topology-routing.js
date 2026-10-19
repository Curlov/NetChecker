/* Orthogonal pixel router for exact canvas anchors; legacy grid checks remain available. */
(function (root) {
    'use strict';

    const pointKey = (x,y) => `${x}:${y}`;
    const stateKey = (x,y,direction,roomPhase=1,boundaryRun=0) =>
        `${x}:${y}:${direction}:${roomPhase}:${boundaryRun}`;
    const DIRECTIONS=[
        {x:1,y:0,id:0},{x:0,y:1,id:1},
        {x:-1,y:0,id:2},{x:0,y:-1,id:3}
    ];
    const directionId=direction=>direction
        ? DIRECTIONS.find(item=>item.x===direction.x && item.y===direction.y)?.id ?? 4
        : 4;
    const pointSet=points=>points instanceof Set ? new Set(points) : new Set(points.map(point=>
        typeof point==='string' ? point : Array.isArray(point)
            ? pointKey(point[0],point[1]) : pointKey(point.x,point.y)));

    function heapPush(heap,item,compare=(a,b)=>a.score-b.score) {
        let index=heap.length;
        heap.push(item);
        while (index>0) {
            const parent=(index-1)>>1;
            if (compare(heap[parent],item)<=0) break;
            heap[index]=heap[parent]; index=parent;
        }
        heap[index]=item;
    }

    function heapPop(heap,compare=(a,b)=>a.score-b.score) {
        if (!heap.length) return null;
        const first=heap[0], last=heap.pop();
        if (heap.length) {
            let index=0;
            while (true) {
                const left=index*2+1, right=left+1;
                if (left>=heap.length) break;
                const child=right<heap.length && compare(heap[right],heap[left])<0 ? right : left;
                if (compare(heap[child],last)>=0) break;
                heap[index]=heap[child]; index=child;
            }
            heap[index]=last;
        }
        return first;
    }

    function simplify(points) {
        const result=[];
        for (const point of points) {
            const previous=result[result.length-1];
            if (previous && previous.x===point.x && previous.y===point.y) continue;
            if (result.length>=2) {
                const before=result[result.length-2];
                if ((before.x===previous.x && previous.x===point.x) ||
                    (before.y===previous.y && previous.y===point.y)) {
                    result[result.length-1]=point;
                    continue;
                }
            }
            result.push(point);
        }
        return result;
    }

    function isOrthogonalPath(points) {
        return Array.isArray(points) && points.every((point,index)=>
            Number.isFinite(point?.x) && Number.isFinite(point?.y) && (index===0 ||
                points[index-1].x===point.x || points[index-1].y===point.y));
    }

    function orthogonalPathMetrics(points) {
        if (!isOrthogonalPath(points)) return null;
        let turns=0,length=0,previousAxis=null;
        for (let index=1;index<points.length;index++) {
            const from=points[index-1],to=points[index];
            if (from.x===to.x && from.y===to.y) continue;
            const axis=from.x===to.x ? 'y' : 'x';
            if (previousAxis && axis!==previousAxis) turns++;
            previousAxis=axis;
            length+=Math.abs(to.x-from.x)+Math.abs(to.y-from.y);
        }
        return {turns,length};
    }

    function chooseOrthogonalRoute(candidates) {
        return candidates.map(candidate=>({candidate,metrics:orthogonalPathMetrics(candidate.points)}))
            .filter(item=>item.metrics)
            .sort((a,b)=>a.metrics.turns-b.metrics.turns || a.metrics.length-b.metrics.length ||
                (a.candidate.opticalPenalty || 0)-(b.candidate.opticalPenalty || 0))
            [0]?.candidate || null;
    }

    function orthogonalAnchorLead(anchor,gridPoint,normal) {
        if (![anchor?.x,anchor?.y,gridPoint?.x,gridPoint?.y,normal?.x,normal?.y]
            .every(Number.isFinite) || Math.abs(normal.x)+Math.abs(normal.y)!==1) return null;
        const corner=normal.x ? {x:gridPoint.x,y:anchor.y} : {x:anchor.x,y:gridPoint.y};
        const points=simplify([anchor,corner,gridPoint]);
        if (!isOrthogonalPath(points) || points.length<2) return null;
        const first=points[1];
        const outward=(first.x-anchor.x)*normal.x+(first.y-anchor.y)*normal.y;
        return outward>0 ? points : null;
    }

    function joinOrthogonalRoute(sourceLead,gridRoute,targetLead) {
        if (!sourceLead?.length || !gridRoute?.length || !targetLead?.length) return null;
        const same=(a,b)=>a.x===b.x && a.y===b.y;
        if (!same(sourceLead.at(-1),gridRoute[0]) || !same(targetLead.at(-1),gridRoute.at(-1)))
            return null;
        const raw=[...sourceLead,...gridRoute.slice(1),...targetLead.slice(0,-1).reverse()];
        const before=orthogonalPathMetrics(raw);
        const points=simplify(raw);
        const after=orthogonalPathMetrics(points);
        return before && after && after.turns<=before.turns ? points : null;
    }

    function anchorRouteCandidates(source,target,{maxTurns=2,axes={x:[],y:[]},preferredAxis=null}={}) {
        if (![source?.x,source?.y,target?.x,target?.y].every(Number.isFinite) ||
            directionId(source.normal)===4 || directionId(target.normal)===4) return [];
        const start={x:source.x,y:source.y},end={x:target.x,y:target.y};
        const candidates=[],seen=new Set();
        const add=(points,opticalPenalty=0)=>{
            const path=simplify(points);
            if (path.length<2 || !isOrthogonalPath(path)) return;
            const metrics=orthogonalPathMetrics(path);
            if (metrics.turns>maxTurns) return;
            const first=path[1],last=path.at(-2);
            if ((first.x-start.x)*source.normal.x+(first.y-start.y)*source.normal.y<=0 ||
                (end.x-last.x)*target.normal.x+(end.y-last.y)*target.normal.y>=0) return;
            const key=path.map(point=>pointKey(point.x,point.y)).join('|');
            if (seen.has(key)) return;
            seen.add(key); candidates.push({points:path,opticalPenalty,metrics});
        };
        add([start,end]);
        add([start,{x:end.x,y:start.y},end]);
        add([start,{x:start.x,y:end.y},end]);
        if (maxTurns>1) {
            for (const axis of ['x','y']) {
                const midpoint=axis==='x' ? (start.x+end.x)/2 : (start.y+end.y)/2;
                const startAxis=axis==='x' ? start.x : start.y;
                const endAxis=axis==='x' ? end.x : end.y;
                for (const value of new Set([midpoint,Math.min(startAxis,endAxis)-8,
                    Math.max(startAxis,endAxis)+8,...(axes[axis] || [])])) {
                    if (!Number.isFinite(value)) continue;
                    const points=axis==='x'
                        ? [start,{x:value,y:start.y},{x:value,y:end.y},end]
                        : [start,{x:start.x,y:value},{x:end.x,y:value},end];
                    add(points,Math.abs(value-midpoint)+(preferredAxis && preferredAxis!==axis ? 0.01 : 0));
                }
            }
        }
        return candidates.sort((a,b)=>a.metrics.turns-b.metrics.turns ||
            a.metrics.length-b.metrics.length || a.opticalPenalty-b.opticalPenalty);
    }

    function routeCrossesRect(from,to,rect) {
        const left=rect.x,right=rect.x+rect.width,top=rect.y,bottom=rect.y+rect.height;
        if (from.y===to.y) return from.y>top && from.y<bottom &&
            Math.max(from.x,to.x)>left && Math.min(from.x,to.x)<right;
        return from.x>left && from.x<right &&
            Math.max(from.y,to.y)>top && Math.min(from.y,to.y)<bottom;
    }

    function routeFollowsRoomBoundary(from,to,rect,clearance={x:0,y:0}) {
        const left=rect.x,right=rect.x+rect.width,top=rect.y,bottom=rect.y+rect.height;
        const tooClose=(distance,minimum)=>distance<1e-9 || distance<minimum-1e-9;
        if (from.y===to.y &&
            Math.min(Math.max(from.x,to.x),right)-Math.max(Math.min(from.x,to.x),left)>1e-9)
            return tooClose(Math.abs(from.y-top),clearance.y) ||
                tooClose(Math.abs(from.y-bottom),clearance.y);
        if (from.x===to.x &&
            Math.min(Math.max(from.y,to.y),bottom)-Math.max(Math.min(from.y,to.y),top)>1e-9)
            return tooClose(Math.abs(from.x-left),clearance.x) ||
                tooClose(Math.abs(from.x-right),clearance.x);
        return false;
    }

    function advanceAnchorSegment(from,to,nodeRects,roomRects,startIds,endIds,phase,roomClearance) {
        if (nodeRects.some(({rect})=>routeCrossesRect(from,to,rect))) return null;
        if (roomRects.some(({rect})=>routeFollowsRoomBoundary(from,to,rect,roomClearance))) return null;
        const horizontal=from.y===to.y;
        const start=horizontal ? from.x : from.y,end=horizontal ? to.x : to.y;
        const cuts=[start,end];
        for (const {rect} of roomRects) {
            const low=horizontal ? rect.x : rect.y;
            const high=low+(horizontal ? rect.width : rect.height);
            if (low>Math.min(start,end) && low<Math.max(start,end)) cuts.push(low);
            if (high>Math.min(start,end) && high<Math.max(start,end)) cuts.push(high);
        }
        cuts.sort((a,b)=>start<=end ? a-b : b-a);
        for (let part=1;part<cuts.length;part++) {
            const middle=(cuts[part-1]+cuts[part])/2;
            const x=horizontal ? middle : from.x,y=horizontal ? from.y : middle;
            let inStart=false,inEnd=false;
            for (const {id,rect} of roomRects) {
                if (x<=rect.x || x>=rect.x+rect.width ||
                    y<=rect.y || y>=rect.y+rect.height) continue;
                if (!startIds.has(id) && !endIds.has(id)) return null;
                inStart ||= startIds.has(id);
                inEnd ||= endIds.has(id);
            }
            if (phase===0) phase=inStart ? 0 : inEnd ? 2 : 1;
            else if (phase===1) {
                if (inStart && !inEnd) return null;
                if (inEnd) phase=2;
            } else if (!inEnd) return null;
        }
        return phase;
    }

    function validAnchorRoute(points,nodeRects=[],roomRects=[],startIds=new Set(),endIds=new Set(),
        roomClearance={x:0,y:0}) {
        if (!isOrthogonalPath(points)) return false;
        let phase=startIds.size ? 0 : 1;
        for (let index=1;index<points.length;index++) {
            phase=advanceAnchorSegment(points[index-1],points[index],nodeRects,roomRects,
                startIds,endIds,phase,roomClearance);
            if (phase===null) return false;
        }
        return true;
    }

    function validEndpointDirections(points,source,target) {
        if (!isOrthogonalPath(points) || points.length<2) return false;
        const first=points[1],last=points.at(-2);
        return (first.x-source.x)*source.normal.x+(first.y-source.y)*source.normal.y>0 &&
            (target.x-last.x)*target.normal.x+(target.y-last.y)*target.normal.y<0;
    }

    function selfIntersects(points) {
        for (let i=1;i<points.length;i++) for (let j=i+2;j<points.length;j++) {
            const a=points[i-1],b=points[i],c=points[j-1],d=points[j];
            if (a.x===b.x && c.x===d.x) {
                if (a.x===c.x && Math.max(Math.min(a.y,b.y),Math.min(c.y,d.y))<=
                    Math.min(Math.max(a.y,b.y),Math.max(c.y,d.y))) return true;
            } else if (a.y===b.y && c.y===d.y) {
                if (a.y===c.y && Math.max(Math.min(a.x,b.x),Math.min(c.x,d.x))<=
                    Math.min(Math.max(a.x,b.x),Math.max(c.x,d.x))) return true;
            } else {
                const vertical=a.x===b.x ? [a,b] : [c,d];
                const horizontal=a.y===b.y ? [a,b] : [c,d];
                if (vertical[0].x>=Math.min(horizontal[0].x,horizontal[1].x) &&
                    vertical[0].x<=Math.max(horizontal[0].x,horizontal[1].x) &&
                    horizontal[0].y>=Math.min(vertical[0].y,vertical[1].y) &&
                    horizontal[0].y<=Math.max(vertical[0].y,vertical[1].y)) return true;
            }
        }
        return false;
    }

    function shiftOrthogonalSegment(points,index,coordinate,leadSize=12,
        {allowSelfIntersections=false}={}) {
        if (!isOrthogonalPath(points) || points.length<2 || !Number.isInteger(index) ||
            index<0 || index>=points.length-1 || !Number.isFinite(coordinate)) return null;
        const a=points[index],b=points[index+1];
        const horizontal=a.y===b.y && a.x!==b.x;
        const vertical=a.x===b.x && a.y!==b.y;
        if (!horizontal && !vertical) return null;
        const axis=horizontal ? 'x' : 'y',cross=horizontal ? 'y' : 'x';
        if (coordinate===a[cross]) return points.map(point=>({...point}));
        const distance=Math.abs(b[axis]-a[axis]);
        const lead=Math.min(Math.abs(leadSize),distance/4);
        if (lead<=0) return null;
        const direction=Math.sign(b[axis]-a[axis]);
        const first=index===0,last=index===points.length-2;
        const startStub={...a,[axis]:a[axis]+direction*lead};
        const endStub={...b,[axis]:b[axis]-direction*lead};
        const movedA={...(first ? startStub : a),[cross]:coordinate};
        const movedB={...(last ? endStub : b),[cross]:coordinate};
        const shifted=[...points.slice(0,index),...(first ? [a,startStub] : []),movedA,movedB,
            ...(last ? [endStub,b] : []),...points.slice(index+2)];
        const result=simplify(shifted);
        return isOrthogonalPath(result) && (allowSelfIntersections || !selfIntersects(result))
            ? result : null;
    }

    function snapSegmentCoordinate(initial,delta,origin,spacing) {
        if (![initial,delta,origin,spacing].every(Number.isFinite) || spacing<=0) return null;
        return origin+Math.round((initial+delta-origin)/spacing)*spacing;
    }

    function routeThroughWaypoints(source,target,waypoints,{nodeRects=[],roomRects=[],
        startIds=new Set(),endIds=new Set(),roomClearance={x:0,y:0},unrestricted=false}={}) {
        if (!Array.isArray(waypoints) || !waypoints.length || waypoints.length>128 ||
            !waypoints.every(point=>Number.isFinite(point?.x) && Number.isFinite(point?.y))) return null;
        const start={x:source.x,y:source.y},end={x:target.x,y:target.y};
        const fixed=waypoints.map(point=>({
            x:Math.abs(point.x-source.x)<1e-7 ? source.x :
                Math.abs(point.x-target.x)<1e-7 ? target.x : point.x,
            y:Math.abs(point.y-source.y)<1e-7 ? source.y :
                Math.abs(point.y-target.y)<1e-7 ? target.y : point.y
        }));
        const valid=points=>isOrthogonalPath(points) && (unrestricted ||
            !selfIntersects(points) && validEndpointDirections(points,source,target) &&
            validAnchorRoute(points,nodeRects,roomRects,startIds,endIds,roomClearance));
        const direct=simplify([start,...fixed,end]);
        if (valid(direct)) return direct;
        if (!isOrthogonalPath(fixed)) return null;
        const normals=DIRECTIONS.map(({x,y})=>({x,y}));
        const first=fixed[0],last=fixed.at(-1);
        const simpleLeads=(a,b)=>a.x===b.x || a.y===b.y ? [[a,b]] : [
            [a,{x:b.x,y:a.y},b],[a,{x:a.x,y:b.y},b]
        ];
        const starts=unrestricted ? simpleLeads(start,first) :
            normals.flatMap(normal=>anchorRouteCandidates(source,{...first,normal},
                {maxTurns:2}).slice(0,2).map(candidate=>candidate.points));
        const ends=unrestricted ? simpleLeads(last,end) :
            normals.flatMap(normal=>anchorRouteCandidates({...last,normal},target,
                {maxTurns:2}).slice(0,2).map(candidate=>candidate.points));
        const candidates=[];
        for (const lead of starts) for (const tail of ends) {
            const points=simplify([...lead,...fixed.slice(1,-1),...tail]);
            if (valid(points)) candidates.push({points});
        }
        return chooseOrthogonalRoute(candidates)?.points || null;
    }

    function routeOrthogonalPixels(source,target,{nodeRects=[],roomRects=[],
        startIds=new Set(),endIds=new Set(),roomClearance={x:0,y:0}}={}) {
        if (![source?.x,source?.y,target?.x,target?.y,source?.normal?.x,
            source?.normal?.y,target?.normal?.x,target?.normal?.y].every(Number.isFinite)) return null;
        const sourceDirection=directionId(source.normal);
        const targetDirection=directionId({x:-target.normal.x,y:-target.normal.y});
        if (sourceDirection===4 || targetDirection===4 ||
            source.x===target.x && source.y===target.y) return null;
        const xs=new Set([source.x,target.x,(source.x+target.x)/2,
            source.x-8,source.x+8,target.x-8,target.x+8]);
        const ys=new Set([source.y,target.y,(source.y+target.y)/2,
            source.y-8,source.y+8,target.y-8,target.y+8]);
        for (const {rect} of nodeRects) {
            xs.add(rect.x-4); xs.add(rect.x); xs.add(rect.x+rect.width);
            xs.add(rect.x+rect.width+4);
            ys.add(rect.y-4); ys.add(rect.y); ys.add(rect.y+rect.height);
            ys.add(rect.y+rect.height+4);
        }
        for (const {rect} of roomRects) {
            const left=rect.x,right=rect.x+rect.width,top=rect.y,bottom=rect.y+rect.height;
            for (const x of [left-roomClearance.x,left,left+roomClearance.x,
                right-roomClearance.x,right,right+roomClearance.x]) xs.add(x);
            for (const y of [top-roomClearance.y,top,top+roomClearance.y,
                bottom-roomClearance.y,bottom,bottom+roomClearance.y]) ys.add(y);
        }
        const columns=[...xs].sort((a,b)=>a-b),rows=[...ys].sort((a,b)=>a-b);
        const startX=columns.indexOf(source.x),startY=rows.indexOf(source.y);
        const endX=columns.indexOf(target.x),endY=rows.indexOf(target.y);
        const key=(x,y,direction,phase)=>`${x}:${y}:${direction}:${phase}`;
        const compareCost=(a,b)=>a.turns-b.turns || a.length-b.length;
        const compareHeap=(a,b)=>a.turns-b.turns || a.estimate-b.estimate;
        const heuristic=(x,y)=>Math.abs(target.x-columns[x])+Math.abs(target.y-rows[y]);
        const initialPhase=startIds.size ? 0 : 1;
        const firstKey=key(startX,startY,sourceDirection,initialPhase);
        const best=new Map([[firstKey,{turns:0,length:0}]]),previous=new Map();
        const open=[];
        heapPush(open,{x:startX,y:startY,direction:sourceDirection,phase:initialPhase,
            turns:0,length:0,estimate:heuristic(startX,startY),key:firstKey},compareHeap);
        while (open.length) {
            const current=heapPop(open,compareHeap);
            if (compareCost(current,best.get(current.key))!==0) continue;
            if (current.x===endX && current.y===endY) {
                const raw=[];
                for (let state=current.key;state;state=previous.get(state)) {
                    const [x,y]=state.split(':').map(Number);
                    raw.push({x:columns[x],y:rows[y]});
                }
                raw.reverse();
                const points=simplify(raw);
                const before=orthogonalPathMetrics(raw),after=orthogonalPathMetrics(points);
                return before && after && after.turns<=before.turns &&
                    validAnchorRoute(points,nodeRects,roomRects,startIds,endIds,roomClearance)
                    ? points : null;
            }
            const from={x:columns[current.x],y:rows[current.y]};
            for (const direction of DIRECTIONS) {
                if (current.length===0 && direction.id!==sourceDirection) continue;
                const x=current.x+direction.x,y=current.y+direction.y;
                if (x<0 || x>=columns.length || y<0 || y>=rows.length) continue;
                if (x===endX && y===endY && direction.id!==targetDirection) continue;
                const to={x:columns[x],y:rows[y]};
                const phase=advanceAnchorSegment(from,to,nodeRects,roomRects,
                    startIds,endIds,current.phase,roomClearance);
                if (phase===null) continue;
                const turns=current.turns+Number(current.direction!==direction.id);
                const length=current.length+Math.abs(to.x-from.x)+Math.abs(to.y-from.y);
                const nextKey=key(x,y,direction.id,phase);
                const prior=best.get(nextKey);
                if (prior && compareCost({turns,length},prior)>=0) continue;
                best.set(nextKey,{turns,length}); previous.set(nextKey,current.key);
                heapPush(open,{x,y,direction:direction.id,phase,turns,length,
                    estimate:length+heuristic(x,y),key:nextKey},compareHeap);
            }
        }
        return null;
    }

    function cellsOnPath(points) {
        const cells=[];
        for (let index=1;index<points.length;index++) {
            const start=points[index-1],end=points[index];
            const steps=Math.max(Math.abs(end.x-start.x),Math.abs(end.y-start.y));
            for (let step=0;step<=steps;step++) {
                const point={x:start.x+(end.x-start.x)*(steps ? step/steps : 0),
                    y:start.y+(end.y-start.y)*(steps ? step/steps : 0)};
                const key=pointKey(point.x,point.y);
                if (cells[cells.length-1]!==key) cells.push(key);
            }
        }
        if (points.length===1) cells.push(pointKey(points[0].x,points[0].y));
        return cells;
    }

    function createRoomContext(rooms,startRoomIds,endRoomIds) {
        if (!rooms?.length) return null;
        const startIds=new Set([...startRoomIds].map(String));
        const endIds=new Set([...endRoomIds].map(String));
        const contains=(room,x,y)=>room.useCells ? room.cells.has(pointKey(x,y)) : room.bounds &&
            x>=room.bounds.left && x<=room.bounds.right && y>=room.bounds.top && y<=room.bounds.bottom;
        const parsed=rooms.map(room=>{
            const cells=pointSet(room.cells || []);
            const hasBounds=Boolean(room.bounds);
            let bounds=room.bounds || null;
            if (!bounds && cells.size) {
                bounds={left:Infinity,right:-Infinity,top:Infinity,bottom:-Infinity};
                for (const key of cells) {
                    const [x,y]=key.split(':').map(Number);
                    bounds.left=Math.min(bounds.left,x); bounds.right=Math.max(bounds.right,x);
                    bounds.top=Math.min(bounds.top,y); bounds.bottom=Math.max(bounds.bottom,y);
                }
            }
            return {id:String(room.id),cells,bounds,useCells:!hasBounds && cells.size>0,
                isStart:startIds.has(String(room.id)),
                isEnd:endIds.has(String(room.id))};
        });
        const roomFlags=(x,y)=>{
            const owners=parsed.filter(room=>contains(room,x,y));
            return {blocked:owners.some(room=>!room.isStart && !room.isEnd),
                start:owners.some(room=>room.isStart),end:owners.some(room=>room.isEnd)};
        };
        return {roomFlags,
            roomBounds:parsed.map(room=>room.bounds).filter(Boolean)};
    }

    function initialRoomPhase(context,start) {
        if (!context) return 1;
        const flags=context.roomFlags(start.x,start.y);
        if (flags.blocked || flags.end && !flags.start) return null;
        return flags.start ? 0 : 1;
    }

    function advanceRoomPhase(context,phase,key) {
        if (!context) return phase;
        const [x,y]=key.split(':').map(Number);
        const flags=context.roomFlags(x,y);
        if (flags.blocked) return null;
        const startOnly=flags.start && !flags.end,endOnly=flags.end && !flags.start;
        if (phase===0) {
            if (flags.start) return 0;
            return endOnly ? 2 : 1;
        }
        if (phase===1) {
            if (startOnly) return null;
            return flags.end ? 2 : 1;
        }
        return flags.end ? 2 : null;
    }

    function roomPathAllowed(points,context) {
        if (!context) return true;
        let phase=initialRoomPhase(context,points[0]);
        if (phase===null) return false;
        for (const key of cellsOnPath(points).slice(1)) {
            phase=advanceRoomPhase(context,phase,key);
            if (phase===null) return false;
        }
        const end=context.roomFlags(points.at(-1).x,points.at(-1).y);
        return !end.end || end.start || phase===2;
    }

    function preferredAxisRoute(start,end,preferredAxis,{blocked,boundaries,margin,
        initialDirection,finalDirection,roomContext,maxTurns=Infinity}) {
        const reverse=id=>id<4 ? (id+2)%4 : 4;
        const inspect=points=>{
            if (!isOrthogonalPath(points)) return null;
            const routeCells=cellsOnPath(points);
            if (routeCells.some(key=>blocked.has(key)) || !roomPathAllowed(points,roomContext)) return null;

            let firstDirection=4,lastDirection=4,turns=0,previousDirection=4;
            for (let index=1;index<points.length;index++) {
                const direction=directionId({x:Math.sign(points[index].x-points[index-1].x),
                    y:Math.sign(points[index].y-points[index-1].y)});
                if (firstDirection===4) firstDirection=direction;
                if (previousDirection<4 && direction!==previousDirection) turns++;
                previousDirection=direction;
                lastDirection=direction;
            }
            if (initialDirection<4 && firstDirection===reverse(initialDirection)) return null;
            if (finalDirection<4 && lastDirection===reverse(finalDirection)) return null;
            if (turns>maxTurns) return null;
            const totalTurns=turns+
                Number(initialDirection<4 && firstDirection<4 && firstDirection!==initialDirection)+
                Number(finalDirection<4 && lastDirection<4 && lastDirection!==finalDirection);

            let boundaryRun=0,boundaryCells=0;
            for (let segment=1;segment<points.length;segment++) {
                const from=points[segment-1],to=points[segment];
                const steps=Math.max(Math.abs(to.x-from.x),Math.abs(to.y-from.y));
                let segmentBoundaryRun=0;
                for (let step=0;step<=steps;step++) {
                    const key=pointKey(from.x+(to.x-from.x)*(steps ? step/steps : 0),
                        from.y+(to.y-from.y)*(steps ? step/steps : 0));
                    if (boundaries.has(key)) {
                        segmentBoundaryRun++;
                        boundaryCells++;
                    } else segmentBoundaryRun=0;
                    boundaryRun=Math.max(boundaryRun,segmentBoundaryRun);
                }
            }
            if (boundaryRun>1) return null;

            const length=points.slice(1).reduce((sum,point,index)=>sum+
                Math.abs(point.x-points[index].x)+Math.abs(point.y-points[index].y),0);
            return {points,length,boundaryCells,turns,totalTurns,opticalPenalty:0};
        };
        const candidates=[];
        const direct=inspect(simplify([start,end]));
        if (direct) candidates.push(direct);
        const elbows=[
            simplify([start,{x:end.x,y:start.y},end]),
            simplify([start,{x:start.x,y:end.y},end])
        ].map(inspect).filter(Boolean);
        candidates.push(...elbows);
        const compare=(a,b)=>a.totalTurns-b.totalTurns || a.length-b.length ||
            a.boundaryCells-b.boundaryCells || a.opticalPenalty-b.opticalPenalty;
        candidates.sort(compare);
        if (maxTurns>1 && (!candidates.length || candidates[0].totalTurns>1)) {
            axisSearch: for (const axis of ['x','y']) {
                const startAxis=axis==='x' ? start.x : start.y;
                const endAxis=axis==='x' ? end.x : end.y;
                const origin=preferredAxis?.axis===axis && Number.isInteger(preferredAxis.value)
                    ? preferredAxis.value : Math.round((startAxis+endAxis)/2);
                const searchRadius=Math.max(margin,Math.ceil(Math.abs(endAxis-startAxis)/2)+margin);
                for (let distance=0;distance<=searchRadius;distance++) {
                    const coordinates=distance===0 ? [origin] : [origin-distance,origin+distance];
                    for (const coordinate of coordinates) {
                        const points=simplify(axis==='x'
                            ? [start,{x:coordinate,y:start.y},{x:coordinate,y:end.y},end]
                            : [start,{x:start.x,y:coordinate},{x:end.x,y:coordinate},end]);
                        const route=inspect(points);
                        if (!route) continue;
                        route.opticalPenalty=distance+Number(preferredAxis?.axis!==axis)*0.01;
                        candidates.push(route);
                        if (route.totalTurns===2 && route.length===
                            Math.abs(end.x-start.x)+Math.abs(end.y-start.y) &&
                            route.boundaryCells===0 && route.opticalPenalty===0) break axisSearch;
                    }
                }
            }
        }
        candidates.sort(compare);
        // If all simple paths need more than two complete bends, A* must be
        // allowed to find a better way through the anchor transitions.
        return candidates[0] && (maxTurns<=2 || candidates[0].totalTurns<=2)
            ? candidates[0].points : null;
    }

    function routeWithinBounds(start,end,blocked,boundaries,bounds,boundaryCost,
        startDirection,endDirection,roomContext) {
        // Encode turns, length, and boundary proximity as a lexicographic cost:
        // one fewer bend always wins over every possible shorter path in bounds.
        const area=(bounds.right-bounds.left+1)*(bounds.bottom-bounds.top+1);
        const maxPathLength=Math.max(1,area*30);
        const boundaryWeight=boundaryCost>0 ? 1 : 0;
        const lengthWeight=maxPathLength+1;
        const turnPenalty=maxPathLength*(lengthWeight+boundaryWeight)+1;
        const heuristic=(x,y) => (Math.abs(end.x-x)+Math.abs(end.y-y))*lengthWeight;
        const initialPhase=initialRoomPhase(roomContext,start);
        if (initialPhase===null) return null;
        const initialBoundaryRun=boundaries.has(pointKey(start.x,start.y)) ? 1 : 0;
        const startKey=stateKey(start.x,start.y,startDirection,initialPhase,initialBoundaryRun);
        const open=[];
        const best=new Map([[startKey,0]]);
        const previous=new Map();
        heapPush(open,{x:start.x,y:start.y,direction:startDirection,roomPhase:initialPhase,
            boundaryRun:initialBoundaryRun,key:startKey,cost:0,score:heuristic(start.x,start.y)});
        let finish=null;
        while (open.length) {
            if (finish && open[0].score>=finish.totalCost) break;
            const current=heapPop(open);
            if (current.cost!==best.get(current.key)) continue;
            if (current.x===end.x && current.y===end.y) {
                const endRoomFlags=roomContext?.roomFlags(end.x,end.y);
                if (endRoomFlags?.end && !endRoomFlags.start && current.roomPhase!==2) continue;
                if (endDirection<4 && current.direction===(endDirection+2)%4) continue;
                const terminalTurn=endDirection===4 || current.direction===endDirection ? 0 : turnPenalty;
                const totalCost=current.cost+terminalTurn;
                if (!finish || totalCost<finish.totalCost) finish={current,totalCost};
                continue;
            }
            for (const direction of DIRECTIONS) {
                if (current.key===startKey && startDirection<4 &&
                    direction.id===(startDirection+2)%4) continue;
                const x=current.x+direction.x, y=current.y+direction.y;
                if (x<bounds.left || x>bounds.right || y<bounds.top || y>bounds.bottom) continue;
                const pointKeyValue=pointKey(x,y);
                if (blocked.has(pointKeyValue)) continue;
                const roomPhase=advanceRoomPhase(roomContext,current.roomPhase,pointKeyValue);
                if (roomPhase===null) continue;
                const boundaryRun=boundaries.has(pointKeyValue) ? current.boundaryRun+1 : 0;
                if (boundaryRun>1) continue;
                const isTurn=current.direction!==4 && current.direction!==direction.id;
                const cost=current.cost+lengthWeight+(isTurn ? turnPenalty : 0)+
                    (boundaries.has(pointKeyValue) ? boundaryWeight : 0);
                const key=stateKey(x,y,direction.id,roomPhase,boundaryRun);
                if (cost>=(best.get(key) ?? Infinity)) continue;
                best.set(key,cost); previous.set(key,current.key);
                heapPush(open,{x,y,direction:direction.id,roomPhase,boundaryRun,key,cost,
                    score:cost+heuristic(x,y)});
            }
        }
        if (!finish) return null;
        const points=[];
        for (let key=finish.current.key;key;) {
            const [x,y]=key.split(':').map(Number);
            points.push({x,y});
            key=previous.get(key);
        }
        return simplify(points.reverse());
    }

    function routeOrthogonalGrid(start,end,{blockedCells=[],boundaryCells=[],roomCells=[],
        startRoomIds=[],endRoomIds=[],margin=12,
        boundaryCost=1.25,
        initialDirection=null,finalDirection=null,preferredAxis=null,maxTurns=Infinity}={}) {
        if (![start?.x,start?.y,end?.x,end?.y].every(Number.isInteger))
            throw new TypeError('Routing points must use integer grid coordinates');
        const blocked=pointSet(blockedCells);
        const boundaries=pointSet(boundaryCells);
        const roomContext=createRoomContext(roomCells,startRoomIds,endRoomIds);
        blocked.delete(pointKey(start.x,start.y)); blocked.delete(pointKey(end.x,end.y));
        const startDirection=directionId(initialDirection),endDirection=directionId(finalDirection);
        if (roomContext?.roomFlags(start.x,start.y).blocked ||
            roomContext?.roomFlags(end.x,end.y).blocked) return null;
        const preferred=preferredAxisRoute(start,end,preferredAxis,{blocked,boundaries,margin,
            initialDirection:startDirection,finalDirection:endDirection,
            roomContext,maxTurns});
        if (preferred) return preferred;
        if (maxTurns<=2) return null;
        const reach=margin*4;
        const relevantBounds={left:Math.min(start.x,end.x),right:Math.max(start.x,end.x),
            top:Math.min(start.y,end.y),bottom:Math.max(start.y,end.y)};
        const interestBounds={left:relevantBounds.left-reach,right:relevantBounds.right+reach,
            top:relevantBounds.top-reach,bottom:relevantBounds.bottom+reach};
        if (roomContext) for (const roomBounds of roomContext.roomBounds) {
            if (roomBounds.right<interestBounds.left || roomBounds.left>interestBounds.right ||
                roomBounds.bottom<interestBounds.top || roomBounds.top>interestBounds.bottom) continue;
            relevantBounds.left=Math.min(relevantBounds.left,roomBounds.left);
            relevantBounds.right=Math.max(relevantBounds.right,roomBounds.right);
            relevantBounds.top=Math.min(relevantBounds.top,roomBounds.top);
            relevantBounds.bottom=Math.max(relevantBounds.bottom,roomBounds.bottom);
        }
        const candidates=[];
        for (const padding of [margin,margin*2,margin*4]) {
            const bounds={left:relevantBounds.left-padding,right:relevantBounds.right+padding,
                top:relevantBounds.top-padding,bottom:relevantBounds.bottom+padding};
            const route=routeWithinBounds(start,end,blocked,boundaries,bounds,boundaryCost,
                startDirection,endDirection,roomContext);
            if (!route) continue;
            const routeCells=cellsOnPath(route);
            let turns=0,firstDirection=4,previousDirection=4,length=0;
            for (let index=1;index<route.length;index++) {
                const from=route[index-1],to=route[index];
                const direction=directionId({x:Math.sign(to.x-from.x),y:Math.sign(to.y-from.y)});
                if (firstDirection===4) firstDirection=direction;
                if (previousDirection<4 && direction!==previousDirection) turns++;
                previousDirection=direction;
                length+=Math.abs(to.x-from.x)+Math.abs(to.y-from.y);
            }
            const boundaryCells=routeCells.reduce((count,key)=>count+Number(boundaries.has(key)),0);
            const totalTurns=turns+
                Number(startDirection<4 && firstDirection<4 && firstDirection!==startDirection)+
                Number(endDirection<4 && previousDirection<4 && previousDirection!==endDirection);
            candidates.push({route,totalTurns,length,boundaryCells});
        }
        candidates.sort((a,b)=>a.totalTurns-b.totalTurns || a.length-b.length ||
            a.boundaryCells-b.boundaryCells);
        return candidates[0]?.route || null;
    }

    const api={routeOrthogonalGrid,isOrthogonalPath,orthogonalAnchorLead,joinOrthogonalRoute,
        anchorRouteCandidates,validAnchorRoute,routeOrthogonalPixels,
        orthogonalPathMetrics,chooseOrthogonalRoute,shiftOrthogonalSegment,snapSegmentCoordinate,
        routeThroughWaypoints,validEndpointDirections,selfIntersects};
    if (typeof module!=='undefined' && module.exports) module.exports=api;
    root.TopologyRouting=api;
})(typeof globalThis!=='undefined' ? globalThis : this);
