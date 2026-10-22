'use strict';

const assert=require('node:assert/strict');
const {pageDimensions,expandBounds,planPages,readability,CSS_PX_MM}= 
    require('../web/static/topology-export-layout.js');

const paper=pageDimensions('A4','landscape');
assert.deepEqual(paper,{width:297,height:210},'A4 landscape uses its physical dimensions');
assert.deepEqual(pageDimensions('A1','portrait'),{width:594,height:841},
    'A1 portrait uses its physical dimensions');

const bounds=expandBounds({x:-500,y:120,width:500,height:300},20,10);
assert.deepEqual(bounds,{x:-520,y:110,width:540,height:320},
    'One raster margin expands bounds in topology coordinates, including negative positions');

const single=planPages({x:-500,y:120,width:500,height:300},{
    format:'A4',orientation:'landscape',margin:'small',header:true,
    pagination:'one',scaling:'auto',scalePercent:100
});
assert.equal(single.pages.length,1,'A small topology fits onto one A4 landscape page');
assert.ok(single.usableWidth<297 && single.usableHeight<210,
    'Printable area accounts for 7 mm margins and the header');
assert.ok(single.mmPerUnit>0 && single.pages[0].x<=bounds.x+20,
    'Automatic scaling centers the plan in the physical page area');
assert.ok(single.pages[0].width+1e-9>=single.bounds.width && single.pages[0].height+1e-9>=single.bounds.height,
    'Single-page output contains all geometry without clipping');

const smallMargins=planPages({x:0,y:0,width:1000,height:500},{
    format:'A3',orientation:'landscape',margin:'small',header:false,
    pagination:'one',scaling:'auto',scalePercent:100
});
const zeroMargins=planPages({x:0,y:0,width:1000,height:500},{
    format:'A3',orientation:'landscape',margin:'none',header:false,
    pagination:'one',scaling:'auto',scalePercent:100
});
assert.ok(zeroMargins.usableWidth>smallMargins.usableWidth,
    '0 mm margins provide more width than 7 mm margins');

const tiled=planPages({x:-1000,y:-800,width:4500,height:2600},{
    format:'A3',orientation:'landscape',margin:'none',header:true,
    pagination:'multi',scaling:'auto',scalePercent:100
});
assert.ok(tiled.pages.length>1,'A large topology is distributed across multiple pages');
assert.ok(tiled.pages.every(page=>page.width===tiled.pages[0].width &&
    page.height===tiled.pages[0].height),
    'Every page uses the same topology scale and coordinate window');
assert.ok(tiled.overlapMm>0,'Adjacent plan pages include a small overlap');
assert.equal(tiled.pages[0].row,0);
assert.equal(tiled.pages[0].column,0);
assert.equal(tiled.pages[1].row,0,'Page numbering traverses rows from left to right');
assert.equal(tiled.pages[1].column,1);
const lastRight=Math.max(...tiled.pages.map(page=>page.x+page.width));
const lastBottom=Math.max(...tiled.pages.map(page=>page.y+page.height));
assert.ok(lastRight>=tiled.bounds.x+tiled.bounds.width,
    'The regular page grid covers geometry beyond the visible browser window');
assert.ok(lastBottom>=tiled.bounds.y+tiled.bounds.height,
    'The regular page grid covers the final row without leaving a gap');
assert.ok(tiled.pages.some(page=>page.x<0 || page.y<0),
    'Multi-page coordinates preserve objects outside the positive canvas area');

const custom=planPages({x:0,y:0,width:5000,height:2500},{
    format:'A2',orientation:'portrait',margin:'small',header:true,
    pagination:'multi',scaling:'manual',scalePercent:125
});
assert.equal(custom.scalePercent,125,'Manual scaling is independent of browser zoom');
assert.ok(custom.columns>1 && custom.rows>1,
    'Manual scale produces a regular multi-row, multi-column page grid');
const clamped=planPages({x:0,y:0,width:5000,height:2500},{
    format:'A4',orientation:'portrait',margin:'none',header:true,
    pagination:'one',scaling:'manual',scalePercent:100
});
assert.equal(clamped.pages.length,1,'Single-page mode always remains one page');
assert.equal(clamped.clampedToSinglePage,true,
    'A manual scale that would crop a single page is bounded with an explicit state');
assert.ok(clamped.scalePercent<100);

assert.ok(Math.abs(readability(12,CSS_PX_MM).points-9)<1e-9,
    'Font size is converted from CSS pixels to final PDF points');
assert.equal(readability(12,CSS_PX_MM).rating,'good');
assert.equal(readability(10,CSS_PX_MM).rating,'limited');
assert.equal(readability(8,CSS_PX_MM).rating,'critical');

console.log('Topology PDF layout: physical page sizes, margins, vector scale, readability, centered fit, and full multi-page coordinate coverage OK');

// Interactive framing uses the same camera for preview and printable pages.
const {frameDimensions,planViewportPages,fitCamera,reframeCamera,panCamera,zoomCamera}=
    require('../web/static/topology-export-layout.js');
const near=(actual,expected,message)=>assert.ok(Math.abs(actual-expected)<1e-8,message);
const frameSettings=Object.freeze({format:'A3',orientation:'landscape',margin:'none',
    header:true,pagination:'one',columns:2,rows:1});
const currentView=Object.freeze({x:-1200,y:250,width:1400,height:700});
const initialCamera=Object.freeze(fitCamera(currentView,frameSettings));
const firstFrame=planViewportPages(initialCamera,frameSettings);
assert.equal(firstFrame.pages.length,1,'The current view starts with one fixed paper frame');
near(firstFrame.bounds.x+firstFrame.bounds.width/2,currentView.x+currentView.width/2,
    'Opening the editor preserves the horizontal center of the current topology view');
near(firstFrame.bounds.y+firstFrame.bounds.height/2,currentView.y+currentView.height/2,
    'Opening the editor preserves the vertical center of the current topology view');
assert.ok(firstFrame.bounds.width+1e-9>=currentView.width && firstFrame.bounds.height+1e-9>=currentView.height,
    'Adapting the current view to the paper ratio initially includes the visible topology');

const moved=panCamera(initialCamera,{x:18,y:-12});
near((initialCamera.x-moved.x)*moved.mmPerUnit,18,'Dragging right moves the plan right by the physical pointer distance');
near((initialCamera.y-moved.y)*moved.mmPerUnit,-12,'Dragging upwards moves the plan up');
assert.equal(moved.mmPerUnit,initialCamera.mmPerUnit,'Panning never changes the export scale');

const anchor={x:-400,y:500};
const zoomed=zoomCamera(initialCamera,2,anchor);
near((anchor.x-zoomed.x)*zoomed.mmPerUnit,(anchor.x-initialCamera.x)*initialCamera.mmPerUnit,
    'Wheel zoom keeps the world point under the pointer horizontally fixed');
near((anchor.y-zoomed.y)*zoomed.mmPerUnit,(anchor.y-initialCamera.y)*initialCamera.mmPerUnit,
    'Wheel zoom keeps the world point under the pointer vertically fixed');
const zoomedFrame=planViewportPages(zoomed,frameSettings);
assert.deepEqual(zoomedFrame.paper,firstFrame.paper,'Wheel zoom never enlarges the physical paper frame');
near(zoomedFrame.pages[0].width,firstFrame.pages[0].width/2,
    'Zooming into a single page selects a smaller crop without auto-fitting it back out');
const restored=zoomCamera(zoomed,.5,anchor);
near(restored.x,initialCamera.x,'Inverse zoom restores the original horizontal crop');
near(restored.y,initialCamera.y,'Inverse zoom restores the original vertical crop');

const portraitSettings={...frameSettings,orientation:'portrait',margin:'small',header:false};
const portraitCamera=reframeCamera(zoomed,frameSettings,portraitSettings);
const portraitFrame=planViewportPages(portraitCamera,portraitSettings);
assert.deepEqual(portraitFrame.paper,{width:297,height:420},'The visible paper frame changes to portrait dimensions');
assert.equal(portraitCamera.mmPerUnit,zoomed.mmPerUnit,'Orientation, margins and header changes preserve the chosen scale');
near(portraitFrame.bounds.x+portraitFrame.bounds.width/2,zoomedFrame.bounds.x+zoomedFrame.bounds.width/2,
    'Changing page settings keeps the chosen plan center horizontally');
near(portraitFrame.bounds.y+portraitFrame.bounds.height/2,zoomedFrame.bounds.y+zoomedFrame.bounds.height/2,
    'Changing page settings keeps the chosen plan center vertically');

const gridSettings={...frameSettings,pagination:'multi',columns:3,rows:2};
const gridCamera=fitCamera({x:-2500,y:-1800,width:8000,height:4500},gridSettings);
const grid=planViewportPages(gridCamera,gridSettings);
assert.equal(grid.pages.length,6,'A fixed three-by-two frame produces exactly six PDF pages');
assert.deepEqual(grid.pages.map(page=>[page.row,page.column]),[[0,0],[0,1],[0,2],[1,0],[1,1],[1,2]],
    'Frames and exported pages share row-major order');
assert.ok(grid.pages.every(page=>page.width===grid.pages[0].width && page.height===grid.pages[0].height),
    'Every interactive frame uses exactly the same scale');
near((grid.pages[0].x+grid.pages[0].width-grid.pages[1].x)*grid.mmPerUnit,8,
    'Neighbouring columns overlap by exactly eight physical millimetres');
near((grid.pages[0].y+grid.pages[0].height-grid.pages[3].y)*grid.mmPerUnit,8,
    'Neighbouring rows overlap by exactly eight physical millimetres');
assert.ok(grid.bounds.x<=-2500 && grid.bounds.x+grid.bounds.width>=5500 &&
    grid.bounds.y<=-1800 && grid.bounds.y+grid.bounds.height>=2700,
    'Fit all includes negative and offscreen geometry in the complete frame grid');
assert.equal(frameDimensions({...gridSettings,columns:999,rows:999}).columns,8,
    'Page-grid input has a bounded allocation size');
console.log('Interactive PDF framing: pointer-anchored zoom, pan, crop, portrait, center preservation and shared tiled geometry OK');

for (const format of ['A4','A3','A2','A1']) for (const orientation of ['portrait','landscape']) {
    const zero=frameDimensions({...frameSettings,format,orientation,margin:'none',header:false});
    const seven=frameDimensions({...frameSettings,format,orientation,margin:'small',header:false});
    assert.equal(zero.margin,0,'Borderless export has exactly zero margin');
    assert.equal(zero.usableWidth,zero.paper.width,'Borderless content reaches both horizontal paper edges');
    assert.equal(zero.usableHeight,zero.paper.height,'Borderless content reaches both vertical paper edges');
    assert.equal(seven.usableWidth,zero.usableWidth-14,'Seven millimetres are reserved on both sides');
    assert.equal(seven.usableHeight,zero.usableHeight-14,'Seven millimetres are reserved above and below');
}
console.log('PDF margins: zero and seven millimetres in all formats and orientations OK');
