(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.TopologyExportLayout = api;
})(typeof globalThis === 'object' ? globalThis : this, function () {
    'use strict';

    const CSS_PX_MM = 25.4 / 96;
    const PAPER_MM = Object.freeze({
        A4: Object.freeze({width:210,height:297}),
        A3: Object.freeze({width:297,height:420}),
        A2: Object.freeze({width:420,height:594}),
        A1: Object.freeze({width:594,height:841})
    });

    function pageDimensions(format, orientation) {
        const source = PAPER_MM[format];
        if (!source) throw new RangeError(`Unbekanntes Papierformat: ${format}`);
        const landscape = orientation === 'landscape';
        return landscape
            ? {width:source.height,height:source.width}
            : {width:source.width,height:source.height};
    }

    function expandBounds(bounds, horizontal, vertical = horizontal) {
        const x = Number(bounds?.x), y = Number(bounds?.y);
        const width = Number(bounds?.width), height = Number(bounds?.height);
        if (![x,y,width,height,horizontal,vertical].every(Number.isFinite) ||
            width < 0 || height < 0 || horizontal < 0 || vertical < 0)
            throw new RangeError('Ungültige Topologiebegrenzungen oder Abstände');
        return {x:x-horizontal,y:y-vertical,width:width+horizontal*2,height:height+vertical*2};
    }

    function planPages(bounds, settings) {
        const paper = pageDimensions(settings.format,settings.orientation);
        const margin = settings.margin === 'small' ? 7 : 0;
        const headerHeight = settings.header ? 12 : 0;
        const usableWidth = paper.width - 2*margin;
        const usableHeight = paper.height - 2*margin - headerHeight;
        if (!(usableWidth > 0 && usableHeight > 0))
            throw new RangeError('Papierformat bietet keine nutzbare Fläche');
        const safeBounds = {
            x:Number(bounds.x),y:Number(bounds.y),
            width:Math.max(1,Number(bounds.width)),height:Math.max(1,Number(bounds.height))
        };
        if (![safeBounds.x,safeBounds.y,safeBounds.width,safeBounds.height].every(Number.isFinite))
            throw new RangeError('Topologiebereich ist ungültig');

        const fitMmPerUnit = Math.min(usableWidth/safeBounds.width,usableHeight/safeBounds.height);
        const fitPercent = fitMmPerUnit / CSS_PX_MM * 100;
        const customPercent = Math.max(1,Math.min(1000,Number(settings.scalePercent) || 100));
        let scalePercent = settings.scaling === 'manual' ? customPercent :
            settings.pagination === 'multi' ? 100 : fitPercent;
        let clampedToSinglePage = false;
        if (settings.pagination !== 'multi' && scalePercent > fitPercent) {
            scalePercent = fitPercent;
            clampedToSinglePage = settings.scaling === 'manual';
        }
        const mmPerUnit = CSS_PX_MM * scalePercent / 100;
        const tileWidth = usableWidth / mmPerUnit;
        const tileHeight = usableHeight / mmPerUnit;
        const overlapMm = settings.pagination === 'multi' ? 8 : 0;
        const minimumOverlapUnits = overlapMm/mmPerUnit;
        const overlapX = settings.pagination === 'multi'
            ? Math.min(tileWidth*0.2,Math.max(minimumOverlapUnits,Number(settings.overlapXUnits)||0)) : 0;
        const overlapY = settings.pagination === 'multi'
            ? Math.min(tileHeight*0.2,Math.max(minimumOverlapUnits,Number(settings.overlapYUnits)||0)) : 0;
        const stepX = Math.max(1,tileWidth-overlapX);
        const stepY = Math.max(1,tileHeight-overlapY);
        const columns = settings.pagination === 'multi'
            ? Math.max(1,Math.ceil(Math.max(0,safeBounds.width-tileWidth)/stepX)+1) : 1;
        const rows = settings.pagination === 'multi'
            ? Math.max(1,Math.ceil(Math.max(0,safeBounds.height-tileHeight)/stepY)+1) : 1;
        const pages = [];
        for (let row=0;row<rows;row++) for (let column=0;column<columns;column++) {
            pages.push({
                index:pages.length+1,row,column,
                x:settings.pagination === 'multi'
                    ? safeBounds.x+column*stepX : safeBounds.x+(safeBounds.width-tileWidth)/2,
                y:settings.pagination === 'multi'
                    ? safeBounds.y+row*stepY : safeBounds.y+(safeBounds.height-tileHeight)/2,
                width:tileWidth,height:tileHeight
            });
        }
        return {
            paper,margin,headerHeight,usableWidth,usableHeight,
            contentHeight:usableHeight,scalePercent,mmPerUnit,fitPercent,
            clampedToSinglePage,overlapMm,overlapX,overlapY,stepX,stepY,
            bounds:safeBounds,columns,rows,pages
        };
    }

    function readability(fontSizePx, mmPerUnit) {
        if (!(Number(fontSizePx) > 0) || !(Number(mmPerUnit) > 0))
            return {points:null,rating:'none'};
        const points = Number(fontSizePx)*Number(mmPerUnit)*72/25.4;
        return {points,rating:points >= 9 ? 'good' : points >= 7 ? 'limited' : 'critical'};
    }

    // The editor moves a camera underneath fixed paper frames. All dimensions
    // here are millimetres or topology units; browser zoom never enters them.
    function frameDimensions(settings) {
        const paper=pageDimensions(settings.format,settings.orientation);
        const margin=settings.margin==='small' ? 7 : 0;
        const headerHeight=settings.header ? 12 : 0;
        const usableWidth=paper.width-2*margin;
        const usableHeight=paper.height-2*margin-headerHeight;
        const count=value=>Math.max(1,Math.min(8,Math.round(Number(value)||1)));
        const columns=settings.pagination==='multi' ? count(settings.columns) : 1;
        const rows=settings.pagination==='multi' ? count(settings.rows) : 1;
        const overlapMm=columns>1 || rows>1 ? 8 : 0;
        const stepWidth=usableWidth-overlapMm,stepHeight=usableHeight-overlapMm;
        return {paper,margin,headerHeight,usableWidth,usableHeight,contentHeight:usableHeight,
            columns,rows,overlapMm,stepWidth,stepHeight,
            spreadWidth:usableWidth+(columns-1)*stepWidth,
            spreadHeight:usableHeight+(rows-1)*stepHeight};
    }

    function planViewportPages(camera, settings) {
        const frame=frameDimensions(settings);
        const {x,y,mmPerUnit}=camera;
        if (![x,y,mmPerUnit].every(Number.isFinite) || mmPerUnit<=0)
            throw new RangeError('Ungültiger PDF-Ausschnitt');
        const width=frame.usableWidth/mmPerUnit,height=frame.usableHeight/mmPerUnit;
        const stepX=frame.stepWidth/mmPerUnit,stepY=frame.stepHeight/mmPerUnit;
        const pages=[];
        for (let row=0;row<frame.rows;row++) for (let column=0;column<frame.columns;column++)
            pages.push({index:pages.length+1,row,column,x:x+column*stepX,y:y+row*stepY,width,height});
        return {...frame,mmPerUnit,stepX,stepY,pages,
            bounds:{x,y,width:frame.spreadWidth/mmPerUnit,height:frame.spreadHeight/mmPerUnit}};
    }

    function fitCamera(bounds, settings) {
        const safe=expandBounds(bounds,0);
        const frame=frameDimensions(settings);
        const mmPerUnit=Math.min(frame.spreadWidth/Math.max(1,safe.width),
            frame.spreadHeight/Math.max(1,safe.height));
        return {x:safe.x+(safe.width-frame.spreadWidth/mmPerUnit)/2,
            y:safe.y+(safe.height-frame.spreadHeight/mmPerUnit)/2,mmPerUnit};
    }

    function reframeCamera(camera, previousSettings, nextSettings) {
        const previous=frameDimensions(previousSettings),next=frameDimensions(nextSettings);
        return {...camera,
            x:camera.x+(previous.spreadWidth-next.spreadWidth)/(2*camera.mmPerUnit),
            y:camera.y+(previous.spreadHeight-next.spreadHeight)/(2*camera.mmPerUnit)};
    }

    function panCamera(camera, deltaMm) {
        return {...camera,x:camera.x-deltaMm.x/camera.mmPerUnit,
            y:camera.y-deltaMm.y/camera.mmPerUnit};
    }

    function zoomCamera(camera, factor, anchor) {
        if (!(factor>0) || !Number.isFinite(factor)) return {...camera};
        const mmPerUnit=Math.max(0.000001,Math.min(25,camera.mmPerUnit*factor));
        const ratio=camera.mmPerUnit/mmPerUnit;
        return {x:anchor.x-(anchor.x-camera.x)*ratio,
            y:anchor.y-(anchor.y-camera.y)*ratio,mmPerUnit};
    }

    return {CSS_PX_MM,PAPER_MM,pageDimensions,expandBounds,planPages,readability,
        frameDimensions,planViewportPages,fitCamera,reframeCamera,panCamera,zoomCamera};
});
