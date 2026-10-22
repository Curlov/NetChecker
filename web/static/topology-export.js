(function () {
    'use strict';

    const svgNs = 'http://www.w3.org/2000/svg';
    const layout = window.TopologyExportLayout;
    const dialog = document.querySelector('#topology-export-dialog');
    const graph = document.querySelector('#topology-graph');
    if (!layout || !dialog || !graph) return;

    const controls = {
        padding:document.querySelector('#topology-export-padding'),
        paper:document.querySelector('#topology-export-paper'),
        orientation:document.querySelector('#topology-export-orientation'),
        margin:document.querySelector('#topology-export-margin'),
        pagination:document.querySelector('#topology-export-pagination'),
        columns:document.querySelector('#topology-export-columns'),
        rows:document.querySelector('#topology-export-rows'),
        grid:document.querySelector('#topology-export-grid-settings'),
        options:[...dialog.querySelectorAll('[data-export-option]')],
        preview:document.querySelector('#topology-export-pages'),
        count:document.querySelector('#topology-export-page-count'),
        readability:document.querySelector('#topology-export-readability'),
        readabilityMessage:document.querySelector('#topology-export-readability-message'),
        error:document.querySelector('#topology-export-error'),
        print:document.querySelector('#topology-export-print')
    };
    const optionState = () => Object.fromEntries(controls.options.map(input =>
        [input.dataset.exportOption,input.checked]));
    const frameGutter=0,frameGap=12;
    let snapshot=null;
    let camera=null;
    let frameSettings=null;
    let prepared=null;
    let rebuildVersion=0;
    let spritePromise=null;
    let workspace=null;
    let pageViews=[];
    let drag=null;
    let pendingDraw=null;

    function element(name, attributes = {}) {
        const result = document.createElementNS(svgNs,name);
        for (const [key,value] of Object.entries(attributes)) result.setAttribute(key,String(value));
        return result;
    }

    function displayError(message = '') {
        controls.error.textContent = message;
        controls.error.hidden = !message;
    }

    function networkCaption() {
        const option = document.querySelector('#network-select')?.selectedOptions?.[0];
        return String(option?.textContent || 'Netzwerk').replace(/\s+\(\d+ Geräte\)\s*$/,'').trim();
    }

    function networkCidr() {
        const match = networkCaption().match(/[0-9a-f:.]+\/\d{1,3}/i);
        return match ? match[0] : 'Netzwerk';
    }

    function exportDate() {
        const value = new Date();
        const pad = number => String(number).padStart(2,'0');
        return {
            date:`${value.getFullYear()}-${pad(value.getMonth()+1)}-${pad(value.getDate())}`,
            display:value.toLocaleString('de-DE',{dateStyle:'short',timeStyle:'short'})
        };
    }

    function filename(date=exportDate()) {
        const cidr = networkCidr().replace('/','-').replace(/[^\w.-]/g,'_');
        return `NetChecker_Topologie_${cidr}_${date.date}.pdf`;
    }

    function optionsAsStyles(scene, options) {
        scene.setAttribute('xmlns',svgNs);
        scene.setAttribute('preserveAspectRatio','xMidYMid meet');
        scene.setAttribute('overflow','hidden');
        scene.style.cssText='display:block;background:#ffffff;color:#172554';

        scene.querySelectorAll('.topology-room-handle,.topology-manual-link-hit,'+
            '.topology-manual-link-corners,.topology-connection-preview,'+
            '.topology-room-draw-preview,.topology-drop-preview,'+
            '.topology-link-preview,.topology-node-measurement').forEach(item=>item.remove());
        scene.querySelectorAll('title').forEach(item=>item.remove());
        scene.querySelectorAll('[tabindex],[aria-label],[data-topology-key],[data-link-id],'+
            '[data-room-id]').forEach(item=>{
            for (const name of ['tabindex','aria-label','data-topology-key','data-link-id','data-room-id'])
                item.removeAttribute(name);
        });
        scene.querySelectorAll('*').forEach(item=>item.classList.remove(
            'topology-node-selected','topology-room-selected','topology-manual-link-selected',
            'topology-link-target-valid','topology-link-target-invalid','topology-drop-preview',
            'topology-room-drop-target','topology-manual-link-drag-preview'));

        scene.querySelectorAll('.topology-room').forEach(room=>{
            if (!options.rooms) {room.remove();return;}
            const rect=room.querySelector('.topology-room-shape');
            if (rect) rect.setAttribute('style',
                'fill:#f8fafc;fill-opacity:1;stroke:#475569;stroke-width:1.8;vector-effect:non-scaling-stroke');
            const label=room.querySelector('.topology-room-label');
            if (label && options.rooms) label.setAttribute('style',
                'fill:#0f172a;font-family:Arial,sans-serif;font-size:13px;font-weight:600');
            else label?.remove();
        });

        scene.querySelectorAll('.topology-link').forEach(link=>{
            if (!options.links) {link.remove();return;}
            const physical=link.classList.contains('physical');
            link.setAttribute('style',physical
                ? 'fill:none;stroke:#0369a1;stroke-width:2.2;vector-effect:non-scaling-stroke'
                : 'fill:none;stroke:#64748b;stroke-width:1.8;stroke-dasharray:7 4;vector-effect:non-scaling-stroke');
        });

        scene.querySelectorAll('.topology-manual-link').forEach(link=>{
            if (!options.links) {link.remove();return;}
            const path=link.querySelector('.topology-manual-link-path');
            const type=[...link.classList].find(name=>name.startsWith('topology-link-type-'))?.slice(19) || 'unknown';
            const styles={
                ethernet:['#0284c7','none',2.2],fiber:['#7c3aed','none',3.2],
                wifi:['#059669','7 4',2.2],logical:['#b45309','2 4',2.2],
                unknown:['#64748b','5 4',2.2]
            };
            const [stroke,dash,width]=styles[type] || styles.unknown;
            if (path) path.setAttribute('style',
                `fill:none;stroke:${stroke};stroke-width:${width};stroke-dasharray:${dash};stroke-linecap:round;stroke-linejoin:round;vector-effect:non-scaling-stroke`);
            const label=link.querySelector('.topology-manual-link-label');
            if (!options.linkLabels) label?.remove();
            else if (label) label.setAttribute('style',
                'fill:#111827;stroke:#ffffff;stroke-width:4;paint-order:stroke;stroke-linejoin:round;font-family:Arial,sans-serif;font-size:11px');
        });

        scene.querySelectorAll('.topology-node').forEach(node=>{
            const deviceId=node.getAttribute('data-device-id');
            const manualId=node.getAttribute('data-manual-node-id');
            const rendered=snapshot.nodes.get(manualId ? `manual:${manualId}` : `device:${deviceId}`);
            const actualDevice=rendered?.device || null;
            const actualManual=rendered?.manual || null;
            const includeDevice=Boolean(actualDevice && options.devices);
            const includeManual=Boolean(actualManual && options.manual);
            if (!includeDevice && !includeManual) {node.remove();return;}
            const device=includeDevice ? actualDevice : null;
            const manual=includeManual ? actualManual : null;
            const present=node.classList.contains('topology-status-present');
            const missing=node.classList.contains('topology-status-missing');
            const color=!includeDevice && includeManual ? '#7c3aed' :
                present ? '#15803d' : missing ? '#b91c1c' : '#334155';
            node.setAttribute('style',`color:${color}`);
            const badge=node.querySelector('.topology-node-background');
            if (badge) badge.setAttribute('style',
                `fill:${!includeDevice && includeManual ? '#ede9fe' : present ? '#dcfce7' : missing ? '#fee2e2' : '#f1f5f9'};stroke:${color};stroke-width:1.8`+
                (includeManual ? ';stroke-dasharray:4 2' : ''));
            const icon=node.querySelector('.lucide-icon');
            if (icon) icon.setAttribute('style',`color:${color}`);
            node.querySelectorAll('.topology-node-label,.topology-status-label').forEach(label=>label.remove());

            let ipLine=device && options.ip ? String(device.ip || '').trim() : '';
            let nameLine=device && options.names
                ? String(device.display_name || device.hostname || '').trim() : '';
            if (!device && manual && options.manual)
                nameLine=String(manual.label || '').trim();
            if (device && options.details) {
                const details=[];
                const category=typeof deviceClassDesign==='function'
                    ? deviceClassDesign(device.category).label : device.category;
                if (category) details.push(category);
                for (const value of [device.manufacturer,device.vendor,device.model,
                    device.os_name,device.operating_system]) {
                    const clean=String(value || '').trim();
                    if (clean && !details.some(item=>item.toLocaleLowerCase('de')===clean.toLocaleLowerCase('de')))
                        details.push(clean);
                }
                if (details.length) nameLine=[nameLine,details.join(' · ')].filter(Boolean).join(' · ');
            }
            if (device && options.mac && device.mac)
                nameLine=[nameLine,String(device.mac).trim()].filter(Boolean).join(' · ');

            // Keep the two rows used by the live topology: address at y=32,
            // name/status at y=47. SVG measurement and the same truncation
            // helper prevent long names or optional metadata from wrapping.
            const labelRows=[
                {value:ipLine,y:32,className:'topology-node-label',size:12},
                {value:nameLine,y:47,className:'topology-status-label',size:10}
            ];
            let ipLabelWidth=0;
            // Keep the same width limit even when the IP row is switched off.
            if (device?.ip && !ipLine) {
                const reference=element('text',{x:0,y:32});
                reference.setAttribute('style','font-family:Arial,sans-serif;font-size:12px;font-weight:400');
                node.appendChild(reference);
                fitTopologyNodeLabel(reference,String(device.ip),topologyLabelMaxWidth);
                ipLabelWidth=reference.getBBox().width;
                reference.remove();
            }
            for (const row of labelRows) {
                if (!row.value) continue;
                const text=element('text',{x:0,y:row.y,'text-anchor':'middle',class:row.className});
                text.textContent=row.value;
                text.setAttribute('style',`fill:#111827;font-family:Arial,sans-serif;font-size:${row.size}px;font-weight:400`);
                node.appendChild(text);
                const maxWidth=Number(topologyLabelMaxWidth);
                if (typeof fitTopologyNodeLabel==='function' && maxWidth>0) {
                    const rowMaxWidth=row.className==='topology-status-label' && ipLabelWidth>0
                        ? Math.min(maxWidth,ipLabelWidth) : maxWidth;
                    fitTopologyNodeLabel(text,row.value,rowMaxWidth);
                }
                if (row.className==='topology-node-label') {
                    try {ipLabelWidth=text.getBBox().width;} catch (_) {ipLabelWidth=0;}
                }
            }
            node.removeAttribute('data-device-id');
            node.removeAttribute('data-manual-node-id');
        });
        // Scale strokes with the page SVG as well as the plan, so a fitted
        // onscreen sheet and the corresponding PDF have identical proportions.
        scene.querySelectorAll('*').forEach(item=>{
            item.removeAttribute('vector-effect');
            item.style.removeProperty('vector-effect');
        });
        return scene;
    }

    async function inlineIcons(scene) {
        if (!spritePromise) spritePromise=fetch('/static/vendor/lucide/sprite.svg?v=1.55.0-devices-1')
            .then(response=>response.ok ? response.text() : Promise.reject(new Error('SVG-Icons konnten nicht geladen werden')))
            .then(source=>new DOMParser().parseFromString(source,'image/svg+xml'));
        try {
            const sprite=await spritePromise;
            for (const use of scene.querySelectorAll('use')) {
                const href=use.getAttribute('href') || use.getAttributeNS('http://www.w3.org/1999/xlink','href') || '';
                const id=href.split('#').at(-1);
                const symbol=sprite.getElementById(id);
                if (!symbol) continue;
                use.replaceWith(...[...symbol.childNodes].filter(child=>child.nodeType===1)
                    .map(child=>document.importNode(child,true)));
            }
        } catch (_) {
            // The original same-origin <use> references are still printable if
            // a browser refuses to fetch the bundled sprite sheet.
        }
        return scene;
    }

    function currentOptions() {
        for (const input of [controls.columns,controls.rows])
            input.value=String(Math.max(1,Math.min(8,Math.round(Number(input.value)||1))));
        return {
            format:controls.paper.value,orientation:controls.orientation.value,
            margin:controls.margin.value,pagination:controls.pagination.value,
            columns:Number(controls.columns.value),rows:Number(controls.rows.value),
            header:optionState().header
        };
    }

    function currentGraphBounds() {
        const matrix=graph.getScreenCTM();
        if (matrix) {
            const rect=graph.getBoundingClientRect();
            const inverse=matrix.inverse();
            const left=rect.left+graph.clientLeft,top=rect.top+graph.clientTop;
            const first=new DOMPoint(left,top).matrixTransform(inverse);
            const last=new DOMPoint(left+graph.clientWidth,top+graph.clientHeight).matrixTransform(inverse);
            if (last.x>first.x && last.y>first.y)
                return {x:first.x,y:first.y,width:last.x-first.x,height:last.y-first.y};
        }
        const {x,y,width,height}=graph.viewBox.baseVal;
        return {x,y,width,height};
    }

    function captureSnapshot() {
        if (!topologyCurrentRenderData || !graph.childElementCount)
            throw new Error('Es ist keine geladene Topologie vorhanden.');
        if (typeof topologyEditorGesture!=='undefined' && topologyEditorGesture)
            throw new Error('Bitte zuerst die aktuelle Topologiebearbeitung abschließen.');
        if (typeof topologyPendingWrites!=='undefined' && topologyPendingWrites>0)
            throw new Error('Das Layout wird noch gespeichert. Bitte einen Moment warten.');
        const nodes=new Map(topologyRenderedNodes.map(node=>[
            node.manual ? `manual:${node.manual.id}` : `device:${node.device.id}`,
            {device:node.device ? structuredClone(node.device) : null,
                manual:node.manual ? structuredClone(node.manual) : null}
        ]));
        const date=exportDate();
        return {source:graph.cloneNode(true),nodes,view:currentGraphBounds(),
            spacing:{...topologyGridSpacing},caption:networkCaption(),date,filename:filename(date)};
    }

    function measureAttached(scene, read) {
        // getBBox() on a detached SVG can return zero. Keep measurement in the
        // document so the IP/name width limit also holds in the exported SVG.
        const host=document.createElement('div');
        host.style.cssText='position:fixed;left:-100000px;top:0;width:2000px;height:1200px;visibility:hidden;pointer-events:none';
        host.appendChild(scene);
        document.body.appendChild(host);
        try {return read();}
        finally {scene.remove();host.remove();}
    }

    function getCleanScene(options) {
        if (!snapshot) throw new Error('Bitte den Export erneut öffnen.');
        const scene=snapshot.source.cloneNode(true);
        for (const attribute of ['id','role','aria-label']) scene.removeAttribute(attribute);
        return measureAttached(scene,()=>optionsAsStyles(scene,options));
    }

    function measureScene(scene) {
        return measureAttached(scene,()=>{
            if (!scene.querySelector('.topology-node,.topology-room,.topology-link,.topology-manual-link'))
                throw new Error('Bitte mindestens einen sichtbaren Topologieinhalt einblenden.');
            const box=scene.getBBox();
            const bounds={x:box.x,y:box.y,width:box.width,height:box.height};
            if (![box.x,box.y,box.width,box.height].every(Number.isFinite))
                throw new Error('Die Topologieabmessungen konnten nicht ermittelt werden.');
            const inverse=scene.getScreenCTM().inverse();
            const labels=[...scene.querySelectorAll('text')].filter(item=>item.textContent.trim()).map(item=>{
                const fontPx=parseFloat(item.style.fontSize || item.getAttribute('font-size') || getComputedStyle(item).fontSize);
                const rect=item.getBBox(),matrix=inverse.multiply(item.getScreenCTM());
                const corners=[[rect.x,rect.y],[rect.x+rect.width,rect.y],
                    [rect.x,rect.y+rect.height],[rect.x+rect.width,rect.y+rect.height]]
                    .map(([x,y])=>new DOMPoint(x,y).matrixTransform(matrix));
                return {fontPx,left:Math.min(...corners.map(point=>point.x)),
                    top:Math.min(...corners.map(point=>point.y)),
                    right:Math.max(...corners.map(point=>point.x)),
                    bottom:Math.max(...corners.map(point=>point.y))};
            }).filter(label=>Number.isFinite(label.fontPx) && label.fontPx>0);
            return {bounds,labels};
        });
    }

    function renderReadability(metrics) {
        const bounds=metrics.bounds;
        const visible=prepared.labels.filter(label=>label.right>bounds.x &&
            label.left<bounds.x+bounds.width && label.bottom>bounds.y && label.top<bounds.y+bounds.height);
        const fontPx=visible.length ? Math.min(...visible.map(label=>label.fontPx)) : null;
        const result=layout.readability(fontPx,metrics.mmPerUnit);
        const names={good:'Gut',limited:'Eingeschränkt',critical:'Kritisch'};
        controls.readability.dataset.rating=result.rating;
        controls.readabilityMessage.replaceChildren();
        const line=document.createElement('span');
        line.textContent=result.points==null ? 'Keine Beschriftungen im PDF-Ausschnitt' :
            `Lesbarkeit: ${names[result.rating]} · kleinste Schrift ${result.points.toFixed(1).replace('.',',')} pt`;
        controls.readabilityMessage.appendChild(line);
        if (result.rating==='limited' || result.rating==='critical') {
            const hint=document.createElement('small');
            hint.textContent='Zum Vergrößern hineinzoomen; bei Bedarf mehr Seiten oder größeres Papier wählen.';
            controls.readabilityMessage.appendChild(hint);
        }
    }

    function headerText(value, x, y, size, attributes={}) {
        const text=element('text',{x,y,'font-family':'Arial,sans-serif','font-size':size,
            fill:'#334155',...attributes});
        text.textContent=value;
        return text;
    }

    function createPage(scene, page, metrics) {
        const paper=element('svg',{xmlns:svgNs,viewBox:`0 0 ${metrics.paper.width} ${metrics.paper.height}`,
            width:metrics.paper.width,height:metrics.paper.height,'aria-hidden':'true'});
        paper.appendChild(element('rect',{width:metrics.paper.width,height:metrics.paper.height,fill:'#fff'}));
        if (frameSettings.header) {
            const baseline=metrics.margin+7;
            paper.appendChild(headerText('NetChecker',metrics.margin+2,baseline,3.175,{'font-weight':'bold'}));
            // A separate clipped field reserves space for the date/page number.
            const dateWidth=metrics.pages.length>1 ? 76 : 48;
            const networkField=element('svg',{x:metrics.margin+29,y:metrics.margin,
                width:Math.max(1,metrics.usableWidth-31-dateWidth),height:metrics.headerHeight,overflow:'hidden'});
            networkField.appendChild(headerText(snapshot.caption,0,7,2.822));
            paper.appendChild(networkField);
            paper.appendChild(headerText(snapshot.date.display+
                (metrics.pages.length>1 ? ` · Seite ${page.index}/${metrics.pages.length}` : ''),
                metrics.paper.width-metrics.margin-2,baseline,2.822,{'text-anchor':'end'}));
            paper.appendChild(element('line',{x1:metrics.margin,y1:metrics.margin+metrics.headerHeight-1,
                x2:metrics.paper.width-metrics.margin,y2:metrics.margin+metrics.headerHeight-1,
                stroke:'#cbd5e1','stroke-width':.2}));
        }
        const content=scene.cloneNode(true);
        content.removeAttribute('class');
        content.setAttribute('x',metrics.margin);
        content.setAttribute('y',metrics.margin+metrics.headerHeight);
        content.setAttribute('width',metrics.usableWidth);
        content.setAttribute('height',metrics.usableHeight);
        content.setAttribute('preserveAspectRatio','none');
        content.setAttribute('style','display:block;background:#fff;overflow:hidden');
        content.setAttribute('viewBox',`${page.x} ${page.y} ${page.width} ${page.height}`);
        paper.appendChild(content);
        return {paper,content};
    }

    function renderWorkspace() {
        const metrics=layout.planViewportPages(camera,frameSettings);
        const width=metrics.columns*metrics.paper.width+(metrics.columns-1)*frameGap+2*frameGutter;
        const height=metrics.rows*metrics.paper.height+(metrics.rows-1)*frameGap+2*frameGutter;
        workspace=element('svg',{viewBox:`0 0 ${width} ${height}`,width:'100%',height:'100%',
            'aria-hidden':'true',class:'topology-export-workspace'});
        pageViews=[];
        for (const page of metrics.pages) {
            const view=createPage(prepared.scene,page,metrics);
            const x=frameGutter+page.column*(metrics.paper.width+frameGap);
            const y=frameGutter+page.row*(metrics.paper.height+frameGap);
            view.paper.setAttribute('x',x);view.paper.setAttribute('y',y);
            workspace.appendChild(view.paper);
            if (metrics.pages.length>1)
                workspace.appendChild(element('rect',{x,y,width:metrics.paper.width,height:metrics.paper.height,
                    fill:'none',stroke:'#94a3b8','stroke-width':1,'vector-effect':'non-scaling-stroke'}));
            if (metrics.margin>0 || metrics.headerHeight>0)
                workspace.appendChild(element('rect',{x:x+metrics.margin,y:y+metrics.margin+metrics.headerHeight,
                    width:metrics.usableWidth,height:metrics.usableHeight,fill:'none',stroke:'#94a3b8',
                    'stroke-width':1,'stroke-dasharray':'4 4','vector-effect':'non-scaling-stroke'}));
            pageViews.push(view);
        }
        controls.preview.replaceChildren(workspace);
        controls.count.textContent=`${metrics.pages.length} Seite${metrics.pages.length===1?'':'n'} · ${frameSettings.format} ${frameSettings.orientation==='landscape'?'quer':'hoch'}`;
        updateCameraView();
        fitDialogToPaper();
    }

    function fitDialogToPaper() {
        if (!workspace || !dialog.open) return;
        const panel=controls.preview.parentElement;
        const settings=dialog.querySelector('.topology-export-settings');
        const body=dialog.querySelector('.topology-export-layout');
        const heading=dialog.querySelector('.topology-export-heading');
        const footer=dialog.querySelector('.topology-export-footer');
        const toolbar=dialog.querySelector('.topology-export-preview-toolbar');
        const help=dialog.querySelector('.topology-export-canvas-help');
        const stacked=window.matchMedia('(max-width:700px)').matches;
        const maxWidth=Math.min(1500,window.innerWidth*(stacked ? .98 : .96));
        const maxHeight=Math.min(940,window.innerHeight*(stacked || window.innerHeight<=650 ? .98 : .94));
        const ratio=workspace.viewBox.baseVal.width/workspace.viewBox.baseVal.height;
        const px=value=>parseFloat(value)||0;
        dialog.style.width=`${maxWidth}px`;
        controls.preview.style.width='100%';
        // Re-measure wrapped headings and the fixed warning slot after each
        // width adjustment. The canvas itself always has the paper's ratio.
        for (let pass=0;pass<4;pass++) {
            if (stacked) panel.style.width='100%';
            const dialogStyle=getComputedStyle(dialog),panelStyle=getComputedStyle(panel);
            const bodyStyle=getComputedStyle(body);
            const panelBorderX=px(panelStyle.borderLeftWidth)+px(panelStyle.borderRightWidth);
            const panelBorderY=px(panelStyle.borderTopWidth)+px(panelStyle.borderBottomWidth);
            const horizontalExtra=px(dialogStyle.paddingLeft)+px(dialogStyle.paddingRight)+
                px(dialogStyle.borderLeftWidth)+px(dialogStyle.borderRightWidth)+panelBorderX+
                (stacked ? 0 : settings.getBoundingClientRect().width+px(bodyStyle.columnGap));
            const verticalExtra=px(dialogStyle.paddingTop)+px(dialogStyle.paddingBottom)+
                px(dialogStyle.borderTopWidth)+px(dialogStyle.borderBottomWidth)+
                heading.getBoundingClientRect().height+footer.getBoundingClientRect().height+
                2*px(dialogStyle.rowGap)+toolbar.getBoundingClientRect().height+
                help.getBoundingClientRect().height+panelBorderY+
                (stacked ? settings.getBoundingClientRect().height+px(bodyStyle.rowGap) : 0);
            const width=Math.max(1,Math.min(maxWidth-horizontalExtra,Math.max(1,maxHeight-verticalExtra)*ratio));
            controls.preview.style.height=`${width/ratio}px`;
            if (stacked) controls.preview.style.width=`${width}px`;
            else {
                panel.style.width='100%';
                dialog.style.width=`${horizontalExtra+width}px`;
            }
        }
    }

    function updateCameraView() {
        if (!prepared || !workspace) return;
        const metrics=layout.planViewportPages(camera,frameSettings);
        pageViews.forEach((view,index)=>{
            const page=metrics.pages[index];
            view.content.setAttribute('viewBox',`${page.x} ${page.y} ${page.width} ${page.height}`);
        });
        prepared.metrics=metrics;
        renderReadability(metrics);
    }

    function scheduleCameraDraw() {
        if (pendingDraw!=null) return;
        pendingDraw=requestAnimationFrame(()=>{pendingDraw=null;updateCameraView();});
    }

    function clearDrag() {
        const pointerId=drag?.pointerId;
        drag=null;
        controls.preview.classList.remove('is-dragging');
        if (pointerId!=null && controls.preview.hasPointerCapture(pointerId))
            controls.preview.releasePointerCapture(pointerId);
    }

    async function rebuildPreview() {
        const version=++rebuildVersion;
        clearDrag();
        prepared=null;
        controls.print.disabled=true;
        controls.preview.setAttribute('aria-busy','true');
        displayError('');
        const settings=currentOptions();
        controls.grid.hidden=settings.pagination!=='multi';
        try {
            if (!snapshot) throw new Error('Bitte den Export erneut öffnen.');
            camera=camera && frameSettings ? layout.reframeCamera(camera,frameSettings,settings) :
                layout.fitCamera(snapshot.view,settings);
            frameSettings=settings;
            const scene=await inlineIcons(getCleanScene(optionState()));
            if (version!==rebuildVersion || !dialog.open) return;
            prepared={scene,...measureScene(scene)};
            renderWorkspace();
            controls.print.disabled=false;
        } catch (error) {
            if (version!==rebuildVersion) return;
            prepared=null;workspace=null;pageViews=[];
            controls.preview.replaceChildren();
            controls.count.textContent='Vorschau nicht verfügbar';
            controls.readabilityMessage.textContent='Kein gültiger PDF-Ausschnitt vorhanden.';
            controls.readability.dataset.rating='none';
            displayError(error.message || 'Die PDF-Vorschau konnte nicht erstellt werden.');
        } finally {
            if (version===rebuildVersion) controls.preview.removeAttribute('aria-busy');
        }
    }

    function canvasPoint(event) {
        const matrix=workspace?.getScreenCTM();
        if (!matrix) return null;
        return new DOMPoint(event.clientX,event.clientY).matrixTransform(matrix.inverse());
    }

    function worldPoint(point) {
        const metrics=layout.planViewportPages(camera,frameSettings);
        const column=Math.max(0,Math.min(metrics.columns-1,
            Math.floor((point.x-frameGutter)/(metrics.paper.width+frameGap))));
        const row=Math.max(0,Math.min(metrics.rows-1,
            Math.floor((point.y-frameGutter)/(metrics.paper.height+frameGap))));
        const page=metrics.pages[row*metrics.columns+column];
        return {x:page.x+(point.x-frameGutter-column*(metrics.paper.width+frameGap)-metrics.margin)/camera.mmPerUnit,
            y:page.y+(point.y-frameGutter-row*(metrics.paper.height+frameGap)-metrics.margin-metrics.headerHeight)/camera.mmPerUnit};
    }

    function resetView(all) {
        if (!prepared) return;
        clearDrag();
        let bounds=snapshot.view;
        if (all) {
            const padding=Math.max(0,Math.min(50,Number(controls.padding.value)||0));
            bounds=layout.expandBounds(prepared.bounds,padding*(snapshot.spacing.column||1),
                padding*(snapshot.spacing.row||1));
        }
        camera=layout.fitCamera(bounds,frameSettings);
        scheduleCameraDraw();
    }

    function printStyles(metrics) {
        return `@page{size:${metrics.paper.width}mm ${metrics.paper.height}mm;margin:0}`+
            'html,body{margin:0;padding:0;background:white;print-color-adjust:exact;-webkit-print-color-adjust:exact}'+
            '.topology-export-printed-page{box-sizing:border-box;display:block;overflow:hidden;'+
            `width:${metrics.paper.width}mm;height:${metrics.paper.height}mm;`+
            'margin:0;padding:0;break-after:page;page-break-after:always}'+
            '.topology-export-printed-page:last-child{break-after:auto;page-break-after:auto}'+
            '.topology-export-printed-page>svg{display:block}';
    }

    function openPrintWindow() {
        if (!prepared) return;
        updateCameraView();
        const popup=window.open('','_blank');
        if (!popup) {
            displayError('Der Druckdialog wurde blockiert. Bitte Pop-ups für NetChecker zulassen.');
            return;
        }
        const metrics=prepared.metrics;
        // Serialize the very same SVGs shown in the editor, without the frame
        // guides. No layout, labels or routes are recalculated.
        const pageSnapshots=pageViews.map(view=>{
            const paper=view.paper.cloneNode(true);
            paper.removeAttribute('x');paper.removeAttribute('y');
            paper.setAttribute('width',`${metrics.paper.width}mm`);
            paper.setAttribute('height',`${metrics.paper.height}mm`);
            return new XMLSerializer().serializeToString(paper);
        });
        popup.document.open();
        popup.document.write('<!doctype html><html lang="de"><head><meta charset="utf-8"></head><body></body></html>');
        popup.document.close();
        popup.document.title=snapshot.filename;
        const style=popup.document.createElement('style');
        style.textContent=printStyles(metrics);
        popup.document.head.appendChild(style);
        for (const markup of pageSnapshots) {
            const article=popup.document.createElement('article');
            article.className='topology-export-printed-page';
            const paper=new DOMParser().parseFromString(markup,'image/svg+xml').documentElement;
            article.appendChild(popup.document.importNode(paper,true));
            popup.document.body.appendChild(article);
        }
        popup.focus();
        const print=()=>{
            if (popup.closed) return;
            try {popup.print();} catch (error) {displayError(`Drucken fehlgeschlagen: ${error.message}`);}
        };
        if (popup.document.fonts?.ready) popup.document.fonts.ready.then(()=>setTimeout(print,150));
        else setTimeout(print,250);
    }

    controls.preview.addEventListener('pointerdown',event=>{
        if (!prepared || drag || event.button!==0) return;
        const point=canvasPoint(event);if (!point) return;
        event.preventDefault();
        controls.preview.focus({preventScroll:true});
        drag={pointerId:event.pointerId,start:point,camera:{...camera}};
        controls.preview.setPointerCapture(event.pointerId);
        controls.preview.classList.add('is-dragging');
    });
    controls.preview.addEventListener('pointermove',event=>{
        if (!drag || drag.pointerId!==event.pointerId || !prepared) return;
        const point=canvasPoint(event);if (!point) return;
        camera=layout.panCamera(drag.camera,{x:point.x-drag.start.x,y:point.y-drag.start.y});
        scheduleCameraDraw();
    });
    for (const type of ['pointerup','pointercancel','lostpointercapture'])
        controls.preview.addEventListener(type,event=>{
            if (drag?.pointerId===event.pointerId) clearDrag();
        });
    controls.preview.addEventListener('wheel',event=>{
        event.preventDefault();
        if (!prepared || drag) return;
        const point=canvasPoint(event);if (!point) return;
        const delta=event.deltaY*(event.deltaMode===1 ? 16 : event.deltaMode===2 ? controls.preview.clientHeight : 1);
        camera=layout.zoomCamera(camera,Math.exp(-Math.max(-300,Math.min(300,delta))*.002),worldPoint(point));
        scheduleCameraDraw();
    },{passive:false});
    controls.preview.addEventListener('keydown',event=>{
        if (!prepared || drag) return;
        const moves={ArrowLeft:{x:8,y:0},ArrowRight:{x:-8,y:0},ArrowUp:{x:0,y:8},ArrowDown:{x:0,y:-8}};
        if (moves[event.key]) camera=layout.panCamera(camera,moves[event.key]);
        else if (['+','=','-','−'].includes(event.key)) {
            const bounds=layout.planViewportPages(camera,frameSettings).bounds;
            camera=layout.zoomCamera(camera,event.key==='+' || event.key==='=' ? 1.15 : 1/1.15,
                {x:bounds.x+bounds.width/2,y:bounds.y+bounds.height/2});
        } else return;
        event.preventDefault();scheduleCameraDraw();
    });
    dialog.addEventListener('cancel',event=>{
        if (!drag) return;
        event.preventDefault();camera=drag.camera;clearDrag();scheduleCameraDraw();
    });
    window.addEventListener('blur',clearDrag);
    window.addEventListener('resize',()=>{clearDrag();fitDialogToPaper();});
    dialog.addEventListener('close',()=>{
        ++rebuildVersion;
        clearDrag();
        if (pendingDraw!=null) cancelAnimationFrame(pendingDraw);
        pendingDraw=null;
        snapshot=null;camera=null;frameSettings=null;prepared=null;workspace=null;pageViews=[];
        controls.preview.replaceChildren();
        controls.print.disabled=true;
        document.documentElement.classList.remove('topology-export-active');
    });
    document.querySelector('#topology-export-open').addEventListener('click',()=>{
        if (dialog.open) return;
        dialog.showModal();
        document.documentElement.classList.add('topology-export-active');
        displayError('');
        controls.count.textContent='Vorschau';
        controls.readabilityMessage.textContent='';
        controls.readability.dataset.rating='none';
        try {snapshot=captureSnapshot();rebuildPreview();}
        catch (error) {displayError(error.message);}
    });
    document.querySelector('#topology-export-close').addEventListener('click',()=>dialog.close());
    document.querySelector('#topology-export-fit').addEventListener('click',()=>resetView(true));
    document.querySelector('#topology-export-current-view').addEventListener('click',()=>resetView(false));
    document.querySelector('#topology-export-settings').addEventListener('submit',event=>event.preventDefault());
    for (const control of [controls.paper,controls.orientation,controls.margin,controls.pagination,
        controls.columns,controls.rows,...controls.options]) control.addEventListener('change',rebuildPreview);
    controls.print.addEventListener('click',openPrintWindow);
    document.querySelector('#network-select')?.addEventListener('change',()=>{if(dialog.open)dialog.close();});

    const tabs=[...dialog.querySelectorAll('[role=tab]')];
    function activateTab(tab) {
        tabs.forEach(item=>{
            const active=item===tab;
            item.setAttribute('aria-selected',String(active));
            item.tabIndex=active ? 0 : -1;
            document.getElementById(item.getAttribute('aria-controls')).hidden=!active;
        });
        fitDialogToPaper();
    }
    tabs.forEach((tab,index)=>{
        tab.addEventListener('click',()=>activateTab(tab));
        tab.addEventListener('keydown',event=>{
            if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
            event.preventDefault();
            const next=event.key==='Home' ? 0 : event.key==='End' ? tabs.length-1 :
                (index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
            activateTab(tabs[next]);tabs[next].focus({preventScroll:true});
        });
    });
})();
