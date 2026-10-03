// app.js

// DOM Selectors
const btnToggleSniffer = document.getElementById('btn-toggle-sniffer');
const selectSnifferMode = document.getElementById('select-sniffer-mode');
const btnInjectDdos = document.getElementById('btn-inject-ddos');
const btnInjectBrute = document.getElementById('btn-inject-brute');
const simulationBanner = document.getElementById('simulation-banner');

const statPps = document.getElementById('stat-pps');
const statBlocks = document.getElementById('stat-blocks');
const statFlows = document.getElementById('stat-flows');
const statPackets = document.getElementById('stat-packets');

const mlStatus = document.getElementById('ml-status');
const snifferStatus = document.getElementById('sniffer-status');
const modeStatus = document.getElementById('mode-status');
const scapyStatusVal = document.getElementById('scapy-status-val');

const xgbConf = document.getElementById('xgb-conf');
const xgbBar = document.getElementById('xgb-bar');
const entropyVal = document.getElementById('entropy-val');
const entropyBar = document.getElementById('entropy-bar');
const rulesStatus = document.getElementById('rules-status');

const alertsTableBody = document.getElementById('alerts-table-body');
const alertsEmptyRow = document.getElementById('alerts-empty-row');
const btnClearLogs = document.getElementById('btn-clear-logs');

const firewallTableBody = document.getElementById('firewall-table-body');
const firewallEmptyRow = document.getElementById('firewall-empty-row');

// State Variables
let snifferActive = true;
let snifferMode = "simulated";
let activeBlocks = new Set();
let flowLogsCount = 0;
let chartLabels = [];
let chartPpsData = [];
let chartThreatData = [];
let liveChartObj = null;

// Initialize Chart.js
function initChart() {
    const ctx = document.getElementById('live-flow-chart').getContext('2d');
    
    // Generate empty initial data
    for (let i = 0; i < 15; i++) {
        chartLabels.push("");
        chartPpsData.push(0);
        chartThreatData.push(0);
    }

    liveChartObj = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [
                {
                    label: 'Throughput (PPS)',
                    data: chartPpsData,
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.05)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    yAxisID: 'y'
                },
                {
                    label: 'Threat Intensity',
                    data: chartThreatData,
                    borderColor: '#ff2a5f',
                    backgroundColor: 'rgba(255, 42, 95, 0.05)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#a4b0be', font: { family: 'Outfit', size: 10 } }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#57606f' }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#a4b0be' },
                    min: 0
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    grid: { drawOnChartArea: false },
                    ticks: { color: '#a4b0be' },
                    min: 0,
                    max: 1.2
                }
            }
        }
    });
}

function updateChart(pps, hasThreat) {
    if (!liveChartObj) return;
    
    // Shift data
    chartPpsData.shift();
    chartPpsData.push(pps);
    
    chartThreatData.shift();
    // If threat detected, spike the intensity index, otherwise let it decay
    const lastThreat = chartThreatData[chartThreatData.length - 1];
    let newThreat = hasThreat ? 1.0 : lastThreat * 0.7; // decay
    if (newThreat < 0.05) newThreat = 0;
    chartThreatData.push(newThreat);
    
    // Add current timestamp for label
    chartLabels.shift();
    chartLabels.push(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    
    liveChartObj.update('none'); // Update without full animation for performance
}

// HTML5 Canvas sniffer Node Map
const canvas = document.getElementById('node-map-canvas');
const ctx = canvas.getContext('2d');
let nodes = {};
let particles = [];
let sparks = [];

function resizeCanvas() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height - 20; // accounting for padding
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

// Node Structure: Server is center
const serverNode = {
    ip: '192.168.1.1',
    label: 'Host Firewall',
    x: 0,
    y: 0,
    radius: 22,
    pulse: 0
};

function spawnNode(ip, classification) {
    if (nodes[ip]) {
        nodes[ip].lastActive = Date.now();
        if (classification !== 'BENIGN') {
            nodes[ip].state = classification;
        }
        return;
    }
    
    // Find a clean angle to spawn the client node
    const numNodes = Object.keys(nodes).length;
    const angle = (numNodes * 55 * Math.PI) / 180;
    
    nodes[ip] = {
        ip: ip,
        angle: angle,
        state: classification,
        radius: 12,
        lastActive: Date.now(),
        pulse: 0
    };
}

function addParticle(srcIp, classification) {
    if (!nodes[srcIp]) return;
    
    const node = nodes[srcIp];
    const isBlocked = activeBlocks.has(srcIp);
    
    let color = '#00f2fe'; // nominal
    if (classification === 'DDOS_FLOOD') color = '#ff2a5f';
    if (classification === 'BRUTE_FORCE_SPRAY') color = '#ff9f43';
    if (classification === 'PORT_SCAN') color = '#bd93f9';
    
    particles.push({
        srcIp: srcIp,
        angle: node.angle,
        progress: 0,
        speed: classification === 'DDOS_FLOOD' ? 0.05 : 0.02,
        color: color,
        size: classification === 'DDOS_FLOOD' ? 3 : 4,
        blocked: isBlocked
    });
}

function triggerSparks(x, y, color) {
    for (let i = 0; i < 8; i++) {
        sparks.push({
            x: x,
            y: y,
            vx: (Math.random() - 0.5) * 4,
            vy: (Math.random() - 0.5) * 4,
            radius: Math.random() * 2 + 1,
            color: color,
            alpha: 1,
            decay: Math.random() * 0.05 + 0.02
        });
    }
}

function drawNodeMap() {
    if (!canvas) return;
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    serverNode.x = cx;
    serverNode.y = cy;
    
    // Draw background concentric radar circles
    ctx.strokeStyle = 'rgba(0, 242, 254, 0.03)';
    ctx.lineWidth = 1;
    for (let r = 80; r < Math.max(canvas.width, canvas.height); r += 60) {
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
    }
    
    const now = Date.now();
    const radiusOffset = 110; // distance of client nodes from center
    
    // Draw client connections & firewall barriers
    Object.keys(nodes).forEach(ip => {
        const node = nodes[ip];
        
        // Remove nodes inactive for more than 40 seconds to keep canvas clean
        if (now - node.lastActive > 40000) {
            delete nodes[ip];
            return;
        }
        
        // Compute current dynamic position
        const nx = cx + Math.cos(node.angle) * radiusOffset;
        const ny = cy + Math.sin(node.angle) * radiusOffset;
        node.x = nx;
        node.y = ny;
        
        const isBlocked = activeBlocks.has(ip);
        
        // Connection Line
        ctx.beginPath();
        if (isBlocked) {
            ctx.strokeStyle = 'rgba(255, 42, 95, 0.05)';
        } else {
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
        }
        ctx.lineWidth = 1;
        ctx.moveTo(nx, ny);
        ctx.lineTo(cx, cy);
        ctx.stroke();
        
        // Draw Firewall Barrier Arch if blocked
        if (isBlocked) {
            const barrierRadius = 45;
            const arcSpan = 0.4; // width of shield
            ctx.beginPath();
            ctx.strokeStyle = '#ff2a5f';
            ctx.lineWidth = 3;
            // Draw glow shadow
            ctx.shadowBlur = 10;
            ctx.shadowColor = '#ff2a5f';
            ctx.arc(cx, cy, barrierRadius, node.angle - arcSpan, node.angle + arcSpan);
            ctx.stroke();
            // Reset shadow
            ctx.shadowBlur = 0;
            
            // Draw glowing lock icon next to the barrier
            ctx.fillStyle = '#ff2a5f';
            ctx.font = '8px FontAwesome';
            const bx = cx + Math.cos(node.angle) * (barrierRadius + 10);
            const by = cy + Math.sin(node.angle) * (barrierRadius + 10);
            ctx.fillText('\uf023', bx - 3, by + 3);
        }
        
        // Draw Client Node
        let nodeColor = '#00ff87'; // green
        if (node.state === 'DDOS_FLOOD') nodeColor = '#ff2a5f';
        if (node.state === 'BRUTE_FORCE_SPRAY') nodeColor = '#ff9f43';
        if (node.state === 'PORT_SCAN') nodeColor = '#bd93f9';
        if (isBlocked) nodeColor = '#ff2a5f'; // turns red if blocked
        
        node.pulse += 0.05;
        const scale = 1 + Math.sin(node.pulse) * 0.15;
        
        ctx.shadowBlur = isBlocked ? 8 : 4;
        ctx.shadowColor = nodeColor;
        ctx.fillStyle = nodeColor;
        ctx.beginPath();
        ctx.arc(nx, ny, node.radius * scale, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
        
        // Node IP Label
        ctx.fillStyle = '#a4b0be';
        ctx.font = '9px Outfit';
        ctx.textAlign = 'center';
        ctx.fillText(ip, nx, ny - node.radius - 5);
    });
    
    // Update & Draw Particles
    particles = particles.filter(p => {
        p.progress += p.speed;
        
        const nx = cx + Math.cos(p.angle) * radiusOffset;
        const ny = cy + Math.sin(p.angle) * radiusOffset;
        
        // Current particle position
        const px = nx + (cx - nx) * p.progress;
        const py = ny + (cy - ny) * p.progress;
        
        // Check barrier collision (at radius = 45)
        const distanceToCenter = Math.sqrt((px - cx) ** 2 + (py - cy) ** 2);
        
        if (p.blocked && distanceToCenter <= 50) {
            // Trigger spark explosion at the shield
            triggerSparks(px, py, '#ff2a5f');
            return false; // destroy particle
        }
        
        if (p.progress >= 1.0) {
            // Particle hit the server
            triggerSparks(cx, cy, p.color);
            return false; // destroy
        }
        
        // Draw particle
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.arc(px, py, p.size, 0, Math.PI * 2);
        ctx.fill();
        return true;
    });
    
    // Draw Sparks
    sparks = sparks.filter(s => {
        s.x += s.vx;
        s.y += s.vy;
        s.alpha -= s.decay;
        
        if (s.alpha <= 0) return false;
        
        ctx.fillStyle = s.color;
        ctx.globalAlpha = s.alpha;
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1.0;
        return true;
    });
    
    // Draw Central Server
    serverNode.pulse += 0.02;
    const serverGlow = 10 + Math.sin(serverNode.pulse) * 5;
    ctx.shadowBlur = serverGlow;
    ctx.shadowColor = '#00f2fe';
    
    const grad = ctx.createRadialGradient(cx, cy, 5, cx, cy, serverNode.radius);
    grad.addColorStop(0, '#00f2fe');
    grad.addColorStop(1, '#10142a');
    ctx.fillStyle = grad;
    
    ctx.beginPath();
    ctx.arc(cx, cy, serverNode.radius, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
    
    // Server Label
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 9px Outfit';
    ctx.textAlign = 'center';
    ctx.fillText('CORE SERVER', cx, cy + 3);
    
    requestAnimationFrame(drawNodeMap);
}
requestAnimationFrame(drawNodeMap);

// Fetch Server Status
async function checkStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        // Update stats
        statPps.innerText = `${data.current_pps} PPS`;
        statPackets.innerText = data.total_packets.toLocaleString();
        statFlows.innerText = data.total_flows.toLocaleString();
        
        // Update Sniffer button state
        snifferActive = data.sniffer_running;
        snifferMode = data.sniffer_mode;
        
        if (snifferActive) {
            btnToggleSniffer.innerHTML = '<i class="fa-solid fa-power-off"></i> Sniffer ON';
            btnToggleSniffer.classList.remove('inactive');
            snifferStatus.innerHTML = '<span class="dot green"></span> SNIFFER: ACTIVE';
        } else {
            btnToggleSniffer.innerHTML = '<i class="fa-solid fa-power-off"></i> Sniffer OFF';
            btnToggleSniffer.classList.add('inactive');
            snifferStatus.innerHTML = '<span class="dot red"></span> SNIFFER: STOPPED';
        }
        
        // Update system badges
        mlStatus.innerHTML = data.model_loaded 
            ? '<span class="dot green"></span> ML ENGINE: LOADED' 
            : '<span class="dot orange"></span> ML ENGINE: FALLBACK';
            
        modeStatus.innerHTML = data.sniffer_mode === 'live'
            ? '<span class="dot blue"></span> LIVE SNIFFER'
            : '<span class="dot orange"></span> SIMULATION MODE';
        modeStatus.className = data.sniffer_mode === 'live' ? 'status-badge mode-badge' : 'status-badge mode-badge warning';
        
        scapyStatusVal.innerText = data.scapy_available ? "Available (Sniffable)" : "Missing (Simulated Only)";
        selectSnifferMode.value = data.sniffer_mode;
        
        // Always enable simulation inject buttons
        btnInjectDdos.disabled = false;
        btnInjectBrute.disabled = false;
        
        // Update graph throughput
        updateChart(data.current_pps, false);
        
    } catch (e) {
        console.error("Failed to check status", e);
    }
}

// Fetch Firewall Rules
async function checkFirewallRules() {
    try {
        const response = await fetch('/api/firewall/rules');
        const rules = await response.json();
        
        // Update block count
        statBlocks.innerText = rules.length;
        
        // Track blocked IPs
        activeBlocks.clear();
        rules.forEach(r => activeBlocks.add(r.ip));
        
        if (rules.length === 0) {
            firewallTableBody.innerHTML = `
                <tr id="firewall-empty-row">
                    <td colspan="5" class="text-center text-muted">No active blocks. Network perimeter secured.</td>
                </tr>`;
            return;
        }
        
        // Build table rows
        let html = '';
        rules.forEach(r => {
            let threatBadge = `<span class="badge brute">${r.threat_type}</span>`;
            if (r.threat_type === 'DDOS_FLOOD') threatBadge = `<span class="badge ddos">${r.threat_type}</span>`;
            if (r.threat_type === 'PORT_SCAN') threatBadge = `<span class="badge portscan">${r.threat_type}</span>`;
            
            html += `
                <tr>
                    <td class="mono font-semibold text-red">${r.ip}</td>
                    <td>${threatBadge}</td>
                    <td class="mono text-muted">${r.blocked_at}</td>
                    <td class="mono text-orange font-bold text-center">${r.remaining}s</td>
                    <td>
                        <button class="btn btn-revoke btn-sm" onclick="revokeBlock('${r.ip}')">
                            <i class="fa-solid fa-lock-open"></i> Revoke
                        </button>
                    </td>
                </tr>
            `;
        });
        firewallTableBody.innerHTML = html;
        
    } catch (e) {
        console.error("Failed to fetch firewall rules", e);
    }
}

// Revoke Specific Block
async function revokeBlock(ip) {
    try {
        const response = await fetch('/api/firewall/revoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const res = await response.json();
        if (res.success) {
            activeBlocks.delete(ip);
            // Redraw immediately
            checkFirewallRules();
        }
    } catch (e) {
        console.error("Failed to revoke block", e);
    }
}

// Connect to EventSource (SSE) Alerts Stream
let sseSource = null;

function connectAlertsStream() {
    if (sseSource) {
        sseSource.close();
    }
    
    sseSource = new EventSource('/api/alerts');
    
    sseSource.onmessage = function(event) {
        const flow = JSON.parse(event.data);
        flowLogsCount++;
        
        // Remove empty table row
        if (alertsEmptyRow) {
            alertsEmptyRow.remove();
        }
        
        // Determine Classification badge styling
        let badgeClass = 'benign';
        if (flow.classification === 'DDOS_FLOOD') badgeClass = 'ddos';
        if (flow.classification === 'BRUTE_FORCE_SPRAY') badgeClass = 'brute';
        if (flow.classification === 'PORT_SCAN') badgeClass = 'portscan';
        
        const badge = `<span class="badge ${badgeClass}">${flow.classification}</span>`;
        
        // Format flow stats
        const flowStats = `Duration: ${flow.duration_ms}ms<br>Packets (F/B): ${flow.fwd_pkts}/${flow.bwd_pkts}<br>Bytes (F/B): ${flow.fwd_bytes}/${flow.bwd_bytes}`;
        
        // Mitigation description
        const mitigation = flow.classification === 'BENIGN'
            ? `<span class="text-green"><i class="fa-solid fa-circle-check"></i> Clean</span>`
            : `<span class="text-red font-semibold"><i class="fa-solid fa-ban animate-pulse"></i> Rule Deployed</span>`;
            
        // Append row to top of the table body
        const newRow = document.createElement('tr');
        newRow.innerHTML = `
            <td class="mono text-muted">${flow.timestamp}</td>
            <td class="mono font-semibold">${flow.src_ip}</td>
            <td class="mono">${flow.dport}</td>
            <td class="mono">${flow.proto}</td>
            <td style="font-size: 0.72rem; line-height: 1.3;" class="mono">${flowStats}</td>
            <td>${badge}</td>
            <td class="mono font-bold">${(flow.confidence * 100).toFixed(2)}%</td>
            <td style="font-size: 0.72rem;">${mitigation}</td>
        `;
        
        alertsTableBody.insertBefore(newRow, alertsTableBody.firstChild);
        
        // Limit logs visible on browser (truncate older rows past 40 to conserve memory)
        if (alertsTableBody.children.length > 40) {
            alertsTableBody.removeChild(alertsTableBody.lastChild);
        }
        
        // Trigger Canvas Particle injection
        spawnNode(flow.src_ip, flow.classification);
        addParticle(flow.src_ip, flow.classification);
        
        // Update Chart variables
        const hasThreat = flow.classification !== 'BENIGN';
        updateChart(liveChartObj ? liveChartObj.data.datasets[0].data[14] : 0.0, hasThreat);
        
        // Update confidence ratings panel
        xgbConf.innerText = `${(flow.confidence * 100).toFixed(1)}%`;
        xgbBar.style.width = `${flow.confidence * 100}%`;
        
        // Shannon Entropy UI update
        if (flow.classification === 'PORT_SCAN') {
            entropyVal.innerText = "2.58";
            entropyBar.style.width = "85%";
            entropyBar.className = "progress-bar red";
        } else {
            // Default random small decay value
            const currentEntropy = parseFloat(entropyVal.innerText);
            let nextEntropy = currentEntropy > 0 ? currentEntropy * 0.8 : 0;
            if (nextEntropy < 0.1) nextEntropy = 0;
            entropyVal.innerText = nextEntropy.toFixed(2);
            entropyBar.style.width = `${(nextEntropy / 3.0) * 100}%`;
            entropyBar.className = "progress-bar cyan";
        }
    };
    
    sseSource.onerror = function() {
        console.warn("SSE disconnected. Reconnecting in 3s...");
        sseSource.close();
        setTimeout(connectAlertsStream, 3000);
    };
}

// Controller Actions Event bindings
btnToggleSniffer.addEventListener('click', async () => {
    try {
        const response = await fetch('/api/sniffer/toggle', { method: 'POST' });
        const data = await response.json();
        checkStatus();
    } catch (e) {
        console.error("Failed to toggle sniffer", e);
    }
});

selectSnifferMode.addEventListener('change', async (e) => {
    const mode = e.target.value;
    try {
        const response = await fetch(`/api/sniffer/mode?mode=${mode}`, { method: 'POST' });
        checkStatus();
    } catch (err) {
        alert("Failed to switch mode: " + err.message);
        checkStatus();
    }
});

// Simulate Injections
async function injectAttack(type) {
    try {
        const response = await fetch('/api/simulate/inject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: type })
        });
        const res = await response.json();
        if (res.success) {
            // Trigger temporary countdown injector visual banner
            simulationBanner.classList.remove('hidden');
            setTimeout(() => {
                simulationBanner.classList.add('hidden');
            }, 12000);
        }
    } catch (e) {
        console.error("Failed to inject simulation", e);
    }
}

btnInjectDdos.addEventListener('click', () => injectAttack('DDOS_FLOOD'));
btnInjectBrute.addEventListener('click', () => injectAttack('BRUTE_FORCE_SPRAY'));

btnClearLogs.addEventListener('click', () => {
    alertsTableBody.innerHTML = `
        <tr id="alerts-empty-row">
            <td colspan="8" class="text-center text-muted">Awaiting network streams. Sniffer is active...</td>
        </tr>`;
    flowLogsCount = 0;
});

// Setup global revoke handler for onclick attribute in dynamically generated HTML
window.revokeBlock = revokeBlock;

// Initialization Calls
initChart();
checkStatus();
connectAlertsStream();

// Regular background polling
setInterval(checkStatus, 1500);
setInterval(checkFirewallRules, 1000);
