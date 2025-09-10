// --------------------- TAB SWITCHING ---------------------
document.querySelectorAll('nav button').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.getElementById(btn.dataset.tab).classList.add('active');
    });
});

// --------------------- GLOBAL SCANNED DEVICES ---------------------
let scannedDevices = [];

// --------------------- NETWORK SCAN ---------------------
document.getElementById('btnScan').addEventListener('click', async () => {
    const btn = document.getElementById('btnScan');
    btn.classList.add('loading');
    btn.textContent = ' Scanning...';

    try {
        const res = await fetch('/api/scan');
        if (!res.ok) throw new Error(`Server error: ${res.status}`);
        const data = await res.json();

        scannedDevices = data.devices || [];
        const tbody = document.querySelector('#scanResults tbody');
        tbody.innerHTML = '';
        scannedDevices.forEach(d => {
            const tr = document.createElement('tr');
            const statusClass = d.status?.toLowerCase() === 'online' ? 'status-online' : 'status-offline';
            tr.innerHTML = `
                <td>${d.ip}</td>
                <td>${d.hostname}</td>
                <td><span class="${statusClass}">${d.status || 'Unknown'}</span></td>
                <td>${d.mac || 'Unknown'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (error) {
        const tbody = document.querySelector('#scanResults tbody');
        tbody.innerHTML = `<tr><td colspan="4" style="color: #ff6666; text-align: center; padding: 20px;">Error: ${error.message}</td></tr>`;
    }

    btn.classList.remove('loading');
    btn.textContent = ' Start Scan';
});

// --------------------- PORT SCANNER ---------------------
document.getElementById('btnPorts').addEventListener('click', async () => {
    const ip = document.getElementById('ipPort').value.trim();
    if (!ip) return alert('Please enter an IP address');

    const btn = document.getElementById('btnPorts');
    btn.classList.add('loading');

    const output = document.getElementById('portResults');
    output.innerHTML = `Starting port scan on ${ip}...\n\n`;

    try {
        const res = await fetch(`/api/ports/${ip}`);
        if (!res.ok) throw new Error(`Server error: ${res.status}`);
        const data = await res.json();

        output.innerHTML = `Port Scan Results for ${ip}\n` + '='.repeat(40) + '\n\n';
        output.innerHTML += JSON.stringify(data, null, 2);
        output.innerHTML += '\n\nScan completed successfully.';
    } catch (error) {
        output.innerHTML = `ERROR: Failed to scan ports on ${ip}\n\n${error.message}`;
    }

    btn.classList.remove('loading');
});

// --------------------- TERMINAL ---------------------
document.getElementById('btnTerminal').addEventListener('click', async () => {
    const cmd = document.getElementById('terminalInput').value.trim();
    if (!cmd) return;

    const output = document.getElementById('terminalOutput');
    output.innerHTML += `\n$ ${cmd}\n`;

    try {
        const res = await fetch(`/api/terminal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: cmd })
        });
        if (!res.ok) throw new Error(`Server error: ${res.status}`);
        const data = await res.json();

        if (data.success) {
            output.innerHTML += (data.output || 'No output') + '\n';
        } else {
            output.innerHTML += `Error: ${data.output || 'Unknown error'}\n`;
        }
    } catch (error) {
        output.innerHTML += `ERROR: ${error.message}\n`;
    }

    output.scrollTop = output.scrollHeight;
    document.getElementById('terminalInput').value = '';
});

// --------------------- AI ANALYSIS ---------------------
document.getElementById('btnAnalyze').addEventListener('click', async () => {
    const output = document.getElementById('analysisOutput');
    output.innerHTML += '\nAnalyzing network...\nPlease wait...\n';

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ devices: scannedDevices })
        });
        if (!res.ok) throw new Error(`Server error: ${res.status}`);
        const data = await res.json();
        output.innerHTML += (data.analysis || 'No analysis returned') + '\n';
    } catch (error) {
        output.innerHTML += `ERROR: ${error.message}\n`;
    }

    output.scrollTop = output.scrollHeight;

    // Update charts and map
    updateCharts(scannedDevices);
    updateMap(scannedDevices);
});

// --------------------- CHARTS ---------------------
const lineCtx = document.getElementById('lineChart').getContext('2d');
const lineChart = new Chart(lineCtx, {
    type: 'line',
    data: { labels: [], datasets: [{ label: 'Network Traffic (MB)', data: [], borderColor:'#ff0000', backgroundColor:'rgba(255,0,0,0.1)', tension:0.3, fill:true }] },
    options: {
        responsive: true,
        plugins: { legend: { labels: { color:'#00ff00' } } },
        scales: {
            x: { ticks: { color:'#00ff00' }, grid: { color:'#111' } },
            y: { ticks: { color:'#00ff00' }, grid: { color:'#111' } }
        }
    }
});

const barCtx = document.getElementById('barChart').getContext('2d');
const barChart = new Chart(barCtx, {
    type: 'bar',
    data: { labels: [], datasets: [{ label:'Open Ports', data:[], backgroundColor:'#ff0000' }] },
    options: {
        responsive: true,
        plugins: { legend: { labels: { color:'#00ff00' } } },
        scales: {
            x: { ticks: { color:'#00ff00' }, grid: { color:'#111' } },
            y: { ticks: { color:'#00ff00' }, grid: { color:'#111' } }
        }
    }
});

// --------------------- LEAFLET MAP ---------------------
const map = L.map('worldMap').setView([20,0], 2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
    subdomains: 'abcd',
    maxZoom: 19,
    detectRetina: true
}).addTo(map);

let deviceMarkers = [];

function updateMap(devices) {
    deviceMarkers.forEach(m => map.removeLayer(m));
    deviceMarkers = [];

    devices.forEach((d, i) => {
        const coords = d.coords || [20 + i*5, 0 + i*5];
        const marker = L.marker(coords).addTo(map).bindPopup(`<b>${d.hostname || d.ip}</b>`);
        deviceMarkers.push(marker);
    });

    if(devices.length > 0) map.setView(deviceMarkers[0].getLatLng(), 3);
}

// --------------------- UPDATE CHARTS FUNCTION ---------------------
function updateCharts(devices) {
    lineChart.data.labels = devices.map(d => d.hostname || d.ip);
    lineChart.data.datasets[0].data = devices.map(() => Math.floor(Math.random()*100));
    lineChart.update();

    barChart.data.labels = devices.map(d => d.hostname || d.ip);
    barChart.data.datasets[0].data = devices.map(() => Math.floor(Math.random()*10));
    barChart.update();
}

// --------------------- CLEAR FUNCTIONS ---------------------
function clearScanResults() {
    document.querySelector('#scanResults tbody').innerHTML = `<tr><td colspan="4" style="text-align:center;color:#666;padding:40px;">Click "Start Scan" to discover network devices</td></tr>`;
    scannedDevices = [];
}
function clearPortResults() { document.getElementById('portResults').innerHTML = 'Ready to scan ports on target device...\nUsage: Enter target IP address and click "Scan Ports"'; }
function clearTerminal() { document.getElementById('terminalOutput').innerHTML = 'Welcome to Kali Linux Terminal\n\nAvailable commands:\n• ping [host]\n• nslookup [domain]\n• traceroute [host]\n• netstat\n• ifconfig\n\nType your command above and press Execute...'; }
function clearAnalysis() { document.getElementById('analysisOutput').innerHTML = 'AI Network Analysis Engine Ready\n\nClick "Analyze Network" to start comprehensive analysis...'; }

// --------------------- Animated Banner Flicker ---------------------
const banner = document.getElementById('animatedBanner');
function flickerBanner() {
    const colors = ['#00ff00', '#66ff66', '#ff0000', '#ffffff', '#ff66ff'];
    banner.style.color = colors[Math.floor(Math.random() * colors.length)];
    banner.style.textShadow = `0 0 ${Math.floor(Math.random()*15)+2}px ${colors[Math.floor(Math.random() * colors.length)]}`;
}
setInterval(flickerBanner, 400);
