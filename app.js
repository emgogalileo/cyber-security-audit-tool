/**
 * Cyber Security Audit Tool — Frontend Logic
 *
 * - Live threat counter updates (blocked attempts, active nodes)
 * - Dynamic log table with new events injected every 2s
 * - "Scan Now" button triggers a simulated vulnerability scan
 * - Alert state badge changes when critical threat detected
 */

document.addEventListener('DOMContentLoaded', () => {
    const rand     = (min, max) => Math.random() * (max - min) + min;
    const randInt  = (min, max) => Math.floor(rand(min, max));
    const randIP   = () => `${randInt(1,255)}.${randInt(1,255)}.${randInt(1,255)}.${randInt(1,255)}`;

    // ── DOM refs ───────────────────────────────────────────────────────────────
    const blockedVal   = document.querySelector('.warning-box .stat-value');
    const nodesVal     = document.querySelectorAll('.stat-box')[2]?.querySelector('.stat-value');
    const logTable     = document.querySelector('.log-table');
    const statusIndicator = document.querySelector('.pulsing-dot');
    const statusText   = document.querySelector('.status-indicator span');
    const vulnVal      = document.querySelectorAll('.stat-box')[0]?.querySelector('.stat-value');
    const btnScan      = document.getElementById('btn-scan');

    let blockedCount = 24;
    let threatDetected = false;

    // ── Event types for simulation ─────────────────────────────────────────────
    const EVENTS = [
        { msg: 'Login Exitoso (Admin)',       status: 'success', label: 'Permitido',  severity: 'low'  },
        { msg: 'Fuerza Bruta Detectada',      status: 'danger',  label: 'Bloqueado',  severity: 'high' },
        { msg: 'Escaneo de Puertos',          status: 'warning', label: 'Mitigado',   severity: 'med'  },
        { msg: 'Token JWT Inválido',          status: 'danger',  label: 'Bloqueado',  severity: 'high' },
        { msg: 'Acceso API Autorizado',       status: 'success', label: 'Permitido',  severity: 'low'  },
        { msg: 'Intento SQL Injection',       status: 'danger',  label: 'Bloqueado',  severity: 'high' },
        { msg: 'Validación CORS Fallida',     status: 'warning', label: 'Rechazado',  severity: 'med'  },
        { msg: 'Health Check Exitoso',        status: 'success', label: 'Permitido',  severity: 'low'  },
    ];

    // ── Add log row ────────────────────────────────────────────────────────────
    const MAX_ROWS = 6; // excluding header

    const addLogRow = (event, ip) => {
        const now = new Date();
        const time = now.toTimeString().substring(0, 8);

        const row = document.createElement('div');
        row.className = 'log-row';
        row.style.animation = 'fadeIn 0.4s ease-in';
        row.innerHTML = `
            <div class="time">${time}</div>
            <div>${event.msg}</div>
            <div class="ip">${ip}</div>
            <div><span class="status-badge ${event.status}">${event.label}</span></div>`;

        // Insert after header row
        const header = logTable.querySelector('.log-row.header');
        logTable.insertBefore(row, header.nextSibling);

        // Remove old rows beyond limit
        const rows = logTable.querySelectorAll('.log-row:not(.header)');
        if (rows.length > MAX_ROWS) {
            logTable.removeChild(rows[rows.length - 1]);
        }

        // Update blocked counter on high-severity
        if (event.severity === 'high') {
            blockedCount++;
            blockedVal.innerHTML = `${blockedCount} <span class="stat-label">Hoy</span>`;
            triggerThreatAlert();
        }
    };

    // ── Threat alert logic ─────────────────────────────────────────────────────
    const triggerThreatAlert = () => {
        statusIndicator.classList.remove('safe');
        statusIndicator.classList.add('danger');
        statusText.textContent = 'Amenaza Detectada';
        threatDetected = true;

        // Auto-clear after 6s
        setTimeout(() => {
            statusIndicator.classList.remove('danger');
            statusIndicator.classList.add('safe');
            statusText.textContent = 'Sistema Seguro';
            threatDetected = false;
        }, 6000);
    };

    // ── Main event loop ────────────────────────────────────────────────────────
    setInterval(() => {
        const event = EVENTS[randInt(0, EVENTS.length)];
        const ip    = randIP();
        addLogRow(event, ip);
    }, 2200);

    // ── Scan Now button ────────────────────────────────────────────────────────
    if (btnScan) {
        btnScan.addEventListener('click', () => {
            btnScan.textContent = '🔍 Escaneando…';
            btnScan.disabled = true;

            let step = 0;
            const steps = [
                () => addLogRow({ msg:'Scan: Verificando puertos abiertos…', status:'warning', label:'Scanning', severity:'low' }, '127.0.0.1'),
                () => addLogRow({ msg:'Scan: Revisando certificados TLS…',   status:'warning', label:'Scanning', severity:'low' }, '127.0.0.1'),
                () => addLogRow({ msg:'Scan: Analizando cabeceras HTTP…',     status:'warning', label:'Scanning', severity:'low' }, '127.0.0.1'),
                () => {
                    const vulns = randInt(0, 3);
                    if (vulnVal) vulnVal.innerHTML = `${vulns} <span class="stat-label">Críticas</span>`;
                    addLogRow({
                        msg: vulns > 0 ? `Scan completo — ${vulns} vulnerabilidad(es) encontrada(s)` : 'Scan completo — Sin vulnerabilidades críticas',
                        status: vulns > 0 ? 'danger' : 'success',
                        label: vulns > 0 ? 'Alerta' : 'Limpio',
                        severity: vulns > 0 ? 'high' : 'low',
                    }, '127.0.0.1');
                    btnScan.textContent = 'Scan Now';
                    btnScan.disabled = false;
                },
            ];

            const runStep = () => {
                if (step < steps.length) {
                    steps[step]();
                    step++;
                    setTimeout(runStep, 900);
                }
            };
            runStep();
        });
    }
});
