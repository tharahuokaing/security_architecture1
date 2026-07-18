(() => {
    "use strict";

    /* =========================================================
       ACTIVE FIREWALL ARCHITECTURE SYSTEM REGISTRY LOGS
    ========================================================= */
    const ATTACK_LOGS = [
        { id: "SEC-9081", vector: "SQL Injection Probe", node: "/api/v2/auth/sweep", ip: "185.220.101.5", policy: "Blocked" },
        { id: "SEC-9082", vector: "Rate Limit Violation", node: "/api/v2/ledger/transfer", ip: "45.132.22.84", policy: "Isolated" },
        { id: "SEC-9083", vector: "Suspicious UserAgent Profile", node: "/index.html", ip: "192.168.4.112", policy: "Monitored" },
        { id: "SEC-9084", vector: "Cross-Site Scripting (XSS)", node: "/api/v2/compliance/audit", ip: "91.240.118.49", policy: "Blocked" },
        { id: "SEC-9085", vector: "Session Token Hijack Attempt", node: "/api/v2/auth/guardian", ip: "103.25.190.12", policy: "Blocked" },
        { id: "SEC-9086", vector: "Anomalous ISO 20022 Frame", node: "/api/v2/interbank/clear", ip: "172.56.21.99", policy: "Monitored" }
    ];

    let currentLogFilter = "all";

    /* =========================================================
       THREAT VECTOR RISK CALCULATION PIPELINES
    ========================================================= */
    function recalculateThreatTelemetry() {
        const isolatedCount = ATTACK_LOGS.filter(log => log.policy === "Isolated").length;
        const totalBlocked = ATTACK_LOGS.filter(log => log.policy === "Blocked").length;

        const threatStateEl = document.getElementById("threatStateText");
        const lockoutEl = document.getElementById("lockoutCountText");
        const subtextEl = threatStateEl?.nextElementSibling;

        if (lockoutEl) lockoutEl.textContent = isolatedCount.toString();

        if (threatStateEl && subtextEl) {
            if (isolatedCount > 2) {
                threatStateEl.textContent = "ATTACK IN PROGRESS";
                threatStateEl.style.color = "#f43f5e";
                subtextEl.className = "card-subtext state-danger";
                subtextEl.textContent = "▲ Perimeter rules scaling up countermeasures";
            } else if (isolatedCount > 0) {
                threatStateEl.textContent = "MITIGATING THREATS";
                threatStateEl.style.color = "#f59e0b";
                subtextEl.className = "card-subtext state-warning";
                subtextEl.textContent = "⚠️ Edge routing containing sandbox deviations";
            } else {
                threatStateEl.textContent = "SECURED";
                threatStateEl.style.color = "#10b981";
                subtextEl.className = "card-subtext state-success";
                subtextEl.textContent = "● Zero zero-day exploits active";
            }
        }
    }

    /* =========================================================
       PERIMETER MATRIX COMPONENT DATA GRID RENDERING
    ========================================================= */
    function renderIncidentLedger() {
        const tbody = document.getElementById("securityTableBody");
        if (!tbody) return;

        const mappedDataset = ATTACK_LOGS.filter(log => {
            if (currentLogFilter === "all") return true;
            if (currentLogFilter === "blocked") return log.policy === "Blocked" || log.policy === "Isolated";
            if (currentLogFilter === "monitored") return log.policy === "Monitored";
            return true;
        });

        if (mappedDataset.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#64748b; padding:30px;">Zero incident mutations recorded across targeted pipeline boundaries.</td></tr>`;
            return;
        }

        tbody.innerHTML = mappedDataset.map(log => {
            const policyClass = log.policy.toLowerCase();
            return `
                <tr>
                    <td style="font-weight:600; color:#f43f5e;">${log.id}</td>
                    <td style="font-weight:500;">${log.vector}</td>
                    <td style="color:#38bdf8;">${log.node}</td>
                    <td class="ip-column">${log.ip}</td>
                    <td><span class="mitigation-tag ${policyClass}">${log.policy.toUpperCase()}</span></td>
                </tr>
            `;
        }).join("");
    }

    /* =========================================================
       SOC SECURITY MONITORING SIMULATED CONSOLE STREAMS
    ========================================================= */
    function pushSocConsoleStream(level, logBody) {
        const consoleEl = document.getElementById("socTerminalConsole");
        if (!consoleEl) return;

        const timestampStr = new Date().toISOString().substring(11, 19);
        let levelClass = "level-info";
        if (level === "WARN") levelClass = "level-warn";
        if (level === "ERROR") levelClass = "level-error";

        const newElement = document.createElement("div");
        newElement.className = "terminal-line";
        newElement.innerHTML = `<span class="timestamp">[${timestampStr}]</span><span class="${levelClass}">[${level}]</span> ${logBody}`;

        consoleEl.appendChild(newElement);
        consoleEl.scrollTop = consoleEl.scrollHeight;

        // Prevent console logs memory pool leaks by keeping maximum array trace cap
        while (consoleEl.children.length > 40) {
            consoleEl.removeChild(consoleEl.firstChild);
        }
    }

    function initDynamicSocConsoleTelemetry() {
        const diagnosticTraces = [
            { level: "INFO", message: "SOC Pipeline core scanning daemon started execution." },
            { level: "INFO", message: "Hashing firewall baseline config against checksum rules..." },
            { level: "INFO", message: "Edge perimeter integrity checks resolved successfully." },
            { level: "WARN", message: "WAF intercepted atypical protocol structure from pool routing." },
            { level: "INFO", message: "Synchronizing localized rate throttling token logs..." },
            { level: "ERROR", message: "Hardened perimeter drop configured for target block: 185.220.101.5" }
        ];

        // Process seed trace lines immediately into view allocation map
        diagnosticTraces.forEach((trace, idx) => {
            setTimeout(() => pushSocConsoleStream(trace.level, trace.message), idx * 400);
        });

        // Setup persistent loop task generating low frequency event simulation metrics
        setInterval(() => {
            const r = Math.random();
            if (r > 0.85) {
                pushSocConsoleStream("WARN", "High-frequency transaction probe triggered over network sweeps.");
            } else if (r > 0.70) {
                pushSocConsoleStream("INFO", "Flushing expired token mappings from active sessions guardian.");
            } else if (r > 0.55) {
                pushSocConsoleStream("INFO", "ISO 20022 message layout schema parsed under nominal range.");
            }
        }, 4500);
    }

    /* =========================================================
       EVENT ACTIONS LOGIC REGISTRATION INTERFACE
    ========================================================= */
    document.addEventListener("DOMContentLoaded", () => {
        recalculateThreatTelemetry();
        renderIncidentLedger();
        initDynamicSocConsoleTelemetry();

        // Control segment filter button navigation hooks loops
        const pillsGroup = document.getElementById("securityFilterGroup");
        if (pillsGroup) {
            pillsGroup.addEventListener("click", (e) => {
                const targetPill = e.target.closest(".pill");
                if (!targetPill) return;

                pillsGroup.querySelectorAll(".pill").forEach(p => p.classList.remove("active"));
                targetPill.classList.add("active");

                currentLogFilter = targetPill.getAttribute("data-filter");
                renderIncidentLedger();
            });
        }

        // Script trigger simulations for security patch rollout loops
        document.getElementById("purgeLogsBtn")?.addEventListener("click", () => {
            pushSocConsoleStream("WARN", "Initializing environment hotfix integration run...");
            alert("Security architecture patches compiled. Broadcasting deployment parameters across edge infrastructure nodes.");
            pushSocConsoleStream("INFO", "Hotfix deployment successfully integrated. Checksum matching.");
        });

        // Script trigger simulations for public key rotation updates loops
        document.getElementById("rotateKeysBtn")?.addEventListener("click", () => {
            pushSocConsoleStream("WARN", "Flushing active RSA keys pool. Compiling new asymmetric cipher pairs...");
            alert("Cryptographic infrastructure key rotation sequence completed successfully.");
            pushSocConsoleStream("INFO", "2048-bit vault keys rotated. All subsequent encryption instances verified.");
        });
    });

})();
