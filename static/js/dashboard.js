
"use strict";

/* =========================================================
   DASHBOARD.JS
   Autonomous Threat Hunting System
   ========================================================= */


/* =========================================================
   GLOBAL VARIABLES
========================================================= */

let severityChart = null;
let topIpsChart = null;
let liveThreatChart = null;

let liveThreatHistory = [];
let liveThreatLabels = [];

let liveRefreshTimer = null;
let liveRefreshInProgress = false;


/* =========================================================
   SAFE NUMBER
========================================================= */

function safeNumber(value) {

    const number = Number(value);

    return Number.isFinite(number)
        ? number
        : 0;
}


/* =========================================================
   GET ELEMENT
========================================================= */

function getElement(id) {

    return document.getElementById(id);
}


/* =========================================================
   SET TEXT
========================================================= */

function setText(id, value) {

    const element = getElement(id);

    if (element) {
        element.textContent = value;
    }
}


/* =========================================================
   ESCAPE HTML
========================================================= */

function escapeHtml(value) {

    const div = document.createElement("div");

    div.textContent = value ?? "";

    return div.innerHTML;
}


/* =========================================================
   DARK / LIGHT MODE
========================================================= */

function initializeTheme() {

    const themeToggle =
        getElement("themeToggle");

    const themeIcon =
        getElement("themeIcon");

    const themeText =
        getElement("themeText");


    function applyTheme(theme) {

        if (theme === "dark") {

            document.body.classList.add(
                "dark-mode"
            );

            if (themeIcon) {

                themeIcon.className =
                    "fa-solid fa-sun";
            }

            if (themeText) {

                themeText.textContent =
                    "Light Mode";
            }

        } else {

            document.body.classList.remove(
                "dark-mode"
            );

            if (themeIcon) {

                themeIcon.className =
                    "fa-solid fa-moon";
            }

            if (themeText) {

                themeText.textContent =
                    "Dark Mode";
            }
        }
    }


    const savedTheme =
        localStorage.getItem(
            "ath-theme"
        );


    applyTheme(
        savedTheme || "light"
    );


    if (themeToggle) {

        themeToggle.addEventListener(
            "click",
            function () {

                const dark =
                    document.body.classList.contains(
                        "dark-mode"
                    );


                const newTheme =
                    dark
                        ? "light"
                        : "dark";


                localStorage.setItem(
                    "ath-theme",
                    newTheme
                );


                applyTheme(
                    newTheme
                );

            }
        );
    }
}


/* =========================================================
   THREAT OVERVIEW
========================================================= */

function updateThreatOverview(data) {

    const critical =
        safeNumber(data.critical);

    const high =
        safeNumber(data.high);

    const medium =
        safeNumber(data.medium);

    const low =
        safeNumber(data.low);


    setText(
        "tiCritical",
        critical
    );

    setText(
        "tiHigh",
        high
    );

    setText(
        "tiMedium",
        medium
    );

    setText(
        "tiLow",
        low
    );


    updateSeverityBars(
        low,
        medium,
        high,
        critical
    );
}


/* =========================================================
   SEVERITY BARS
========================================================= */

function updateSeverityBars(
    low,
    medium,
    high,
    critical
) {

    const values = [
        low,
        medium,
        high,
        critical
    ];


    const maximum =
        Math.max(
            ...values,
            0
        );


    const severities = [
        "Low",
        "Medium",
        "High",
        "Critical"
    ];


    severities.forEach(
        function (severity, index) {

            const value =
                safeNumber(
                    values[index]
                );


            setText(
                "severity" + severity,
                value
            );


            const bar =
                getElement(
                    "severity" +
                    severity +
                    "Bar"
                );


            if (bar) {

                const percentage =
                    maximum > 0
                        ? (
                            value /
                            maximum
                          ) * 100
                        : 0;


                bar.style.width =
                    Math.max(
                        0,
                        Math.min(
                            100,
                            percentage
                        )
                    ) + "%";
            }

        }
    );
}


/* =========================================================
   SYSTEM METRICS
========================================================= */

function updateSystemMetrics(data) {

    setText(
        "tiTotalThreats",
        safeNumber(data.total)
    );


    setText(
        "tiOpenThreats",
        safeNumber(data.open)
    );


    setText(
        "tiCorrelated",
        safeNumber(data.correlated)
    );


    setText(
        "tiLlmAnalyzed",
        safeNumber(data.llmAnalyzed)
    );


    setText(
        "tiMitreMapped",
        safeNumber(data.mitreMapped)
    );
}


/* =========================================================
   DETECTION CONFIDENCE
========================================================= */

function updateConfidence(value) {

    let confidence =
        safeNumber(value);


    confidence =
        Math.max(
            0,
            Math.min(
                100,
                confidence
            )
        );


    setText(
        "tiConfidence",
        Math.round(
            confidence
        ) + "%"
    );


    const ring =
        getElement(
            "confidenceRing"
        );


    if (ring) {

        ring.style.setProperty(
            "--confidence",
            confidence + "%"
        );
    }
}


/* =========================================================
   UPDATE SUSPICIOUS IPS
========================================================= */

function updateSuspiciousIps(items) {

    const tbody =
        getElement(
            "suspiciousIpRows"
        );


    if (!tbody) {
        return;
    }


    tbody.innerHTML = "";


    if (
        !Array.isArray(items)
        ||
        items.length === 0
    ) {

        tbody.innerHTML = `

            <tr>

                <td
                    colspan="3"
                    class="ti-empty"
                >
                    No suspicious IPs detected
                </td>

            </tr>

        `;

        return;
    }


    items
        .slice(0, 5)
        .forEach(
            function (item) {

                const row =
                    document.createElement(
                        "tr"
                    );


                const ip =
                    item.ip ??
                    item.address ??
                    "-";


                const events =
                    safeNumber(
                        item.events ??
                        item.count
                    );


                const risk =
                    item.risk ??
                    "HIGH";


                row.innerHTML = `

                    <td>
                        <code></code>
                    </td>

                    <td></td>

                    <td>
                        <span
                            class="risk-badge high"
                        ></span>
                    </td>

                `;


                row
                    .querySelector("code")
                    .textContent =
                    ip;


                row.children[1]
                    .textContent =
                    events;


                row
                    .querySelector(
                        ".risk-badge"
                    )
                    .textContent =
                    risk;


                tbody.appendChild(
                    row
                );

            }
        );
}


/* =========================================================
   UPDATE AUTOMATED RESPONSE
========================================================= */

function updateResponseList(items) {

    const container =
        getElement(
            "responseList"
        );


    if (!container) {
        return;
    }


    container.innerHTML = "";


    if (
        !Array.isArray(items)
        ||
        items.length === 0
    ) {

        const empty =
            document.createElement(
                "div"
            );


        empty.className =
            "ti-empty";


        empty.textContent =
            "No recent alerts";


        container.appendChild(
            empty
        );


        return;
    }


    items
        .slice(0, 5)
        .forEach(
            function (item) {

                const wrapper =
                    document.createElement(
                        "div"
                    );


                wrapper.className =
                    "response-item";


                const main =
                    document.createElement(
                        "div"
                    );


                main.className =
                    "response-main";


                const title =
                    document.createElement(
                        "strong"
                    );


                title.textContent =
                    item.title ??
                    "Threat detected";


                const time =
                    document.createElement(
                        "small"
                    );


                time.textContent =
                    item.time ??
                    item.created_at ??
                    "--:--:--";


                main.appendChild(
                    title
                );


                main.appendChild(
                    time
                );


                const severity =
                    document.createElement(
                        "span"
                    );


                const severityValue =
                    String(
                        item.severity ??
                        "MEDIUM"
                    );


                severity.className =
                    "severity-badge " +
                    severityValue.toLowerCase();


                severity.textContent =
                    severityValue;


                wrapper.appendChild(
                    main
                );


                wrapper.appendChild(
                    severity
                );


                container.appendChild(
                    wrapper
                );

            }
        );
}


/* =========================================================
   LIVE THREAT CHART
========================================================= */

function createLiveThreatChart() {

    const canvas =
        getElement(
            "liveThreatChart"
        );


    if (
        !canvas
        ||
        typeof Chart === "undefined"
    ) {

        console.warn(
            "Chart.js is not loaded."
        );

        return;
    }


    const context =
        canvas.getContext(
            "2d"
        );


    liveThreatChart =
        new Chart(
            context,
            {
                type: "line",

                data: {

                    labels:
                        liveThreatLabels,

                    datasets: [

                        {

                            label:
                                "Threats",

                            data:
                                liveThreatHistory,

                            borderWidth:
                                2,

                            tension:
                                0.35,

                            fill:
                                true,

                            pointRadius:
                                2,

                            pointHoverRadius:
                                5

                        }

                    ]

                },

                options: {

                    responsive:
                        true,

                    maintainAspectRatio:
                        false,

                    animation:
                        {
                            duration:
                                300
                        },

                    plugins: {

                        legend:
                            {
                                display:
                                    false
                            }

                    },

                    scales: {

                        x: {

                            grid:
                                {
                                    display:
                                        false
                                },

                            ticks:
                                {
                                    maxTicksLimit:
                                        8
                                }

                        },

                        y: {

                            beginAtZero:
                                true,

                            ticks:
                                {
                                    precision:
                                        0
                                }

                        }

                    }

                }

            }
        );
}


/* =========================================================
   ADD LIVE THREAT POINT
========================================================= */

function addLiveThreatPoint(
    total,
    time = new Date()
) {

    const label =
        time.toLocaleTimeString(
            [],
            {
                hour:
                    "2-digit",

                minute:
                    "2-digit",

                second:
                    "2-digit"
            }
        );


    liveThreatLabels.push(
        label
    );


    liveThreatHistory.push(
        safeNumber(total)
    );


    const maxPoints =
        20;


    while (
        liveThreatHistory.length
        > maxPoints
    ) {

        liveThreatHistory.shift();
    }


    while (
        liveThreatLabels.length
        > maxPoints
    ) {

        liveThreatLabels.shift();
    }
}


/* =========================================================
   RENDER LIVE CHART
========================================================= */

function renderLiveThreatChart() {

    if (!liveThreatChart) {
        return;
    }


    liveThreatChart.data.labels =
        liveThreatLabels;


    liveThreatChart.data.datasets[0].data =
        liveThreatHistory;


    liveThreatChart.update(
        "none"
    );


    const empty =
        getElement(
            "liveThreatEmpty"
        );


    if (empty) {

        empty.style.display =
            liveThreatHistory.length
                ? "none"
                : "flex";
    }
}


/* =========================================================
   EXTRACT DASHBOARD DATA
========================================================= */

function extractDashboardData(
    documentObject
) {

    function readValue(id) {

        const element =
            documentObject.getElementById(
                id
            );


        if (!element) {
            return 0;
        }


        return safeNumber(
            element.textContent
        );
    }


    const suspiciousIps =
        [];


    const suspiciousRows =
        documentObject.querySelectorAll(
            "#suspiciousIpRows tr"
        );


    suspiciousRows.forEach(
        function (row) {

            const cells =
                row.querySelectorAll(
                    "td"
                );


            if (
                cells.length < 3
            ) {
                return;
            }


            const ip =
                cells[0]
                    .textContent
                    .trim();


            const events =
                safeNumber(
                    cells[1]
                        .textContent
                        .trim()
                );


            const risk =
                cells[2]
                    .textContent
                    .trim();


            if (
                ip
                &&
                ip !==
                    "No suspicious IPs detected"
            ) {

                suspiciousIps.push(
                    {
                        ip:
                            ip,

                        events:
                            events,

                        risk:
                            risk
                    }
                );
            }

        }
    );


    const responses =
        [];


    documentObject
        .querySelectorAll(
            "#responseList .response-item"
        )
        .forEach(
            function (node) {

                const title =
                    node.querySelector(
                        ".response-main strong"
                    );


                const time =
                    node.querySelector(
                        ".response-main small"
                    );


                const severity =
                    node.querySelector(
                        ".severity-badge"
                    );


                responses.push(
                    {

                        title:
                            title
                                ? title
                                    .textContent
                                    .trim()
                                : "Threat detected",

                        time:
                            time
                                ? time
                                    .textContent
                                    .trim()
                                : "--:--:--",

                        severity:
                            severity
                                ? severity
                                    .textContent
                                    .trim()
                                : "MEDIUM"

                    }
                );

            }
        );


    return {

        critical:
            readValue(
                "tiCritical"
            ),

        high:
            readValue(
                "tiHigh"
            ),

        medium:
            readValue(
                "tiMedium"
            ),

        low:
            readValue(
                "tiLow"
            ),

        total:
            readValue(
                "tiTotalThreats"
            ),

        open:
            readValue(
                "tiOpenThreats"
            ),

        correlated:
            readValue(
                "tiCorrelated"
            ),

        llmAnalyzed:
            readValue(
                "tiLlmAnalyzed"
            ),

        mitreMapped:
            readValue(
                "tiMitreMapped"
            ),

        confidence:
            readValue(
                "tiConfidence"
            ),

        suspiciousIps:
            suspiciousIps,

        responses:
            responses
    };
}


/* =========================================================
   UPDATE DASHBOARD
========================================================= */

function updateDashboard(
    data
) {

    updateThreatOverview(
        data
    );


    updateSystemMetrics(
        data
    );


    updateConfidence(
        data.confidence
    );


    updateSuspiciousIps(
        data.suspiciousIps
    );


    updateResponseList(
        data.responses
    );
}


/* =========================================================
   LIVE STATUS
========================================================= */

function setLiveStatus(
    connected,
    message
) {

    const status =
        getElement(
            "liveThreatStatus"
        );


    const updateText =
        getElement(
            "liveUpdateText"
        );


    if (status) {

        status.textContent =
            message;
    }


    if (updateText) {

        updateText.textContent =
            connected
                ? "Connected"
                : "Reconnecting";
    }
}


/* =========================================================
   REFRESH LIVE DATA
========================================================= */

async function refreshLiveData() {

    if (
        liveRefreshInProgress
    ) {

        return;
    }


    liveRefreshInProgress =
        true;


    try {

        const response =
            await fetch(
                window.location.href,
                {

                    method:
                        "GET",

                    headers:
                        {
                            "X-Requested-With":
                                "XMLHttpRequest",

                            "Accept":
                                "text/html"
                        },

                    cache:
                        "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                "HTTP " +
                response.status
            );
        }


        const html =
            await response.text();


        const documentObject =
            new DOMParser()
                .parseFromString(
                    html,
                    "text/html"
                );


        const data =
            extractDashboardData(
                documentObject
            );


        updateDashboard(
            data
        );


        addLiveThreatPoint(
            data.total
        );


        renderLiveThreatChart();


        const now =
            new Date();


        const time =
            now.toLocaleTimeString(
                [],
                {
                    hour:
                        "2-digit",

                    minute:
                        "2-digit",

                    second:
                        "2-digit"
                }
            );


        setLiveStatus(
            true,
            "Live monitoring enabled · last update " +
            time
        );


    } catch (error) {

        console.warn(
            "Live threat update failed:",
            error
        );


        setLiveStatus(
            false,
            "Live monitoring reconnecting..."
        );

    } finally {

        liveRefreshInProgress =
            false;
    }
}


/* =========================================================
   START LIVE MONITORING
========================================================= */

function startLiveMonitoring() {

    if (
        liveRefreshTimer
    ) {

        clearInterval(
            liveRefreshTimer
        );
    }


    /*
       Dashboard updates every 5 seconds.
       The page itself is NOT reloaded.
    */

    liveRefreshTimer =
        setInterval(
            refreshLiveData,
            5000
        );


    refreshLiveData();
}


/* =========================================================
   STOP LIVE MONITORING
========================================================= */

function stopLiveMonitoring() {

    if (
        liveRefreshTimer
    ) {

        clearInterval(
            liveRefreshTimer
        );


        liveRefreshTimer =
            null;
    }
}


/* =========================================================
   SECURITY DETAILS TITLE
========================================================= */

function getSecurityTitle(
    type
) {

    const titles = {

        threat:
            "All Threats",

        open:
            "Open Threats",

        critical:
            "Critical Threats",

        failed:
            "Failed Login Attempts",

        login:
            "Failed Login Attempts",

        suspicious:
            "Suspicious Logins",

        brute_force:
            "Brute Force Attacks",

        port_scan:
            "Port Scan Activity",

        sql_injection:
            "SQL Injection Attempts",

        command_injection:
            "Command Injection Attempts",

        privilege_escalation:
            "Privilege Escalation",

        malware:
            "Malware Detections",

        suspicious_ip:
            "Suspicious IP Activity",

        threat_intelligence:
            "Threat Intelligence Matches"
    };


    return (
        titles[type]
        ||
        "Security Details"
    );
}


/* =========================================================
   OPEN SECURITY DETAILS
========================================================= */

async function openSecurityDetails(
    type
) {

    const modalElement =
        getElement(
            "securityDetailsModal"
        );


    if (!modalElement) {
        return;
    }


    const title =
        getElement(
            "securityDetailsTitle"
        );


    const body =
        getElement(
            "securityDetailsBody"
        );


    if (title) {

        title.textContent =
            getSecurityTitle(
                type
            );
    }


    if (body) {

        body.innerHTML = `

            <tr>

                <td
                    colspan="5"
                    class="details-empty"
                >

                    Loading security details...

                </td>

            </tr>

        `;
    }


    if (
        typeof bootstrap === "undefined"
    ) {

        console.error(
            "Bootstrap is not loaded."
        );

        return;
    }


    const modal =
        bootstrap.Modal
            .getOrCreateInstance(
                modalElement
            );


    modal.show();


    try {

        const response =
            await fetch(
                "/api/threats/details?type=" +
                encodeURIComponent(type),
                {

                    method:
                        "GET",

                    headers:
                        {
                            "X-Requested-With":
                                "XMLHttpRequest",

                            "Accept":
                                "application/json"
                        }
                }
            );


        if (!response.ok) {

            throw new Error(
                "HTTP " +
                response.status
            );
        }


        const data =
            await response.json();


        renderSecurityDetails(
            data
        );


    } catch (error) {

        console.error(
            "Security detail request failed:",
            error
        );


        if (body) {

            body.innerHTML = `

                <tr>

                    <td
                        colspan="5"
                        class="details-empty"
                    >

                        Security detail data is
                        currently unavailable.

                    </td>

                </tr>

            `;
        }
    }
}


/* =========================================================
   RENDER SECURITY DETAILS
========================================================= */

function renderSecurityDetails(
    data
) {

    const body =
        getElement(
            "securityDetailsBody"
        );


    if (!body) {
        return;
    }


    const items =
        Array.isArray(data)
            ? data
            : (
                Array.isArray(
                    data.threats
                )
                    ? data.threats
                    : []
            );


    const total =
        items.length;


    const open =
        items.filter(
            function (item) {

                return String(
                    item.status ?? ""
                )
                    .toLowerCase()
                    === "open";

            }
        ).length;


    const critical =
        items.filter(
            function (item) {

                return String(
                    item.severity ?? ""
                )
                    .toLowerCase()
                    === "critical";

            }
        ).length;


    setText(
        "detailTotal",
        total
    );


    setText(
        "detailOpen",
        open
    );


    setText(
        "detailCritical",
        critical
    );


    body.innerHTML =
        "";


    if (
        items.length === 0
    ) {

        body.innerHTML = `

            <tr>

                <td
                    colspan="5"
                    class="details-empty"
                >

                    No security events found.

                </td>

            </tr>

        `;

        return;
    }


    items.forEach(
        function (item) {

            const row =
                document.createElement(
                    "tr"
                );


            const title =
                item.title ??
                item.name ??
                "Security Event";


            const severity =
                item.severity ??
                "Unknown";


            const sourceIp =
                item.source_ip ??
                item.ip ??
                item.source ??
                "-";


            const status =
                item.status ??
                "-";


            const created =
                item.created_at ??
                item.created ??
                "-";


            row.innerHTML = `

                <td></td>
                <td></td>
                <td></td>
                <td></td>
                <td></td>

            `;


            row.children[0]
                .textContent =
                title;


            row.children[1]
                .textContent =
                severity;


            row.children[2]
                .textContent =
                sourceIp;


            row.children[3]
                .textContent =
                status;


            row.children[4]
                .textContent =
                created;


            body.appendChild(
                row
            );
        }
    );
}


/* =========================================================
   AUTHORIZED USERS
========================================================= */

async function loadAuthorizedUsers() {

    const table =
        getElement(
            "authorizedUsersTable"
        );


    const countElement =
        getElement(
            "authorizedUserCount"
        );


    if (!table) {
        return;
    }


    try {

        const response =
            await fetch(
                "/auth/authorized-users",
                {

                    method:
                        "GET",

                    headers:
                        {
                            "Accept":
                                "application/json"
                        },

                    cache:
                        "no-store"
                }
            );


        const result =
            await response.json();


        if (
            !response.ok
            ||
            !result.success
        ) {

            throw new Error(
                result.message ||
                "Unable to load authorized users."
            );
        }


        const users =
            Array.isArray(
                result.users
            )
                ? result.users
                : [];


        if (countElement) {

            countElement.textContent =
                users.length +
                (
                    users.length === 1
                        ? " User"
                        : " Users"
                );
        }


        if (
            users.length === 0
        ) {

            table.innerHTML = `

                <tr>

                    <td
                        colspan="5"
                        class="empty-table"
                    >

                        <i
                            class="fa-solid fa-users-slash"
                        ></i>

                        No authorized users found.

                    </td>

                </tr>

            `;

            return;
        }


        table.innerHTML =
            "";


        users.forEach(
            function (user, index) {

                const row =
                    document.createElement(
                        "tr"
                    );


                const status =
                    user.status ||
                    (
                        user.used
                            ? "REGISTERED"
                            : "AUTHORIZED"
                    );


                const statusClass =
                    status === "REGISTERED"
                        ? "registered"
                        : "authorized";


                const authorizedDate =
                    user.authorized_at
                        ? new Date(
                            user.authorized_at
                          ).toLocaleString()
                        : "—";


                row.innerHTML = `

                    <td>
                        ${index + 1}
                    </td>

                    <td>

                        <span
                            class="authorized-email"
                        >
                            ${escapeHtml(
                                user.email
                            )}
                        </span>

                    </td>

                    <td>

                        <span
                            class="authorized-status ${statusClass}"
                        >

                            <span
                                class="authorized-status-dot"
                            ></span>

                            ${escapeHtml(
                                status
                            )}

                        </span>

                    </td>

                    <td>

                        ${escapeHtml(
                            authorizedDate
                        )}

                    </td>

                    <td>

                        <button
                            type="button"
                            class="remove-auth-btn"
                            data-email="${escapeHtml(
                                user.email
                            )}"
                            ${user.used ? "disabled" : ""}
                            title="${
                                user.used
                                    ? "Already registered"
                                    : "Remove authorization"
                            }"
                        >

                            <i
                                class="fa-solid fa-trash"
                            ></i>

                        </button>

                    </td>

                `;


                table.appendChild(
                    row
                );
            }
        );


        table
            .querySelectorAll(
                ".remove-auth-btn"
            )
            .forEach(
                function (button) {

                    button.addEventListener(
                        "click",
                        function () {

                            removeAuthorizedUser(
                                this.dataset.email
                            );

                        }
                    );

                }
            );


    } catch (error) {

        console.error(
            "Authorized users error:",
            error
        );


        table.innerHTML = `

            <tr>

                <td
                    colspan="5"
                    class="empty-table text-danger"
                >

                    Unable to load authorized users.

                </td>

            </tr>

        `;
    }
}


/* =========================================================
   REMOVE AUTHORIZED USER
========================================================= */

async function removeAuthorizedUser(
    email
) {

    if (!email) {
        return;
    }


    const confirmed =
        window.confirm(
            "Remove authorization for " +
            email +
            "?"
        );


    if (!confirmed) {
        return;
    }


    try {

        const response =
            await fetch(
                "/auth/authorize-user",
                {

                    method:
                        "DELETE",

                    headers:
                        {
                            "Content-Type":
                                "application/json",

                            "Accept":
                                "application/json"
                        },

                    body:
                        JSON.stringify(
                            {
                                email:
                                    email
                            }
                        )
                }
            );


        const result =
            await response.json();


        if (
            !response.ok
            ||
            !result.success
        ) {

            throw new Error(
                result.message ||
                "Unable to remove authorization."
            );
        }


        alert(
            result.message ||
            "Authorization removed successfully."
        );


        loadAuthorizedUsers();


    } catch (error) {

        console.error(
            "Remove authorization failed:",
            error
        );


        alert(
            error.message ||
            "Unable to remove authorization."
        );
    }
}


/* =========================================================
   AUTHORIZE USER FORM
========================================================= */

function initializeAuthorization() {

    const form =
        getElement(
            "authorizeUserForm"
        );


    const emailInput =
        getElement(
            "userEmail"
        );


    const message =
        getElement(
            "adminMessage"
        );


    const button =
        getElement(
            "authorizeUserButton"
        );


    if (!form) {
        return;
    }


    function showMessage(
        text,
        type
    ) {

        if (!message) {
            return;
        }


        message.textContent =
            text;


        message.className =
            "authorize-message " +
            (
                type === "success"
                    ? "success"
                    : "error"
            );


        message.style.display =
            "block";


        setTimeout(
            function () {

                message.style.display =
                    "none";

            },
            5000
        );
    }


    form.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();


            const email =
                emailInput
                    ? emailInput.value.trim()
                    : "";


            if (!email) {

                showMessage(
                    "Please enter an email address.",
                    "error"
                );

                return;
            }


            if (
                !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
                    .test(email)
            ) {

                showMessage(
                    "Please enter a valid email address.",
                    "error"
                );

                return;
            }


            if (button) {

                button.disabled =
                    true;


                button.innerHTML = `

                    <i
                        class="fa-solid fa-spinner fa-spin"
                    ></i>

                    Authorizing...

                `;
            }


            try {

                const response =
                    await fetch(
                        "/auth/authorize-user",
                        {

                            method:
                                "POST",

                            headers:
                                {
                                    "Content-Type":
                                        "application/json",

                                    "Accept":
                                        "application/json"
                                },

                            body:
                                JSON.stringify(
                                    {
                                        email:
                                            email
                                    }
                                )
                        }
                    );


                const result =
                    await response.json();


                if (
                    !response.ok
                    ||
                    !result.success
                ) {

                    throw new Error(
                        result.message ||
                        "Unable to authorize user."
                    );
                }


                showMessage(
                    result.message ||
                    "User authorized successfully.",
                    "success"
                );


                if (emailInput) {

                    emailInput.value =
                        "";
                }


                await loadAuthorizedUsers();


            } catch (error) {

                console.error(
                    "Authorization failed:",
                    error
                );


                showMessage(
                    error.message ||
                    "Unable to authorize user.",
                    "error"
                );


            } finally {

                if (button) {

                    button.disabled =
                        false;


                    button.innerHTML = `

                        <i
                            class="fa-solid fa-user-check"
                        ></i>

                        Authorize User

                    `;
                }
            }

        }
    );


    loadAuthorizedUsers();
}


/* =========================================================
   SIDEBAR
========================================================= */

function initializeSidebar() {

    const menuButton =
        getElement(
            "sidebarToggle"
        );


    const sidebar =
        document.querySelector(
            ".sidebar"
        );


    const overlay =
        getElement(
            "sidebarOverlay"
        );


    if (
        menuButton
        &&
        sidebar
    ) {

        menuButton.addEventListener(
            "click",
            function () {

                sidebar.classList.toggle(
                    "open"
                );


                if (overlay) {

                    overlay.classList.toggle(
                        "show"
                    );
                }

            }
        );
    }


    if (
        overlay
        &&
        sidebar
    ) {

        overlay.addEventListener(
            "click",
            function () {

                sidebar.classList.remove(
                    "open"
                );


                overlay.classList.remove(
                    "show"
                );

            }
        );
    }


    document
        .querySelectorAll(
            ".sidebar-link"
        )
        .forEach(
            function (link) {

                link.addEventListener(
                    "click",
                    function () {

                        if (
                            window.innerWidth <=
                            991
                            &&
                            sidebar
                        ) {

                            sidebar.classList.remove(
                                "open"
                            );


                            if (overlay) {

                                overlay.classList.remove(
                                    "show"
                                );
                            }
                        }

                    }
                );
            }
        );


    const currentPath =
        window.location.pathname;


    document
        .querySelectorAll(
            ".sidebar-link"
        )
        .forEach(
            function (link) {

                const href =
                    link.getAttribute(
                        "href"
                    );


                if (
                    href
                    &&
                    href !== "#"
                    &&
                    currentPath === href
                ) {

                    link.classList.add(
                        "active"
                    );
                }

            }
        );
}


/* =========================================================
   DASHBOARD CLOCK
========================================================= */

function initializeClock() {

    const clock =
        getElement(
            "dashboardClock"
        );


    if (!clock) {
        return;
    }


    function updateClock() {

        const now =
            new Date();


        clock.textContent =
            now.toLocaleString(
                [],
                {

                    day:
                        "2-digit",

                    month:
                        "short",

                    year:
                        "numeric",

                    hour:
                        "2-digit",

                    minute:
                        "2-digit",

                    second:
                        "2-digit"
                }
            );
    }


    updateClock();


    setInterval(
        updateClock,
        1000
    );
}


/* =========================================================
   REFRESH DASHBOARD BUTTON
========================================================= */

function initializeRefreshButton() {

    const refreshButton =
        getElement(
            "refreshDashboard"
        );


    if (!refreshButton) {
        return;
    }


    refreshButton.addEventListener(
        "click",
        async function () {

            refreshButton.disabled =
                true;


            const original =
                refreshButton.innerHTML;


            refreshButton.innerHTML = `

                <i
                    class="fa-solid fa-spinner fa-spin"
                ></i>

            `;


            try {

                await refreshLiveData();


            } finally {

                setTimeout(
                    function () {

                        refreshButton.disabled =
                            false;


                        refreshButton.innerHTML =
                            original;

                    },
                    500
                );
            }

        }
    );
}


/* =========================================================
   STAT CARD KEYBOARD ACCESS
========================================================= */

function initializeSecurityCards() {

    document
        .querySelectorAll(
            ".stat-card[data-security-type]"
        )
        .forEach(
            function (card) {

                card.setAttribute(
                    "tabindex",
                    "0"
                );


                card.setAttribute(
                    "role",
                    "button"
                );


                card.addEventListener(
                    "keydown",
                    function (event) {

                        if (
                            event.key ===
                            "Enter"
                            ||
                            event.key ===
                            " "
                        ) {

                            event.preventDefault();


                            const type =
                                card.dataset
                                    .securityType;


                            openSecurityDetails(
                                type
                            );
                        }

                    }
                );
            }
        );
}


/* =========================================================
   SMOOTH INTERNAL NAVIGATION
========================================================= */

function initializeSmoothNavigation() {

    document
        .querySelectorAll(
            'a[href^="#"]'
        )
        .forEach(
            function (link) {

                link.addEventListener(
                    "click",
                    function (event) {

                        const targetId =
                            link.getAttribute(
                                "href"
                            );


                        if (
                            !targetId
                            ||
                            targetId === "#"
                        ) {

                            return;
                        }


                        const target =
                            document.querySelector(
                                targetId
                            );


                        if (!target) {
                            return;
                        }


                        event.preventDefault();


                        target.scrollIntoView(
                            {

                                behavior:
                                    "smooth",

                                block:
                                    "start"
                            }
                        );
                    }
                );
            }
        );
}


/* =========================================================
   CHART INITIALIZATION
========================================================= */

function initializeCharts() {

    if (
        typeof Chart === "undefined"
    ) {

        console.warn(
            "Chart.js is not loaded."
        );

        return;
    }


    /* =====================================================
       SEVERITY CHART
    ===================================================== */

    const severityCanvas =
        getElement(
            "severityChart"
        );


    if (
        severityCanvas
        &&
        !severityChart
    ) {

        const critical =
            safeNumber(
                getElement(
                    "tiCritical"
                )?.textContent
            );


        const high =
            safeNumber(
                getElement(
                    "tiHigh"
                )?.textContent
            );


        const medium =
            safeNumber(
                getElement(
                    "tiMedium"
                )?.textContent
            );


        const low =
            safeNumber(
                getElement(
                    "tiLow"
                )?.textContent
            );


        severityChart =
            new Chart(
                severityCanvas,
                {

                    type:
                        "doughnut",

                    data:
                        {

                            labels:
                                [
                                    "Critical",
                                    "High",
                                    "Medium",
                                    "Low"
                                ],

                            datasets:
                                [
                                    {

                                        data:
                                            [
                                                critical,
                                                high,
                                                medium,
                                                low
                                            ],

                                        borderWidth:
                                            0

                                    }
                                ]
                        },

                    options:
                        {

                            responsive:
                                true,

                            maintainAspectRatio:
                                false,

                            cutout:
                                "70%",

                            plugins:
                                {

                                    legend:
                                        {
                                            position:
                                                "bottom"
                                        }

                                }

                        }

                }
            );
    }


    /* =====================================================
       TOP IPS CHART
    ===================================================== */

    const topIpCanvas =
        getElement(
            "topIpsChart"
        );


    if (
        topIpCanvas
        &&
        !topIpsChart
    ) {

        const labels =
            [];


        const values =
            [];


        document
            .querySelectorAll(
                "#suspiciousIpRows tr"
            )
            .forEach(
                function (row) {

                    const cells =
                        row.querySelectorAll(
                            "td"
                        );


                    if (
                        cells.length < 2
                    ) {

                        return;
                    }


                    labels.push(
                        cells[0]
                            .textContent
                            .trim()
                    );


                    values.push(
                        safeNumber(
                            cells[1]
                                .textContent
                                .trim()
                        )
                    );

                }
            );


        if (
            labels.length > 0
        ) {

            topIpsChart =
                new Chart(
                    topIpCanvas,
                    {

                        type:
                            "bar",

                        data:
                            {

                                labels:
                                    labels,

                                datasets:
                                    [

                                        {

                                            label:
                                                "Events",

                                            data:
                                                values,

                                            borderWidth:
                                                1

                                        }

                                    ]

                            },

                        options:
                            {

                                responsive:
                                    true,

                                maintainAspectRatio:
                                    false,

                                plugins:
                                    {

                                    legend:
                                        {
                                            display:
                                                false
                                        }

                                    },

                                scales:
                                    {

                                        y:
                                            {

                                                beginAtZero:
                                                    true,

                                                ticks:
                                                    {
                                                        precision:
                                                            0
                                                    }

                                            }

                                    }

                            }

                    }
                );
        }
    }


    /* =====================================================
       LIVE THREAT CHART
    ===================================================== */

    createLiveThreatChart();
}


/* =========================================================
   INITIALIZE LIVE THREAT DATA
========================================================= */

function initializeLiveThreatMonitoring() {

    const initialTotal =
        safeNumber(
            getElement(
                "tiTotalThreats"
            )?.textContent
        );


    addLiveThreatPoint(
        initialTotal
    );


    renderLiveThreatChart();


    startLiveMonitoring();
}


/* =========================================================
   DOCUMENT READY
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        initializeTheme();

        initializeSidebar();

        initializeClock();

        initializeRefreshButton();

        initializeSecurityCards();

        initializeSmoothNavigation();

        initializeAuthorization();

        initializeCharts();

        initializeLiveThreatMonitoring();

    }
);


/* =========================================================
   CLEANUP
========================================================= */

window.addEventListener(
    "beforeunload",
    function () {

        stopLiveMonitoring();

    }
);


/* =========================================================
   GLOBAL FUNCTIONS
   Useful when dashboard HTML onclick handlers
   call these functions directly.
========================================================= */

window.openSecurityDetails =
    openSecurityDetails;

window.refreshLiveData =
    refreshLiveData;

window.loadAuthorizedUsers =
    loadAuthorizedUsers;

window.removeAuthorizedUser =
    removeAuthorizedUser;
