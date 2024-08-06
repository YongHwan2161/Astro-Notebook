// logViewer.js

let logContainer, logContent, levelFilter, searchInput, toggleButton;
let isVisible = false;

function createLogViewer() {
    createLogContainer();
    createToggleButton();
    overrideConsoleMethods();
}

function createLogContainer() {
    logContainer = document.createElement('div');
    logContainer.id = 'log-container';
    logContainer.style.cssText = `
        position: fixed;
        bottom: 40px;
        left: 10px;
        width: 400px;
        height: 300px;
        min-width: 300px;
        min-height: 200px;
        overflow: hidden;
        background: rgba(0,0,0,0.8);
        color: white;
        font-family: monospace;
        padding: 10px;
        z-index: 9999;
        display: none;
        border-radius: 5px;
        box-shadow: 0 0 10px rgba(0,0,0,0.5);
        resize: both;
        display: none;
        flex-direction: column;
    `;

    const controlPanel = createControlPanel();
    logContainer.appendChild(controlPanel);

    logContent = document.createElement('div');
    logContent.style.cssText = `
        flex-grow: 1;
        overflow-y: auto;
        padding-right: 5px;
    `;
    logContainer.appendChild(logContent);

    document.body.appendChild(logContainer);
}

function createControlPanel() {
    const controlPanel = document.createElement('div');
    controlPanel.style.cssText = `
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
        padding: 5px;
        background: rgba(255,255,255,0.1);
        border-radius: 3px;
    `;

    levelFilter = createLevelFilter();
    searchInput = createSearchInput();
    const saveButton = createButton('Save', saveLogs);
    const clearButton = createButton('Clear', clearLogs);

    controlPanel.appendChild(levelFilter);
    controlPanel.appendChild(searchInput);
    controlPanel.appendChild(saveButton);
    controlPanel.appendChild(clearButton);

    return controlPanel;
}

function createLevelFilter() {
    const filter = document.createElement('select');
    filter.style.cssText = `
        background: rgba(255,255,255,0.2);
        color: white;
        border: none;
        padding: 3px;
        border-radius: 3px;
    `;
    filter.innerHTML = `
        <option value="all">All</option>
        <option value="log">Log</option>
        <option value="info">Info</option>
        <option value="warn">Warn</option>
        <option value="error">Error</option>
    `;
    filter.onchange = filterLogs;
    return filter;
}

function createSearchInput() {
    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = 'Search logs...';
    input.style.cssText = `
        background: rgba(255,255,255,0.2);
        color: white;
        border: none;
        padding: 3px;
        border-radius: 3px;
        width: 120px;
    `;
    input.oninput = filterLogs;
    return input;
}

function createButton(text, onClick) {
    const button = document.createElement('button');
    button.textContent = text;
    button.style.cssText = `
        background: rgba(255,255,255,0.2);
        color: white;
        border: none;
        padding: 3px 6px;
        border-radius: 3px;
        cursor: pointer;
        font-size: 12px;
    `;
    button.onclick = onClick;
    return button;
}

function createToggleButton() {
    toggleButton = document.createElement('button');
    toggleButton.textContent = 'Show Logs';
    toggleButton.style.cssText = `
        position: fixed;
        bottom: 10px;
        left: 10px;
        background: #007bff;
        color: white;
        border: none;
        padding: 5px 10px;
        cursor: pointer;
        z-index: 10000;
        border-radius: 5px;
    `;
    toggleButton.onclick = toggleLogViewer;
    document.body.appendChild(toggleButton);
}

function toggleLogViewer() {
    isVisible = !isVisible;
    logContainer.style.display = isVisible ? 'flex' : 'none';
    toggleButton.textContent = isVisible ? 'Hide Logs' : 'Show Logs';
}

function saveLogs() {
    const logs = Array.from(logContent.children).map(log => log.textContent).join('\n');
    const blob = new Blob([logs], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'logs.txt';
    a.click();
}

function clearLogs() {
    logContent.innerHTML = '';
}

function filterLogs() {
    const level = levelFilter.value;
    const searchTerm = searchInput.value.toLowerCase();
    Array.from(logContent.children).forEach(log => {
        const logLevel = log.getAttribute('data-level');
        const logText = log.textContent.toLowerCase();
        const levelMatch = level === 'all' || logLevel === level;
        const searchMatch = logText.includes(searchTerm);
        log.style.display = levelMatch && searchMatch ? 'block' : 'none';
    });
}

function logToPage(message, type) {
    const logElement = document.createElement('div');
    logElement.textContent = `[${type.toUpperCase()}] ${message}`;
    logElement.setAttribute('data-level', type);
    logElement.style.cssText = `
        margin-bottom: 5px;
        padding: 5px;
        border-radius: 3px;
        background: ${
            type === 'error' ? 'rgba(255,0,0,0.2)' :
            type === 'warn' ? 'rgba(255,255,0,0.2)' :
            type === 'info' ? 'rgba(0,255,255,0.2)' :
            'rgba(255,255,255,0.1)'
        };
    `;
    logContent.insertBefore(logElement, logContent.firstChild);

    if (logContent.children.length > 1000) {
        logContent.removeChild(logContent.lastChild);
    }

    filterLogs();
}

function overrideConsoleMethods() {
    const originalConsole = {
        log: console.log,
        info: console.info,
        warn: console.warn,
        error: console.error
    };

    ['log', 'info', 'warn', 'error'].forEach(method => {
        console[method] = function () {
            logToPage(Array.from(arguments).join(' '), method);
            originalConsole[method].apply(console, arguments);
        };
    });
}

export { createLogViewer };