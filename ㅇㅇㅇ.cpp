document.addEventListener('DOMContentLoaded', async () => {
    // ... 기존 코드 ...

    // 로그 컨테이너 생성
    const logContainer = document.createElement('div');
    logContainer.id = 'log-container';
    logContainer.style.cssText = `
        position: fixed;
        bottom: 10px;
        right: 10px;
        width: 300px;
        max-height: 400px;
        overflow-y: auto;
        background: rgba(0,0,0,0.8);
        color: white;
        font-family: monospace;
        padding: 10px;
        z-index: 9999;
        display: none;
        border-radius: 5px;
        box-shadow: 0 0 10px rgba(0,0,0,0.5);
    `;

    // 토글 버튼 생성
    const toggleButton = document.createElement('button');
    toggleButton.textContent = 'Show Logs';
    toggleButton.style.cssText = `
        position: fixed;
        bottom: 10px;
        right: 10px;
        background: #007bff;
        color: white;
        border: none;
        padding: 10px 15px;
        cursor: pointer;
        z-index: 10000;
        border-radius: 5px;
    `;

    // 로그 지우기 버튼 생성
    const clearButton = document.createElement('button');
    clearButton.textContent = 'Clear Logs';
    clearButton.style.cssText = `
        position: absolute;
        top: 5px;
        right: 5px;
        background: #dc3545;
        color: white;
        border: none;
        padding: 5px 10px;
        cursor: pointer;
        border-radius: 3px;
    `;

    // 토글 기능 구현
    let isVisible = false;
    toggleButton.onclick = function () {
        isVisible = !isVisible;
        logContainer.style.display = isVisible ? 'block' : 'none';
        toggleButton.textContent = isVisible ? 'Hide Logs' : 'Show Logs';
    };

    // 로그 지우기 기능 구현
    clearButton.onclick = function () {
        logContainer.innerHTML = '';
        logContainer.appendChild(clearButton);
    };

    logContainer.appendChild(clearButton);
    document.body.appendChild(toggleButton);
    document.body.appendChild(logContainer);

    // console 메소드 오버라이드
    const originalConsole = {
        log: console.log,
        error: console.error,
        warn: console.warn,
        info: console.info
    };

    function logToPage(message, type) {
        const logElement = document.createElement('div');
        logElement.textContent = `[${type.toUpperCase()}] ${message}`;
        logElement.style.cssText = `
            margin-bottom: 5px;
            padding: 5px;
            border-radius: 3px;
            background: ${type === 'error' ? 'rgba(255,0,0,0.2)' : 
                          type === 'warn' ? 'rgba(255,255,0,0.2)' : 
                          'rgba(255,255,255,0.1)'};
        `;
        logContainer.insertBefore(logElement, logContainer.firstChild);
        
        // 로그가 100개를 초과하면 가장 오래된 로그 제거
        if (logContainer.children.length > 101) { // clearButton을 포함하므로 101
            logContainer.removeChild(logContainer.lastChild);
        }
    }

    console.log = function () {
        logToPage(Array.from(arguments).join(' '), 'log');
        originalConsole.log.apply(console, arguments);
    };

    console.error = function () {
        logToPage(Array.from(arguments).join(' '), 'error');
        originalConsole.error.apply(console, arguments);
    };

    console.warn = function () {
        logToPage(Array.from(arguments).join(' '), 'warn');
        originalConsole.warn.apply(console, arguments);
    };

    console.info = function () {
        logToPage(Array.from(arguments).join(' '), 'info');
        originalConsole.info.apply(console, arguments);
    };

    // ... 기존 코드의 나머지 부분 ...
});