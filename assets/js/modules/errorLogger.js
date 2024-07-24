// errorLogger.js

const LOG_LEVELS = {
    INFO: 'INFO',
    WARN: 'WARN',
    ERROR: 'ERROR'
};

export function logError(message, error, level = LOG_LEVELS.ERROR) {
    console.error(`[${level}] ${message}:`, error);

    // 여기에 서버로 에러 로그를 전송하는 코드를 추가할 수 있습니다.
    // 예: sendErrorToServer(message, error, level);
}

export function showUserFriendlyError(message) {
    // 사용자에게 보여줄 친화적인 에러 메시지
    alert(`An error occurred: ${message}\nPlease try again or contact support if the problem persists.`);
}

// 서버로 에러 로그를 전송하는 함수 (실제 구현 필요)
function sendErrorToServer(message, error, level) {
    // 예시 코드:
    // fetch('/log-error', {
    //     method: 'POST',
    //     headers: { 'Content-Type': 'application/json' },
    //     body: JSON.stringify({ message, error: error.toString(), level, timestamp: new Date() })
    // });
}