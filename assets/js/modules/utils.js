// /assets/js/modules/utils.js

export async function verifyToken(token) {
    // verifyToken 함수 구현
    return new Promise((resolve, reject) => {
        fetch('/verify-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `token=${encodeURIComponent(token)}`
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    const decodedUser = decodeURIComponent(data.username);
                    resolve(decodedUser);
                    // showWelcomeMessage(decodedUser);
                } else {
                    reject('Token verification failed');
                    localStorage.removeItem('token');
                    // showLoginForm();
                }
            })
            .catch(error => {
                console.error('Error during fetch:', error);
                reject('An error occurred during token verification: ' + error);
            });
    });
}

export function getToken() {
    return localStorage.getItem('token');
}

export function setToken(token) {
    localStorage.setItem('token', token);
}

export function removeToken() {
    localStorage.removeItem('token');
}
export async function performItemOperation(endpoint, data, successMessage, errorMessage) {
    // performItemOperation 함수 구현
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }

        const responseData = await response.json();
        if (responseData.success) {
            alert(responseData.message || successMessage);
            loadDriveContent();
        } else {
            throw new Error(responseData.message || errorMessage);
        }
    } catch (error) {
        console.error('Error:', error);
        alert(`${errorMessage}: ${error.message}`);
    }
}