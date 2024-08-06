// /assets/js/modules/utils.js
import { loadDriveContent } from './drive.js';

export async function verifyToken(token) {
    try {
        const response = await fetch('/verify-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `token=${encodeURIComponent(token)}`
        });

        if (!response.ok) {
            throw new Error('Network response was not ok ' + response.statusText);
        }

        const data = await response.json();

        if (data.success) {
            const decodedUser = decodeURIComponent(data.username);
            return decodedUser;
        } else {
            throw new Error('Token verification failed');
        }
    } catch (error) {
        console.error('Error during fetch:', error);
        localStorage.removeItem('token');
        throw new Error('An error occurred during token verification: ' + error.message);
    }
}
// export async function verifyToken(token) {
//     // verifyToken 함수 구현
//     return new Promise((resolve, reject) => {
//         fetch('/verify-token', {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/x-www-form-urlencoded'
//             },
//             body: `token=${encodeURIComponent(token)}`
//         })
//             .then(response => {
//                 if (!response.ok) {
//                     throw new Error('Network response was not ok ' + response.statusText);
//                 }
//                 return response.json();
//             })
//             .then(data => {
//                 if (data.success) {
//                     const decodedUser = decodeURIComponent(data.username);
//                     resolve(decodedUser);
//                     // showWelcomeMessage(decodedUser);
//                 } else {
//                     reject('Token verification failed');
//                     localStorage.removeItem('token');
//                     // showLoginForm();
//                 }
//             })
//             .catch(error => {
//                 console.error('Error during fetch:', error);
//                 reject('An error occurred during token verification: ' + error);
//             });
//     });
// }

export function getToken() {
    return localStorage.getItem('token');
}

export function setToken(token) {
    localStorage.setItem('token', token);
}

export function removeToken() {
    localStorage.removeItem('token');
}
// export async function performItemOperation(endpoint, data, { 
//     successMessage, 
//     errorMessage, 
//     onSuccess = () => {}, 
//     onError = () => {} 
// }) {
//     try {
//         const response = await fetch(endpoint, {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json'
//             },
//             body: JSON.stringify(data)
//         });

//         const responseData = await response.json();

//         if (!response.ok || !responseData.success) {
//             throw new Error(responseData.message || `HTTP error! status: ${response.status}`);
//         }

//         alert(responseData.message || successMessage);
//         onSuccess(responseData);
//     } catch (error) {
//         console.error('Error:', error);
//         alert(`${errorMessage}: ${error.message}`);
//         onError(error);
//     }
// }
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