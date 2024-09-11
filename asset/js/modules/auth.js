// auth.js
import { verifyToken, setToken, removeToken, getToken } from './utils.js';
import { emit } from './eventManager.js';

export function initAuth(onLoginSuccess, onLogoutSuccess) {
    // 인증 관련 초기화 코드
    const token = getToken();
    if (token) {
        verifyToken(token)
            .then(username => {
                showWelcomeMessage(username);
            })
            .catch(error => {
                console.error('Token verification failed:', error);
                localStorage.removeItem('token');
            });
    }
    document.getElementById('fetchUserCountBtn').addEventListener('click', fetchUserCount);

}

export function showSignupForm() {
    // showSignupForm 함수 구현
    document.getElementById('loginContainer').classList.remove('active');
    document.getElementById('signupContainer').classList.add('active');
    document.getElementById('welcomeContainer').classList.remove('active');
}

export function showLoginForm() {
    // showLoginForm 함수 구현
    event.preventDefault();
    document.getElementById('signupContainer').classList.remove('active');
    document.getElementById('loginContainer').classList.add('active');
    document.getElementById('welcomeContainer').classList.remove('active');
}
export function checkUsername() {
    const username = document.getElementById('signup_username').value;
    const signupResult = document.getElementById('signupResult');
    
    fetch('/check-username', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `username=${username}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            if (data.is_taken) {
                isUsernameAvailable = false;
                signupResult.textContent = "이미 사용 중인 아이디입니다.";
                document.getElementById('signupButton').disabled = true;
            } else {
                isUsernameAvailable = true;
                signupResult.textContent = "아이디 사용 가능!";
                document.getElementById('signupButton').disabled = false;
            }
        } else {
            // 서버에서 오류 발생
            signupResult.textContent = data.message || "아이디 확인 중 오류가 발생했습니다.";
            document.getElementById('signupButton').disabled = true;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        signupResult.textContent = "네트워크 오류가 발생했습니다.";
        document.getElementById('signupButton').disabled = true;
    });
}
// export function checkUsername() {
//     // checkUsername 함수 구현  
//     const username = document.getElementById('signup_username').value;

//     fetch('/check-username', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/x-www-form-urlencoded'
//         },
//         body: `username=${encodeURIComponent(username)}`
//     })
//         .then(response => response.json())
//         .then(data => {
//             const signupResult = document.getElementById('signupResult');
//             signupResult.textContent = data;
//             if (data === 'Username is available') {
//                 isUsernameAvailable = true;
//                 signupResult.textContent = "아이디 사용 가능!";
//                 document.getElementById('signupButton').disabled = false;
//             } else {
//                 isUsernameAvailable = false;
//                 signupResult.textContent = "이미 사용 중인 아이디입니다.";
//                 document.getElementById('signupButton').disabled = true;
//             }
//         })
//         .catch(error => {
//             console.error('Error:', error);
//         });
// }

export function submitSignup() {
    // submitSignup 함수 구현     
    if (!isUsernameAvailable) {
        document.getElementById('signupResult').textContent = '아이디 중복확인을 해주세요.';
        return;
    }
    const username = document.getElementById('signup_username').value;
    const password = document.getElementById('signup_password').value;
    const confirmPassword = document.getElementById('signup_confirm_password').value;
    const signupResult = document.getElementById('signupResult');
    if (password == "") {
        signupResult.textContent = '비밀번호를 입력하세요.';
        return;
    }
    else if (password !== confirmPassword) {
        signupResult.textContent = 'Passwords do not match';
        return;
    }
    fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `username=${username}&password=${encodeURIComponent(password)}`
    })
        .then(response => response.json())
        .then(data => {
            signupResult.textContent = data;
            fetchUserCount();
        })
        .catch(error => {
            console.error('Error:', error);
        });
}

export async function submitLogin(event) {
    event.preventDefault();
    const username = document.getElementById('login_username').value;
    const password = document.getElementById('login_password').value;
    const loginResult = document.getElementById('loginResult');

    if (!username || !password) {
        showLoginError(loginResult, 'Username and password are required');
        return;
    }

    try {
        showLoginProgress(loginResult);
        const data = await performLoginRequest(username, password);
        handleLoginSuccess(data, username);
    } catch (error) {
        handleLoginError(loginResult, error);
    }
}

function showLoginError(loginResult, message) {
    loginResult.textContent = message;
    loginResult.style.color = 'red';
}

function showLoginProgress(loginResult) {
    loginResult.textContent = 'Logging in...';
    loginResult.style.color = 'blue';
}

async function performLoginRequest(username, password) {
    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ username, password })
    });

    if (!response.ok) {
        throw new Error('Network response was not ok');
    }

    return response.json();
}

function handleLoginSuccess(data, username) {
    if (data.success) {
        setToken(data.token);
        localStorage.setItem('username', username);
        showWelcomeMessage(username);
        emit('login', { username }); // 이벤트 발생
    } else {
        throw new Error('Login failed');
    }
}

function handleLoginError(loginResult, error) {
    console.error('Login error:', error);
    showLoginError(loginResult, 'An error occurred during login. Please try again.');
}

// export async function submitLogin() {
//     // submitLogin 함수 구현
//     const username = document.getElementById('login_username').value;
//     const password = document.getElementById('login_password').value;
//     const loginResult = document.getElementById('loginResult');

//     fetch('/login', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//             'X-Requested-With': 'XMLHttpRequest'
//         },
//         body: JSON.stringify({ username, password })
//     })
//         .then(response => {
//             if (!response.ok) {
//                 throw new Error('Network response was not ok');
//             }
//             return response.json();
//         })
//         .then(data => {
//             if (data.success) {
//                 // 토큰을 안전하게 저장 (HttpOnly 쿠키 사용 권장)
//                 // 여기서는 예시로 localStorage를 사용
//                 //localStorage.setItem('token', data.token);
//                 setToken(data.token);
//                 localStorage.setItem('username', data.username);
//                 showWelcomeMessage(username);
//             } else {
//                 loginResult.textContent = 'Login failed';
//             }
//         })
//         .catch(error => {
//             console.error('Error:', error);
//             loginResult.textContent = 'An error occurred during login';
//         });
// }

export function logout() {
    // logout 함수 구현
            //localStorage.removeItem('token');
            removeToken();
            localStorage.removeItem('username');
            showLoginForm();
}

export function showWelcomeMessage(username) {
    // showWelcomeMessage 함수 구현
            const now = new Date();
            const welcomeMessage = `Welcome, ${username}! \r\nYou logged in at ${now.toLocaleString()}.`;
            document.getElementById('welcomeMessage').textContent = welcomeMessage;
            document.getElementById('loginContainer').classList.remove('active');
            document.getElementById('signupContainer').classList.remove('active');
            document.getElementById('welcomeContainer').classList.add('active');
}

function fetchUserCount() {
    fetch('/usercount')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          document.getElementById('userCount').textContent = "전체 사용자 수: " + data.user_count;
        } else {
          document.getElementById('userCount').textContent = "사용자 수 조회 실패: " + (data.error || "알 수 없는 오류");
        }
      })
      .catch(error => {
        console.error('Error:', error);
        document.getElementById('userCount').textContent = "오류 발생: " + error.message;
      });
  }