// progressBar.js

export function createProgressBar() {
    const progressContainer = document.createElement('div');
    progressContainer.id = 'progress-container';
    progressContainer.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 300px;
        background-color: #f0f0f0;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        z-index: 1000;
    `;

    const progressBar = document.createElement('div');
    progressBar.id = 'progress-bar';
    progressBar.style.cssText = `
        width: 0%;
        height: 20px;
        background-color: #4CAF50;
        border-radius: 10px;
        transition: width 0.3s ease;
    `;

    const progressText = document.createElement('div');
    progressText.id = 'progress-text';
    progressText.style.cssText = `
        text-align: center;
        margin-top: 10px;
        font-family: Arial, sans-serif;
    `;
    progressText.textContent = 'Uploading: 0%';

    progressContainer.appendChild(progressBar);
    progressContainer.appendChild(progressText);

    document.body.appendChild(progressContainer);

    return {
        update: (percent) => {
            progressBar.style.width = `${percent}%`;
            progressText.textContent = `Uploading: ${percent}%`;
        },
        container: progressContainer
    };
}

export function removeProgressBar(progressBar) {
    if (progressBar && progressBar.container) {
        document.body.removeChild(progressBar.container);
    }
}
export async function fetchWithProgress(url, options, onProgress) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open(options.method || 'GET', url);

        for (const header in options.headers) {
            xhr.setRequestHeader(header, options.headers[header]);
        }

        xhr.upload.onprogress = (event) => {
            if (event.lengthComputable) {
                const percentComplete = (event.loaded / event.total) * 100;
                onProgress(Math.round(percentComplete));
            }
        };

        xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve(xhr.response);
            } else {
                reject(new Error(xhr.statusText));
            }
        };

        xhr.onerror = () => reject(new Error('Network Error'));

        xhr.send(options.body);
    });
}