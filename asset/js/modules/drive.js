// drive.js
import { getToken, performItemOperation } from './utils.js';

let currentPath = '';
let isGridView = false;

export function initDrive() {
    // 초기화 코드
    document.getElementById('file-upload').addEventListener('change', uploadFiles);

}
export function loadDriveContent() {
    const driveContent = document.getElementById('drive-content');
    const currentPathElement = document.getElementById('current-path');

    driveContent.innerHTML = '<div class="loading">Loading...</div>';

    fetch(`/drive-contents?path=${encodeURIComponent(currentPath)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Received data:', data);
            
            if (data.error) {
                throw new Error(data.error);
            }

            currentPathElement.textContent = `Current Path: ${currentPath}`;
            driveContent.innerHTML = '';

            if (currentPath !== '') {
                const backItem = createDriveItem('..', { type: 'folder' }, true);
                driveContent.appendChild(backItem);
            }

            if (Array.isArray(data.contents)) {
                data.contents.forEach(item => {
                    const driveItem = createDriveItem(item.name, item, false);
                    driveContent.appendChild(driveItem);
                });
            } else {
                console.warn('Unexpected data format:', data);
                driveContent.innerHTML = '<div class="error">Unexpected data format</div>';
            }
        })
        .catch(error => {
            console.error('Error fetching drive contents:', error);
            driveContent.innerHTML = `<div class="error">Error: ${error.message}</div>`;
        });
}
// export function loadDriveContent() {
//     const driveContent = document.getElementById('drive-content');
//     const currentPathElement = document.getElementById('current-path');

//     driveContent.innerHTML = '<div class="loading">Loading...</div>';

//     fetch(`/drive-contents?path=${encodeURIComponent(currentPath)}`)
//         .then(response => response.json())
//         .then(data => {
//             if (data.error) {
//                 throw new Error(data.error);
//             }

//             currentPathElement.textContent = `Current Path: ${currentPath}`;
//             driveContent.innerHTML = '';

//             if (currentPath !== '') {
//                 const backItem = createDriveItem('..', 'folder', true);
//                 driveContent.appendChild(backItem);
//             }

//             if (Array.isArray(data.contents)) {
//                 data.contents.forEach(item => {
//                     const driveItem = createDriveItem(item.name, item.type);
//                     driveContent.appendChild(driveItem);
//                 });
//             } else {
//                 console.warn('Unexpected data format:', data);
//                 driveContent.innerHTML = '<div class="error">Unexpected data format</div>';
//             }
//         })
//         .catch(error => {
//             console.error('Error fetching drive contents:', error);
//             driveContent.innerHTML = `<div class="error">Error: ${error.message}</div>`;
//         });

// }
export function createDriveItem(name, itemData, isBackButton = false) {
    const item = document.createElement('div');
    item.className = `drive-item ${isGridView ? 'grid' : ''}`;

    const content = document.createElement('div');
    content.className = 'drive-item-content';

    const icon = document.createElement('span');
    icon.className = `icon ${itemData.type === 'folder' ? 'fa-folder' : 'fa-file'}`;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'drive-item-name';
    nameSpan.textContent = name;

    content.appendChild(icon);
    content.appendChild(nameSpan);

    if (!isBackButton) {
        const details = document.createElement('div');
        details.className = 'drive-item-details';

        if (itemData.type === 'folder') {
            details.textContent = `Items: ${itemData.items_count}`;
        } else {
            details.textContent = `Size: ${formatSize(itemData.size)} | Type: ${itemData.extension}`;
        }

        const lastModified = document.createElement('div');
        lastModified.className = 'drive-item-last-modified';
        lastModified.textContent = `Last Modified: ${formatDate(itemData.last_modified)}`;

        content.appendChild(details);
        content.appendChild(lastModified);
    }

    item.appendChild(content);

    if (!isBackButton) {
        const menu = createItemMenu(name, itemData.type);
        item.appendChild(menu);
    }

    item.onclick = (e) => {
        if (e.target === item || e.target === icon || e.target === nameSpan) {
            if (itemData.type === 'folder') {
                currentPath = isBackButton ? currentPath.split('/').slice(0, -2).join('/') + '/' : currentPath + name + '/';
                loadDriveContent();
            } else if (itemData.type === 'file') {
                downloadFile(name);
            }
        }
    };

    return item;
}
// export function createDriveItem(name, type, isBackButton = false) {
//     // createDriveItem 함수 구현
//     const item = document.createElement('div');
//     item.className = `drive-item ${isGridView ? 'grid' : ''}`;

//     const content = document.createElement('div');
//     content.className = 'drive-item-content';

//     const icon = document.createElement('span');
//     icon.className = `icon ${type === 'folder' ? 'fa-folder' : 'fa-file'}`;

//     const nameSpan = document.createElement('span');
//     nameSpan.className = 'drive-item-name';
//     nameSpan.textContent = name;

//     content.appendChild(icon);
//     content.appendChild(nameSpan);
//     item.appendChild(content);

//     if (!isBackButton) {
//         const menu = createItemMenu(name, type);
//         item.appendChild(menu);
//     }

//     item.onclick = (e) => {
//         if (e.target === item || e.target === icon || e.target === nameSpan) {
//             if (type === 'folder') {
//                 currentPath = isBackButton ? currentPath.split('/').slice(0, -2).join('/') + '/' : currentPath + name + '/';
//                 loadDriveContent();
//             } else if (type === 'file') {
//                 downloadFile(name);
//             }
//         }
//     };

//     return item;
// }
export function createItemMenu(name, type) {
    const menu = document.createElement('div');
    menu.className = 'item-menu';

    const renameBtn = document.createElement('button');
    renameBtn.textContent = 'Rename';
    renameBtn.onclick = (e) => {
        e.stopPropagation();
        renameItem(name, type);
    };

    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.onclick = (e) => {
        e.stopPropagation();
        deleteItem(name, type);
    };

    menu.appendChild(renameBtn);
    menu.appendChild(deleteBtn);

    if (type === 'file') {
        const downloadBtn = document.createElement('button');
        downloadBtn.textContent = 'Download';
        downloadBtn.onclick = (e) => {
            e.stopPropagation();
            downloadFile(name);
        };
        menu.appendChild(downloadBtn);
    }

    return menu;
}
// export function createItemMenu(name, type) {
//     // createItemMenu 함수 구현
//     const menu = document.createElement('div');
//     menu.className = 'item-menu';

//     const renameBtn = document.createElement('button');
//     renameBtn.textContent = 'Rename';
//     renameBtn.onclick = (e) => {
//         e.stopPropagation();
//         renameItem(name, type);
//     };

//     const deleteBtn = document.createElement('button');
//     deleteBtn.textContent = 'Delete';
//     deleteBtn.onclick = (e) => {
//         e.stopPropagation();
//         deleteItem(name, type);
//     };

//     menu.appendChild(renameBtn);
//     menu.appendChild(deleteBtn);

//     return menu;
// }

export function toggleView() {
    // toggleView 함수 구현
    isGridView = !isGridView;
    const driveContent = document.getElementById('drive-content');
    const items = driveContent.getElementsByClassName('drive-item');

    for (let item of items) {
        if (isGridView) {
            item.classList.add('grid');
        } else {
            item.classList.remove('grid');
        }
    }
}
export async function uploadFiles() {
    const fileInput = document.getElementById('file-upload');
    const files = fileInput.files;
    if (files.length === 0) {
        alert('Please select files to upload.');
        return;
    }

    const token = getToken();
    if (!token) {
        alert('You must be logged in to upload files.');
        return;
    }

    const progressElement = createProgressElement();
    const totalSize = Array.from(files).reduce((total, file) => total + file.size, 0);
    let uploadedSize = 0;

    try {
        for (const file of files) {
            await uploadFile(file, progressElement, totalSize, uploadedSize);
            uploadedSize += file.size;
        }
        alert('All files uploaded successfully!');
    } catch (error) {
        console.error('Upload error:', error);
        alert(`Error during upload: ${error.message}`);
    } finally {
        removeProgressElement(progressElement);
        loadDriveContent();
    }
}
// export async function uploadFiles() {
//     // uploadFiles 함수 구현
//     const fileInput = document.getElementById('file-upload');
//     const files = fileInput.files;
//     const totalFiles = files.length;
//     let uploadedFiles = 0;

//     // 진행 상황을 표시할 요소 생성
//     const progressElement = document.createElement('div');
//     progressElement.id = 'upload-progress';
//     document.body.appendChild(progressElement);

//     for (let i = 0; i < files.length; i++) {
//         const formData = new FormData();
//         formData.append('file', files[i]);
//         formData.append('path', currentPath);

//         try {
//             const response = await fetch('/upload-file', {
//                 method: 'POST',
//                 body: formData
//             });

//             const data = await response.json();

//             if (data.success) {
//                 uploadedFiles++;
//                 // 진행 상황 업데이트
//                 progressElement.textContent = `Uploading: ${uploadedFiles}/${totalFiles}`;
//             } else {
//                 console.error(`Failed to upload file: ${files[i].name}`);
//             }
//         } catch (error) {
//             console.error('Error uploading file:', error);
//         }
//     }

//     // 업로드 완료 후 처리
//     if (uploadedFiles === totalFiles) {
//         alert('All files uploaded successfully!');
//     } else {
//         alert(`Uploaded ${uploadedFiles} out of ${totalFiles} files.`);
//     }

//     // 진행 상황 표시 요소 제거
//     document.body.removeChild(progressElement);

//     // 드라이브 컨텐츠 새로고침
//     loadDriveContent();
// }
export function createFolder() {
    // createFolder 함수 구현
    const folderName = prompt('Enter folder name:');
    if (folderName) {
        performItemOperation(
            '/create-folder',
            { path: currentPath, name: folderName },
            'Folder created successfully!',
            'Error creating folder'
        );
    }
}
export function renameItem(oldName, type) {
    // renameItem 함수 구현
    const newName = prompt(`Enter new name for ${oldName}:`);
    if (newName) {
        performItemOperation(
            '/rename-item',
            { path: currentPath, oldName, newName, type },
            'Item renamed successfully!',
            'Error renaming item'
        );
    }
}
export function deleteItem(name, type) {
    // deleteItem 함수 구현
    if (confirm(`Are you sure you want to delete ${name}?`)) {
        performItemOperation(
            '/delete-item',
            { path: currentPath, name, type },
            'Item deleted successfully!',
            'Error deleting item'
        );
    }
}
export function downloadFile(fileName) {
    // downloadFile 함수 구현
    window.location.href = `/download-file?path=${encodeURIComponent(currentPath)}&name=${encodeURIComponent(fileName)}`;
}
function createProgressElement() {
    const progressElement = document.createElement('div');
    progressElement.id = 'upload-progress';
    progressElement.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background-color: white;
        padding: 20px;
        border-radius: 5px;
        box-shadow: 0 0 10px rgba(0,0,0,0.5);
        z-index: 1000;
    `;
    document.body.appendChild(progressElement);
    return progressElement;
}

function removeProgressElement(progressElement) {
    document.body.removeChild(progressElement);
}

function updateProgress(progressElement, progress) {
    progressElement.textContent = `Upload Progress: ${Math.round(progress)}%`;
}

async function uploadFile(file, progressElement, totalSize, uploadedSize) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('path', currentPath);

    const response = await fetch('/upload_file', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${getToken()}`
        },
        body: formData,
        onUploadProgress: (progressEvent) => {
            const fileProgress = progressEvent.loaded / progressEvent.total;
            const overallProgress = (uploadedSize + progressEvent.loaded) / totalSize * 100;
            updateProgress(progressElement, overallProgress);
        }
    });

    if (!response.ok) {
        throw new Error(`Failed to upload ${file.name}`);
    }

    const data = await response.json();
    if (!data.success) {
        throw new Error(data.message || `Failed to upload ${file.name}`);
    }
}

function formatSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateString) {
    // ISO 8601 형식의 날짜 문자열을 파싱
    const date = new Date(dateString);
    
    // 유효한 날짜인지 확인
    if (isNaN(date.getTime())) {
        console.warn('Invalid date:', dateString);
        return 'Invalid Date';
    }
    
    // 사용자의 로컬 시간대로 날짜와 시간을 포맷팅
    return new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        second: 'numeric',
        timeZoneName: 'short'
    }).format(date);
}