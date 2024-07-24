// drive.js

let currentPath = '/';
let isGridView = true;

export function initDrive() {
    // 초기화 코드
    document.getElementById('file-upload').addEventListener('change', uploadFiles);

}

export function loadDriveContent() {
    const driveContent = document.getElementById('drive-content');
    const currentPathElement = document.getElementById('current-path');

    driveContent.innerHTML = '<div class="loading">Loading...</div>';

    fetch(`/drive-contents?path=${encodeURIComponent(currentPath)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }

            currentPathElement.textContent = `Current Path: ${currentPath}`;
            driveContent.innerHTML = '';

            if (currentPath !== '/') {
                const backItem = createDriveItem('..', 'folder', true);
                driveContent.appendChild(backItem);
            }

            if (Array.isArray(data.contents)) {
                data.contents.forEach(item => {
                    const driveItem = createDriveItem(item.name, item.type);
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
//     // loadDriveContent 함수 구현
//     const driveContent = document.getElementById('drive-content');
//     const currentPathElement = document.getElementById('current-path');

//     // 로딩 인디케이터 표시
//     driveContent.innerHTML = '<div class="loading">Loading...</div>';

//     fetch(`/drive-contents?path=${encodeURIComponent(currentPath)}`)
//         .then(response => response.json())
//         .then(data => {
//             if (data.error) {
//                 throw new Error(data.error);
//             }

//             currentPathElement.textContent = `Current Path: ${currentPath}`;
//             driveContent.innerHTML = '';

//             if (currentPath !== '/') {
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

export function createDriveItem(name, type, isBackButton = false) {
    // createDriveItem 함수 구현
    const item = document.createElement('div');
    item.className = `drive-item ${isGridView ? 'grid' : ''}`;

    const content = document.createElement('div');
    content.className = 'drive-item-content';

    const icon = document.createElement('span');
    icon.className = `icon ${type === 'folder' ? 'fa-folder' : 'fa-file'}`;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'drive-item-name';
    nameSpan.textContent = name;

    content.appendChild(icon);
    content.appendChild(nameSpan);
    item.appendChild(content);

    if (!isBackButton) {
        const menu = createItemMenu(name, type);
        item.appendChild(menu);
    }

    item.onclick = (e) => {
        if (e.target === item || e.target === icon || e.target === nameSpan) {
            if (type === 'folder') {
                currentPath = isBackButton ? currentPath.split('/').slice(0, -2).join('/') + '/' : currentPath + name + '/';
                loadDriveContent();
            } else if (type === 'file') {
                downloadFile(name);
            }
        }
    };

    return item;
}

export function createItemMenu(name, type) {
    // createItemMenu 함수 구현
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

    return menu;
}

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
    // uploadFiles 함수 구현
    const fileInput = document.getElementById('file-upload');
    const files = fileInput.files;
    const totalFiles = files.length;
    let uploadedFiles = 0;

    // 진행 상황을 표시할 요소 생성
    const progressElement = document.createElement('div');
    progressElement.id = 'upload-progress';
    document.body.appendChild(progressElement);

    for (let i = 0; i < files.length; i++) {
        const formData = new FormData();
        formData.append('file', files[i]);
        formData.append('path', currentPath);

        try {
            const response = await fetch('/upload-file', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (data.success) {
                uploadedFiles++;
                // 진행 상황 업데이트
                progressElement.textContent = `Uploading: ${uploadedFiles}/${totalFiles}`;
            } else {
                console.error(`Failed to upload file: ${files[i].name}`);
            }
        } catch (error) {
            console.error('Error uploading file:', error);
        }
    }

    // 업로드 완료 후 처리
    if (uploadedFiles === totalFiles) {
        alert('All files uploaded successfully!');
    } else {
        alert(`Uploaded ${uploadedFiles} out of ${totalFiles} files.`);
    }

    // 진행 상황 표시 요소 제거
    document.body.removeChild(progressElement);

    // 드라이브 컨텐츠 새로고침
    loadDriveContent();
}

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