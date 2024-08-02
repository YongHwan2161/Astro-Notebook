// posts.js
import { verifyToken, getToken } from './utils.js';
import { render3DModel } from './modelRenderer.js';
import { process3DModelData } from './modelProcessor.js';
import { createProgressBar, removeProgressBar, fetchWithProgress } from './progressBar.js';

let currentUser = null;
const Quill = window.Quill;
let quill;
export function initPosts(setCurrentUser) {
    // 게시글 관련 초기화 코드
    document.getElementById('comment-form').addEventListener('submit', submitComment);
}
export async function loadPosts(category) {
    const postsContainer = document.getElementById('posts-container');
    postsContainer.innerHTML = `
        <tr>
            <td colspan="4" class="text-center py-8">
                <div class="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
                <p class="mt-2 text-gray-600">Loading posts...</p>
            </td>
        </tr>
    `;

    try {
        const response = await fetch(`/posts?category=${encodeURIComponent(category)}`);
        if (!response.ok) {
            throw new Error('Failed to fetch posts');
        }
        const posts = await response.json();

        if (posts.length === 0) {
            postsContainer.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center py-4">No posts found in this category.</td>
                </tr>
            `;
            return;
        }

        renderPosts(posts);
    } catch (error) {
        console.error('Error:', error);
        postsContainer.innerHTML = `
            <tr>
                <td colspan="4" class="text-center py-8">
                    <p class="text-red-600">${error.message}</p>
                    <p class="mt-2 text-gray-600">Please try again later.</p>
                </td>
            </tr>
        `;
    }
}

export function showPostContent(id, title, author, timestamp, encodedContent, category) {
    console.log('Showing post content:', id, title);
    const content = decodeURIComponent(encodedContent);
    document.getElementById('post-title').innerText = title;
    document.getElementById('post-author-timestamp').innerText = `By ${author} on ${timestamp}`;
    document.getElementById('post-category').innerText = `Category: ${category}`;  // 카테고리 표시 추가
    document.getElementById('post-body').innerHTML = content;
    document.getElementById('post-content').dataset.postId = id;
    document.getElementById('posts-table').style.display = 'none';
    document.getElementById('post-content').style.display = 'block';
    console.log('Post body content:', content); // 추가된 로그

    const objectContainers = document.querySelectorAll('#post-body div[data-model-url]');
    console.log('Found 3D model containers:', objectContainers.length);

    objectContainers.forEach((container, index) => {
        console.log(`Processing 3D model container ${index + 1}:`, container);
        const modelUrl = container.getAttribute('data-model-url');
        const modelType = container.getAttribute('data-model-type');
        const mtlUrl = container.getAttribute('data-mtl-url');
        let textureUrls = [];

        try {
            textureUrls = JSON.parse(container.getAttribute('data-texture-urls') || '[]');
            console.log('Parsed texture URLs:', textureUrls);
        } catch (error) {
            console.error('Error parsing texture URLs:', error);
        }

        console.log('3D model data:', { modelUrl, modelType, mtlUrl, textureUrls });

        if (modelUrl) {
            try {
                const canvas = container.querySelector('canvas');
                if (!canvas) {
                    console.error('Canvas element not found in container:', container);
                    return;
                }
                canvas.style.width = '100%';
                canvas.style.height = 'auto';
                // 저장된 스타일 정보 적용
                const savedStyle = container.getAttribute('data-style');
                if (savedStyle) {
                    container.setAttribute('style', savedStyle);
                }

                console.log('Rendering 3D model:', { modelUrl, modelType, mtlUrl, textureUrls });
                render3DModel(canvas, modelUrl, mtlUrl, textureUrls, true, modelType);
                // 다운로드 버튼 추가
                addDownloadButton(container, modelUrl, mtlUrl, textureUrls, modelType);

            } catch (error) {
                console.error('Error rendering 3D model:', error);
                container.textContent = 'Error rendering 3D model: ' + error.message;
            }
        } else {
            console.error('No model URL found for container:', container);
        }
    });

    loadComments(id);
}
function renderCategorizedPosts(categorizedPosts) {
    const postsContainer = document.getElementById('posts-container');
    postsContainer.innerHTML = '';

    for (const [category, posts] of Object.entries(categorizedPosts)) {
        const categoryHeader = document.createElement('tr');
        categoryHeader.innerHTML = `
            <th colspan="5" class="py-2 px-4 bg-gray-200 text-left font-bold">${category}</th>
        `;
        postsContainer.appendChild(categoryHeader);

        posts.forEach(post => {
            const date = new Date(post.timestamp);
            const formattedTimestamp = date.toLocaleString();
            const encodedContent = encodeURIComponent(post.content);
            const decodedAuthor = decodeURIComponent(post.author);

            const row = document.createElement('tr');
            row.className = 'hover:bg-gray-50 transition duration-300 ease-in-out';
            row.innerHTML = `
                <td class="py-2 px-2 sm:px-4 border-b">
                    <a href="#" class="text-blue-600 hover:text-blue-800" 
                    onclick="showPostContent('${post.id}', '${post.title}', '${decodedAuthor}', '${formattedTimestamp}', '${encodedContent}'); return false;">
                        ${post.title}
                    </a>
                </td>
                <td class="py-2 px-2 sm:px-4 border-b">${decodedAuthor}</td>
                <td class="py-2 px-2 sm:px-4 border-b hidden sm:table-cell">${formattedTimestamp}</td>
                <td class="py-2 px-2 sm:px-4 border-b">${post.category}</td>
                <td class="py-2 px-2 sm:px-4 border-b">
                    <button onclick="EditPost(${post.id})" class="text-blue-600 hover:text-blue-800 transition duration-300 ease-in-out px-2 py-1 rounded mr-2">Edit</button>
                    <button onclick="deletePost(${post.id})" class="text-red-600 hover:text-red-800 transition duration-300 ease-in-out px-2 py-1 rounded">Delete</button>
                </td>
            `;
            postsContainer.appendChild(row);
        });
    }
}
function addDownloadButton(container, modelUrl, mtlUrl, textureUrls, modelType) {
    const downloadButton = document.createElement('button');
    downloadButton.textContent = 'Download 3D Model Files';
    downloadButton.className = 'download-3d-button';
    downloadButton.onclick = () => showFileList(container, modelUrl, mtlUrl, textureUrls, modelType);
    container.appendChild(downloadButton);
}
async function showFileList(container, modelUrl, mtlUrl, textureUrls, modelType) {
    const fileListContainer = document.createElement('div');
    fileListContainer.className = 'file-list-container';

    const fileList = document.createElement('ul');
    fileList.className = 'file-list';

    // 모델 파일
    const modelFileName = container.getAttribute('data-model-filename') || `model.${modelType}`;
    addFileToList(fileList, modelFileName, modelUrl);

    // MTL 파일 (있는 경우)
    if (mtlUrl) {
        const mtlFileName = container.getAttribute('data-mtl-filename') || 'model.mtl';
        addFileToList(fileList, mtlFileName, mtlUrl);
    }
    // 텍스처 파일들
    for (const texture of textureUrls) {
        if (texture && texture.url) {
            await addFileToList(fileList, texture.name, texture.url);
        } else {
            console.error('Invalid texture object:', texture);
        }
    }

    fileListContainer.appendChild(fileList);

    // 다운로드 모두 버튼
    const downloadAllButton = document.createElement('button');
    downloadAllButton.textContent = 'Download All Files';
    downloadAllButton.className = 'download-all-button';
    downloadAllButton.onclick = () => downloadAllFiles(fileList);
    fileListContainer.appendChild(downloadAllButton);

    // 닫기 버튼
    const closeButton = document.createElement('button');
    closeButton.textContent = 'Close';
    closeButton.className = 'close-button';
    closeButton.onclick = () => fileListContainer.remove();
    fileListContainer.appendChild(closeButton);

    container.appendChild(fileListContainer);
}
async function addFileToList(fileList, fileName, fileUrl) {
    const listItem = document.createElement('li');
    const downloadLink = document.createElement('a');
    downloadLink.href = fileUrl;
    downloadLink.download = fileName;
    downloadLink.textContent = fileName;

    // 파일 크기 정보 가져오기
    const fileSize = await getFileSize(fileUrl);

    const fileSizeSpan = document.createElement('span');
    fileSizeSpan.className = 'file-size';
    fileSizeSpan.textContent = ` (${fileSize})`;

    listItem.appendChild(downloadLink);
    listItem.appendChild(fileSizeSpan);
    fileList.appendChild(listItem);
}
async function getFileSize(fileUrl) {
    try {
        // URL에서 경로 부분만 추출
        const urlPath = new URL(fileUrl, window.location.origin).pathname;
        const response = await fetch(`/get-file-info?path=${encodeURIComponent(urlPath)}`);
        const data = await response.json();
        return data.size;
    } catch (error) {
        console.error('Error fetching file size:', error);
        return 'Unknown';
    }
}
async function downloadAllFiles(fileList) {
    const links = fileList.querySelectorAll('a');
    for (const link of links) {
        link.click();
        await new Promise(resolve => setTimeout(resolve, 1000)); // 1초 대기
    }
    alert('All files downloaded successfully!');
}
export function hidePostContent() {
    // hidePostContent 함수 구현

    document.getElementById('post-content').style.display = 'none';
    document.getElementById('posts-table').style.display = 'table';
}

export async function deletePost(id) {
    // deletePost 함수 구현
    const token = getToken();
    if (!token) {
        alert('You must be logged in to delete a post');
        return;
    }

    try {
        const username = await verifyToken(token);
        const postData = { id: id, username: username };

        const response = await fetch('/delete_post', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(postData)
        });

        const data = await response.json();

        if (data.success) {
            alert('Post deleted successfully!');
            loadPosts();  // 게시글 삭제 후 게시글 목록을 다시 로드
        } else {
            alert('Failed to delete post.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error: ' + error);
    }
}

export function writePost() {


    var form = document.getElementById('form1');
    form.style.display = 'block';
    // 카테고리 선택 옵션 추가
    var categorySelect = document.createElement('select');
    categorySelect.id = 'post-category';
    categorySelect.innerHTML = `
        <option value="">Select Category</option>
        <option value="general">General</option>
        <option value="news">News</option>
        <option value="tech">Technology</option>
        <option value="science">Science</option>
    `;
    form.insertBefore(categorySelect, form.firstChild);

    // Define custom icon
    var icons = Quill.import('ui/icons');
    icons['upload-3d'] = '<strong>3D</strong>';

    quill = new Quill('#editor-container', {
        modules: {
            toolbar: {
                container: [
                    [{ 'font': [] }, { 'size': [] }],
                    ['bold', 'italic', 'underline', 'strike'],
                    [{ 'color': [] }, { 'background': [] }],
                    [{ 'script': 'sub' }, { 'script': 'super' }],
                    [{ 'header': '1' }, { 'header': '2' }, 'blockquote', 'code-block'],
                    [{ 'list': 'ordered' }, { 'list': 'bullet' }, { 'indent': '-1' }, { 'indent': '+1' }],
                    [{ 'direction': 'rtl' }, { 'align': [] }],
                    ['link', 'image', 'video', 'formula'],
                    ['upload-3d'], // Custom button for 3D model upload
                    ['clean']

                ],
                handlers: {
                    'upload-3d': function () {
                        select3DFile();
                    }
                }
            },
        },
        theme: 'snow'
    });
    // 전역 quill 변수에 할당 (window 객체를 통해)
    //window.quill = quill;
}
export async function savePost() {
    if (!isEditorInitialized()) return;
    if (!isUserLoggedIn()) return;

    try {
        const postData = await preparePostData();
        await uploadPost(postData);
        handlePostSaveSuccess();
    } catch (error) {
        handlePostSaveError(error);
    }
}
// 3D 모델 삽입 관련 함수들
export function select3DFile() {
    var input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.accept = '.obj,.mtl,.stl,.png,.jpg,.jpeg';
    input.onchange = function (event) {
        var files = event.target.files;
        if (files.length > 0) {
            load3DModel(files);
        }
    };
    input.click();
}
export async function load3DModel(files) {
    // index4.html의 load3DModel 함수 내용을 여기로 옮깁니다.
    // quill 객체 사용 시 window.quill로 접근합니다.
    let objFile, mtlFile, stlFile, textureFiles = [];
    for (let file of files) {
        if (file.name.endsWith('.obj')) objFile = file;
        else if (file.name.endsWith('.mtl')) mtlFile = file;
        else if (file.name.endsWith('.stl')) stlFile = file;
        else if (/\.(png|jpg|jpeg)$/i.test(file.name)) textureFiles.push(file);
    }

    if (!objFile && !stlFile) {
        alert('Either OBJ or STL file is required.');
        return;
    }

    try {
        // quill 객체가 초기화되었는지 확인
        if (!quill) {
            throw new Error('Quill editor is not initialized');
        }

        let modelContent, modelType;
        if (objFile) {
            modelContent = await readFile(objFile);
            modelType = 'obj';
        } else {
            // modelContent = await readFile(stlFile);
            modelContent = await readFile(stlFile, 'arraybuffer');
            modelType = 'stl';
        }

        let mtlContent = null;
        let textureContents = [];

        if (mtlFile) {
            mtlContent = await readFile(mtlFile);
        }

        for (let textureFile of textureFiles) {
            const textureContent = await readFile(textureFile, 'dataURL');
            textureContents.push({
                name: textureFile.name,
                content: textureContent
            });
        }

        // Create a container for the canvas
        var canvasContainer = document.createElement('div');
        canvasContainer.style.width = '100%';
        canvasContainer.style.height = '400px';
        canvasContainer.style.position = 'relative';
        canvasContainer.style.background = '#f0f0f0';
        canvasContainer.style.marginTop = '10px';

        // Set attributes for OBJ file

        canvasContainer.setAttribute('data-model-type', modelType);
        canvasContainer.setAttribute('data-model-filename', modelType === 'obj' ? objFile.name : stlFile.name);

        if (modelType === 'obj') {
            canvasContainer.setAttribute('data-model-file', modelContent);
            if (mtlContent) {
                canvasContainer.setAttribute('data-mtl-file', mtlContent);
                canvasContainer.setAttribute('data-mtl-filename', mtlFile.name);
            }
        } else {
            // For STL, we store the ArrayBuffer as a base64 string
            const base64Content = btoa(String.fromCharCode.apply(null, new Uint8Array(modelContent)));
            canvasContainer.setAttribute('data-model-file', base64Content);
        }

        // Set attributes for texture files
        if (textureContents.length > 0) {
            canvasContainer.setAttribute('data-texture-files', JSON.stringify(textureContents));
        }

        // Create a canvas element to render the 3D model
        var canvas = document.createElement('canvas');
        canvas.style.width = '100%';
        canvas.style.height = '100%';
        canvasContainer.appendChild(canvas);

        // Create a block blot for the canvas container
        var Block = Quill.import('blots/block/embed');
        class CanvasBlot extends Block {
            static create(value) {
                let node = super.create();
                Object.keys(value).forEach(key => {
                    if (key === 'style') {
                        node.setAttribute('style', value[key]);
                    } else if (key === 'data-texture-files') {
                        node.setAttribute(key, JSON.stringify(value[key]));
                    } else {
                        node.setAttribute(key, value[key]);
                    }
                });
                node.innerHTML = '<canvas style="width: 100%; height: 100%;"></canvas>';
                return node;
            }
            static value(node) {
                const attrs = node.attributes;
                const value = {};
                for (let i = 0; i < attrs.length; i++) {
                    if (attrs[i].name === 'data-texture-files') {
                        value[attrs[i].name] = JSON.parse(attrs[i].value);
                    } else {
                        value[attrs[i].name] = attrs[i].value;
                    }
                }
                return value;
            }
        }
        CanvasBlot.blotName = 'canvas';
        CanvasBlot.tagName = 'div';
        Quill.register(CanvasBlot);

        // Insert the canvas container as a block blot
        var range = quill.getSelection(true);
        quill.insertEmbed(range.index, 'canvas', {
            style: canvasContainer.getAttribute('style'),
            'data-model-type': modelType,
            'data-model-file': modelContent,
            'data-model-filename': modelType === 'obj' ? objFile.name : stlFile.name,
            'data-mtl-file': mtlContent || '',
            'data-mtl-filename': mtlFile ? mtlFile.name : '',
            'data-texture-files': textureContents
        });

        // 3D 모델 렌더링
        setTimeout(() => {
            var canvasElements = document.querySelectorAll('canvas');
            var lastCanvas = canvasElements[canvasElements.length - 1];
            render3DModel(lastCanvas, modelContent, mtlContent, textureContents, false, modelType);
        }, 100);
    } catch (error) {
        console.error('Error processing files:', error);
        alert('Failed to process files: ' + error.message);
    }
}
export async function loadCategories() {
    try {
        const response = await fetch('/categories');
        if (!response.ok) {
            throw new Error('Failed to fetch categories');
        }
        const categories = await response.json();
        renderCategories(categories);
    } catch (error) {
        console.error('Error:', error);
        alert('Error loading categories: ' + error.message);
    }
}
function renderCategories(categories) {
    const categoriesContainer = document.getElementById('categories-container');
    categoriesContainer.innerHTML = '';
    categories.forEach(category => {
        const categoryElement = document.createElement('button');
        categoryElement.textContent = category;
        categoryElement.onclick = () => loadPosts(category);
        categoriesContainer.appendChild(categoryElement);
    });
}
function readFile(file, readAs = 'text') {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (event) => resolve(event.target.result);
        reader.onerror = (error) => reject(error);
        if (readAs === 'dataURL') {
            reader.readAsDataURL(file);
        } else if (readAs === 'arraybuffer') {
            reader.readAsArrayBuffer(file);
        } else {
            reader.readAsText(file);
        }
    });
}
function isEditorInitialized() {
    if (!quill) {
        alert('Editor is not initialized.');
        return false;
    }
    return true;
}
function isUserLoggedIn() {
    const token = getToken();
    if (!token) {
        alert('You must be logged in to save a post');
        return false;
    }
    return true;
}
async function preparePostData() {
    const username = await verifyToken(getToken());
    const title = getPostTitle();
    const category = document.getElementById('post-category').value;
    let content = quill.root.innerHTML;

    //console.log('Original content:', content); // 추가된 로그
    content = await process3DModelData(content);

    console.log('Processed content:', content); // 추가된 로그
    return {
        title,
        content,
        author: username,
        timestamp: new Date().toISOString(),
        category: category  // 카테고리 추가
    };
}

function getPostTitle() {
    const title = document.getElementById('name').value;
    if (title === "") {
        throw new Error('Please enter a title.');
    }
    return title;
}

async function uploadPost(postData) {
    const progressBar = createProgressBar();
    try {
        const response = await fetchWithProgress('/save_post', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(postData)
        });
        const data = JSON.parse(response);
        if (!data.success) {
            throw new Error(data.message || 'Failed to save post.');
        }
    } finally {
        removeProgressBar(progressBar);
    }
}

function handlePostSaveSuccess() {
    alert('Post saved successfully!');
    loadPosts();
}

function handlePostSaveError(error) {
    console.error('Error:', error);
    alert('Error: ' + error.message);
}

export function loadComments(postId) {
    // loadComments 함수 구현
    fetch(`/comments?postId=${postId}`)
        .then(response => response.json())
        .then(data => {
            const commentsContainer = document.getElementById('comments-container');
            commentsContainer.innerHTML = '';
            if (data.comments && Array.isArray(data.comments)) {
                data.comments.forEach(comment => {
                    const timestamp = parseInt(comment.timestamp); // Convert timestamp string to integer
                    const date = new Date(timestamp); // Create a Date object

                    const commentElement = document.createElement('div');
                    commentElement.className = 'comment';
                    commentElement.innerHTML = `
            <p><strong>${comment.author}</strong>: ${comment.text}</p>
            <p><em>${date.toLocaleString()}</em></p>
            <button onclick="editComment(${comment.id})">Edit</button>
            <button onclick="deleteComment(${comment.id})">Delete</button>
        `;
                    commentsContainer.appendChild(commentElement);
                });
            } else {
                const noCommentsElement = document.createElement('div');
                noCommentsElement.className = 'no-comments';
                noCommentsElement.innerText = 'No comments available.';
                commentsContainer.appendChild(noCommentsElement);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error on loadComments: ' + error);
        });
}

export async function submitComment(event) {
    // submitComment 함수 구현
    event.preventDefault(); // Prevent form from submitting the default way
    const postId = document.getElementById('post-content').dataset.postId;
    const commentText = document.getElementById('comment-text').value;

    const token = getToken();
    if (!token) {
        alert('You must be logged in to add a comment');
        return;
    }

    try {
        const username = await verifyToken(token);

        const commentData = {
            postId: postId,
            commentText: commentText,
            author: username
        };

        const response = await fetch('/add_comment', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(commentData)
        });

        const data = await response.json();

        if (data.success) {
            alert('Comment added successfully!');
            loadComments(postId); // Function to reload comments for the post
        } else {
            alert('Failed to add comment.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error: ' + error);
    }
}

export function editComment(commentId) {
    // editComment 함수 구현
    const newText = prompt("Enter new comment text:");
    if (newText) {
        fetch(`/edit_comment`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id: commentId, newText: newText })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Comment edited successfully!');
                    loadComments(data.postId); // Reload comments for the post
                } else {
                    alert('Failed to edit comment.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error: ' + error);
            });
    }
}

export function deleteComment(commentId) {
    // deleteComment 함수 구현
    if (confirm("Are you sure you want to delete this comment?")) {
        fetch(`/delete_comment`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id: commentId })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Comment deleted successfully!');
                    loadComments(data.postId); // Reload comments for the post
                } else {
                    alert('Failed to delete comment.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error: ' + error);
            });
    }
}
let currentSortColumn = 'timestamp'; // 기본 정렬 컬럼
let currentSortOrder = 'desc'; // 기본 정렬 순서
let postsData = []; // 전체 게시글 데이터를 저장할 배열

export function sortPosts(column) {
    if (column === currentSortColumn) {
        // 같은 컬럼을 다시 클릭하면 정렬 순서를 변경
        currentSortOrder = currentSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
        currentSortColumn = column;
        currentSortOrder = 'asc';
    }

    renderSortedPosts();
}

function renderSortedPosts() {
    const sortedPosts = [...postsData].sort((a, b) => {
        let valueA = a[currentSortColumn];
        let valueB = b[currentSortColumn];

        if (currentSortColumn === 'timestamp') {
            valueA = new Date(valueA);
            valueB = new Date(valueB);
        }

        if (valueA < valueB) return currentSortOrder === 'asc' ? -1 : 1;
        if (valueA > valueB) return currentSortOrder === 'asc' ? 1 : -1;
        return 0;
    });

    // 활성 정렬 버튼 표시
    document.querySelectorAll('.sort-button').forEach(button => {
        button.classList.remove('active');
        button.textContent = '⇅';
    });
    const activeButton = document.getElementById(`sort-${currentSortColumn}`);
    if (activeButton) {
        activeButton.classList.add('active');
        activeButton.textContent = currentSortOrder === 'asc' ? '↑' : '↓';
    }

    renderPosts(sortedPosts);
}

function renderPosts(posts) {
    const postsContainer = document.getElementById('posts-container');
    postsContainer.innerHTML = '';

    posts.forEach(post => {
        const date = new Date(post.timestamp);
        const formattedTimestamp = date.toLocaleString();
        const encodedContent = encodeURIComponent(post.content);
        const decodedAuthor = decodeURIComponent(post.author);

        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50 transition duration-300 ease-in-out';
        row.innerHTML = `
            <td class="py-2 px-2 sm:px-4 border-b">
                <a href="#" class="text-blue-600 hover:text-blue-800" 
                onclick="showPostContent('${post.id}', '${post.title}', '${decodedAuthor}', '${formattedTimestamp}', '${encodedContent}'); return false;">
                    ${post.title}
                </a>
            </td>
            <td class="py-2 px-2 sm:px-4 border-b">${decodedAuthor}</td>
            <td class="py-2 px-2 sm:px-4 border-b hidden sm:table-cell">${formattedTimestamp}</td>
            <td class="py-2 px-2 sm:px-4 border-b">
                <button onclick="EditPost(${post.id})" class="text-blue-600 hover:text-blue-800 transition duration-300 ease-in-out px-2 py-1 rounded mr-2">Edit</button>
                <button onclick="deletePost(${post.id})" class="text-red-600 hover:text-red-800 transition duration-300 ease-in-out px-2 py-1 rounded">Delete</button>
            </td>
        `;
        postsContainer.appendChild(row);
    });
}
let quillEdit; // Quill 인스턴스를 저장할 전역 변수

export function EditPost(postId) {
    const post = postsData.find(p => p.id === postId);
    if (!post) {
        console.error('Post not found');
        return;
    }

    // 수정 폼 표시
    const editForm = document.createElement('div');
    editForm.id = 'edit-form';
    editForm.innerHTML = `
        <h2 class="text-2xl font-bold mb-4">Edit Post</h2>
        <input type="text" id="edit-title" value="${post.title}" class="w-full mb-2 p-2 border rounded">
        <div id="edit-content" class="w-full mb-2 border rounded" style="height: 300px;"></div>
        <button onclick="updatePost(${postId})" class="bg-blue-500 text-white px-4 py-2 rounded">Update</button>
        <button onclick="cancelEdit()" class="bg-gray-500 text-white px-4 py-2 rounded ml-2">Cancel</button>
    `;

    const postsContainer = document.getElementById('posts-container');
    postsContainer.parentNode.insertBefore(editForm, postsContainer);
    postsContainer.style.display = 'none';

    // Quill 에디터 초기화
    quillEdit = new Quill('#edit-content', {
        theme: 'snow',
        modules: {
            toolbar: [
                [{ 'header': [1, 2, false] }],
                ['bold', 'italic', 'underline'],
                ['image', 'code-block']
            ]
        }
    });

    // 에디터에 기존 내용 설정
    quillEdit.root.innerHTML = post.content;
}