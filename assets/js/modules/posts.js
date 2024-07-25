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

export async function loadPosts() {
    // loadPosts 함수 구현
    fetch('/posts')
        .then(response => response.json())
        .then(data => {
            const postsContainer = document.getElementById('posts-container');
            postsContainer.innerHTML = '';  // 기존 게시글 목록을 초기화
            data.forEach(post => {
                const row = document.createElement('tr');
                // Convert timestamp to a more readable format
                const date = new Date(post.timestamp);
                const formattedTimestamp = date.toLocaleString();

                const encodedContent = encodeURIComponent(post.content);
                const decodedAuthor = decodeURIComponent(post.author);

                row.innerHTML = `
        <td><a href="#" onclick="showPostContent('${post.id}', '${post.title}', '${decodedAuthor}', '${formattedTimestamp}', '${encodedContent}')">${post.title}</a></td>
        <td>${decodedAuthor}</td>
        <td>${formattedTimestamp}</td>
        <td><button onclick="deletePost(${post.id})">Delete</button></td>
    `;
                postsContainer.appendChild(row);
            });
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error: ' + error);
        });
}

export function showPostContent(id, title, author, timestamp, encodedContent) {
    // showPostContent 함수 구현
    console.log('Showing post content:', id, title);
    const content = decodeURIComponent(encodedContent);
    document.getElementById('post-title').innerText = title;
    document.getElementById('post-author-timestamp').innerText = `By ${author} on ${timestamp}`;
    document.getElementById('post-body').innerHTML = content;
    document.getElementById('post-content').dataset.postId = id;
    document.getElementById('posts-table').style.display = 'none';
    document.getElementById('post-content').style.display = 'block';

    const objectContainers = document.querySelectorAll('#post-body div[data-obj-url]');
    console.log('Found 3D model containers:', objectContainers.length);

    objectContainers.forEach((container, index) => {
        console.log(`Processing 3D model container ${index + 1}:`, container);
        const objUrl = container.getAttribute('data-obj-url');
        const mtlUrl = container.getAttribute('data-mtl-url');
        let textureUrls = [];

        try {
            textureUrls = JSON.parse(container.getAttribute('data-texture-urls') || '[]');
        } catch (error) {
            console.error('Error parsing texture URLs:', error);
        }

        console.log('3D model data:', { objUrl, mtlUrl, textureUrls });

        if (objUrl) {
            try {
                const canvas = container.querySelector('canvas');
                if (!canvas) {
                    console.error('Canvas element not found in container:', container);
                    return;
                }
                canvas.style.width = '100%';
                canvas.style.height = 'auto';

                console.log('Rendering 3D model:', { objUrl, mtlUrl, textureUrls });
                render3DModel(canvas, objUrl, mtlUrl, textureUrls, true);
            } catch (error) {
                console.error('Error rendering OBJ:', error);
                container.textContent = 'Error rendering 3D model: ' + error.message;
            }
        } else {
            console.error('No OBJ URL found for container:', container);
        }
    });

    loadComments(id);
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

export function EditPost() {

    // EditPost 함수 구현
    var form = document.getElementById('form1');
    form.style.display = 'block';

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
    input.accept = '.obj,.mtl,.png,.jpg,.jpeg';
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
    let objFile, mtlFile, textureFiles = [];
    for (let file of files) {
        if (file.name.endsWith('.obj')) objFile = file;
        else if (file.name.endsWith('.mtl')) mtlFile = file;
        else if (/\.(png|jpg|jpeg)$/i.test(file.name)) textureFiles.push(file);
    }

    if (!objFile) {
        alert('OBJ file is required.');
        return;
    }

    try {
        // quill 객체가 초기화되었는지 확인
        if (!quill) {
            throw new Error('Quill editor is not initialized');
        }

        const objContent = await readFile(objFile);
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
        canvasContainer.setAttribute('data-obj-file', objContent);
        canvasContainer.setAttribute('data-obj-filename', objFile.name);

        // Set attributes for MTL file if exists
        if (mtlContent) {
            canvasContainer.setAttribute('data-mtl-file', mtlContent);
            canvasContainer.setAttribute('data-mtl-filename', mtlFile.name);
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
            'data-obj-file': objContent,
            'data-obj-filename': objFile.name,
            'data-mtl-file': mtlContent || '',
            'data-mtl-filename': mtlFile ? mtlFile.name : '',
            'data-texture-files': textureContents
        });

        // 3D 모델 렌더링
        setTimeout(() => {
            var canvasElements = document.querySelectorAll('canvas');
            var lastCanvas = canvasElements[canvasElements.length - 1];
            render3DModel(lastCanvas, objContent, mtlContent, textureContents, false);
        }, 100);
    } catch (error) {
        console.error('Error processing files:', error);
        alert('Failed to process files: ' + error.message);
    }
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
    let content = quill.root.innerHTML;
    content = await process3DModelData(content);

    return {
        title,
        content,
        author: username,
        timestamp: new Date().toISOString()
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
