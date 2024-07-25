// posts.js
import { verifyToken, getToken } from './utils.js';
import { render3DModel } from './modelRenderer.js';
import { process3DModelData } from './modelProcessor.js';
import { createProgressBar, removeProgressBar, fetchWithProgress } from './progressBar.js';

let currentUser = null; 
const Quill = window.Quill;

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
let quill;
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

// export async function savePost() {
//     if (!quill) {
//         alert('Editor is not initialized.');
//         return;
//     }

//     const token = getToken();
//     if (!token) {
//         alert('You must be logged in to save a post');
//         return;
//     }

//     try {
//         const username = await verifyToken(token);
//         const title = document.getElementById('name').value;
//         if (title === "") {
//             alert('제목을 입력해 주세요.');
//             return;
//         }

//         let content = quill.root.innerHTML;
//         const author = username;
//         const timestamp = new Date().toISOString();

//         // 3D 모델 데이터 처리
//         content = await process3DModelData(content);

//         const postData = { title, content, author, timestamp };

//         // 프로그레스 표시 시작
//         const progressBar = createProgressBar();

//         // 프로그레스 바를 업데이트하는 커스텀 fetch 함수
//         // const fetchWithProgress = async (url, options) => {
//         //     const xhr = new XMLHttpRequest();
//         //     xhr.open(options.method || 'GET', url);

//         //     for (const header in options.headers) {
//         //         xhr.setRequestHeader(header, options.headers[header]);
//         //     }

//         //     xhr.upload.onprogress = (event) => {
//         //         if (event.lengthComputable) {
//         //             const percentComplete = (event.loaded / event.total) * 100;
//         //             progressBar.update(Math.round(percentComplete));
//         //         }
//         //     };

//         //     return new Promise((resolve, reject) => {
//         //         xhr.onload = () => {
//         //             if (xhr.status >= 200 && xhr.status < 300) {
//         //                 resolve(xhr.response);
//         //             } else {
//         //                 reject(xhr.statusText);
//         //             }
//         //         };
//         //         xhr.onerror = () => reject(xhr.statusText);
//         //         xhr.send(options.body);
//         //     });
//         // };

//         const response = await fetchWithProgress('/save_post', {
//             method: 'POST',
//             headers: { 'Content-Type': 'application/json' },
//             body: JSON.stringify(postData)
//         });

//         // 프로그레스 표시 종료
//         removeProgressBar(progressBar);

//         const data = JSON.parse(response);

//         if (data.success) {
//             alert('Post saved successfully!');
//             loadPosts();
//         } else {
//             throw new Error(data.message || 'Failed to save post.');
//         }
//     } catch (error) {
//         console.error('Error:', error);
//         alert('Error: ' + error.message);
//     }
// }

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
