let currentPage = 1;
let postsPerPage = 10;
// 전역 변수로 현재 선택된 카테고리를 저장
let currentCategory = null;


document.addEventListener('DOMContentLoaded', function () {
    loadCategories();
    loadPosts();

    const createPostBtn = document.getElementById('btn-create-post');
    const postModal = document.getElementById('post-modal');
    const closeBtn = document.querySelector('.close');

    createPostBtn.addEventListener('click', openPostModal);
    closeBtn.addEventListener('click', closePostModal);
    document.getElementById('post-form').addEventListener('submit', submitPost);

    // Close the modal if clicked outside of it
    window.addEventListener('click', function (event) {
        if (event.target === postModal) {
            closePostModal();
        }
    });
});


function displayPosts(posts) {
    const container = document.getElementById('posts-container');
    container.innerHTML = '';

    posts.forEach(post => {
        const postElement = document.createElement('div');
        postElement.className = 'article-box';
        postElement.innerHTML = `
            <a href="#" class="article-box-link" data-post-id="${post.id}">
                <div class="article-box-text">
                    <div class="article-box-title"><h3>${post.title}</h3></div>
                    <div class="article-box-info">${post.content.substring(0, 200)}...</div>
                    <div class="article-box-catag">
                        <h5>작성자: ${post.author}, 작성일: ${new Date(post.timestamp).toLocaleString()}</h5>
                    </div>
                </div>
            </a>
        `;
        container.appendChild(postElement);
    });

    // Add event listeners for post links
    document.querySelectorAll('.article-box-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            openPostModal(link.dataset.postId);
        });
    });
}

function openPostModal() {
    const modal = document.getElementById('post-modal');
    const modalTitle = document.getElementById('modal-title');
    const form = document.getElementById('post-form');

    // Create new post
    modalTitle.textContent = '새 글 작성';
    form.reset();
    delete form.dataset.postId;

    modal.style.display = 'block';
}

function closePostModal() {
    document.getElementById('post-modal').style.display = 'none';
}

function loadCategories() {
    fetch('/categories')
        .then(response => response.json())
        .then(categories => {
            const categoryButtons = document.getElementById('category-buttons');
            categoryButtons.innerHTML = ''; // 기존 버튼들을 모두 제거

            categories.forEach((category, index) => {
                const button = document.createElement('div');
                button.className = 'btn-rtg';
                button.id = category.id;
                button.innerHTML = `<h6>${category.name}</h6>`;
                button.addEventListener('click', () => selectCategory(category.id));
                categoryButtons.appendChild(button);

                // 첫 번째 카테고리를 currentCategory로 설정하고 'selected' 클래스 추가
                if (index === 0) {
                    currentCategory = category.id;
                    button.classList.add('selected');
                    // 첫 번째 카테고리의 게시글 로드
                    loadPosts(category.id);
                }
            });

            // 카테고리 선택 모달에도 카테고리 추가
            const categorySelect = document.getElementById('post-category');
            categorySelect.innerHTML = ''; // 기존 옵션들을 모두 제거
            categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category.id;
                option.textContent = category.name;
                categorySelect.appendChild(option);
            });
        })
        .catch(error => {
            console.error('Error loading categories:', error);
        });
}

function selectCategory(categoryId) {
    // 이전에 선택된 카테고리의 스타일 제거
    if (currentCategory) {
        document.getElementById(currentCategory).classList.remove('selected');
    }

    // 새로 선택된 카테고리에 스타일 적용
    const selectedButton = document.getElementById(categoryId);
    selectedButton.classList.add('selected');

    currentCategory = categoryId;

    // 선택된 카테고리에 따라 게시글 필터링
    loadPosts(categoryId);
}
async function loadPosts(categoryId = null) {
    try {
        const response = await fetch(`/posts?categoryId=${encodeURIComponent(categoryId)}`);
        if (!response.ok) {
            throw new Error('Failed to fetch posts');
        }
        const posts = await response.json();
        displayPosts(posts);
    } catch (error) {
        console.error('Error:', error);
    }
}
function displayPosts(posts) {
    const container = document.getElementById('posts-container');
    container.innerHTML = '';

    posts.forEach(post => {
        const postElement = document.createElement('div');
        postElement.className = 'article-box';
        postElement.innerHTML = `
            <a href="#" class="article-box-link" data-post-id="${post.id}">
                <div class="article-box-img"></div>
                <div class="article-box-text">
                    <div class="article-box-title"><h3>${post.title}</h3></div>
                    <div class="article-box-info">${post.content.substring(0, 200)}...</div>
                    <div class="article-box-catag">
                        <h5>카테고리: ${post.category}, 작성자: ${post.author}, 작성일: ${new Date(post.timestamp).toLocaleString()}</h5>
                    </div>
                </div>
            </a>
        `;
        container.appendChild(postElement);
    });

    document.querySelectorAll('.article-box-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            openPostModal(link.dataset.postId);
        });
    });
}
