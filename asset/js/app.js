// app.js
import * as auth from './modules/auth.js';
import * as posts from './modules/posts.js';
import * as drive from './modules/drive.js';
import * as modelRenderer from './modules/modelRenderer.js';
import { loadCategories, renderCategories, loadPosts, sortPosts } from './modules/posts.js';
import { EditPost } from './modules/posts.js';
import { createLogViewer } from './modules/logViewer.js';

let currentUser = null;

document.addEventListener('DOMContentLoaded', () => {
    createLogViewer();
    console.log('app.js loaded');
    initApp();
});

function setCurrentUser(user) {
    currentUser = user;
    // 필요한 경우 UI 업데이트
}
function onLoginSuccess(user) {
    setCurrentUser(user);
    //posts.loadPosts();
}

function onLogoutSuccess() {
    setCurrentUser(null);
    //posts.loadPosts();
}

function initApp() {
    auth.initAuth(onLoginSuccess, onLogoutSuccess);
    posts.initPosts();
    drive.initDrive();
    //modelRenderer.initModelRenderer();
}


// 전역 스코프에 노출할 함수들
window.showSection = async (sectionId) => {
    // showSection 함수의 현재 구현을 여기로 옮깁니다.
    // Hide all sections
    document.getElementById('banner').classList.add('hidden');
    document.getElementById('banner_project').classList.add('hidden');
    document.getElementById('banner_drive').classList.add('hidden');

    // Show the selected section
    document.getElementById(sectionId).classList.remove('hidden');
    if (sectionId == 'banner_project') {
        const categoriesContainer = document.getElementById('categories-container');

        try {
            const categories = await loadCategories();
            renderCategories(categories, categoriesContainer);

            categoriesContainer.addEventListener('click', (event) => {
                const target = event.target; // 이 줄을 추가합니다.

                if (target.classList.contains('category-button')) {
                    // const category = event.target.dataset;
                    // loadPosts(category);
                    const categoryId = target.dataset.categoryId;
                    const categoryName = target.dataset.categoryName;
                    const category = {
                        id: categoryId,
                        name: categoryName
                    };
                    loadPosts(category);
                }
            });

            //기본 카테고리 로드 (예: 'All' 또는 첫 번째 카테고리)
            if (categories.length > 0) {
                loadPosts(categories[0]);
            }
        } catch (error) {
            console.error('Failed to initialize categories:', error);
            categoriesContainer.innerHTML = '<p>Failed to load categories. Please try again later.</p>';
        }
    } else if (sectionId == 'banner_drive') {
        //loadImage();  // 페이지가 로드될 때 게시글 목록을 로드
        drive.loadDriveContent();
    }
};
window.showSignupForm = auth.showSignupForm;
window.showLoginForm = auth.showLoginForm;
window.checkUsername = auth.checkUsername;
window.submitSignup = auth.submitSignup;
window.submitLogin = auth.submitLogin;
window.logout = auth.logout;

window.loadPosts = posts.loadPosts;
window.showPostContent = posts.showPostContent;
window.hidePostContent = posts.hidePostContent;
window.deletePost = posts.deletePost;
window.writePost = posts.writePost;
window.savePost = posts.savePost;
window.submitComment = posts.submitComment;
window.editComment = posts.editComment;
window.deleteComment = posts.deleteComment;

window.toggleView = drive.toggleView;
window.createFolder = drive.createFolder;
window.downloadFile = drive.downloadFile;
// 파일 업로드 이벤트 리스너 설정
document.getElementById('file-upload').addEventListener('change', drive.uploadFiles);


window.render3DModel = modelRenderer.render3DModel;
// 기타 전역으로 노출해야 하는 함수들...
window.sortPosts = sortPosts;
window.EditPost = EditPost;