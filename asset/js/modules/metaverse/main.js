import { initScene, onWindowResize } from './scene.js';
import { createAvatar, moveAvatar } from './avatar.js';
import { ObjectManager } from './objects.js';
import { initInputHandlers, getKeyState, getMousePosition } from './input.js';
import { createChatUI } from './chat.js';
import * as THREE from '../three/three.module.js';

let scene, camera, renderer, avatar;
let objectManager;
let targetRotationX = 0, targetRotationY = 0;
let clock, deltaTime, elapsedTime;

const TARGET_FPS = 60;
const FRAME_INTERVAL = 1000 / TARGET_FPS;
let lastFrameTime = 0;

function init() {
    ({ scene, camera, renderer } = initScene());
    avatar = createAvatar();
    scene.add(avatar);

    camera.position.set(0, 3, 5);
    camera.lookAt(avatar.position);

    initInputHandlers();
    createChatUI();
    objectManager = new ObjectManager(scene);

    window.addEventListener('resize', onWindowResize, false);
    document.addEventListener('click', onClick, false);
    document.addEventListener('contextmenu', onRightClick, false);

    clock = new THREE.Clock();
    requestAnimationFrame(animate);

    lastFrameTime = performance.now();
    requestAnimationFrame(animate);
}

function onClick(event) {
    event.preventDefault();
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2(getMousePosition().x, getMousePosition().y);
    raycaster.setFromCamera(mouse, camera);

    const intersects = raycaster.intersectObjects(objectManager.objects);
    if (intersects.length > 0) {
        objectManager.selectObject(intersects[0].object);
    } else {
        const objectTypes = ['cube', 'sphere', 'cone'];
        const randomType = objectTypes[Math.floor(Math.random() * objectTypes.length)];
        const newObject = objectManager.createObject(avatar.position, raycaster.ray.direction, randomType);
    }
}

function onRightClick(event) {
    event.preventDefault();
    objectManager.removeSelectedObject();
}
function getMovementDirection() {
    const direction = new THREE.Vector3();
    if (getKeyState('KeyW')) direction.z -= 1;
    if (getKeyState('KeyS')) direction.z += 1;
    if (getKeyState('KeyA')) direction.x -= 1;
    if (getKeyState('KeyD')) direction.x += 1;
    return direction.normalize();
}

function updateAvatar(deltaTime) {
    const direction = getMovementDirection();
    if (direction.length() > 0) {
        const speed = 10; // 초당 5 유닛
        moveAvatar(direction.multiplyScalar(speed * deltaTime));
    }
}
function updateCamera(deltaTime) {
    const sensitivity = 0.002;
    const mousePosition = getMousePosition();
    targetRotationY += mousePosition.x * sensitivity;
    targetRotationX += mousePosition.y * sensitivity;

    targetRotationX = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, targetRotationX));

    const smoothFactor = 1 - Math.pow(0.001, deltaTime);
    camera.position.x = avatar.position.x + Math.sin(targetRotationY) * 5;
    camera.position.y = avatar.position.y + 2 + Math.sin(targetRotationX) * 2;
    camera.position.z = avatar.position.z + Math.cos(targetRotationY) * 5;

    camera.position.lerp(new THREE.Vector3(
        avatar.position.x + Math.sin(targetRotationY) * 5,
        avatar.position.y + 2 + Math.sin(targetRotationX) * 2,
        avatar.position.z + Math.cos(targetRotationY) * 5
    ), smoothFactor);

    camera.lookAt(avatar.position);
}

function getObjectMovementDirection() {
    const direction = new THREE.Vector3();
    if (getKeyState('ArrowUp')) direction.y += 1;
    if (getKeyState('ArrowDown')) direction.y -= 1;
    if (getKeyState('ArrowLeft')) direction.x -= 1;
    if (getKeyState('ArrowRight')) direction.x += 1;
    return direction.normalize();
}
function updateSelectedObject(deltaTime) {
    const direction = getObjectMovementDirection();
    if (direction.length() > 0) {
        const speed = 10; // 초당 2 유닛
        objectManager.moveSelectedObject(direction.multiplyScalar(speed * deltaTime));
    }
}
function animate(currentTime) {
    requestAnimationFrame(animate);

    const deltaTime = (currentTime - lastFrameTime) / 1000;
    if (deltaTime < FRAME_INTERVAL / 1000) return;

    lastFrameTime = currentTime;
    elapsedTime = clock.getElapsedTime();

    updateAvatar(deltaTime);
    updateCamera(deltaTime);
    updateSelectedObject(deltaTime);

    renderer.render(scene, camera);
}
init();