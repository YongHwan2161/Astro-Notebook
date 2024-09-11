import * as THREE from '../three/three.module.js';
import { OrbitControls } from '../three/controls/OrbitControls.js';

export function initScene() {
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer();
    renderer.setSize(window.innerWidth, window.innerHeight);
    document.body.appendChild(renderer.domElement);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.rotateSpeed = 0.5;
    controls.minDistance = 1;
    controls.maxDistance = 450;

    const celestialSphere = createCelestialSphere();
    scene.add(celestialSphere);

    const groundPlane = createGroundPlane();
    scene.add(groundPlane);

    const celestialContainer = new THREE.Object3D();
    scene.add(celestialContainer);

    const raDecGrid = createRADecGrid();
    celestialContainer.add(raDecGrid);

    camera.position.set(0, 10, 0);
    controls.update();

    return { scene, camera, renderer, controls, celestialContainer, groundPlane };
}

function createCelestialSphere() {
    const sphereGeometry = new THREE.SphereGeometry(500, 64, 64);
    const sphereMaterial = new THREE.MeshBasicMaterial({ color: 0x000000, side: THREE.BackSide });
    return new THREE.Mesh(sphereGeometry, sphereMaterial);
}

function createGroundPlane() {
    const groundGeometry = new THREE.CircleGeometry(500, 32);
    const groundMaterial = new THREE.MeshBasicMaterial({ color: 0x228B22, side: THREE.DoubleSide });
    const groundPlane = new THREE.Mesh(groundGeometry, groundMaterial);
    groundPlane.rotation.x = Math.PI / 2;
    groundPlane.position.y = -0.1;
    return groundPlane;
}

function createRADecGrid() {
    // ... (existing createRADecGrid function code)
}

export function animate(renderer, scene, camera, controls) {
    requestAnimationFrame(() => animate(renderer, scene, camera, controls));
    controls.update();
    renderer.render(scene, camera);
}