import * as THREE from '../three/three.module.js';

let scene, camera, renderer;

function initScene() {
    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    
    const canvas = document.createElement('canvas');
    document.body.appendChild(canvas);
    renderer = new THREE.WebGLRenderer({ canvas: canvas });
    renderer.setSize(window.innerWidth, window.innerHeight);

    // Lighting
    const ambientLight = new THREE.AmbientLight(0x404040);
    scene.add(ambientLight);
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.5);
    directionalLight.position.set(1, 1, 1);
    scene.add(directionalLight);

    // Ground
    const textureLoader = new THREE.TextureLoader();
    const groundTexture = textureLoader.load('/uploads/images/textures/ground.jpeg');
    groundTexture.wrapS = THREE.RepeatWrapping;
    groundTexture.wrapT = THREE.RepeatWrapping;
    groundTexture.repeat.set(10, 10);

    const groundGeometry = new THREE.PlaneGeometry(100, 100);
    const groundMaterial = new THREE.MeshStandardMaterial({ map: groundTexture });
    const ground = new THREE.Mesh(groundGeometry, groundMaterial);
    ground.rotation.x = -Math.PI / 2;
    scene.add(ground);

    // Skybox
    const skyboxTexture = textureLoader.load('/uploads/images/textures/skybox/skybox_panorama.png');
    skyboxTexture.mapping = THREE.EquirectangularReflectionMapping;
    scene.background = skyboxTexture;

    return { scene, camera, renderer };
}

function onWindowResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
}

export { initScene, onWindowResize };