import * as THREE from './three/three.module.js';
import { OrbitControls } from './three/controls/OrbitControls.js';
import { OBJLoader } from './three/loaders/OBJLoader.js';
import { MTLLoader } from './three/loaders/MTLLoader.js';
import { STLLoader } from './three/loaders/STLLoader.js';

export function initModelRenderer() {
    // 초기화 코드 (필요한 경우)
}

export function render3DModel(canvas, modelData, mtlData, textureData, isUrl = false, modelType = 'obj') {
    // render3DModel 함수 구현
    console.log('Render3DModel called with:', {
        modelData: modelData ? modelData.substring(0, 100) + '...' : 'None',
        mtlData: mtlData ? mtlData.substring(0, 100) + '...' : 'None',
        textureData: textureData,
        isUrl: isUrl,
        modelType: modelType
    });

    let animationFrameId;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true });
    renderer.setSize(canvas.clientWidth, canvas.clientHeight);
    renderer.setClearColor(0xcccccc);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.25;
    controls.screenSpacePanning = false;
    controls.maxPolarAngle = Math.PI / 2;

    const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    scene.add(ambientLight);
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(1, 1, 1).normalize();
    scene.add(directionalLight);

    let loader;
    if (modelType === 'obj') {
        loader = new OBJLoader();
    } else if (modelType === 'stl') {
        loader = new STLLoader();
    }
    const textureLoader = new THREE.TextureLoader();

    function loadMtl() {
        return new Promise((resolve, reject) => {
            if (mtlData && modelType === 'obj') {
                const mtlLoader = new MTLLoader();
                mtlLoader.setMaterialOptions({ side: THREE.DoubleSide });
                if (isUrl) {
                    mtlLoader.load(mtlData,
                        (materials) => {
                            console.log('MTL loaded successfully', materials);
                            materials.preload();
                            logMaterials(materials.materials);
                            loader.setMaterials(materials);
                            resolve(materials);
                        },
                        undefined,
                        (error) => reject(new Error('Failed to load MTL: ' + error.message))
                    );
                } else {
                    try {
                        const materialsCreator = mtlLoader.parse(mtlData);
                        materialsCreator.preload();
                        logMaterials(materialsCreator.materials);
                        loader.setMaterials(materialsCreator);
                        console.log('MTL parsed successfully', materialsCreator);
                        resolve(materialsCreator);
                    } catch (error) {
                        reject(new Error('Failed to parse MTL: ' + error.message));
                    }
                }
            } else {
                console.log('No MTL data provided or not applicable for STL');
                resolve(null);
            }
        });
    }

    function loadModel(materials) {
        return new Promise((resolve, reject) => {
            const onLoad = (object) => {
                console.log('Model loaded successfully:', object);
                if (modelType === 'obj') {
                    object.traverse((child) => {
                        if (child instanceof THREE.Mesh) {
                            console.log('Mesh found:', child.name);
                            console.log('Material:', child.material);
                            if (child.material.map) {
                                console.log('Material has texture map:', child.material.map.name);
                            } else {
                                console.log('Material does not have texture map');
                            }
                            // Ensure the material is MeshPhongMaterial
                            if (!(child.material instanceof THREE.MeshPhongMaterial)) {
                                child.material = new THREE.MeshPhongMaterial({
                                    color: child.material.color,
                                    map: child.material.map,
                                    normalMap: child.material.normalMap,
                                    specularMap: child.material.specularMap
                                });
                            }
                            child.material.needsUpdate = true;
                        }
                    });
                } else if (modelType === 'stl') {
                    // STL files typically come as a single mesh
                    const material = new THREE.MeshPhongMaterial({ color: 0xcccccc });
                    const mesh = new THREE.Mesh(object, material);
                    object = new THREE.Group();
                    object.add(mesh);
                }
                resolve(object);
            };

            if (isUrl) {
                loader.load(modelData, onLoad, onProgress,
                    (error) => reject(new Error(`Failed to load ${modelType.toUpperCase()}: ` + error.message)));
            } else {
                const modelBlob = new Blob([modelData], { type: 'text/plain' });
                const modelUrl = URL.createObjectURL(modelBlob);
                loader.load(modelUrl, (object) => {
                    URL.revokeObjectURL(modelUrl);
                    onLoad(object);
                }, onProgress,
                    (error) => reject(new Error(`Failed to load ${modelType.toUpperCase()}: ` + error.message)));
            }
        });
    }

    function loadTextures() {
        // loadTextures 함수 구현 (변경 없음)
    }

    loadMtl()
        .then(materials => {
            console.log('MTL loading completed, starting model and texture loading');
            return Promise.all([loadModel(materials), loadTextures()]);
        })
        .then(([object, textures]) => {
            console.log('Model and textures loaded, applying textures');
            console.log('Loaded textures:', textures);
            applyTextures(object, textures);
            scene.add(object);
            console.log('Object added to scene with textures');
            fitCameraToObject(camera, object, controls);
            console.log('Scene contents:', scene.children);
            animate();
        })
        .catch((error) => {
            console.error('Error in render3DModel:', error.message);
            canvas.parentNode.textContent = 'Error rendering 3D model: ' + error.message;
        });

    function applyTextures(object, textures) {
        // applyTextures 함수 구현 (변경 없음)
    }

    function onProgress(xhr) {
        // onProgress 함수 구현 (변경 없음)
    }

    function animate() {
        animationFrameId = requestAnimationFrame(animate);
        controls.update();
        renderer.render(scene, camera);
    }

    function fitCameraToObject(camera, object, controls) {
        // fitCameraToObject 함수 구현 (변경 없음)
    }

    function logMaterials(materials) {
        // logMaterials 함수 구현 (변경 없음)
    }

    window.addEventListener('resize', onWindowResize);

    function onWindowResize() {
        camera.aspect = canvas.clientWidth / canvas.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(canvas.clientWidth, canvas.clientHeight);
    }

    return () => {
        cancelAnimationFrame(animationFrameId);
        window.removeEventListener('resize', onWindowResize);
        // 필요한 경우 다른 정리 작업 수행
    };
}