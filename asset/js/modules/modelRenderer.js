// modelRenderer.js

import * as THREE from './three/three.module.js';
import { OrbitControls } from './three/controls/OrbitControls.js';
import { OBJLoader } from './three/loaders/OBJLoader.js';
import { MTLLoader } from './three/loaders/MTLLoader.js';
import { STLLoader } from './three/loaders/STLLoader.js';
import { TDSLoader } from './three/loaders/TDSLoader.js';
import { load3DModel } from './posts.js';

export function render3DModel(canvas, modelData, mtlData, textureData, isUrl = false, modelType = 'obj') {
    // render3DModel 함수 구현
    console.log('Render3DModel called with:');
    console.log('modelData:', modelData ? modelData.substring(0, 100) + '...' : 'None');
    console.log('mtlData:', mtlData ? mtlData.substring(0, 100) + '...' : 'None');
    console.log('textureData:', JSON.stringify(textureData, null, 2));
    console.log('isUrl:', isUrl);
    console.log('modelType:', modelType);

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
    } else if (modelType === '3ds') {
        loader = new TDSLoader();
    } else {
        throw new Error('Unsupported model type: ' + modelType);
    }
    async function renderModel() {
        try {
            let object;
            if (modelType === 'obj') {
                const materials = await loadMtl();
                console.log('MTL loading completed, starting OBJ and texture loading');
                const [loadedObject, textures] = await Promise.all([loadModel(materials), loadTextures()]);
                //console.log('Model loaded:', JSON.stringify(loadedObject, null, 2));
                console.log('Textures loaded:', JSON.stringify(textures, null, 2));

                applyTextures(loadedObject, textures);
                object = loadedObject;
            } else if (modelType === 'stl') {
                console.log('Starting STL loading');
                object = await loadModel(null); // null을 전달하거나 기본 재질을 전달
                console.log('STL loaded');

            } else {
                throw new Error('Unsupported model type: ' + modelType);
            }

            scene.add(object);
            console.log('Object added to scene');
            fitCameraToObject(camera, object, controls);
            console.log('Scene contents:', scene.children);
            animate();
        } catch (error) {
            console.error('Error in render3DModel:', error.message);
            canvas.parentNode.textContent = 'Error rendering 3D model: ' + error.message;
        }
    }
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
    function base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function loadModel(materials) {
        return new Promise((resolve, reject) => {
            const onLoad = (object) => {
                console.log('Model loaded successfully:', object);
                if (modelType === 'obj') {
                    object.traverse((child) => {
                        if (child instanceof THREE.Mesh) {
                            console.log('Mesh found:', child.name);
                            if (materials && materials.materials[child.material.name]) {
                                child.material = materials.materials[child.material.name];
                                console.log('Applied material from MTL:', child.material.name);
                            } else {
                                console.log('Material not found in MTL, using default');
                                child.material = new THREE.MeshPhongMaterial({
                                    color: child.material.color,
                                    map: child.material.map,
                                    normalMap: child.material.normalMap,
                                    specularMap: child.material.specularMap
                                });
                            }
                            console.log('Material:', child.material);
                            if (child.material.map) {
                                console.log('Material has texture map:', child.material.map.name);
                            } else {
                                console.log('Material does not have texture map');
                            }
                            child.material.needsUpdate = true;
                        }
                    });
                } else if (modelType === 'stl') {
                    const material = new THREE.MeshPhongMaterial({
                        color: 0x555555,
                        specular: 0x111111,
                        shininess: 200
                    });
                    let mesh;
                    if (object instanceof THREE.BufferGeometry) {
                        mesh = new THREE.Mesh(object, material);
                    } else {
                        mesh = object;
                        mesh.material = material;
                    }
                    // 객체 크기 정규화
                    const box = new THREE.Box3().setFromObject(mesh);
                    const size = box.getSize(new THREE.Vector3());
                    const maxDim = Math.max(size.x, size.y, size.z);
                    mesh.scale.multiplyScalar(1 / maxDim);
                    mesh.position.set(0, 0, 0);

                    object = new THREE.Group();
                    object.add(mesh);
                } else if (modelType === '3ds') {
                    const material = new THREE.MeshPhongMaterial({
                        color: 0xcccccc,
                        specular: 0x111111,
                        shininess: 200
                    });
                    object.traverse((child) => {
                        if (child instanceof THREE.Mesh) {
                            child.material = material;
                        }
                    });
                }
                resolve(object);
            };

            if (isUrl) {
                if (modelType === 'obj' && materials) {
                    loader.setMaterials(materials);
                }
                loader.load(modelData, onLoad, onProgress,
                    (error) => reject(new Error(`Failed to load ${modelType.toUpperCase()}: ` + error.message)));
            } else {
                if (modelType === 'stl' || modelType === '3ds') {
                    // STL 파일의 경우, modelData가 이미 ArrayBuffer 형태라고 가정
                    try {
                        // base64 문자열을 ArrayBuffer로 변환
                        // if (typeof modelData === 'string') {
                        //     const binary = atob(modelData);
                        //     const len = binary.length;
                        //     const bytes = new Uint8Array(len);
                        //     for (let i = 0; i < len; i++) {
                        //         bytes[i] = binary.charCodeAt(i);
                        //     }
                        //     modelData = bytes.buffer;
                        // }

                        // // ArrayBuffer 확인
                        // if (!(modelData instanceof ArrayBuffer)) {
                        //     throw new Error('STL data is not in ArrayBuffer format');
                        // }
                        const arrayBuffer = base64ToArrayBuffer(modelData);
                        const geometry = loader.parse(arrayBuffer);
                        onLoad(geometry);
                    } catch (error) {
                        reject(new Error(`Failed to parse STL data: ${error.message}`));
                    }
                } else {
                    const modelBlob = new Blob([modelData], { type: 'text/plain' });
                    const modelUrl = URL.createObjectURL(modelBlob);
                    if (modelType === 'obj' && materials) {
                        loader.setMaterials(materials);
                    }
                    loader.load(modelUrl, (object) => {
                        URL.revokeObjectURL(modelUrl);
                        onLoad(object);
                    }, onProgress,
                        (error) => reject(new Error(`Failed to load ${modelType.toUpperCase()}: ` + error.message)));
                }
            }
        });
    }
    function loadTexture(textureData, textureName) {
        return new Promise((resolve, reject) => {
            const loader = new THREE.TextureLoader();
            loader.setCrossOrigin('anonymous');
            
            console.log('Loading texture:', textureName, typeof textureData);
    
            if (typeof textureData === 'string' && textureData.startsWith('data:')) {
                // Base64 데이터 URL인 경우
                loader.load(
                    textureData,
                    onLoad,
                    onProgress,
                    onError
                );
            } else if (typeof textureData === 'string') {
                // URL 문자열인 경우
                loader.load(
                    '/' + textureData,
                    onLoad,
                    onProgress,
                    onError
                );
            } else {
                // 텍스처 데이터가 직접 전달된 경우 (예: ArrayBuffer)
                const blob = new Blob([textureData]);
                const textureUrl = URL.createObjectURL(blob);
                loader.load(
                    textureUrl,
                    (texture) => {
                        onLoad(texture);
                        URL.revokeObjectURL(textureUrl);
                    },
                    onProgress,
                    onError
                );
            }
    
            function onLoad(loadedTexture) {
                console.log(`Texture ${textureName} loaded successfully:`, loadedTexture);
                if (loadedTexture.image) {
                    console.log(`Texture ${textureName} image details:`, {
                        width: loadedTexture.image.width,
                        height: loadedTexture.image.height,
                        complete: loadedTexture.image.complete,
                        src: loadedTexture.image.src
                    });
                } else {
                    console.warn(`Texture ${textureName} does not have image data`);
                }
                loadedTexture.name = textureName;
                resolve({ name: textureName, texture: loadedTexture, url: textureData });
            }
    
            function onProgress(xhr) {
                console.log(`${textureName} ${(xhr.loaded / xhr.total * 100)}% loaded`);
            }
    
            function onError(error) {
                console.error(`Failed to load texture ${textureName}:`, error);
                reject({ name: textureName, texture: null, url: textureData, error: error.message });
            }
        });
    }
    function loadTextures() {
        console.log('Loading textures:', JSON.stringify(textureData, null, 2));
        return Promise.all(textureData.map(texture => {
            const textureName = texture.name;
            const textureData = isUrl ? texture.url.url : texture.content;
            console.log(`Attempting to load texture: ${textureName}`);
            return loadTexture(textureData, textureName);
        }));
    }

    renderModel();

    function applyTextures(object, textures) {
        object.traverse((child) => {
            if (child instanceof THREE.Mesh) {
                const material = child.material;
                console.log('Applying textures to material:', material.name);

                textures.forEach(tex => {
                    if (tex.texture) {
                        const textureName = tex.name.toLowerCase();
                        console.log(`Processing texture: ${textureName}, URL: ${tex.url}`);

                        // URL에서 텍스처 유형을 추측
                        const isColor = tex.url.includes('color') || tex.url.includes('diffuse');
                        const isNormal = tex.url.includes('normal') || tex.url.includes('bump');
                        const isSpecular = tex.url.includes('specular');

                        if (isColor || textureName.includes('diffuse') || textureName.includes('color')) {
                            material.map = tex.texture;
                            console.log('Applied diffuse/color map:', textureName);
                        } else if (isNormal || textureName.includes('bump') || textureName.includes('normal')) {
                            material.normalMap = tex.texture;
                            console.log('Applied normal/bump map:', textureName);
                        } else if (isSpecular || textureName.includes('specular')) {
                            material.specularMap = tex.texture;
                            console.log('Applied specular map:', textureName);
                        } else {
                            console.log(`Unrecognized texture type: ${textureName}`);
                        }
                    } else if (tex.error) {
                        console.warn(`Texture ${tex.name} failed to load: ${tex.error}`);
                    }
                });

                material.needsUpdate = true;
                //console.log('Updated material:', JSON.stringify(material.toJSON(), null, 2));
            }
        });
    }
    function onProgress(xhr) {
        // onProgress 함수 구현
        //console.log((xhr.loaded / xhr.total * 100) + '% loaded');
    }

    function animate() {
        animationFrameId = requestAnimationFrame(animate);
        controls.update();
        renderer.render(scene, camera);
    }

    function fitCameraToObject(camera, object, controls) {
        // fitCameraToObject 함수 구현
        const box = new THREE.Box3().setFromObject(object);
        const center = box.getCenter(new THREE.Vector3());
        const size = box.getSize(new THREE.Vector3());
        const maxDim = Math.max(size.x, size.y, size.z);
        const fov = camera.fov * (Math.PI / 180);
        let cameraZ = Math.abs(maxDim / 2 / Math.tan(fov / 2));
        cameraZ *= 1.5;
        camera.position.z = cameraZ;
        const minZ = box.min.z;
        const cameraToFarEdge = (minZ < 0) ? -minZ + cameraZ : cameraZ - minZ;
        camera.far = cameraToFarEdge * 3;
        camera.updateProjectionMatrix();
        if (controls) {
            controls.target = center;
            controls.maxDistance = cameraToFarEdge * 2;
        }
        console.log('Camera fitted to object:', { position: camera.position, target: controls.target });
    }
    function logMaterials(materials) {
        Object.keys(materials).forEach(key => {
            const mat = materials[key];
            console.log(`Material ${key}:`, {
                color: mat.color ? mat.color.getHexString() : 'N/A',
                map: mat.map ? mat.map.name : 'N/A',
                normalMap: mat.normalMap ? mat.normalMap.name : 'N/A',
                specularMap: mat.specularMap ? mat.specularMap.name : 'N/A'
            });
        });
    }
    // 이벤트 리스너를 render3DModel 함수 내부로 이동
    window.addEventListener('resize', onWindowResize);

    function onWindowResize() {
        camera.aspect = canvas.clientWidth / canvas.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(canvas.clientWidth, canvas.clientHeight);
    }
    // 정리 함수 반환
    return () => {
        cancelAnimationFrame(animationFrameId);
        window.removeEventListener('resize', onWindowResize);
        // 필요한 경우 다른 정리 작업 수행
    };
}