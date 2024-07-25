// modelRenderer.js

import * as THREE from './three/three.module.js';
import { OrbitControls } from './three/controls/OrbitControls.js';
import { OBJLoader } from './three/loaders/OBJLoader.js';
import { MTLLoader } from './three/loaders/MTLLoader.js';

export function initModelRenderer() {
    // 초기화 코드 (필요한 경우)

}
export function render3DModel(canvas, objData, mtlData, textureData, isUrl = false) {
    console.log('Render3DModel called with:', {
        objData: objData ? objData.substring(0, 100) + '...' : 'None',
        mtlData: mtlData ? mtlData.substring(0, 100) + '...' : 'None',
        textureData: textureData,
        isUrl: isUrl
    });

    const renderer = initRenderer(canvas);
    const scene = new THREE.Scene();
    const camera = initCamera(canvas);
    const controls = initControls(camera, renderer);

    addLights(scene);

    loadModel(objData, mtlData, textureData, isUrl)
        .then(object => {
            addObjectToScene(scene, object);
            fitCameraToObject(camera, object, controls);
            animate(renderer, scene, camera, controls);
        })
        .catch(error => {
            console.error('Error rendering 3D model:', error);
            showErrorMessage(canvas, error.message);
        });

    window.addEventListener('resize', () => onWindowResize(camera, renderer), false);

    return () => {
        window.removeEventListener('resize', onWindowResize);
        renderer.dispose();
    };
}

function initRenderer(canvas) {
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
    renderer.setSize(canvas.clientWidth, canvas.clientHeight);
    renderer.setClearColor(0xcccccc);
    return renderer;
}

function initCamera(canvas) {
    const camera = new THREE.PerspectiveCamera(75, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
    camera.position.z = 5;
    return camera;
}

function initControls(camera, renderer) {
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.25;
    controls.screenSpacePanning = false;
    controls.maxPolarAngle = Math.PI / 2;
    return controls;
}

function addLights(scene) {
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    scene.add(ambientLight);
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(1, 1, 1).normalize();
    scene.add(directionalLight);
}

async function loadModel(objData, mtlData, textureData, isUrl) {
    const loader = new OBJLoader();
    const materials = await loadMtl(mtlData, isUrl);
    if (materials) {
        loader.setMaterials(materials);
    }
    const object = await loadObj(loader, objData, isUrl);
    await applyTextures(object, textureData, isUrl);
    return object;
}

function loadMtl(mtlData, isUrl) {
    if (!mtlData) return null;
    const mtlLoader = new MTLLoader();
    mtlLoader.setMaterialOptions({ side: THREE.DoubleSide });
    return new Promise((resolve, reject) => {
        if (isUrl) {
            mtlLoader.load(mtlData, resolve, undefined, reject);
        } else {
            try {
                const materials = mtlLoader.parse(mtlData);
                resolve(materials);
            } catch (error) {
                reject(error);
            }
        }
    });
}

function loadObj(loader, objData, isUrl) {
    return new Promise((resolve, reject) => {
        const onLoad = object => {
            object.traverse(child => {
                if (child instanceof THREE.Mesh) {
                    child.material = new THREE.MeshPhongMaterial({
                        color: child.material.color,
                        map: child.material.map,
                        normalMap: child.material.normalMap,
                        specularMap: child.material.specularMap
                    });
                }
            });
            resolve(object);
        };
        if (isUrl) {
            loader.load(objData, onLoad, undefined, reject);
        } else {
            const objBlob = new Blob([objData], { type: 'text/plain' });
            const objUrl = URL.createObjectURL(objBlob);
            loader.load(objUrl, object => {
                URL.revokeObjectURL(objUrl);
                onLoad(object);
            }, undefined, reject);
        }
    });
}

async function applyTextures(object, textureData, isUrl) {
    const textureLoader = new THREE.TextureLoader();
    const loadTexture = (textureUrl) => new Promise((resolve, reject) => {
        textureLoader.load(textureUrl, resolve, undefined, reject);
    });

    const textures = await Promise.all(textureData.map(async texture => {
        const textureUrl = isUrl ? texture : texture.content;
        try {
            const loadedTexture = await loadTexture(textureUrl);
            return { name: texture.name, texture: loadedTexture };
        } catch (error) {
            console.error(`Failed to load texture ${texture.name}:`, error);
            return { name: texture.name, texture: null };
        }
    }));

    object.traverse(child => {
        if (child instanceof THREE.Mesh) {
            textures.forEach(tex => {
                if (tex.texture) {
                    applyTextureToMaterial(child.material, tex);
                }
            });
            child.material.needsUpdate = true;
        }
    });
}

function applyTextureToMaterial(material, tex) {
    const textureName = tex.name.toLowerCase();
    if (textureName.includes('diffuse') || textureName.includes('color')) {
        material.map = tex.texture;
    } else if (textureName.includes('bump') || textureName.includes('normal')) {
        material.normalMap = tex.texture;
    } else if (textureName.includes('specular')) {
        material.specularMap = tex.texture;
    }
}

function addObjectToScene(scene, object) {
    scene.add(object);
}

function fitCameraToObject(camera, object, controls) {
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
    camera.lookAt(center);
}

function animate(renderer, scene, camera, controls) {
    requestAnimationFrame(() => animate(renderer, scene, camera, controls));
    controls.update();
    renderer.render(scene, camera);
}

function onWindowResize(camera, renderer) {
    const canvas = renderer.domElement;
    camera.aspect = canvas.clientWidth / canvas.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(canvas.clientWidth, canvas.clientHeight);
}

function showErrorMessage(canvas, message) {
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = 'white';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'red';
    ctx.font = '16px Arial';
    ctx.fillText(`Error: ${message}`, 10, 50);
}
// export function render3DModel(canvas, objData, mtlData, textureData, isUrl = false) {
//     // render3DModel 함수 구현
//     console.log('Render3DModel called with:', {
//         objData: objData ? objData.substring(0, 100) + '...' : 'None',
//         mtlData: mtlData ? mtlData.substring(0, 100) + '...' : 'None',
//         textureData: textureData,
//         isUrl: isUrl
//     });

//     let animationFrameId;

//     const scene = new THREE.Scene();
//     const camera = new THREE.PerspectiveCamera(75, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
//     const renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true });
//     renderer.setSize(canvas.clientWidth, canvas.clientHeight);
//     renderer.setClearColor(0xcccccc);

//     const controls = new OrbitControls(camera, renderer.domElement);
//     controls.enableDamping = true;
//     controls.dampingFactor = 0.25;
//     controls.screenSpacePanning = false;
//     controls.maxPolarAngle = Math.PI / 2;

//     const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
//     scene.add(ambientLight);
//     const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
//     directionalLight.position.set(1, 1, 1).normalize();
//     scene.add(directionalLight);

//     const loader = new OBJLoader();
//     const textureLoader = new THREE.TextureLoader();

//     function loadMtl() {
//         return new Promise((resolve, reject) => {
//             if (mtlData) {
//                 const mtlLoader = new MTLLoader();
//                 mtlLoader.setMaterialOptions({ side: THREE.DoubleSide });
//                 if (isUrl) {
//                     mtlLoader.load(mtlData,
//                         (materials) => {
//                             console.log('MTL loaded successfully', materials);
//                             materials.preload();
//                             logMaterials(materials.materials);
//                             loader.setMaterials(materials);
//                             resolve(materials);
//                         },
//                         undefined,
//                         (error) => reject(new Error('Failed to load MTL: ' + error.message))
//                     );
//                 } else {
//                     try {
//                         const materialsCreator = mtlLoader.parse(mtlData);
//                         materialsCreator.preload();
//                         logMaterials(materialsCreator.materials);
//                         loader.setMaterials(materialsCreator);
//                         console.log('MTL parsed successfully', materialsCreator);
//                         resolve(materialsCreator);
//                     } catch (error) {
//                         reject(new Error('Failed to parse MTL: ' + error.message));
//                     }
//                 }
//             } else {
//                 console.log('No MTL data provided');
//                 resolve(null);
//             }
//         });
//     }

//     function loadObj(materials) {
//         // loadObj 함수 구현
//         return new Promise((resolve, reject) => {
//             const onLoad = (object) => {
//                 console.log('OBJ loaded successfully:', object);
//                 object.traverse((child) => {
//                     if (child instanceof THREE.Mesh) {
//                         console.log('Mesh found:', child.name);
//                         console.log('Material:', child.material);
//                         if (child.material.map) {
//                             console.log('Material has texture map:', child.material.map.name);
//                         } else {
//                             console.log('Material does not have texture map');
//                         }
//                         // Ensure the material is MeshPhongMaterial
//                         if (!(child.material instanceof THREE.MeshPhongMaterial)) {
//                             child.material = new THREE.MeshPhongMaterial({
//                                 color: child.material.color,
//                                 map: child.material.map,
//                                 normalMap: child.material.normalMap,
//                                 specularMap: child.material.specularMap
//                             });
//                         }
//                         child.material.needsUpdate = true;
//                     }
//                 });
//                 resolve(object);
//             };

//             if (isUrl) {
//                 loader.load(objData, onLoad, onProgress,
//                     (error) => reject(new Error('Failed to load OBJ: ' + error.message)));
//             } else {
//                 const objBlob = new Blob([objData], { type: 'text/plain' });
//                 const objUrl = URL.createObjectURL(objBlob);
//                 loader.load(objUrl, (object) => {
//                     URL.revokeObjectURL(objUrl);
//                     onLoad(object);
//                 }, onProgress,
//                     (error) => reject(new Error('Failed to load OBJ: ' + error.message)));
//             }
//         });
//     }


//     function loadTextures() {
//         // loadTextures 함수 구현
//         console.log('Loading textures:', textureData);
//         return Promise.all(textureData.map(texture => {
//             return new Promise((resolve, reject) => {
//                 const textureName = isUrl ? texture : texture.name;
//                 const textureUrl = isUrl ? texture : texture.content;

//                 console.log(`Attempting to load texture: ${textureName} from ${textureUrl}`);

//                 textureLoader.load(
//                     textureUrl,
//                     (loadedTexture) => {
//                         console.log(`Texture ${textureName} loaded successfully:`, loadedTexture);
//                         resolve({ name: textureName, texture: loadedTexture });
//                     },
//                     (xhr) => {
//                         console.log(`${textureName} ${(xhr.loaded / xhr.total * 100)}% loaded`);
//                     },
//                     (error) => {
//                         console.error(`Failed to load texture ${textureName}: ${error.message}`);
//                         resolve({ name: textureName, texture: null });
//                     }
//                 );
//             });
//         }));
//     }


//     // In the main render3DModel function:
//     loadMtl()
//         .then(materials => {
//             console.log('MTL loading completed, starting OBJ and texture loading');
//             return Promise.all([loadObj(materials), loadTextures()]);
//         })
//         .then(([object, textures]) => {
//             console.log('OBJ and textures loaded, applying textures');
//             console.log('Loaded textures:', textures);
//             applyTextures(object, textures);
//             scene.add(object);
//             console.log('Object added to scene with textures');
//             fitCameraToObject(camera, object, controls);
//             console.log('Scene contents:', scene.children);
//             animate();
//         })
//         .catch((error) => {
//             console.error('Error in render3DModel:', error.message);
//             canvas.parentNode.textContent = 'Error rendering 3D model: ' + error.message;
//         });

//     function applyTextures(object, textures) {
//         // applyTextures 함수 구현
//         object.traverse((child) => {
//             if (child instanceof THREE.Mesh) {
//                 const material = child.material;
//                 console.log('Applying textures to material:', material.name);

//                 textures.forEach(tex => {
//                     if (tex.texture) {
//                         const textureName = tex.name.toLowerCase();
//                         console.log(`Processing texture: ${textureName}`);

//                         if (textureName.includes('diffuse') || textureName.includes('color')) {
//                             material.map = tex.texture;
//                             console.log('Applied diffuse/color map');
//                         } else if (textureName.includes('bump') || textureName.includes('normal')) {
//                             material.bumpMap = tex.texture;
//                             console.log('Applied bump/normal map');
//                         } else if (textureName.includes('specular')) {
//                             material.specularMap = tex.texture;
//                             console.log('Applied specular map');
//                         }
//                         // Add more conditions for other texture types if needed
//                     }
//                 });

//                 material.needsUpdate = true;
//                 console.log('Updated material:', JSON.stringify(material.toJSON(), null, 2));
//             }
//         });
//     }

//     function onProgress(xhr) {
//         // onProgress 함수 구현
//         console.log((xhr.loaded / xhr.total * 100) + '% loaded');
//     }

//     function animate() {
//         animationFrameId = requestAnimationFrame(animate);
//         controls.update();
//         renderer.render(scene, camera);
//     }

//     function fitCameraToObject(camera, object, controls) {
//         // fitCameraToObject 함수 구현
//         const box = new THREE.Box3().setFromObject(object);
//         const center = box.getCenter(new THREE.Vector3());
//         const size = box.getSize(new THREE.Vector3());
//         const maxDim = Math.max(size.x, size.y, size.z);
//         const fov = camera.fov * (Math.PI / 180);
//         let cameraZ = Math.abs(maxDim / 2 / Math.tan(fov / 2));
//         cameraZ *= 1.5;
//         camera.position.z = cameraZ;
//         const minZ = box.min.z;
//         const cameraToFarEdge = (minZ < 0) ? -minZ + cameraZ : cameraZ - minZ;
//         camera.far = cameraToFarEdge * 3;
//         camera.updateProjectionMatrix();
//         if (controls) {
//             controls.target = center;
//             controls.maxDistance = cameraToFarEdge * 2;
//         }
//         console.log('Camera fitted to object:', { position: camera.position, target: controls.target });
//     }
//     function logMaterials(materials) {
//         Object.keys(materials).forEach(key => {
//             const mat = materials[key];
//             console.log(`Material ${key}:`, {
//                 color: mat.color ? mat.color.getHexString() : 'N/A',
//                 map: mat.map ? mat.map.name : 'N/A',
//                 normalMap: mat.normalMap ? mat.normalMap.name : 'N/A',
//                 specularMap: mat.specularMap ? mat.specularMap.name : 'N/A'
//             });
//         });
//     }
//         // 이벤트 리스너를 render3DModel 함수 내부로 이동
//         window.addEventListener('resize', onWindowResize);

//     function onWindowResize() {
//         camera.aspect = canvas.clientWidth / canvas.clientHeight;
//         camera.updateProjectionMatrix();
//         renderer.setSize(canvas.clientWidth, canvas.clientHeight);
//     }
//         // 정리 함수 반환
//         return () => {
//             cancelAnimationFrame(animationFrameId);
//             window.removeEventListener('resize', onWindowResize);
//             // 필요한 경우 다른 정리 작업 수행
//         };
// }
