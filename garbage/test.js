import { GLTFLoader } from './three/loaders/GLTFLoader.js';
import { FBXLoader } from './three/loaders/FBXLoader.js';
import { STLLoader } from './three/loaders/STLLoader.js';
import { ColladaLoader } from './three/loaders/ColladaLoader.js';
import { PLYLoader } from './three/loaders/PLYLoader.js';
import { TDSLoader } from './three/loaders/TDSLoader.js';

// ... existing imports ...

export function select3DFile() {
    var input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.accept = '.obj,.mtl,.gltf,.glb,.fbx,.stl,.dae,.ply,.3ds,.png,.jpg,.jpeg';
    input.onchange = function (event) {
        var files = event.target.files;
        if (files.length > 0) {
            load3DModel(files);
        }
    };
    input.click();
}

export async function load3DModel(files) {
    let modelFile, materialFile, textureFiles = [];
    for (let file of files) {
        const extension = file.name.split('.').pop().toLowerCase();
        if (['obj', 'gltf', 'glb', 'fbx', 'stl', 'dae', 'ply', '3ds'].includes(extension)) {
            modelFile = file;
        } else if (extension === 'mtl') {
            materialFile = file;
        } else if (['png', 'jpg', 'jpeg'].includes(extension)) {
            textureFiles.push(file);
        }
    }

    if (!modelFile) {
        alert('Please select a 3D model file.');
        return;
    }

    try {
        const modelContent = await readFile(modelFile);
        let materialContent = null;
        if (materialFile) {
            materialContent = await readFile(materialFile);
        }
        let textureContents = [];
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

        // Set attributes for model file
        canvasContainer.setAttribute('data-model-file', modelContent);
        canvasContainer.setAttribute('data-model-filename', modelFile.name);

        // Set attributes for material file if exists
        if (materialContent) {
            canvasContainer.setAttribute('data-material-file', materialContent);
            canvasContainer.setAttribute('data-material-filename', materialFile.name);
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
            'data-model-file': modelContent,
            'data-model-filename': modelFile.name,
            'data-material-file': materialContent || '',
            'data-material-filename': materialFile ? materialFile.name : '',
            'data-texture-files': textureContents
        });

        // 3D model rendering
        setTimeout(() => {
            var canvasElements = document.querySelectorAll('canvas');
            var lastCanvas = canvasElements[canvasElements.length - 1];
            render3DModel(lastCanvas, modelContent, materialContent, textureContents, false);
        }, 100);
    } catch (error) {
        console.error('Error processing files:', error);
        alert('Failed to process files: ' + error.message);
    }
}

export function render3DModel(canvas, modelData, materialData, textureData, isUrl = false) {
    // ... existing code ...

    const loader = getLoader(modelData);
    const textureLoader = new THREE.TextureLoader();

    function loadModel() {
        return new Promise((resolve, reject) => {
            if (isUrl) {
                loader.load(modelData,
                    (object) => resolve(object),
                    onProgress,
                    (error) => reject(new Error('Failed to load model: ' + error.message))
                );
            } else {
                const modelBlob = new Blob([modelData], { type: 'application/octet-stream' });
                const modelUrl = URL.createObjectURL(modelBlob);
                loader.load(modelUrl, (object) => {
                    URL.revokeObjectURL(modelUrl);
                    resolve(object);
                }, onProgress,
                    (error) => reject(new Error('Failed to load model: ' + error.message)));
            }
        });
    }

    // ... rest of the existing code ...
}

function getLoader(modelData) {
    const extension = modelData.name ? modelData.name.split('.').pop().toLowerCase() : 'obj';
    switch (extension) {
        case 'obj':
            return new OBJLoader();
        case 'gltf':
        case 'glb':
            return new GLTFLoader();
        case 'fbx':
            return new FBXLoader();
        case 'stl':
            return new STLLoader();
        case 'dae':
            return new ColladaLoader();
        case 'ply':
            return new PLYLoader();
        case '3ds':
            return new TDSLoader();
        default:
            throw new Error('Unsupported file format: ' + extension);
    }
}

// ... rest of the existing code ...