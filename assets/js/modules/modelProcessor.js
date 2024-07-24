// modelProcessor.js

export async function process3DModelData(content) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(content, 'text/html');
    const model3dElements = doc.querySelectorAll('div[data-obj-file]');

    for (const element of model3dElements) {
        try {
            const objData = await upload3DFile(element, 'data-obj-file', 'data-obj-filename');
            element.setAttribute('data-obj-url', objData.url);
            element.removeAttribute('data-obj-file');

            if (element.hasAttribute('data-mtl-file')) {
                const mtlData = await upload3DFile(element, 'data-mtl-file', 'data-mtl-filename');
                element.setAttribute('data-mtl-url', mtlData.url);
                element.removeAttribute('data-mtl-file');
            }

            await uploadTextureFiles(element);
        } catch (error) {
            console.error('Error processing 3D model:', error);
            element.innerHTML = `<p>Error loading 3D model: ${error.message}</p>`;
        }
    }

    return doc.body.innerHTML;
}

async function upload3DFile(element, fileAttr, filenameAttr) {
    const file = element.getAttribute(fileAttr);
    const filename = element.getAttribute(filenameAttr);
    const blob = new Blob([file], { type: 'text/plain' });
    return await uploadFile(blob, filename);
}

async function uploadTextureFiles(element) {
    const textureFiles = JSON.parse(element.getAttribute('data-texture-files') || '[]');
    const uploadedTextures = await Promise.all(textureFiles.map(async (texture) => {
        const textureBlob = dataURItoBlob(texture.content);
        const textureUrl = await uploadFile(textureBlob, texture.name);
        return { name: texture.name, url: textureUrl };
    }));
    element.setAttribute('data-texture-urls', JSON.stringify(uploadedTextures));
    element.removeAttribute('data-texture-files');
}

async function uploadFile(blob, filename) {
    const formData = new FormData();
    formData.append('file', blob, filename);

    const response = await fetch('/upload_file', {
        method: 'POST',
        body: formData
    });

    if (!response.ok) {
        throw new Error(`Failed to upload file: ${filename}`);
    }

    return await response.json();
}

function dataURItoBlob(dataURI) {
    const byteString = atob(dataURI.split(',')[1]);
    const mimeString = dataURI.split(',')[0].split(':')[1].split(';')[0];
    const ab = new ArrayBuffer(byteString.length);
    const ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
    }
    return new Blob([ab], { type: mimeString });
}