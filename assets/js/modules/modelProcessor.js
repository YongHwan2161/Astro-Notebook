// modelProcessor.js

export async function process3DModelData(content) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(content, 'text/html');
    const model3dElements = doc.querySelectorAll('div[data-model-file]');
    console.log('Found 3D model elements:', model3dElements.length); // 추가된 로그

    for (const element of model3dElements) {
        try {
            // 모델 타입 저장
            const modelType = element.getAttribute('data-model-type');
            // STL 파일인 경우 ArrayBuffer로 읽기
            if (modelType === 'stl') {
                const stlData = await upload3DFileAsArrayBuffer(element, 'data-model-file', 'data-model-filename');
                element.setAttribute('data-model-url', stlData.url);
                element.removeAttribute('data-model-file');
            } else {
                // OBJ 파일 등 기존 처리 방식
                const objData = await upload3DFile(element, 'data-model-file', 'data-model-filename');
                element.setAttribute('data-model-url', objData.url);
                element.removeAttribute('data-model-file');
                console.log('Set data-model-url:', objData.url); // 추가된 로그
            }

            // 모델 타입 유지
            element.setAttribute('data-model-type', modelType);
            console.log('Processing 3D model:', modelType); // 추가된 로그

            // MTL 파일 업로드 (OBJ 파일의 경우)
            if (element.hasAttribute('data-mtl-file')) {
                const mtlData = await upload3DFile(element, 'data-mtl-file', 'data-mtl-filename');
                element.setAttribute('data-mtl-url', mtlData.url);
                element.removeAttribute('data-mtl-file');
            }

            // 텍스처 파일 업로드
            const textureUrls = await uploadTextureFiles(element);
            element.setAttribute('data-texture-urls', JSON.stringify(textureUrls));
            element.removeAttribute('data-texture-files');  // 이 줄을 추가합니다

            // 스타일 정보 유지
            const style = element.getAttribute('style');
            if (style) {
                element.setAttribute('data-style', style);
            }

        } catch (error) {
            console.error('Error processing 3D model:', error);
            element.innerHTML = `<p>Error loading 3D model: ${error.message}</p>`;
        }
    }
    console.log('Processed HTML:', doc.body.innerHTML); // 추가된 로그

    return doc.body.innerHTML;
}
async function upload3DFile(element, fileAttr, filenameAttr) {
    const file = element.getAttribute(fileAttr);
    const filename = element.getAttribute(filenameAttr);
    const blob = new Blob([file], { type: 'text/plain' });
    return await uploadFile(blob, filename);
}

// async function uploadTextureFiles(element) {
//     const textureFiles = JSON.parse(element.getAttribute('data-texture-files') || '[]');
//     const uploadedTextures = await Promise.all(textureFiles.map(async (texture) => {
//         const textureBlob = dataURItoBlob(texture.content);
//         const textureUrl = await uploadFile(textureBlob, texture.name);
//         return { name: texture.name, url: textureUrl };
//     }));
//     element.setAttribute('data-texture-urls', JSON.stringify(uploadedTextures));
//     element.removeAttribute('data-texture-files');
// }
async function uploadTextureFiles(element) {
    const textureFiles = JSON.parse(element.getAttribute('data-texture-files') || '[]');
    const uploadedTextures = await Promise.all(textureFiles.map(async (texture) => {
        const textureBlob = dataURItoBlob(texture.content);
        const textureData = await uploadFile(textureBlob, texture.name);
        return { name: texture.name, url: textureData.url };
    }));
    return uploadedTextures;
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