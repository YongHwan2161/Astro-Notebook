import * as THREE from '../three/three.module.js';

export function updateSimulation(camera, controls, celestialContainer, groundPlane, guiControls) {
    const lat = THREE.MathUtils.degToRad(guiControls.latitude);
    const lon = THREE.MathUtils.degToRad(guiControls.longitude);
    const localTime = guiControls.localTime;

    const lst = (localTime + guiControls.longitude / 15) % 24;
    const lstRad = lst * (Math.PI / 12);

    celestialContainer.rotation.y = lstRad;

    groundPlane.rotation.x = Math.PI / 2 - lat;

    camera.position.set(0, 10 * Math.sin(lat), -10 * Math.cos(lat));
    camera.lookAt(0, Math.sin(lat), Math.cos(lat));
    controls.target.set(0, Math.sin(lat) * 100, Math.cos(lat) * 100);
    controls.update();
}