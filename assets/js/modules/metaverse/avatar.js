import * as THREE from '../three/three.module.js';

let avatar;

function createAvatar() {
    const avatarGeometry = new THREE.BoxGeometry(1, 2, 1);
    const avatarMaterial = new THREE.MeshStandardMaterial({ color: 0x0000ff });
    avatar = new THREE.Mesh(avatarGeometry, avatarMaterial);
    avatar.position.set(0, 1, 0);
    return avatar;
}

function moveAvatar(direction) {
    const moveSpeed = 0.1;
    avatar.position.add(direction.multiplyScalar(moveSpeed));
}

export { createAvatar, moveAvatar };