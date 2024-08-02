import * as THREE from '../three/three.module.js';

class ObjectManager {
    constructor(scene) {
        this.objects = [];
        this.selectedObject = null;
        this.scene = scene;
    }

    createObject(position, direction, type = 'cube') {
        let geometry, material;

        switch (type) {
            case 'cube':
                geometry = new THREE.BoxGeometry(1, 1, 1);
                break;
            case 'sphere':
                geometry = new THREE.SphereGeometry(0.5, 32, 32);
                break;
            case 'cone':
                geometry = new THREE.ConeGeometry(0.5, 1, 32);
                break;
            default:
                geometry = new THREE.BoxGeometry(1, 1, 1);
        }

        material = new THREE.MeshStandardMaterial({ color: Math.random() * 0xffffff });
        const object = new THREE.Mesh(geometry, material);

        object.position.copy(position);
        object.position.add(direction.multiplyScalar(3));

        this.objects.push(object);
        this.scene.add(object);
        return object;
    }

    selectObject(object) {
        if (this.selectedObject) {
            this.selectedObject.material.emissive.setHex(0x000000);
        }
        this.selectedObject = object;
        if (object) {
            object.material.emissive.setHex(0x555555);
        }
    }

    moveSelectedObject(direction) {
        if (this.selectedObject) {
            const moveSpeed = 0.05;
            const newPosition = this.selectedObject.position.clone().add(direction.multiplyScalar(moveSpeed));

            if (!this.checkCollision(newPosition)) {
                this.selectedObject.position.copy(newPosition);
            }
        }
    }

    checkCollision(position) {
        for (let object of this.objects) {
            if (object !== this.selectedObject) {
                if (position.distanceTo(object.position) < 1) {
                    return true;
                }
            }
        }
        return false;
    }

    removeSelectedObject() {
        if (this.selectedObject) {
            const index = this.objects.indexOf(this.selectedObject);
            if (index > -1) {
                this.objects.splice(index, 1);
            }

            const removeAnimation = gsap.to(this.selectedObject.scale, {
                x: 0,
                y: 0,
                z: 0,
                duration: 0.5,
                onComplete: () => {
                    this.scene.remove(this.selectedObject);
                    this.selectedObject = null;
                }
            });

            removeAnimation.play();
        }
    }
}

export { ObjectManager };