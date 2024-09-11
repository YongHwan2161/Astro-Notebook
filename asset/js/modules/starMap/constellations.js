import * as THREE from '../three/three.module.js';
import { constellationData, starData } from './data.js';

export function createConstellationLines(celestialContainer) {
    const constellationLines = new THREE.Object3D();
    const lineMaterial = new THREE.LineBasicMaterial({ color: 0x00FF00 });

    constellationData.forEach(constellation => {
        const points = [];
        constellation.stars.forEach(starName => {
            const star = starData.find(s => s.name === starName);
            if (star) {
                const { x, y, z } = calculatePosition(star.ra, star.dec);
                points.push(new THREE.Vector3(x, y, z));
            }
        });
        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        const line = new THREE.Line(geometry, lineMaterial);
        constellationLines.add(line);
    });

    celestialContainer.add(constellationLines);
    return constellationLines;
}

export function toggleConstellations(visible, celestialContainer, constellationLines) {
    if (visible) {
        celestialContainer.add(constellationLines);
    } else {
        celestialContainer.remove(constellationLines);
    }
}

function calculatePosition(ra, dec) {
    const phi = (90 - dec) * (Math.PI / 180);
    const theta = ra * (Math.PI / 180);
    return {
        x: -499 * Math.sin(phi) * Math.cos(theta),
        y: 499 * Math.cos(phi),
        z: -499 * Math.sin(phi) * Math.sin(theta)
    };
}