import * as THREE from '../three/three.module.js';
import { starData, planetData } from './data.js';

export function addCelestialObjects(celestialContainer) {
    const starField = createStarField();
    celestialContainer.add(starField);

    createPlanets(celestialContainer);
}

function createStarField() {
    const starMaterial = new THREE.PointsMaterial({ color: 0xFFFFFF, sizeAttenuation: false });
    const starGeometry = new THREE.BufferGeometry();
    const starPositions = [];
    const starSizes = [];

    starData.forEach(star => {
        const { x, y, z } = calculatePosition(star.ra, star.dec);
        starPositions.push(x, y, z);
        const size = Math.max(1, 10 - star.mag * 2);
        starSizes.push(size);
    });

    starGeometry.setAttribute('position', new THREE.Float32BufferAttribute(starPositions, 3));
    starGeometry.setAttribute('size', new THREE.Float32BufferAttribute(starSizes, 1));

    return new THREE.Points(starGeometry, starMaterial);
}

function createPlanets(celestialContainer) {
    planetData.forEach(planet => {
        const planetGeometry = new THREE.SphereGeometry(2, 32, 32);
        const planetMaterial = new THREE.MeshBasicMaterial({ color: planet.color });
        const planetMesh = new THREE.Mesh(planetGeometry, planetMaterial);

        const { x, y, z } = calculatePosition(planet.ra, planet.dec);
        planetMesh.position.set(x, y, z);

        celestialContainer.add(planetMesh);
    });
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