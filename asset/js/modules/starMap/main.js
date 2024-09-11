import { initScene, animate } from './sceneSetup.js';
import { addCelestialObjects } from './celestialObjects.js';
import { createConstellationLines, toggleConstellations } from './constellations.js';
import { initGUI } from './gui.js';
import { updateSimulation } from './simulation.js';

const { scene, camera, renderer, controls, celestialContainer, groundPlane } = initScene();
addCelestialObjects(celestialContainer);
const constellationLines = createConstellationLines(celestialContainer);

const guiControls = initGUI(updateSimulation, toggleConstellations, toggleGround);

function toggleGround(visible) {
    groundPlane.visible = visible;
}

// Initial setup
updateSimulation(camera, controls, celestialContainer, groundPlane, guiControls);
animate(renderer, scene, camera, controls);

// Handle window resize
window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
});