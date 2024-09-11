import * as dat from '../dat.gui';

export function initGUI(updateSimulation, toggleConstellations, toggleGround) {
    const guiControls = {
        latitude: 0,
        longitude: 0,
        localTime: 0,
        showConstellations: false,
        showGround: true
    };

    const gui = new dat.GUI();
    gui.add(guiControls, 'latitude', -90, 90).onChange(updateSimulation);
    gui.add(guiControls, 'longitude', -180, 180).onChange(updateSimulation);
    gui.add(guiControls, 'localTime', 0, 24).onChange(updateSimulation);
    gui.add(guiControls, 'showConstellations').onChange(toggleConstellations);
    gui.add(guiControls, 'showGround').onChange(toggleGround);

    return guiControls;
}