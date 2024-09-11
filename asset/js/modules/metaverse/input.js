const keyState = {};
let mouseX = 0, mouseY = 0;

function initInputHandlers() {
    document.addEventListener('keydown', onKeyDown, false);
    document.addEventListener('keyup', onKeyUp, false);
    document.addEventListener('mousemove', onMouseMove, false);
}

function onKeyDown(event) {
    keyState[event.code] = true;
}

function onKeyUp(event) {
    keyState[event.code] = false;
}

function onMouseMove(event) {
    mouseX = (event.clientX / window.innerWidth) * 2 - 1;
    mouseY = -(event.clientY / window.innerHeight) * 2 + 1;
}

function getKeyState(key) {
    return keyState[key] || false;
}

function getMousePosition() {
    return { x: mouseX, y: mouseY };
}

export { initInputHandlers, getKeyState, getMousePosition };