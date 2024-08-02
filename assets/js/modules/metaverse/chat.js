let chatMessages = [];

function createChatUI() {
    const chatContainer = document.createElement('div');
    chatContainer.style.position = 'absolute';
    chatContainer.style.bottom = '10px';
    chatContainer.style.left = '10px';
    chatContainer.style.width = '300px';
    chatContainer.style.height = '200px';
    chatContainer.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    chatContainer.style.color = 'white';
    chatContainer.style.overflow = 'auto';
    document.body.appendChild(chatContainer);

    const chatInput = document.createElement('input');
    chatInput.style.position = 'absolute';
    chatInput.style.bottom = '220px';
    chatInput.style.left = '10px';
    chatInput.style.width = '290px';
    document.body.appendChild(chatInput);

    chatInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            const message = chatInput.value;
            sendChatMessage(message);
            chatInput.value = '';
        }
    });
}

function sendChatMessage(message) {
    chatMessages.push(message);
    if (chatMessages.length > 10) {
        chatMessages.shift();
    }
    updateChatDisplay();
}

function updateChatDisplay() {
    const chatContainer = document.querySelector('div');
    chatContainer.innerHTML = chatMessages.join('<br>');
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

export { createChatUI, sendChatMessage };