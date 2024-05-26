#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <openssl/sha.h>

const int PORT = 8080;
const int BUFFER_SIZE = 1024;

const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';

    }

    return ret;

}

std::string sha1(const std::string& str) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(str.c_str()), str.size(), hash);
    return std::string(reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH);
}

std::string generate_websocket_accept_key(const std::string& client_key) {
    std::string magic_key = client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string hash = sha1(magic_key);
    return base64_encode(reinterpret_cast<const unsigned char*>(hash.c_str()), hash.size());
}

void send_html_response(int client_socket) {
    const char* html_content = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSocket Client</title>
</head>
<body>
    <h1>WebSocket Client</h1>
    <div id="messages"></div>

    <script>
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log('WebSocket connection established');
        };

        ws.onmessage = (event) => {
            const messagesDiv = document.getElementById('messages');
            const message = document.createElement('div');
            message.textContent = `Message from server: ${event.data}`;
            messagesDiv.appendChild(message);
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        ws.onclose = () => {
            console.log('WebSocket connection closed');
        };
    </script>
</body>
</html>
)";

    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html\r\n"
                           "Content-Length: " + std::to_string(strlen(html_content)) + "\r\n"
                           "Connection: close\r\n\r\n" + html_content;

    int sent_bytes = send(client_socket, response.c_str(), response.size(), 0);
    if (sent_bytes < 0) {
        perror("send failed");
    }

    // Ensure all data is sent before closing
    shutdown(client_socket, SHUT_RDWR);
    close(client_socket);
}

void handle_websocket_connection(int client_socket, const std::string& client_key) {
    std::string accept_key = generate_websocket_accept_key(client_key);
    std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: " + accept_key + "\r\n\r\n";
    send(client_socket, response.c_str(), response.size(), 0);
    
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::string message = "Server message";
        std::vector<char> ws_frame;

        // Create WebSocket frame
        ws_frame.push_back(0x81); // FIN and text frame
        ws_frame.push_back(message.size()); // No mask, payload length

        ws_frame.insert(ws_frame.end(), message.begin(), message.end());
        send(client_socket, ws_frame.data(), ws_frame.size(), 0);
    }
    close(client_socket);
}

void start_server() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 3) < 0) {
        perror("listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server started on port " << PORT << std::endl;

    while (true) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }

        std::thread([client_socket]() {
            char buffer[BUFFER_SIZE];
            int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);

            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                std::string request(buffer);
                std::string client_key;

                if (request.find("GET /ws") != std::string::npos) {
                    // Extract Sec-WebSocket-Key
                    size_t key_start = request.find("Sec-WebSocket-Key: ");
                    if (key_start != std::string::npos) {
                        key_start += 19;
                        size_t key_end = request.find("\r\n", key_start);
                        client_key = request.substr(key_start, key_end - key_start);
                    }
                    handle_websocket_connection(client_socket, client_key);
                } else {
                    send_html_response(client_socket);
                }
            }
        }).detach();
    }
}

int main() {
    start_server();
    return 0;
}
