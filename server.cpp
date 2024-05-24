#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PORT 8080

void handleClient(int client_socket) {
    char buffer[1024] = {0};
    std::string hello = "Hello from server";
    int valread;
    
    while ((valread = read(client_socket, buffer, 1024)) > 0) {
        std::cout << "Received: " << buffer << std::endl;
        send(client_socket, hello.c_str(), hello.length(), 0);
        std::memset(buffer, 0, sizeof(buffer));
    }

    close(client_socket);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // 소켓 파일 디스크립터 생성
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 소켓 옵션 설정
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 소켓을 주소와 포트에 바인드
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 연결 대기 상태로 전환
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    std::vector<std::thread> threads;

    // 클라이언트 연결 대기
    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        threads.push_back(std::thread(handleClient, new_socket));
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    return 0;
}
