#include <iostream>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

void handle_create_folder(int client_socket, const std::string& request_body) {
    json response;
    try {
        json request_data = json::parse(request_body);
        
        if (!request_data.contains("path") || !request_data.contains("name")) {
            throw std::runtime_error("Missing required fields in request");
        }

        std::string path = request_data["path"];
        std::string folder_name = request_data["name"];
        std::string root_path = UPLOAD_ROOT_DIR; // 실제 루트 경로로 변경해야 합니다
        std::string full_path = root_path + path + folder_name;

        // 보안 검사: path가 root_path 밖으로 나가지 않는지 확인
        if (full_path.substr(0, root_path.length()) != root_path) {
            throw std::runtime_error("Access denied: Path is outside of allowed directory");
        }

        // 폴더가 이미 존재하는지 확인
        if (fs::exists(full_path)) {
            throw std::runtime_error("A folder with this name already exists");
        }

        // 폴더 생성
        if (fs::create_directory(full_path)) {
            response["success"] = true;
            response["message"] = "Folder created successfully";
        } else {
            throw std::runtime_error("Failed to create folder");
        }

    } catch (const std::exception& e) {
        response["success"] = false;
        response["message"] = e.what();
    }

    send_json_response2(client_socket, response["success"] ? 200 : 400,
                        response["success"] ? "OK" : "Bad Request", response);
}