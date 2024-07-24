#include <vector>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

using json = nlohmann::json;

// 파일 타입 열거형
enum class FileType {
    OBJ,
    MTL,
    TEXTURE
};

// 파일 정보 구조체
struct FileInfo {
    std::string filename;
    std::string content;
    FileType type;
};

// 파일 타입 확인 함수
FileType getFileType(const std::string& filename) {
    std::string ext = filename.substr(filename.find_last_of(".") + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if (ext == "obj") return FileType::OBJ;
    if (ext == "mtl") return FileType::MTL;
    return FileType::TEXTURE;
}

void handleUpload3DFiles(SSL *ssl, const std::string &request_body)
{
    std::vector<FileInfo> files;
    std::string boundary = extractBoundary(request_body);
    std::vector<std::string> parts = splitMultipartData(request_body, boundary);

    for (const auto& part : parts) {
        std::string filename;
        std::string content = parseMultipartData(part, filename);
        if (!filename.empty() && !content.empty()) {
            files.push_back({filename, content, getFileType(filename)});
        }
    }

    if (files.empty()) {
        send_json_response2(ssl, 400, "Bad Request", json{{"success", false}, {"message", "No valid files found"}});
        return;
    }

    json response;
    response["success"] = true;

    for (const auto& file : files) {
        std::string directory;
        std::string urlPrefix;
        switch (file.type) {
            case FileType::OBJ:
                directory = UPLOAD_OBJ_DIR;
                urlPrefix = "uploads/objs/";
                break;
            case FileType::MTL:
                directory = UPLOAD_MTL_DIR;
                urlPrefix = "uploads/mtls/";
                break;
            case FileType::TEXTURE:
                directory = UPLOAD_TEXTURE_DIR;
                urlPrefix = "uploads/textures/";
                break;
        }

        if (uploadFile(file.content, file.filename, directory)) {
            std::string url = urlPrefix + file.filename;
            switch (file.type) {
                case FileType::OBJ:
                    response["objUrl"] = url;
                    break;
                case FileType::MTL:
                    response["mtlUrl"] = url;
                    break;
                case FileType::TEXTURE:
                    if (!response.contains("textureUrls")) {
                        response["textureUrls"] = json::array();
                    }
                    response["textureUrls"].push_back(url);
                    break;
            }
        } else {
            response["success"] = false;
            response["message"] = "Failed to save file: " + file.filename;
            send_json_response2(ssl, 500, "Internal Server Error", response);
            return;
        }
    }

    send_json_response2(ssl, 200, "OK", response);
}

// 헬퍼 함수들 (이미 구현되어 있다고 가정)
std::string extractBoundary(const std::string &request_body);
std::vector<std::string> splitMultipartData(const std::string &request_body, const std::string &boundary);
std::string parseMultipartData(const std::string &part, std::string &filename);
bool uploadFile(const std::string &content, const std::string &filename, const std::string &directory);
void send_json_response2(SSL *ssl, int status_code, const std::string &status_message, const json &response_json);