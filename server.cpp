#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <signal.h>
#include <errno.h>
#include <unordered_map>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <map>
#include <jsoncpp/json/json.h>
#include <algorithm>
#include <functional>
#include <regex>
#include <random>
#include "nlohmann/json.hpp"
#include <filesystem>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <chrono>
#include <ctime>
#include <syslog.h>
#include <mutex>
#include <mysql/mysql.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <poll.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/bufferevent_ssl.h>
#include <event2/http_struct.h>
#include <curl/curl.h>
#include "header/router.h"
#include "header/database.h"
#include "header/crypto_utils.h"

// HTTP status codes
#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_UNAUTHORIZED 401
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_INTERNAL 500
#define HTTP_CREATED 201
#define HTTP_NO_CONTENT 204
#define HTTP_BAD_REQUEST 400
#define HTTP_UNAUTHORIZED 401
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_CONFLICT 409
#define HTTP_INTERNAL 500
#define HTTP_SERVICE_UNAVAILABLE 503

namespace fs = std::filesystem;
using json = nlohmann::json;

const int HTTP_PORT = 8081;
const int HTTPS_PORT = 8444;
const int BUFFER_SIZE = 2048;

struct event_base *base;
struct evhttp *http;
struct evhttp *https;

struct bufferevent *bevcb(struct event_base *base, void *arg)
{
    SSL *ssl = (SSL *)arg;
    struct bufferevent *bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
    return bev;
}
struct bufferevent *https_bevcb(struct event_base *base, void *arg)
{
    SSL_CTX *ctx = (SSL_CTX *)arg;
    SSL *ssl = SSL_new(ctx);
    return bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
}

const std::string UPLOAD_DIR = "uploads/";
const std::string UPLOAD_IMAGE_DIR = "images/";
const std::string UPLOAD_OBJ_DIR = "uploads/objs/"; // .obj 파일을 저장할 디렉토리 경로
const std::string UPLOAD_ROOT_DIR = "./";

SSL *ssl;

class Logger
{
public:
    enum class Level
    {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    // Logger(const std::string &filename, Level level = Level::INFO)
    //     : file(filename, std::ios::app), level(level) {}
    Logger() : level(Level::INFO) {}

    void initialize(const std::string &filename, Level log_level = Level::INFO)
    {
        file.open(filename, std::ios::out | std::ios::trunc);
        if (!file.is_open())
        {
            throw std::runtime_error("Failed to open log file: " + filename);
        }
        level = log_level;
        log(Level::INFO, "Log initialized");
    }

    void log(Level msg_level, const std::string &message)
    {
        if (msg_level >= level)
        {
            std::time_t now = std::time(nullptr);
            file << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S")
                 << " [" << levelToString(msg_level) << "] "
                 << message << std::endl;
        }
    }

    void setLevel(Level new_level)
    {
        level = new_level;
    }

private:
    std::ofstream file;
    Level level;

    std::string levelToString(Level l)
    {
        switch (l)
        {
        case Level::DEBUG:
            return "DEBUG";
        case Level::INFO:
            return "INFO";
        case Level::WARNING:
            return "WARNING";
        case Level::ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
        }
    }
};

// 전역 로거 인스턴스
Logger g_logger;

class ServerError : public std::runtime_error
{
public:
    ServerError(const std::string &message, int code)
        : std::runtime_error(message), error_code(code) {}

    int getErrorCode() const { return error_code; }

private:
    int error_code;
};
void complex_operation()
{
    sql::Connection *con = get_connection();
    if (!con)
        return;

    try
    {
        con->setAutoCommit(false);
        sql::Statement *stmt = con->createStatement();

        stmt->execute("INSERT INTO ...");
        stmt->execute("UPDATE ...");

        con->commit();

        delete stmt;
        delete con;
    }
    catch (sql::SQLException &e)
    {
        g_logger.log(Logger::Level::ERROR, "SQL Exception: " + std::string(e.what()));
        con->rollback();
        delete con;
    }
}

const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

const std::string SECRET_KEY = "your_secret_key";

std::string base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
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

std::string base64_url_encode(unsigned char const *bytes_to_encode, unsigned int in_len)
{
    std::string base64 = base64_encode(bytes_to_encode, in_len);

    // Replace '+' with '-', '/' with '_'
    for (char &c : base64)
    {
        if (c == '+')
        {
            c = '-';
        }
        else if (c == '/')
        {
            c = '_';
        }
    }

    // Remove padding characters
    base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());

    return base64;
}
std::string base64_decode(const char *encoded_string, unsigned int in_len)
{
    BIO *b64, *bmem;
    char *buffer = (char *)malloc(in_len);
    memset(buffer, 0, in_len);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf((void *)encoded_string, in_len);
    bmem = BIO_push(b64, bmem);

    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    int decoded_len = BIO_read(bmem, buffer, in_len);
    BIO_free_all(bmem);

    std::string result(buffer, decoded_len);
    free(buffer);

    return result;
}
// Base64 디코딩 함수
std::vector<unsigned char> base64_decode_uchar(const std::string &encoded_string)
{
    BIO *b64, *bmem;
    size_t in_len = encoded_string.size();
    std::vector<unsigned char> buffer(in_len);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(encoded_string.c_str(), in_len);
    bmem = BIO_push(b64, bmem);

    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    int decoded_len = BIO_read(bmem, buffer.data(), in_len);
    buffer.resize(decoded_len);
    BIO_free_all(bmem);

    return buffer;
}
std::string base64_url_decode(const std::string &input)
{
    std::string base64 = input;

    // Replace '-' with '+', '_' with '/'
    for (char &c : base64)
    {
        if (c == '-')
        {
            c = '+';
        }
        else if (c == '_')
        {
            c = '/';
        }
    }

    // Add padding characters
    while (base64.size() % 4)
    {
        base64 += '=';
    }

    return base64_decode(base64.c_str(), base64.size());
}
std::string urlDecode(const std::string &encoded)
{
    std::string decoded;
    char ch;
    int i, ii;
    for (i = 0; i < encoded.length(); i++)
    {
        if (int(encoded[i]) == 37)
        {
            sscanf(encoded.substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            decoded += ch;
            i = i + 2;
        }
        else
        {
            decoded += encoded[i];
        }
    }
    return decoded;
}
std::string url_decode(const std::string &encoded)
{
    std::string result;
    for (size_t i = 0; i < encoded.length(); ++i)
    {
        if (encoded[i] == '%' && i + 2 < encoded.length())
        {
            int value;
            std::istringstream is(encoded.substr(i + 1, 2));
            if (is >> std::hex >> value)
            {
                result += static_cast<char>(value);
                i += 2;
            }
            else
            {
                result += encoded[i];
            }
        }
        else if (encoded[i] == '+')
        {
            result += ' ';
        }
        else
        {
            result += encoded[i];
        }
    }
    return result;
}
std::string sha1(const std::string &str)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), hash);
    return std::string(reinterpret_cast<char *>(hash), SHA_DIGEST_LENGTH);
}

std::string generate_websocket_accept_key(const std::string &client_key)
{
    std::string magic_key = client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string hash = sha1(magic_key);
    return base64_url_encode(reinterpret_cast<const unsigned char *>(hash.c_str()), hash.size());
}
std::string read_file(const std::string &file_path)
{
    std::ifstream file(file_path);
    if (!file.is_open())
    {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}
void send_response(SSL *ssl, int client_socket, const std::string &response)
{
    if (ssl)
    {
        SSL_write(ssl, response.c_str(), response.length());
    }
    else if (client_socket != -1)
    {
        send(client_socket, response.c_str(), response.length(), 0);
    }
}
void send_html(SSL *ssl, int client_socket, const std::string &file_path)
{
    std::string html_content = read_file(file_path);
    if (html_content.empty())
    {
        std::cerr << "Failed to read " << file_path << std::endl;
        return;
    }

    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html\r\n"
                           "Content-Length: " +
                           std::to_string(html_content.size()) + "\r\n"
                                                                 "Connection: close\r\n\r\n" +
                           html_content;

    // SSL_write(ssl, response.c_str(), response.size());
    send_response(ssl, client_socket, response);
}
void handle_websocket_connection(SSL *ssl, int client_socket, const std::string &client_key)
{
    std::string accept_key = generate_websocket_accept_key(client_key);
    std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: " +
                           accept_key + "\r\n\r\n";
    send_response(ssl, client_socket, response);
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        std::string message = "Server message";
        std::vector<char> ws_frame;

        // Create WebSocket frame
        ws_frame.push_back(0x81);           // FIN and text frame
        ws_frame.push_back(message.size()); // No mask, payload length

        ws_frame.insert(ws_frame.end(), message.begin(), message.end());
        int sent_bytes = SSL_write(ssl, ws_frame.data(), ws_frame.size());
        if (sent_bytes < 0)
        {
            perror("send failed");
            break; // Exit the loop if sending fails
        }
    }
}
// URL 인코딩된 데이터 파싱 함수
std::unordered_map<std::string, std::string> parse_urlencoded(const std::string &body)
{
    std::unordered_map<std::string, std::string> params;
    std::istringstream stream(body);
    std::string key_value;
    while (std::getline(stream, key_value, '&'))
    {
        size_t pos = key_value.find('=');
        if (pos != std::string::npos)
        {
            std::string key = key_value.substr(0, pos);
            std::string value = key_value.substr(pos + 1);
            params[key] = value;
        }
    }
    return params;
}

void handle_signup(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();
    json response;

    auto params = parse_urlencoded(body);

    if (params.find("username") != params.end() && params.find("password") != params.end())
    {
        std::string username = params["username"];
        std::string password = params["password"];

        std::string salt = generate_salt();
        std::string hashed_password = hash_password(password, salt);

        try
        {
            bool signup_success = withConnection([&](sql::Connection &con)
                                                 {
                std::unique_ptr<sql::PreparedStatement> pstmt(con.prepareStatement(
                    "INSERT INTO USERS (USERNAME, PASSWORD, SALT) VALUES (?, ?, ?)"));
                pstmt->setString(1, username);
                pstmt->setString(2, hashed_password);
                pstmt->setString(3, salt);

                int affected_rows = pstmt->executeUpdate();
                return affected_rows > 0; });

            if (signup_success)
            {
                g_logger.log(Logger::Level::INFO, "Signup successful for user: " + username);
                response["success"] = true;
                response["message"] = "Signup successful";
            }
            else
            {
                g_logger.log(Logger::Level::WARNING, "Signup failed for user: " + username);
                response["success"] = false;
                response["message"] = "Signup failed (DB error)";
            }
        }
        catch (const sql::SQLException &e)
        {
            response["success"] = false;
            response["message"] = "Signup failed (DB error: " + std::string(e.what()) + ")";
        }
    }
    else
    {
        response["success"] = false;
        response["message"] = "Bad Request";
    }

    std::string json_response = response.dump();
    evbuffer_add(buf, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
bool verify_user(const std::string &username, const std::string &password)
{
    sql::Connection *con = get_connection();
    if (!con)
        return false;

    try
    {
        sql::PreparedStatement *pstmt = con->prepareStatement(
            "SELECT PASSWORD, SALT FROM USERS WHERE USERNAME = ?");
        pstmt->setString(1, username);
        sql::ResultSet *res = pstmt->executeQuery();

        if (res->next())
        {
            std::string stored_password = res->getString("PASSWORD");
            std::string salt = res->getString("SALT");
            delete res;
            delete pstmt;
            delete con;

            std::string hashed_input = hash_password(password, salt);
            return stored_password == hashed_input;
        }

        delete res;
        delete pstmt;
        delete con;
        return false;
    }
    catch (sql::SQLException &e)
    {
        std::cerr << "SQL Exception: " << e.what() << std::endl;
        delete con;
        return false;
    }
}
std::string hmac_sha256(const std::string &key, const std::string &data)
{
    unsigned char *digest;
    unsigned int len = SHA256_DIGEST_LENGTH;
    digest = HMAC(EVP_sha256(), key.c_str(), key.size(), (unsigned char *)data.c_str(), data.size(), NULL, NULL);
    return std::string(reinterpret_cast<char *>(digest), len);
}
std::string create_jwt(const std::string &username, const std::string &secret_key)
{
    // Header
    Json::Value header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";

    // Payload
    Json::Value payload;
    payload["username"] = username;
    std::time_t now = std::time(nullptr);
    payload["exp"] = static_cast<Json::UInt64>(now + 3600); // 1 hour expiration

    // JSON 객체를 문자열로 변환
    Json::StreamWriterBuilder writer;
    std::string header_str = Json::writeString(writer, header);
    std::string payload_str = Json::writeString(writer, payload);

    // Base64 URL 인코딩
    std::string header_base64 = base64_url_encode(reinterpret_cast<const unsigned char *>(header_str.c_str()), header_str.length());
    std::string payload_base64 = base64_url_encode(reinterpret_cast<const unsigned char *>(payload_str.c_str()), payload_str.length());

    // Signature
    std::string signature = hmac_sha256(secret_key, header_base64 + "." + payload_base64);
    std::string signature_base64 = base64_url_encode(reinterpret_cast<const unsigned char *>(signature.c_str()), signature.length());

    // JWT
    return header_base64 + "." + payload_base64 + "." + signature_base64;
}
// 로그인 요청을 처리하는 함수
void handle_login(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();
    json response;

    try
    {
        json request_data = json::parse(body);
        if (!request_data.contains("username") || !request_data.contains("password"))
        {
            throw std::runtime_error("Missing username or password");
        }
        std::string username = request_data["username"];
        std::string password = request_data["password"];

        withConnection([&](sql::Connection &conn)
                       {
            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
                "SELECT PASSWORD, SALT FROM USERS WHERE USERNAME = ?"));
            pstmt->setString(1, username);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

            if (res->next()) {
                std::string stored_password = res->getString("PASSWORD");
                std::string salt = res->getString("SALT");

                std::string hashed_input = hash_password(password, salt);
                if (stored_password == hashed_input) {
                                g_logger.log(Logger::Level::INFO, "Login successful for user: " + username);
                    std::string token = create_jwt(username, SECRET_KEY);
                    response["success"] = true;
                    response["token"] = token;
                    response["username"] = username;
                } else {
                                g_logger.log(Logger::Level::WARNING, "Login failed for user: " + username);
                    response["success"] = false;
                    response["message"] = "Invalid credentials";
                }
            } else {    
                        g_logger.log(Logger::Level::WARNING, "Login failed for user: " + username);
                response["success"] = false;
                response["message"] = "Invalid credentials";
            } });
    }
    catch (const sql::SQLException &e)
    {
        g_logger.log(Logger::Level::ERROR, "Database error during login: " + std::string(e.what()));
        response["success"] = false;
        response["message"] = "Database error: " + std::string(e.what());
    }
    catch (const std::exception &e)
    {
        g_logger.log(Logger::Level::ERROR, "Unexpected error during login: " + std::string(e.what()));
        response["success"] = false;
        response["message"] = e.what();
    }

    std::string json_response = response.dump();
    evbuffer_add(buf, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_add_header(evhttp_request_get_output_headers(req), "X-Content-Type-Options", "nosniff");
    evhttp_add_header(evhttp_request_get_output_headers(req), "X-Frame-Options", "DENY");
    evhttp_add_header(evhttp_request_get_output_headers(req), "X-XSS-Protection", "1; mode=block");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
bool is_username_taken(const std::string &username)
{
    return withConnection([&username](sql::Connection &conn)
                          {
        bool is_taken = false;
        try
        {
            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
                "SELECT COUNT(*) FROM USERS WHERE USERNAME = ?"));
            pstmt->setString(1, username);

            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

            if (res->next())
            {
                int count = res->getInt(1);
                is_taken = (count > 0);
            }
        }
        catch (const sql::SQLException &e)
        {
            std::cerr << "SQL Exception in is_username_taken: " << e.what() << std::endl;
            // 에러 발생 시 예외를 던져서 상위에서 처리하도록 합니다.
            throw;
        }

        return is_taken; });
}
// 아이디 중복 확인 요청을 처리하는 함수
void handle_check_username(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();
    json response;

    try
    {
        auto params = parse_urlencoded(body);
        if (params.find("username") != params.end())
        {
            std::string username = params["username"];
            bool is_taken = is_username_taken(username);

            response["success"] = true;
            response["is_taken"] = is_taken;
            response["message"] = is_taken ? "Username is taken" : "Username is available";
        }
        else
        {
            response["success"] = false;
            response["message"] = "Bad Request";
        }
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = "Error checking username: " + std::string(e.what());
    }

    std::string json_response = response.dump();
    evbuffer_add(buf, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
void send_json_response(SSL *ssl, int client_socket, int status_code, const std::string &status_message, const json &response_json)
{
    std::string json_str = response_json.dump();
    std::ostringstream header_stream;
    header_stream << "HTTP/1.1 " << status_code << " " << status_message << "\r\n"
                  << "Content-Type: application/json\r\n"
                  << "Content-Length: " << json_str.length() << "\r\n"
                  << "Connection: close\r\n\r\n";

    std::string header = header_stream.str();
    std::string full_response = header + json_str;

    size_t total_sent = 0;
    const size_t chunk_size = 4096; // 4KB chunks

    while (total_sent < full_response.length())
    {
        size_t remaining = full_response.length() - total_sent;
        size_t to_send = std::min(remaining, chunk_size);

        ssize_t sent;
        if (ssl)
        {
            sent = SSL_write(ssl, full_response.c_str() + total_sent, to_send);
        }
        else
        {
            sent = send(client_socket, full_response.c_str() + total_sent, to_send, 0);
        }

        if (sent <= 0)
        {
            if (ssl)
            {
                int ssl_error = SSL_get_error(ssl, sent);
                if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ)
                {
                    // 재시도 필요
                    continue;
                }
                ERR_print_errors_fp(stderr);
            }
            else
            {
                perror("send failed");
            }
            break;
        }

        total_sent += sent;
    }

    if (total_sent != full_response.length())
    {
        std::cerr << "Warning: Not all data was sent. Sent "
                  << total_sent << " out of " << full_response.length() << " bytes." << std::endl;
    }
}
// void send_json_response(SSL *ssl, int client_socket, int status_code, const std::string &status_message, const json &response_json)
// {
//     std::string json_str = response_json.dump();
//     std::ostringstream response_stream;
//     response_stream << "HTTP/1.1 " << status_code << " " << status_message << "\r\n";
//     response_stream << "Content-Type: application/json\r\n";
//     response_stream << "Content-Length: " << json_str.length() << "\r\n";
//     response_stream << "\r\n";
//     response_stream << json_str;

//     std::string response = response_stream.str();
//     // SSL_write(ssl, response.c_str(), response.length());
//     send_response(ssl, client_socket, response);
// }
// void send_json_response(SSL *ssl, int client_socket, int status_code, const std::string &status_message, const std::string &json_content)
// {
//     std::ostringstream response;
//     response << "HTTP/1.1 " << status_code << " " << status_message << "\r\n";
//     response << "Content-Type: application/json\r\n";
//     response << "Cache-Control: no-cache\r\n";
//     response << "Content-Length: " << json_content.length() << "\r\n";
//     response << "\r\n";
//     response << json_content;

//     std::string response_str = response.str();
//     size_t total_sent = 0;
//     size_t remaining = response_str.length();

//     while (total_sent < response_str.length()) {
//         ssize_t bytes_sent;
//         if (ssl) {
//             bytes_sent = SSL_write(ssl, response_str.c_str() + total_sent, remaining);
//         } else {
//             bytes_sent = send(client_socket, response_str.c_str() + total_sent, remaining, 0);
//         }

//         if (bytes_sent <= 0) {
//             // 에러 처리
//             if (ssl) {
//                 std::cerr << "SSL_write failed. Error: " << SSL_get_error(ssl, bytes_sent) << std::endl;
//             } else {
//                 std::cerr << "send failed. Error: " << strerror(errno) << std::endl;
//             }
//             break;
//         }

//         total_sent += bytes_sent;
//         remaining -= bytes_sent;
//     }

//     if (total_sent != response_str.length()) {
//         std::cerr << "Failed to send full response. Sent " << total_sent << " out of " << response_str.length() << " bytes." << std::endl;
//     }
// }
// void send_json_response(SSL *ssl, int client_socket, int status_code, const std::string &status_message, const std::string &json_content)
// {
//     std::ostringstream response;
//     response << "HTTP/1.1 " << status_code << " " << status_message << "\r\n";
//     response << "Content-Type: application/json\r\n";
//     response << "Cache-Control: no-cache\r\n";
//     response << "Content-Length: " << json_content.length() << "\r\n";
//     response << "\r\n";
//     response << json_content;

//     std::string response_str = response.str();
//     ssize_t bytes_sent = SSL_write(ssl, response_str.c_str(), response_str.length());
//     if (bytes_sent != static_cast<ssize_t>(response_str.length()))
//     {
//         std::cerr << "Failed to send full response. Sent " << bytes_sent << " out of " << response_str.length() << " bytes." << std::endl;
//     }
// }
void handle_user_count_request(SSLInfo *ssl_info, struct evhttp_request *req)
{
    struct evbuffer *buf = evbuffer_new();
    json response_json;
    int status_code = HTTP_OK;
    std::string status_message = "OK";

    try
    {
        int user_count = withConnection([](sql::Connection &conn)
                                        {
            std::unique_ptr<sql::Statement> stmt(conn.createStatement());
            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT COUNT(*) FROM USERS"));
            res->next();
            return res->getInt(1); });

        response_json["success"] = true;
        response_json["user_count"] = user_count;
    }
    catch (const std::exception &e)
    {
        status_code = HTTP_INTERNAL;
        status_message = "Internal Server Error";
        response_json["success"] = false;
        response_json["error"] = e.what();
    }

    std::string response_str = response_json.dump();
    evbuffer_add(buf, response_str.c_str(), response_str.length());

    struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Content-Type", "application/json");

    evhttp_send_reply(req, status_code, status_message.c_str(), buf);
    evbuffer_free(buf);
}
// 파일 업로드 요청을 처리하는 함수
void handle_file_upload(SSL *ssl, int client_socket, const std::string &boundary, int bytes_received)
{
    std::ofstream outfile;
    char buffer[BUFFER_SIZE];
    // int bytes_received;
    bool file_started = false;
    std::string filename;

    while (bytes_received > 0)
    {
        std::string data(buffer, bytes_received);

        if (!file_started)
        {
            size_t filename_pos = data.find("filename=\"");
            if (filename_pos != std::string::npos)
            {
                filename_pos += 10;
                size_t filename_end = data.find("\"", filename_pos);
                filename = data.substr(filename_pos, filename_end - filename_pos);
                outfile.open(UPLOAD_DIR + filename, std::ios::binary);
                file_started = true;
            }
        }
        else
        {
            size_t boundary_pos = data.find(boundary);
            if (boundary_pos != std::string::npos)
            {
                outfile.write(data.c_str(), boundary_pos);
                break;
            }
            else
            {
                outfile.write(data.c_str(), bytes_received);
            }
        }
    }

    outfile.close();
    g_logger.log(Logger::Level::INFO, "File uploaded: " + filename);

    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: 7\r\n"
                           "Connection: close\r\n\r\n"
                           "Success";
    send_response(ssl, client_socket, response);
}
// 파일 다운로드 요청을 처리하는 함수
void handle_file_download(SSL *ssl, int client_socket, const std::string &filename)
{
    std::ifstream infile(UPLOAD_DIR + filename, std::ios::binary);
    if (!infile)
    {
        g_logger.log(Logger::Level::WARNING, "File not found: " + filename);
        std::string response = "HTTP/1.1 404 Not Found\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: 9\r\n"
                               "Connection: close\r\n\r\n"
                               "Not Found";
        send_response(ssl, client_socket, response);
    }
    else
    {
        g_logger.log(Logger::Level::INFO, "File download started: " + filename);
        infile.seekg(0, std::ios::end);
        size_t file_size = infile.tellg();
        infile.seekg(0, std::ios::beg);
        g_logger.log(Logger::Level::INFO, "File download completed: " + filename);

        std::string response = "HTTP/1.1 200 OK\r\n"
                               "Content-Type: application/octet-stream\r\n"
                               "Content-Length: " +
                               std::to_string(file_size) + "\r\n"
                                                           "Content-Disposition: attachment; filename=\"" +
                               filename + "\"\r\n"
                                          "Connection: close\r\n\r\n";
        send_response(ssl, client_socket, response);

        char buffer[BUFFER_SIZE];
        size_t total_sent = 0;

        while (infile.read(buffer, BUFFER_SIZE))
        {
            size_t bytes_read = infile.gcount();
            size_t bytes_sent = 0;

            while (bytes_sent < bytes_read)
            {
                ssize_t result;
                if (ssl)
                {
                    result = SSL_write(ssl, buffer + bytes_sent, bytes_read - bytes_sent);
                }
                else
                {
                    result = send(client_socket, buffer + bytes_sent, bytes_read - bytes_sent, 0);
                }

                if (result <= 0)
                {
                    // 에러 처리
                    if (ssl)
                    {
                        std::cerr << "SSL_write failed. Error: " << SSL_get_error(ssl, result) << std::endl;
                    }
                    else
                    {
                        std::cerr << "send failed. Error: " << strerror(errno) << std::endl;
                    }
                    infile.close();
                    return;
                }

                bytes_sent += result;
            }

            total_sent += bytes_sent;
        }

        // 마지막 부분 처리
        size_t remaining = infile.gcount();
        if (remaining > 0)
        {
            size_t bytes_sent = 0;
            while (bytes_sent < remaining)
            {
                ssize_t result;
                if (ssl)
                {
                    result = SSL_write(ssl, buffer + bytes_sent, remaining - bytes_sent);
                }
                else
                {
                    result = send(client_socket, buffer + bytes_sent, remaining - bytes_sent, 0);
                }

                if (result <= 0)
                {
                    // 에러 처리
                    if (ssl)
                    {
                        std::cerr << "SSL_write failed. Error: " << SSL_get_error(ssl, result) << std::endl;
                    }
                    else
                    {
                        std::cerr << "send failed. Error: " << strerror(errno) << std::endl;
                    }
                    break;
                }

                bytes_sent += result;
            }

            total_sent += bytes_sent;
        }

        if (total_sent != file_size)
        {
            std::cerr << "Failed to send entire file. Sent " << total_sent << " out of " << file_size << " bytes." << std::endl;
        }
    }

    infile.close();
}
// 파일 목록 요청을 처리하는 함수
void handle_file_list_request(SSLInfo *ssl_info, struct evhttp_request *req)
{
    struct evbuffer *evb = evbuffer_new();
    if (evb == NULL)
    {
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        return;
    }

    DIR *dir;
    struct dirent *ent;
    std::vector<std::string> files;

    if ((dir = opendir(UPLOAD_DIR.c_str())) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            if (ent->d_type == DT_REG)
            {
                files.push_back(ent->d_name);
            }
        }
        closedir(dir);
    }
    else
    {
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to open directory");
        evbuffer_free(evb);
        return;
    }

    json response_json = json::array();
    for (const auto &file : files)
    {
        response_json.push_back(file);
    }

    std::string response_body = response_json.dump();
    evbuffer_add(evb, response_body.c_str(), response_body.length());

    struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Content-Type", "application/json");
    evhttp_add_header(headers, "Connection", "close");

    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
void send_image(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::string not_found_response = "404 Not Found";
        struct evbuffer *buf = evbuffer_new();
        evbuffer_add(buf, not_found_response.c_str(), not_found_response.length());
        evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", buf);
        evbuffer_free(buf);
        return;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> file_content(file_size);
    file.read(file_content.data(), file_size);

    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, file_content.data(), file_size);

    struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Content-Type", "image/jpeg");

    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void send_js(SSL *ssl, int client_socket, const std::string &file_path)
{
    std::ifstream file(file_path);
    if (!file)
    {
        std::string not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                         "Content-Type: text/plain\r\n"
                                         "Content-Length: 13\r\n"
                                         "Connection: close\r\n\r\n"
                                         "404 Not Found";
        send_response(ssl, client_socket, not_found_response);
        return;
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    std::string file_content = oss.str();

    std::string header = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/javascript\r\n"
                         "Content-Length: " +
                         std::to_string(file_content.size()) + "\r\n"
                                                               "Connection: close\r\n\r\n";
    send_response(ssl, client_socket, header);
    send_response(ssl, client_socket, file_content);

    file.close();
}
void send_css(SSL *ssl, int client_socket, const std::string &file_path)
{
    std::ifstream file(file_path);
    if (!file)
    {
        std::string not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                         "Content-Type: text/plain\r\n"
                                         "Content-Length: 13\r\n"
                                         "Connection: close\r\n\r\n"
                                         "404 Not Found";
        send_response(ssl, client_socket, not_found_response);
        return;
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    std::string file_content = oss.str();

    std::string header = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/css\r\n"
                         "Content-Length: " +
                         std::to_string(file_content.size()) + "\r\n"
                                                               "Connection: close\r\n\r\n";
    send_response(ssl, client_socket, header);
    send_response(ssl, client_socket, file_content);

    file.close();
}
void send_font(SSL *ssl, int client_socket, const std::string &file_path, const std::string &content_type)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::string not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                         "Content-Type: text/plain\r\n"
                                         "Content-Length: 13\r\n"
                                         "Connection: close\r\n\r\n"
                                         "404 Not Found";
        send_response(ssl, client_socket, not_found_response);
        return;
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    std::string file_content = oss.str();

    std::string header = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: " +
                         content_type + "\r\n"
                                        "Content-Length: " +
                         std::to_string(file_content.size()) + "\r\n"
                                                               "Connection: close\r\n\r\n";
    send_response(ssl, client_socket, header);
    send_response(ssl, client_socket, file_content);

    file.close();
}
std::string get_content_type(const std::string &file_extension)
{
    if (file_extension == ".eot")
        return "application/vnd.ms-fontobject";
    if (file_extension == ".otf")
        return "font/otf";
    if (file_extension == ".svg")
        return "image/svg+xml";
    if (file_extension == ".ttf")
        return "font/ttf";
    if (file_extension == ".woff")
        return "font/woff";
    if (file_extension == ".woff2")
        return "font/woff2";
    if (file_extension == "html")
        return "text/html";
    if (file_extension == ".html")
        return "text/html";
    if (file_extension == ".css")
        return "text/css";
    if (file_extension == ".js")
        return "application/javascript";
    if (file_extension == ".json")
        return "application/json";
    if (file_extension == ".png")
        return "image/png";
    if (file_extension == ".jpg" || file_extension == ".jpeg")
        return "image/jpeg";
    if (file_extension == ".gif")
        return "image/gif";
    if (file_extension == ".pdf")
        return "application/pdf";
    if (file_extension == ".3ds")
        return "application/x-3ds";
    // Add more file types as needed
    return "application/octet-stream"; // Default type for unknown extensions
}

void send_uploads_file(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::string not_found_response = "404 Not Found";
        struct evbuffer *buf = evbuffer_new();
        evbuffer_add(buf, not_found_response.c_str(), not_found_response.length());
        evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", buf);
        evbuffer_free(buf);
        return;
    }

    std::string file_extension = file_path.substr(file_path.find_last_of("."));
    std::string content_type = get_content_type(file_extension);

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> file_content(file_size);
    file.read(file_content.data(), file_size);

    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, file_content.data(), file_size);

    struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Content-Type", content_type.c_str());

    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}
std::map<std::string, std::string> parse_json(const std::string &json_str)
{
    std::map<std::string, std::string> json_map;
    std::string key, value;
    bool in_key = false, in_value = false;
    bool is_escaped = false;

    for (size_t i = 0; i < json_str.length(); ++i)
    {
        char c = json_str[i];

        if (c == '\\' && !is_escaped)
        {
            is_escaped = true;
            continue;
        }

        if (c == '"' && !is_escaped)
        {
            if (in_key)
            {
                in_key = false;
            }
            else if (in_value)
            {
                in_value = false;
                json_map[key] = value;
                key.clear();
                value.clear();
            }
            else
            {
                if (key.empty())
                {
                    in_key = true;
                }
                else
                {
                    in_value = true;
                }
            }
            is_escaped = false;
            continue;
        }

        if (in_key)
        {
            key += c;
        }
        else if (in_value)
        {
            value += c;
        }

        is_escaped = false;
    }

    return json_map;
}
std::string json_escape(const std::string &s)
{
    std::ostringstream o;
    for (auto c = s.cbegin(); c != s.cend(); c++)
    {
        switch (*c)
        {
        case '"':
            o << "\\\"";
            break;
        case '\\':
            o << "\\\\";
            break;
        case '\b':
            o << "\\b";
            break;
        case '\f':
            o << "\\f";
            break;
        case '\n':
            o << "\\n";
            break;
        case '\r':
            o << "\\r";
            break;
        case '\t':
            o << "\\t";
            break;
        default:
            if ('\x00' <= *c && *c <= '\x1f')
            {
                o << "\\u"
                  << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(*c);
            }
            else
            {
                o << *c;
            }
        }
    }
    return o.str();
}
bool verify_jwt(const std::string &token, const std::string &secret_key, std::string &username)
{
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);

    if (first_dot == std::string::npos || second_dot == std::string::npos)
        return false;

    std::string header_base64 = token.substr(0, first_dot);
    std::string payload_base64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string signature_base64 = token.substr(second_dot + 1);

    std::string expected_signature = base64_url_encode(reinterpret_cast<const unsigned char *>(hmac_sha256(secret_key, header_base64 + "." + payload_base64).c_str()), SHA256_DIGEST_LENGTH);

    std::cout << "Expected Signature: " << expected_signature << std::endl;
    std::cout << "Signature from Token: " << signature_base64 << std::endl;

    if (expected_signature != signature_base64)
        return false;

    std::string payload_json = base64_url_decode(payload_base64);
    Json::Value payload;
    Json::CharReaderBuilder reader;
    std::string errs;
    std::istringstream s(payload_json);
    if (!Json::parseFromStream(reader, s, &payload, &errs))
        return false;

    std::time_t now = std::time(nullptr);
    if (payload["exp"].asUInt64() < now)
        return false;

    username = payload["username"].asString();
    return true;
}
std::unordered_map<std::string, std::string> parse_query_params(const std::string &query)
{
    std::unordered_map<std::string, std::string> params;
    std::stringstream ss(query);
    std::string item;
    while (std::getline(ss, item, '&'))
    {
        size_t pos = item.find('=');
        if (pos != std::string::npos)
        {
            params[item.substr(0, pos)] = item.substr(pos + 1);
        }
    }
    return params;
}
void handle_verify_token(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();

    auto params = parse_urlencoded(body);
    std::string token = params.at("token");
    std::string username;

    std::ostringstream response;
    if (verify_jwt(token, SECRET_KEY, username))
    {
        response << "{\"success\": true, \"username\": \"" << username << "\"}";
    }
    else
    {
        response << "{\"success\": false}";
    }

    std::string response_str = response.str();
    evbuffer_add(buf, response_str.c_str(), response_str.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
// Function to get current timestamp in milliseconds
std::string get_current_timestamp()
{
    auto now = std::chrono::system_clock::now();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return std::to_string(milliseconds);
}
// Function to generate a random number
std::string generate_random_number()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(100000, 999999);
    return std::to_string(dist(mt));
}
// Function to save an image from base64 data
std::string save_image(const std::string &base64_data, const std::string &output_path, const std::string &extension)
{
    std::string timestamp = get_current_timestamp();
    std::string random_number = generate_random_number();
    std::string file_path = output_path + "image_" + timestamp + "_" + random_number + "." + extension;
    std::ofstream out_file(file_path, std::ios::binary);
    std::vector<unsigned char> decoded_data = base64_decode_uchar(base64_data);
    out_file.write(reinterpret_cast<const char *>(decoded_data.data()), decoded_data.size());
    out_file.close();
    return file_path;
}
std::string process_content_and_save_images(const std::string &content, const std::string &output_path)
{
    std::string processed_content = content;
    size_t pos = 0;

    while ((pos = processed_content.find("data:image/", pos)) != std::string::npos)
    {
        size_t start_pos = pos;
        size_t end_pos = processed_content.find('>', start_pos);
        if (end_pos == std::string::npos)
        {
            break;
        }

        // Extract the entire data:image/... base64, data
        std::string data_uri = processed_content.substr(start_pos, end_pos - start_pos);

        // Find the base64 comma position
        size_t base64_pos = data_uri.find("base64,");
        if (base64_pos == std::string::npos)
        {
            pos = end_pos;
            continue;
        }
        base64_pos += 7; // Move past "base64,"

        // Extract the extension and base64 data
        std::string extension = data_uri.substr(11, data_uri.find(';') - 11);
        std::string base64_data = data_uri.substr(base64_pos);

        // Save the image and get the file path
        std::string file_path = save_image(base64_data, output_path, extension);

        // Create the replacement string with the file path
        std::string quoted_file_path = file_path + "\"";

        // Replace the base64 data with the file path in processed_content
        processed_content.replace(start_pos, end_pos - start_pos, quoted_file_path);

        // Update the position to continue searching after the replacement
        pos = start_pos + quoted_file_path.length();
    }

    return processed_content;
}
// Function to escape JSON string
std::string escape_json_string(const std::string &input)
{
    std::ostringstream ss;
    for (char c : input)
    {
        switch (c)
        {
        case '\"':
            ss << "\\\"";
            break;
        case '\\':
            ss << "\\\\";
            break;
        case '\b':
            ss << "\\b";
            break;
        case '\f':
            ss << "\\f";
            break;
        case '\n':
            ss << "\\n";
            break;
        case '\r':
            ss << "\\r";
            break;
        case '\t':
            ss << "\\t";
            break;
        default:
            ss << c;
            break;
        }
    }
    return ss.str();
}
void save_post(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();
    json response;

    try
    {
        json postData = json::parse(body);
        bool success = withConnection([&](sql::Connection &conn)
                                      {
            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
                "INSERT INTO posts (title, content, author, timestamp, category) VALUES (?, ?, ?, ?, ?)"));

            pstmt->setString(1, postData["title"].get<std::string>());
            pstmt->setString(2, postData["content"].get<std::string>());
            pstmt->setString(3, postData["author"].get<std::string>());
            pstmt->setString(4, postData["timestamp"].get<std::string>());
            pstmt->setString(5, postData["category"].get<std::string>());

            return pstmt->executeUpdate() > 0; });

        if (success)
        {
            response["success"] = true;
        }
        else
        {
            response["success"] = false;
            response["error"] = "Failed to insert post";
        }
    }
    catch (const sql::SQLException &e)
    {
        response["success"] = false;
        response["error"] = "Database error: " + std::string(e.what());
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["error"] = "Unknown error: " + std::string(e.what());
    }

    std::string json_response = response.dump();
    evbuffer_add(buf, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
// Function to replace all occurrences of a substring with another substring in a string
void replace_all(std::string &str, const std::string &from, const std::string &to)
{
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos)
    {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}
void handle_get_posts(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
{
    struct evbuffer *buf = evbuffer_new();

    std::unordered_map<std::string, std::string> params = parse_query_params(query);
    std::string category = params["categoryId"];
    std::string sortColumn = params["sortColumn"];
    std::string sortOrder = params["sortOrder"];

    try
    {
        Json::Value posts = withConnection([&](sql::Connection &conn)
                                           {
            std::string sql = "SELECT id, title, content, author, timestamp FROM posts WHERE category = ?";
            
            if (!sortColumn.empty() && !sortOrder.empty()) {
                sql += " ORDER BY " + sortColumn + " " + sortOrder;
            }

            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(sql));
            pstmt->setString(1, category);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

            Json::Value posts(Json::arrayValue);
            while (res->next()) {
                Json::Value post;
                post["id"] = Json::Int64(res->getInt64("id"));
                post["title"] = res->getString("title").c_str();
                post["content"] = res->getString("content").c_str();
                post["author"] = res->getString("author").c_str();
                post["timestamp"] = res->getString("timestamp").c_str();
                posts.append(post);
            }
            return posts; });

        Json::StreamWriterBuilder writer;
        std::string json_response = Json::writeString(writer, posts);
        evbuffer_add(buf, json_response.c_str(), json_response.length());
        evhttp_send_reply(req, HTTP_OK, "OK", buf);
    }
    catch (const std::exception &e)
    {
        std::string error_message = std::string("Error fetching posts: ") + e.what();
        Json::Value error_json;
        error_json["success"] = false;
        error_json["error"] = error_message;

        Json::StreamWriterBuilder writer;
        std::string json_response = Json::writeString(writer, error_json);
        evbuffer_add(buf, json_response.c_str(), json_response.length());
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", buf);
    }

    evbuffer_free(buf);
}
void handle_get_posts(SSL *ssl, int client_socket, const std::string &query)
{
    std::unordered_map<std::string, std::string> params = parse_query_params(query);
    std::string category = params["categoryId"];
    std::string sortColumn = params["sortColumn"];
    std::string sortOrder = params["sortOrder"];

    try
    {
        Json::Value posts = withConnection([&](sql::Connection &conn)
                                           {
            std::string sql = "SELECT id, title, content, author, timestamp FROM posts WHERE category = ?";
            
            if (!sortColumn.empty() && !sortOrder.empty()) {
                sql += " ORDER BY " + sortColumn + " " + sortOrder;
            }

            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(sql));
            pstmt->setString(1, category);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

            Json::Value posts(Json::arrayValue);
            while (res->next())
            {
                Json::Value post;
                post["id"] = Json::Int64(res->getInt64("id"));
                post["title"] = res->getString("title").c_str();
                post["content"] = res->getString("content").c_str();
                post["author"] = res->getString("author").c_str();
                post["timestamp"] = res->getString("timestamp").c_str();
                posts.append(post);
            }
            return posts; });

        Json::StreamWriterBuilder writer;
        std::string json_response = Json::writeString(writer, posts);
        std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json_response;
        // SSL_write(ssl, response.c_str(), response.length());
        send_response(ssl, client_socket, response);
    }
    catch (const std::exception &e)
    {
        std::string error_message = std::string("Error fetching posts: ") + e.what();
        std::string response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n"
                               "{\"success\": false, \"error\": \"" +
                               error_message + "\"}";
        // SSL_write(ssl, response.c_str(), response.length());
        send_response(ssl, client_socket, response);
    }
}
std::vector<std::string> getImagesList(const std::string &directory)
{
    std::vector<std::string> images;
    for (const auto &entry : fs::directory_iterator(directory))
    {
        if (entry.is_regular_file())
        {
            images.push_back(entry.path().filename().string());
        }
    }
    return images;
}
void handle_get_images(SSLInfo *ssl_info, struct evhttp_request *req)
{
    std::vector<std::string> images = getImagesList("./images");
    Json::Value json_images(Json::arrayValue);
    for (const auto &image : images)
    {
        json_images.append(image);
    }

    Json::StreamWriterBuilder writer;
    std::string response_body = Json::writeString(writer, json_images);

    struct evbuffer *buf = evbuffer_new();
    if (buf == NULL)
    {
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        return;
    }

    evbuffer_add(buf, response_body.c_str(), response_body.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
void handle_delete_post(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();
    json response;

    try
    {
        json postData = json::parse(body);
        int post_id = postData["id"].get<int>();
        std::string username = postData["username"];

        bool success = withConnection([&](sql::Connection &con)
                                      {
            std::unique_ptr<sql::PreparedStatement> pstmt(con.prepareStatement("SELECT author FROM posts WHERE id = ?"));
            pstmt->setInt(1, post_id);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

            if (res->next()) {
                std::string author = res->getString("author");
                if (author != username) {
                    return false;
                }

                pstmt.reset(con.prepareStatement("DELETE FROM posts WHERE id = ?"));
                pstmt->setInt(1, post_id);
                return pstmt->executeUpdate() > 0;
            }
            return false; });

        if (success)
        {
            response["success"] = true;
        }
        else
        {
            response["success"] = false;
            response["message"] = "Failed to delete post or unauthorized";
        }
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = "Error: " + std::string(e.what());
    }

    std::string json_response = response.dump();
    evbuffer_add(buf, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
std::string parseMultipartData(const std::string &data, std::string &filename)
{
    // Parse the boundary
    size_t boundary_pos = data.find("\r\n");
    std::string boundary = data.substr(0, boundary_pos);

    // Find the start of the file content
    size_t file_start_pos = data.find("filename=\"", boundary_pos);
    if (file_start_pos == std::string::npos)
        return "";

    file_start_pos += 10;
    size_t file_end_pos = data.find("\"", file_start_pos);
    filename = data.substr(file_start_pos, file_end_pos - file_start_pos);

    // Find the start of the file content
    file_start_pos = data.find("\r\n\r\n", file_end_pos) + 4;
    size_t file_end_boundary_pos = data.find(boundary, file_start_pos) - 4;

    return data.substr(file_start_pos, file_end_boundary_pos - file_start_pos);
}
// 공통 파일 업로드 함수
bool uploadFile(const std::string &content, const std::string &filename, const std::string &directory)
{
    std::string filepath = directory + filename;
    std::ofstream outfile(filepath, std::ios::binary);
    if (!outfile)
    {
        return false;
    }
    outfile.write(content.c_str(), content.size());
    outfile.close();
    return true;
}
// 이미지 업로드 핸들러
void handleUploadImage(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();
    json response;

    try
    {
        std::string filename;
        std::string file_content = parseMultipartData(body, filename);

        if (filename.empty() || file_content.empty())
        {
            response["success"] = false;
            response["message"] = "Invalid file data";
        }
        else if (uploadFile(file_content, filename, UPLOAD_IMAGE_DIR))
        {
            response["success"] = true;
            response["url"] = "images/" + filename;
        }
        else
        {
            response["success"] = false;
            response["message"] = "Failed to save file";
        }
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = "Error: " + std::string(e.what());
    }

    std::string json_response = response.dump();
    evbuffer_add(buf, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
// OBJ 파일 업로드 핸들러
void handleUploadObj(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();

    const char *content_type = evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type");
    if (!content_type || strncmp(content_type, "multipart/form-data", 19) != 0)
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"message\": \"Invalid content type\"}");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad Request", evb);
        evbuffer_free(evb);
        return;
    }

    struct evbuffer *req_body = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(req_body);
    char *data = (char *)malloc(len);
    evbuffer_copyout(req_body, data, len);

    std::string filename;
    std::string file_content = parseMultipartData(std::string(data, len), filename);
    free(data);

    if (filename.empty() || file_content.empty())
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"message\": \"Invalid file data\"}");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad Request", evb);
        evbuffer_free(evb);
        return;
    }

    if (uploadFile(file_content, filename, UPLOAD_OBJ_DIR))
    {
        evbuffer_add_printf(evb, "{\"success\": true, \"url\": \"uploads/objs/%s\"}", filename.c_str());
        evhttp_send_reply(req, HTTP_OK, "OK", evb);
    }
    else
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"message\": \"Failed to save file\"}");
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", evb);
    }

    evbuffer_free(evb);
}
// 일반 파일 업로드 핸들러
void handleUploadFiles(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();

    const char *content_type = evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type");
    if (!content_type || strncmp(content_type, "multipart/form-data", 19) != 0)
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"message\": \"Invalid content type\"}");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad Request", evb);
        evbuffer_free(evb);
        return;
    }

    struct evbuffer *req_body = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(req_body);
    char *data = (char *)malloc(len);
    evbuffer_copyout(req_body, data, len);

    std::string filename;
    std::string file_content = parseMultipartData(std::string(data, len), filename);
    free(data);

    if (filename.empty() || file_content.empty())
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"message\": \"Invalid file data\"}");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad Request", evb);
        evbuffer_free(evb);
        return;
    }

    if (uploadFile(file_content, filename, UPLOAD_DIR))
    {
        evbuffer_add_printf(evb, "{\"success\": true, \"url\": \"uploads/%s\"}", filename.c_str());
        evhttp_send_reply(req, HTTP_OK, "OK", evb);
    }
    else
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"message\": \"Failed to save file\"}");
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", evb);
    }

    evbuffer_free(evb);
}
void handle_get_comments(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
{
    struct evbuffer *buf = evbuffer_new();

    // 쿼리 파라미터 파싱
    std::unordered_map<std::string, std::string> params = parse_query_params(query);
    int postId = std::stoi(params["postId"]);

    try
    {
        Json::Value jsonResponse = withConnection([postId](sql::Connection &conn)
                                                  {
            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
                "SELECT id, author, content, timestamp FROM comments WHERE post_id = ?"));
            pstmt->setInt(1, postId);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

            Json::Value comments(Json::arrayValue);

            while (res->next()) {
                Json::Value comment;
                comment["id"] = Json::Int64(res->getInt64("id"));
                comment["author"] = res->getString("author").c_str();
                comment["text"] = res->getString("content").c_str();
                comment["timestamp"] = res->getString("timestamp").c_str();
                comments.append(comment);
            }

            Json::Value response;
            response["comments"] = comments;
            return response; });

        Json::StreamWriterBuilder writer;
        std::string json_response = Json::writeString(writer, jsonResponse);

        evbuffer_add(buf, json_response.c_str(), json_response.length());
        evhttp_send_reply(req, HTTP_OK, "OK", buf);
    }
    catch (const std::exception &e)
    {
        std::string error_message = "Failed to fetch comments: " + std::string(e.what());
        evbuffer_add_printf(buf, "{\"success\": false, \"error\": \"%s\"}", error_message.c_str());
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", buf);
    }

    evbuffer_free(buf);
}
void handle_edit_comment(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();

    try
    {
        json jsonData = json::parse(body);
        int commentId = jsonData["id"].get<int>();
        std::string newText = jsonData["newText"];

        bool success = withConnection([&](sql::Connection &conn)
                                      {
            std::unique_ptr<sql::PreparedStatement> updateStmt(conn.prepareStatement(
                "UPDATE comments SET content = ?, timestamp = NOW() WHERE id = ?"));
            updateStmt->setString(1, newText);
            updateStmt->setInt(2, commentId);
            int affectedRows = updateStmt->executeUpdate();

            if (affectedRows == 0) {
                return false; // Comment not found or not updated
            }

            std::unique_ptr<sql::PreparedStatement> selectStmt(conn.prepareStatement(
                "SELECT post_id FROM comments WHERE id = ?"));
            selectStmt->setInt(1, commentId);
            std::unique_ptr<sql::ResultSet> res(selectStmt->executeQuery());

            if (res->next()) {
                int postId = res->getInt("post_id");
                evbuffer_add_printf(evb, "{\"success\": true, \"postId\": %d}", postId);
                return true;
            }
            return false; });

        if (success)
        {
            evhttp_send_reply(req, HTTP_OK, "OK", evb);
        }
        else
        {
            evbuffer_add_printf(evb, "{\"success\": false, \"error\": \"Comment not found or not updated\"}");
            evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", evb);
        }
    }
    catch (const sql::SQLException &e)
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"error\": \"Database error: %s\"}", e.what());
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", evb);
    }
    catch (const json::exception &e)
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"error\": \"JSON parsing error: %s\"}", e.what());
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad Request", evb);
    }
    catch (const std::exception &e)
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"error\": \"Unexpected error: %s\"}", e.what());
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", evb);
    }

    evbuffer_free(evb);
}
void handle_delete_comment(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();
    json response;

    try
    {
        json jsonData = json::parse(body);
        int commentId = jsonData["id"].get<int>();

        auto result = withConnection([commentId](sql::Connection &conn)
                                     {
            int postId = -1;
            bool commentFound = false;
            int affectedRows = 0;

            {
                std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
                    "SELECT post_id FROM comments WHERE id = ?"));
                pstmt->setInt(1, commentId);
                std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

                if (res->next()) {
                    postId = res->getInt("post_id");
                    commentFound = true;
                }
            }

            if (commentFound) {
                std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement("DELETE FROM comments WHERE id = ?"));
                pstmt->setInt(1, commentId);
                affectedRows = pstmt->executeUpdate();
            }

            return std::make_tuple(commentFound, affectedRows, postId); });

        auto [commentFound, affectedRows, postId] = result;

        if (commentFound && affectedRows > 0)
        {
            response["success"] = true;
            response["postId"] = postId;
        }
        else
        {
            response["success"] = false;
            response["error"] = "Comment not found";
        }
    }
    catch (const sql::SQLException &e)
    {
        response["success"] = false;
        response["error"] = "Database error: " + std::string(e.what());
    }
    catch (const json::exception &e)
    {
        response["success"] = false;
        response["error"] = "JSON parsing error: " + std::string(e.what());
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["error"] = "Unexpected error: " + std::string(e.what());
    }

    evbuffer_add_printf(evb, "%s", response.dump().c_str());
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
void handle_add_comment(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();

    json jsonData = json::parse(body);
    int postId = std::stoi(jsonData["postId"].get<std::string>());
    std::string commentText = jsonData["commentText"];
    std::string author = jsonData["author"];

    try
    {
        bool success = withConnection([&](sql::Connection &conn)
                                      {
            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
                "INSERT INTO comments (post_id, author, content, timestamp) VALUES (?, ?, ?, NOW())"));

            pstmt->setInt(1, postId);
            pstmt->setString(2, author);
            pstmt->setString(3, commentText);
            int affectedRows = pstmt->executeUpdate();

            return affectedRows > 0; });

        if (success)
        {
            evbuffer_add_printf(evb, "{\"success\": true}");
            evhttp_send_reply(req, HTTP_OK, "OK", evb);
        }
        else
        {
            evbuffer_add_printf(evb, "{\"success\": false, \"error\": \"Failed to add comment\"}");
            evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", evb);
        }
    }
    catch (const sql::SQLException &e)
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"error\": \"Database error: %s\"}", e.what());
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", evb);
    }
    catch (const std::exception &e)
    {
        evbuffer_add_printf(evb, "{\"success\": false, \"error\": \"Unexpected error: %s\"}", e.what());
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", evb);
    }

    evbuffer_free(evb);
}
std::string get_file_extension(const std::string &filename)
{
    size_t dot_pos = filename.find_last_of(".");
    if (dot_pos != std::string::npos)
    {
        return filename.substr(dot_pos + 1);
    }
    return "";
}

std::string format_iso8601(const std::chrono::system_clock::time_point &tp)
{
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm = *std::gmtime(&tt);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}
void handle_drive_contents(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
{
    struct evbuffer *buf = evbuffer_new();

    std::string path = "/";
    size_t path_pos = query.find("path=");
    if (path_pos != std::string::npos)
    {
        path = query.substr(path_pos + 5);
        size_t end_pos = path.find('&');
        if (end_pos != std::string::npos)
        {
            path = path.substr(0, end_pos);
        }
    }

    std::string decoded_path = url_decode(path);
    std::string root_path = UPLOAD_DIR;
    std::string full_path = root_path + decoded_path;

    // 보안 검사
    if (full_path.substr(0, root_path.length()) != root_path)
    {
        evbuffer_add_printf(buf, "{\"error\": \"Access is not allowed\"}");
        evhttp_send_reply(req, HTTP_FORBIDDEN, "Forbidden", buf);
        evbuffer_free(buf);
        return;
    }

    try
    {
        if (!fs::exists(full_path))
        {
            throw fs::filesystem_error("Directory does not exist", full_path, std::error_code());
        }

        Json::Value jsonResponse;
        Json::Value contents(Json::arrayValue);

        for (const auto &entry : fs::directory_iterator(full_path))
        {
            Json::Value item;
            std::string filename = json_escape(entry.path().filename().string());
            std::string type = fs::is_directory(entry) ? "folder" : "file";

            item["name"] = filename;
            item["type"] = type;

            if (type == "file")
            {
                item["extension"] = get_file_extension(filename);
                item["size"] = Json::UInt64(fs::file_size(entry));
            }
            else
            {
                item["items_count"] = Json::UInt64(std::distance(fs::directory_iterator(entry), fs::directory_iterator{}));
            }

            auto last_modified = fs::last_write_time(entry);
            auto last_modified_tp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                last_modified - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
            item["last_modified"] = format_iso8601(last_modified_tp);

            contents.append(item);
        }

        jsonResponse["contents"] = contents;

        Json::StreamWriterBuilder writer;
        std::string json_str = Json::writeString(writer, jsonResponse);
        evbuffer_add(buf, json_str.c_str(), json_str.length());
        evhttp_send_reply(req, HTTP_OK, "OK", buf);
    }
    catch (const fs::filesystem_error &e)
    {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        std::string error_json = "{\"error\": \"" + json_escape(e.what()) + "\"}";
        evbuffer_add(buf, error_json.c_str(), error_json.length());
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", buf);
    }

    evbuffer_free(buf);
}
void handle_download_file(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
{
    struct evbuffer *evb = evbuffer_new();

    // 쿼리 문자열 파싱
    std::unordered_map<std::string, std::string> params;
    size_t start = 0;
    size_t end = query.find('&');
    while (end != std::string::npos)
    {
        std::string param = query.substr(start, end - start);
        size_t equals_pos = param.find('=');
        if (equals_pos != std::string::npos)
        {
            params[param.substr(0, equals_pos)] = param.substr(equals_pos + 1);
        }
        start = end + 1;
        end = query.find('&', start);
    }
    std::string param = query.substr(start);
    size_t equals_pos = param.find('=');
    if (equals_pos != std::string::npos)
    {
        params[param.substr(0, equals_pos)] = param.substr(equals_pos + 1);
    }

    std::string path = params["path"];
    std::string name = params["name"];

    std::string decoded_path = evhttp_uridecode(path.c_str(), 0, NULL);
    std::string decoded_name = evhttp_uridecode(name.c_str(), 0, NULL);
    std::string root_path = UPLOAD_ROOT_DIR;
    std::string full_path = root_path + decoded_path + decoded_name;

    // 보안 검사: 경로가 root_path 밖으로 나가지 않도록 확인
    if (full_path.substr(0, root_path.length()) != root_path)
    {
        evbuffer_add_printf(evb, "Access is not allowed");
        evhttp_send_reply(req, HTTP_FORBIDDEN, "Forbidden", evb);
        evbuffer_free(evb);
        return;
    }

    // 파일 존재 여부 확인
    if (!fs::exists(full_path) || !fs::is_regular_file(full_path))
    {
        evbuffer_add_printf(evb, "File not found");
        evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", evb);
        evbuffer_free(evb);
        return;
    }

    // 파일 열기
    std::ifstream file(full_path, std::ios::binary);
    if (!file)
    {
        evbuffer_add_printf(evb, "Error opening file");
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", evb);
        evbuffer_free(evb);
        return;
    }

    // 파일 크기 확인
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    // HTTP 응답 헤더 설정
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/octet-stream");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Disposition",
                      ("attachment; filename=\"" + decoded_name + "\"").c_str());
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Length", std::to_string(file_size).c_str());

    // 파일 내용 전송
    char buffer[8192]; // 8KB 버퍼
    while (file.read(buffer, sizeof(buffer)))
    {
        evbuffer_add(evb, buffer, file.gcount());
    }
    if (file.gcount() > 0)
    {
        evbuffer_add(evb, buffer, file.gcount());
    }

    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
    file.close();
}
void handle_delete_item(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();
    json response;

    try
    {
        json request_data = json::parse(body);

        if (!request_data.contains("path") || !request_data.contains("name"))
        {
            throw std::runtime_error("Missing 'path' or 'name' in request");
        }

        std::string path = request_data["path"];
        std::string name = request_data["name"];
        std::string root_path = UPLOAD_DIR; // 실제 루트 경로로 변경해야 합니다
        std::string full_path = root_path + path + name;

        // 보안 검사: path가 root_path 밖으로 나가지 않는지 확인
        if (full_path.substr(0, root_path.length()) != root_path)
        {
            throw std::runtime_error("Access denied: Path is outside of allowed directory");
        }

        if (fs::exists(full_path))
        {
            if (fs::is_directory(full_path))
            {
                fs::remove_all(full_path);
            }
            else
            {
                fs::remove(full_path);
            }
            response["success"] = true;
            response["message"] = "Item deleted successfully";
        }
        else
        {
            response["success"] = false;
            response["message"] = "Item not found";
        }
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = e.what();
    }

    evbuffer_add_printf(evb, "%s", response.dump().c_str());
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
void handle_rename_item(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();
    json response;

    try
    {
        json request_data = json::parse(body);

        if (!request_data.contains("path") || !request_data.contains("oldName") ||
            !request_data.contains("newName") || !request_data.contains("type"))
        {
            throw std::runtime_error("Missing required fields in request");
        }

        std::string path = request_data["path"];
        std::string old_name = request_data["oldName"];
        std::string new_name = request_data["newName"];
        std::string type = request_data["type"];
        std::string root_path = UPLOAD_DIR; // 실제 루트 경로로 변경해야 합니다
        std::string old_full_path = root_path + path + old_name;
        std::string new_full_path = root_path + path + new_name;

        // 보안 검사: path가 root_path 밖으로 나가지 않는지 확인
        if (old_full_path.substr(0, root_path.length()) != root_path ||
            new_full_path.substr(0, root_path.length()) != root_path)
        {
            throw std::runtime_error("Access denied: Path is outside of allowed directory");
        }

        // 파일/폴더 존재 여부 확인
        if (!fs::exists(old_full_path))
        {
            throw std::runtime_error("Item does not exist");
        }

        // 새 이름의 파일/폴더가 이미 존재하는지 확인
        if (fs::exists(new_full_path))
        {
            throw std::runtime_error("An item with the new name already exists");
        }

        // 이름 변경
        fs::rename(old_full_path, new_full_path);

        response["success"] = true;
        response["message"] = "Item renamed successfully";
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = e.what();
    }

    evbuffer_add_printf(evb, "%s", response.dump().c_str());
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
void handle_create_folder(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();
    json response;

    try
    {
        json request_data = json::parse(body);

        if (!request_data.contains("path") || !request_data.contains("name"))
        {
            throw std::runtime_error("Missing required fields in request");
        }

        std::string path = request_data["path"];
        std::string folder_name = request_data["name"];
        std::string root_path = UPLOAD_DIR; // 실제 루트 경로로 변경해야 합니다
        std::string full_path = root_path + path + folder_name;

        // 보안 검사: path가 root_path 밖으로 나가지 않는지 확인
        if (full_path.substr(0, root_path.length()) != root_path)
        {
            throw std::runtime_error("Access denied: Path is outside of allowed directory");
        }

        // 폴더가 이미 존재하는지 확인
        if (fs::exists(full_path))
        {
            throw std::runtime_error("A folder with this name already exists");
        }

        // 폴더 생성
        if (fs::create_directory(full_path))
        {
            response["success"] = true;
            response["message"] = "Folder created successfully";
        }
        else
        {
            throw std::runtime_error("Failed to create folder");
        }
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = e.what();
    }

    evbuffer_add_printf(evb, "%s", response.dump().c_str());
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
// 파일 크기를 가져오는 함수
std::string get_file_size(const std::string &file_path)
{
    struct stat file_status;
    if (stat(file_path.c_str(), &file_status) != 0)
    {
        return "Unknown";
    }

    off_t size = file_status.st_size;

    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size_in_units = static_cast<double>(size);

    while (size_in_units >= 1024 && unit_index < 4)
    {
        size_in_units /= 1024;
        unit_index++;
    }

    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << size_in_units << " " << units[unit_index];
    return ss.str();
}

// 파일 정보를 가져오는 엔드포인트
void handle_get_file_info(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
{
    struct evbuffer *buf = evbuffer_new();

    std::string file_path = "";
    size_t path_pos = query.find("path=");
    if (path_pos != std::string::npos)
    {
        file_path = query.substr(path_pos + 5);
        file_path = url_decode(file_path);
    }

    std::string full_path = UPLOAD_ROOT_DIR + file_path;

    // 보안 검사: 경로가 UPLOAD_ROOT_DIR 밖으로 나가지 않도록 확인
    // if (full_path.substr(0, strlen(UPLOAD_ROOT_DIR)) != UPLOAD_ROOT_DIR) {
    //     evbuffer_add_printf(buf, "{\"error\": \"Access is not allowed\"}");
    //     evhttp_send_reply(req, HTTP_FORBIDDEN, "Forbidden", buf);
    //     evbuffer_free(buf);
    //     return;
    // }

    std::string file_size = get_file_size(full_path);

    Json::Value response;
    response["size"] = file_size;

    Json::StreamWriterBuilder writer;
    std::string json_response = Json::writeString(writer, response);

    evbuffer_add(buf, json_response.c_str(), json_response.length());
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
void handle_get_categories(SSLInfo *ssl_info, struct evhttp_request *req)
{
    try
    {
        Json::Value categories = withConnection([](sql::Connection &conn)
                                                {
            Json::Value cats(Json::arrayValue);
            std::unique_ptr<sql::Statement> stmt(conn.createStatement());
            // std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT id, name FROM categories"));
            //is_active == true인 카테고리만 가져옴.
            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT id, name FROM categories WHERE is_active = TRUE"));
 
            while (res->next()) {
                Json::Value category;
                category["id"] = res->getInt("id");
                category["name"] = res->getString("name").c_str();
                cats.append(category);
            }
            return cats; });

        Json::StreamWriterBuilder writer;
        std::string json_response = Json::writeString(writer, categories);

        struct evbuffer *buf = evbuffer_new();
        if (buf == NULL)
        {
            evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
            return;
        }

        evbuffer_add(buf, json_response.c_str(), json_response.length());

        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
        evhttp_send_reply(req, HTTP_OK, "OK", buf);

        evbuffer_free(buf);
    }
    catch (const std::exception &e)
    {
        struct evbuffer *buf = evbuffer_new();
        if (buf == NULL)
        {
            evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
            return;
        }

        std::string error_message = "{\"error\":\"Internal Server Error\"}";
        evbuffer_add(buf, error_message.c_str(), error_message.length());

        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", buf);

        evbuffer_free(buf);
    }
}
void handle_edit_category(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *evb = evbuffer_new();
    json response;

    try
    {
        json request_data = json::parse(body);
        int category_id = request_data["id"].get<int>();
        std::string new_name = request_data["name"];

        bool success = withConnection([&](sql::Connection &conn)
                                      {
            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
                "UPDATE categories SET name = ? WHERE id = ?"));
            pstmt->setString(1, new_name);
            pstmt->setInt(2, category_id);
            int affected_rows = pstmt->executeUpdate();
            return affected_rows > 0; });

        if (success)
        {
            response["success"] = true;
            response["message"] = "Category updated successfully";
        }
        else
        {
            response["success"] = false;
            response["message"] = "Failed to update category";
        }
    }
    catch (const sql::SQLException &e)
    {
        response["success"] = false;
        response["message"] = "Database error: " + std::string(e.what());
    }
    catch (const json::exception &e)
    {
        response["success"] = false;
        response["message"] = "JSON parsing error: " + std::string(e.what());
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = "Unexpected error: " + std::string(e.what());
    }

    std::string json_response = response.dump();
    evbuffer_add(evb, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", evb);

    evbuffer_free(evb);
}
void handle_add_category(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();
    json response;

    try
    {
        json requestData = json::parse(body);
        std::string categoryName = requestData["name"];

        bool success = withConnection([&](sql::Connection &conn)
                                      {
            std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
                "INSERT INTO categories (name) VALUES (?)"));
            pstmt->setString(1, categoryName);
            return pstmt->executeUpdate() > 0; });

        if (success)
        {
            response["success"] = true;
            response["message"] = "Category added successfully";
        }
        else
        {
            response["success"] = false;
            response["message"] = "Failed to add category";
        }
    }
    catch (const sql::SQLException &e)
    {
        response["success"] = false;
        response["message"] = "Database error: " + std::string(e.what());
    }
    catch (const json::exception &e)
    {
        response["success"] = false;
        response["message"] = "JSON parsing error: " + std::string(e.what());
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = "Error: " + std::string(e.what());
    }

    std::string json_response = response.dump();
    evbuffer_add(buf, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
void handle_delete_category(SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
{
    struct evbuffer *buf = evbuffer_new();
    json response;

    try
    {
        const char *uri = evhttp_request_get_uri(req);
        struct evkeyvalq params;
        evhttp_parse_query(uri, &params);
        const char *id_str = evhttp_find_header(&params, "id");

        if (id_str == nullptr)
        {
            throw std::runtime_error("Category ID is missing");
        }

        int category_id = std::stoi(id_str);

        bool success = withConnection([&](sql::Connection &conn)
                                      {
            conn.setAutoCommit(false);
            std::unique_ptr<sql::PreparedStatement> checkPosts(conn.prepareStatement(
                "SELECT COUNT(*) FROM posts WHERE category = ?"));
            checkPosts->setInt(1, category_id);
            std::unique_ptr<sql::ResultSet> postCount(checkPosts->executeQuery());
            
            if (postCount->next() && postCount->getInt(1) > 0) {
                conn.rollback();
                response["success"] = false;
                response["message"] = "Cannot delete category: It contains posts";
                return false;
            }

            std::unique_ptr<sql::PreparedStatement> deleteCat(conn.prepareStatement(
                "DELETE FROM categories WHERE id = ?"));
            deleteCat->setInt(1, category_id);
            int affectedRows = deleteCat->executeUpdate();
            
            if (affectedRows > 0) {
                conn.commit();
                response["success"] = true;
                response["message"] = "Category deleted successfully";
                return true;
            } else {
                conn.rollback();
                response["success"] = false;
                response["message"] = "Category not found";
                return false;
            } });

        if (!success)
        {
            // response is already set in the lambda function
        }
    }
    catch (const sql::SQLException &e)
    {
        response["success"] = false;
        response["message"] = "Database error: " + std::string(e.what());
    }
    catch (const std::exception &e)
    {
        response["success"] = false;
        response["message"] = "Error: " + std::string(e.what());
    }

    std::string json_response = response.dump();
    evbuffer_add(buf, json_response.c_str(), json_response.length());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);

    evbuffer_free(buf);
}
// Callback function for CURL
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}
std::string request_kakao_access_token(const char* auth_code)
{
    CURL *curl;
    CURLcode res;
    std::string response_string;
    std::string post_fields = "grant_type=authorization_code&client_id=b8e35d5ad1b8a036ecbd7c862e4b5fad&redirect_uri=https://improved-zebra-wpw5q79q7wg3559r-8080.app.github.dev/kakao-oauth&code=";
    post_fields += auth_code;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://kauth.kakao.com/oauth/token");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    Json::Value root;
    Json::Reader reader;
    reader.parse(response_string, root);

    return root["access_token"].asString();
}

Json::Value request_kakao_user_info(const std::string& access_token)
{
    CURL *curl;
    CURLcode res;
    std::string response_string;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://kapi.kakao.com/v2/user/me");
        
        struct curl_slist *headers = NULL;
        std::string auth_header = "Authorization: Bearer " + access_token;
        headers = curl_slist_append(headers, auth_header.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    Json::Value root;
    Json::Reader reader;
    reader.parse(response_string, root);

    return root;
}

void handle_kakao_oauth(SSLInfo *ssl_info, struct evhttp_request *req)
{    
    const char *uri = evhttp_request_get_uri(req);
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);

    const char *code = evhttp_find_header(&params, "code");
    const char *state = evhttp_find_header(&params, "state");

    if (code == NULL) {
        // 에러 처리
        struct evbuffer *buf = evbuffer_new();
        evbuffer_add_printf(buf, "Authorization code is missing");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad Request", buf);
        evbuffer_free(buf);
        return;
    }

    // 여기서 인가 코드를 사용하여 액세스 토큰을 요청하고 사용자 정보를 가져옵니다.
    std::string access_token = request_kakao_access_token(code);
    if (access_token.empty()) {
        // 액세스 토큰 요청 실패 처리
        struct evbuffer *buf = evbuffer_new();
        evbuffer_add_printf(buf, "Failed to obtain access token");
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", buf);
        evbuffer_free(buf);
        return;
    }

    Json::Value user_info = request_kakao_user_info(access_token);
    if (user_info.empty()) {
        // 사용자 정보 요청 실패 처리
        struct evbuffer *buf = evbuffer_new();
        evbuffer_add_printf(buf, "Failed to obtain user info");
        evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", buf);
        evbuffer_free(buf);
        return;
    }

    // 사용자 정보를 처리하고 세션을 생성하거나 JWT 토큰을 발행합니다.
    std::string username = user_info["properties"]["nickname"].asString();
    std::string token = create_jwt(username, SECRET_KEY);

    // 클라이언트에게 응답을 보냅니다. 
    // 여기서는 JavaScript로 토큰을 로컬 스토리지에 저장하고 메인 페이지로 리다이렉트합니다.
    struct evbuffer *buf = evbuffer_new();
    evbuffer_add_printf(buf, 
        "<html><body>"
        "<script>"
        "localStorage.setItem('token', '%s');"
        "localStorage.setItem('username', '%s');"
        "window.location.href = '/index.html';"
        "</script>"
        "</body></html>",
        token.c_str(), username.c_str());

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/html");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

using StaticRouteHandler = std::function<void(SSLInfo *, struct evhttp_request *, const std::string &)>;
using GetRouteHandler = std::function<void(SSLInfo *, struct evhttp_request *)>;
using PostRouteHandler = std::function<void(SSLInfo *, struct evhttp_request *, const std::string &)>;
using QueryHandler = std::function<void(SSLInfo *, struct evhttp_request *, const std::string &)>;

std::unordered_map<std::string, GetRouteHandler> get_routes = {
    {"/usercount", [](SSLInfo *ssl_info, struct evhttp_request *req)
     { handle_user_count_request(ssl_info, req); }},
    {"/filelist", [](SSLInfo *ssl_info, struct evhttp_request *req)
     { handle_file_list_request(ssl_info, req); }},
    {"/categories", [](SSLInfo *ssl_info, struct evhttp_request *req)
     { handle_get_categories(ssl_info, req); }},
    {"/images", [](SSLInfo *ssl_info, struct evhttp_request *req)
     { handle_get_images(ssl_info, req); }},
         {"/kakao-oauth", [](SSLInfo *ssl_info, struct evhttp_request *req)
     { handle_kakao_oauth(ssl_info, req); }},
};

std::unordered_map<std::string, PostRouteHandler> post_routes = {
    {"/signup", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_signup(ssl_info, req, body); }},
    {"/login", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_login(ssl_info, req, body); }},
    {"/verify-token", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_verify_token(ssl_info, req, body); }},
    {"/check-username", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_check_username(ssl_info, req, body); }},
    {"/save_post", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { save_post(ssl_info, req, body); }},
    {"/delete_post", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_delete_post(ssl_info, req, body); }},
    {"/upload_image", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handleUploadImage(ssl_info, req, body); }},
    {"/upload_obj", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handleUploadObj(ssl_info, req, body); }},
    {"/upload_file", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handleUploadFiles(ssl_info, req, body); }},
    {"/add_comment", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_add_comment(ssl_info, req, body); }},
    {"/edit_comment", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_edit_comment(ssl_info, req, body); }},
    {"/delete_comment", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_delete_comment(ssl_info, req, body); }},
    {"/delete-item", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_delete_item(ssl_info, req, body); }},
    {"/rename-item", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_rename_item(ssl_info, req, body); }},
    {"/create-folder", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_create_folder(ssl_info, req, body); }},
    {"/edit-category", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     { handle_edit_category(ssl_info, req, body); }},
    {"/categories", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     {
         handle_add_category(ssl_info, req, body);
     }},
    {"/delete-category", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &body)
     {
         handle_delete_category(ssl_info, req, body);
     }},
};

std::unordered_map<std::string, QueryHandler> get_routes_with_query = {
    {"/comments", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
     { handle_get_comments(ssl_info, req, query); }},
    {"/drive-contents", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
     { handle_drive_contents(ssl_info, req, query); }},
    {"/get-file-info", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
     { handle_get_file_info(ssl_info, req, query); }},
    {"/posts", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
     { handle_get_posts(ssl_info, req, query); }},
    {"/download-file", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &query)
     { handle_download_file(ssl_info, req, query); }},
};
std::unordered_map<std::string, StaticRouteHandler> static_routes = {
    {"/asset", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &path)
     { send_uploads_file(ssl_info, req, path); }},
    {"/uploads", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &path)
     { send_uploads_file(ssl_info, req, path); }},
    {"/page", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &path)
     { send_uploads_file(ssl_info, req, path); }},
    {"/script", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &path)
     { send_uploads_file(ssl_info, req, path); }},
    {"/css", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &path)
     { send_uploads_file(ssl_info, req, path); }},
    {"/index.html", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &path)
     { send_uploads_file(ssl_info, req, path); }},
    // {"/kakao-redirect.html", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &path)
    //  { send_uploads_file(ssl_info, req, path); }},
    {"/image", [](SSLInfo *ssl_info, struct evhttp_request *req, const std::string &path)
     { send_uploads_file(ssl_info, req, path); }},
};

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
SSL_CTX *create_ssl_context()
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_chain_file(ctx, "/etc/letsencrypt/live/alsteam23.kro.kr/fullchain.pem") <= 0)
    {
        if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/letsencrypt/live/alsteam23.kro.kr/privkey.pem", SSL_FILETYPE_PEM) <= 0)
    {
        if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    return ctx;
}
void configure_context(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_chain_file(ctx, "/etc/letsencrypt/live/alsteam23.kro.kr/fullchain.pem") <= 0)
    {
        if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/letsencrypt/live/alsteam23.kro.kr/privkey.pem", SSL_FILETYPE_PEM) <= 0)
    {
        if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
}
const std::string PID_FILE = "./server.pid";

bool is_process_running(pid_t pid)
{
    return (kill(pid, 0) == 0);
}

void write_pid_file(pid_t pid)
{
    std::ofstream pid_file(PID_FILE);
    if (pid_file.is_open())
    {
        pid_file << pid;
        pid_file.close();
    }
    else
    {
        std::cerr << "Unable to create PID file" << std::endl;
    }
}

void remove_pid_file()
{
    if (std::remove(PID_FILE.c_str()) != 0)
    {
        std::cerr << "Error deleting PID file" << std::endl;
    }
}

void terminate_existing_server()
{
    std::ifstream pid_file(PID_FILE);
    if (pid_file.is_open())
    {
        pid_t pid;
        pid_file >> pid;
        pid_file.close();

        if (pid > 0 && is_process_running(pid))
        {
            std::cout << "Terminating existing server process (PID: " << pid << ")" << std::endl;
            kill(pid, SIGTERM);
            // Wait for the process to terminate
            sleep(2);
        }
    }
}
void log_error(const std::string &message)
{
    std::ofstream log_file("server_error.log", std::ios_base::app);
    if (log_file.is_open())
    {
        std::time_t now = std::time(nullptr);
        log_file << std::ctime(&now) << message << std::endl;
        log_file.close();
    }
    else
    {
        std::cerr << "Unable to open log file" << std::endl;
    }
    std::cerr << message << std::endl;
}

void setup_https_server(struct evhttp *https, SSL_CTX *ctx)
{
    evhttp_set_bevcb(https, https_bevcb, ctx);
}


void handle_request_cb(struct evhttp_request *req, void *arg)
{
    Router *router = static_cast<Router *>(arg);
    SSLInfo *ssl_info = nullptr; // SSL 정보가 필요한 경우 적절히 설정

    router->handleRequest(req, ssl_info);
}
int main()
{
    try
    {
        // 로그 파일 초기화
        g_logger.initialize("server.log", Logger::Level::DEBUG);
        g_logger.log(Logger::Level::INFO, "Server starting up...");

        // 데이터베이스 설정
        const char *db_host = std::getenv("DB_HOST");
        const char *db_port = std::getenv("DB_PORT");
        const char *db_user = std::getenv("DB_USER");
        const char *db_password = std::getenv("DB_PASSWORD");
        const char *db_name = std::getenv("DB_NAME");

        if (!db_host || !db_port || !db_user || !db_password || !db_name)
        {
            g_logger.log(Logger::Level::ERROR, "Database configuration not set in environment variables");
            throw std::runtime_error("Database configuration not set in environment variables");
        }
        std::string connection_string = "tcp://" + std::string(db_host) + ":" + std::string(db_port);

        connectionPool = std::make_unique<ConnectionPool>(
            10, connection_string, db_user, db_password, db_name);

        // 라우터 설정
        Router router;

        // GET 라우트 설정
        for (const auto &[path, handler] : get_routes)
        {
            router.addRoute(path, [handler](struct evhttp_request *req, SSLInfo *ssl_info)
                            { handler(ssl_info, req); }, EVHTTP_REQ_GET);
        }

        // POST 라우트 설정
        for (const auto &[path, handler] : post_routes)
        {
            router.addRoute(path, [handler](struct evhttp_request *req, SSLInfo *ssl_info)
                            {
                struct evbuffer *req_body = evhttp_request_get_input_buffer(req);
                size_t len = evbuffer_get_length(req_body);
                std::string body(len, 0);
                evbuffer_copyout(req_body, &body[0], len);
                handler(ssl_info, req, body); }, EVHTTP_REQ_POST);
        }
        // 쿼리 라우트 설정
        for (const auto &[path, handler] : get_routes_with_query)
        {
            router.addQueryRoute(path, [handler](struct evhttp_request *req, SSLInfo *ssl_info, const std::string &query)
                                 { handler(ssl_info, req, query); });
        }

        // 정적 라우트 설정
        for (const auto &[prefix, handler] : static_routes)
        {
            router.addStaticRoute(prefix, handler);
        }

        // SSL 설정
        SSL_library_init();
        SSL_load_error_strings();
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(create_ssl_context(), SSL_CTX_free);

        // Event base 설정
        std::unique_ptr<event_base, decltype(&event_base_free)> base(event_base_new(), event_base_free);
        if (!base)
        {
            throw std::runtime_error("Couldn't create an event_base");
        }

        // HTTP 서버 설정
        std::unique_ptr<evhttp, decltype(&evhttp_free)> http(evhttp_new(base.get()), evhttp_free);
        if (!http)
        {
            throw std::runtime_error("Couldn't create evhttp for HTTP");
        }

        // HTTPS 서버 설정
        std::unique_ptr<evhttp, decltype(&evhttp_free)> https(evhttp_new(base.get()), evhttp_free);
        if (!https)
        {
            throw std::runtime_error("Couldn't create evhttp for HTTPS");
        }

        std::unique_ptr<SSLInfo> ssl_info(new SSLInfo{ctx.get(), nullptr});

        // 콜백 설정
        evhttp_set_gencb(http.get(), handle_request_cb, &router);
        evhttp_set_gencb(https.get(), handle_request_cb, &router);

        // 서버 바인딩
        if (evhttp_bind_socket(http.get(), "0.0.0.0", HTTP_PORT) != 0)
        {
            g_logger.log(Logger::Level::ERROR, "Failed to bind HTTP server socket");
            throw std::runtime_error("Failed to bind HTTP server socket");
        }

        auto https_handle = evhttp_bind_socket_with_handle(https.get(), "0.0.0.0", HTTPS_PORT);
        if (!https_handle)
        {
            g_logger.log(Logger::Level::ERROR, "Failed to bind HTTPS server socket");
            throw std::runtime_error("Failed to bind HTTPS server socket");
        }
        evhttp_set_bevcb(https.get(), https_bevcb, ctx.get());

        g_logger.log(Logger::Level::INFO, "HTTP server running on port " + std::to_string(HTTP_PORT));
        g_logger.log(Logger::Level::INFO, "HTTPS server running on port " + std::to_string(HTTPS_PORT));

        event_base_dispatch(base.get());
        g_logger.log(Logger::Level::INFO, "Server shutting down...");

        return 0;
    }
    catch (const std::exception &e)
    {
        g_logger.log(Logger::Level::ERROR, "Fatal error: " + std::string(e.what()));
        return 1;
    }
}
