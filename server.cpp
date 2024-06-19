#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <signal.h>
#include <errno.h> // errno 사용을 위해
#include <unordered_map>
#include <sqlite3.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <map>
#include <json/json.h>
#include <algorithm>
#include <functional>
#include <regex>
#include <random>

const int PORT = 35500;
const int BUFFER_SIZE = 2048;
// 사용자 데이터를 저장할 간단한 해시맵
std::unordered_map<std::string, std::string> user_data;
// SQLite 데이터베이스 연결 객체
sqlite3 *db;
const std::string UPLOAD_DIR = "uploads/";
const std::string UPLOAD_IMAGE_DIR = "images/";

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

void send_html(int client_socket, const std::string &file_path)
{
    std::string html_content = read_file(file_path);
    if (html_content.empty())
    {
        std::cerr << "Failed to read " << file_path << std::endl;
        close(client_socket);
        return;
    }

    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html\r\n"
                           "Content-Length: " +
                           std::to_string(html_content.size()) + "\r\n"
                                                                 "Connection: close\r\n\r\n" +
                           html_content;

    // const char *response_ptr = response.c_str();
    // size_t total_bytes_sent = 0;
    // size_t response_size = response.size();
    int sent_bytes = send(client_socket, response.c_str(), response.size(), 0);
    if (sent_bytes < 0)
    {
        perror("send failed");
    }
    // while (total_bytes_sent < response_size)
    // {
    //     ssize_t sent_bytes = send(client_socket, response_ptr + total_bytes_sent, response_size - total_bytes_sent, 0);
    //     if (sent_bytes < 0)
    //     {
    //         if (errno == EPIPE || errno == ECONNRESET)
    //         {
    //             // Broken pipe or connection reset by peer
    //             perror("send failed");
    //             std::cerr << "Error code: " << errno << ", Message: " << strerror(errno) << std::endl;
    //             break;
    //         }
    //         perror("send failed");
    //         std::cerr << "Error code: " << errno << ", Message: " << strerror(errno) << std::endl;
    //     }
    //     else
    //     {
    //         total_bytes_sent += sent_bytes;
    //     }
    // }

    shutdown(client_socket, SHUT_RDWR);
    close(client_socket);
}

void handle_websocket_connection(int client_socket, const std::string &client_key)
{
    std::string accept_key = generate_websocket_accept_key(client_key);
    std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: " +
                           accept_key + "\r\n\r\n";
    send(client_socket, response.c_str(), response.size(), 0);

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        std::string message = "Server message";
        std::vector<char> ws_frame;

        // Create WebSocket frame
        ws_frame.push_back(0x81);           // FIN and text frame
        ws_frame.push_back(message.size()); // No mask, payload length

        ws_frame.insert(ws_frame.end(), message.begin(), message.end());
        int sent_bytes = send(client_socket, ws_frame.data(), ws_frame.size(), 0);
        if (sent_bytes < 0)
        {
            perror("send failed");
            break; // Exit the loop if sending fails
        }
    }
    close(client_socket);
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
// 데이터베이스 초기화 함수
void init_database()
{
    int rc = sqlite3_open("users.db", &db);
    if (rc)
    {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    else
    {
        std::cout << "Opened database successfully" << std::endl;
    }

    const char *sql_create_users_table =
        "CREATE TABLE IF NOT EXISTS USERS ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "USERNAME TEXT NOT NULL, "
        "PASSWORD TEXT NOT NULL);";

    const char *sql_create_posts_table =
        "CREATE TABLE IF NOT EXISTS posts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "title TEXT NOT NULL, "
        "content TEXT NOT NULL, "
        "author TEXT NOT NULL, "
        "timestamp TEXT NOT NULL);";

    char *err_msg = nullptr;

    rc = sqlite3_exec(db, sql_create_users_table, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        sqlite3_close(db);
        exit(1);
    }
    else
    {
        std::cout << "Users table created successfully" << std::endl;
    }

    rc = sqlite3_exec(db, sql_create_posts_table, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        sqlite3_close(db);
        exit(1);
    }
    else
    {
        std::cout << "Posts table created successfully" << std::endl;
    }

    // Check if 'timestamp' column exists
    std::string sql_check_column = "PRAGMA table_info(posts);";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql_check_column.c_str(), -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        exit(EXIT_FAILURE);
    }

    bool timestamp_exists = false;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        std::string column_name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        if (column_name == "timestamp")
        {
            timestamp_exists = true;
            break;
        }
    }
    sqlite3_finalize(stmt);
    char *error_message = 0;
    // Add 'timestamp' column if it does not exist
    if (!timestamp_exists)
    {
        std::string sql_add_column = "ALTER TABLE posts ADD COLUMN timestamp TEXT;";
        rc = sqlite3_exec(db, sql_add_column.c_str(), 0, 0, &error_message);
        if (rc != SQLITE_OK)
        {
            std::cerr << "SQL error (add column): " << error_message << std::endl;
            sqlite3_free(error_message);
            exit(EXIT_FAILURE);
        }
    }
}
// 회원가입 요청을 처리하는 함수
void handle_signup(int client_socket, const std::string &body)
{
    auto params = parse_urlencoded(body);
    if (params.find("username") != params.end() && params.find("password") != params.end())
    {
        std::string username = params["username"];
        std::string password = params["password"];

        // 데이터베이스에 사용자 데이터를 저장
        const char *sql_insert = "INSERT INTO USERS (USERNAME, PASSWORD) VALUES (?, ?);";
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, 0);
        if (rc == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);

            rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE)
            {
                std::string response_body = "Signup successful";
                std::string response = "HTTP/1.1 200 OK\r\n"
                                       "Content-Type: text/plain\r\n"
                                       "Content-Length: " +
                                       std::to_string(response_body.size()) + "\r\n"
                                                                              "Connection: close\r\n\r\n" +
                                       response_body;
                send(client_socket, response.c_str(), response.size(), 0);
            }
            else
            {
                std::string response_body = "Signup failed (DB error)";
                std::string response = "HTTP/1.1 500 Internal Server Error\r\n"
                                       "Content-Type: text/plain\r\n"
                                       "Content-Length: " +
                                       std::to_string(response_body.size()) + "\r\n"
                                                                              "Connection: close\r\n\r\n" +
                                       response_body;
                send(client_socket, response.c_str(), response.size(), 0);
            }
        }
        else
        {
            std::string response_body = "Signup failed (DB error)";
            std::string response = "HTTP/1.1 500 Internal Server Error\r\n"
                                   "Content-Type: text/plain\r\n"
                                   "Content-Length: " +
                                   std::to_string(response_body.size()) + "\r\n"
                                                                          "Connection: close\r\n\r\n" +
                                   response_body;
            send(client_socket, response.c_str(), response.size(), 0);
        }
        sqlite3_finalize(stmt);
    }
    else
    {
        std::string response_body = "Bad Request";
        std::string response = "HTTP/1.1 400 Bad Request\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: " +
                               std::to_string(response_body.size()) + "\r\n"
                                                                      "Connection: close\r\n\r\n" +
                               response_body;
        send(client_socket, response.c_str(), response.size(), 0);
    }
    close(client_socket);
}

// 사용자 정보를 데이터베이스에서 확인하는 함수
bool verify_user(const std::string &username, const std::string &password)
{
    const char *sql_select = "SELECT PASSWORD FROM USERS WHERE USERNAME = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        std::string stored_password = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        return stored_password == password;
    }

    sqlite3_finalize(stmt);
    return false;
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
void handle_login(int client_socket, const std::string &body)
{
    auto params = parse_urlencoded(body);
    if (params.find("username") != params.end() && params.find("password") != params.end())
    {
        std::string username = params["username"];
        std::string password = params["password"];
        std::ostringstream response;
        if (verify_user(username, password))
        {
            std::string token = create_jwt(username, SECRET_KEY);
            std::string response_body = "Login successful";
            // std::string response = "HTTP/1.1 200 OK\r\n"
            //                        "Content-Type: text/plain\r\n"
            //                        "Content-Length: " +
            //                        std::to_string(response_body.size()) + "\r\n"
            //                                                               "Connection: close\r\n\r\n" +
            //                        response_body;

            response << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                     << "{\"success\": true, \"token\": \"" << token << "\"}";
            // send(client_socket, response.c_str(), response.size(), 0);
        }
        else
        {
            // std::string response_body = "Login failed";
            // std::string response = "HTTP/1.1 401 Unauthorized\r\n"
            //                        "Content-Type: text/plain\r\n"
            //                        "Content-Length: " +
            //                        std::to_string(response_body.size()) + "\r\n"
            //                                                               "Connection: close\r\n\r\n" +
            //                        response_body;
            response << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                     << "{\"success\": false}";
        }

        send(client_socket, response.str().c_str(), response.str().length(), 0);
    }
    else
    {
        std::string response_body = "Bad Request";
        std::string response = "HTTP/1.1 400 Bad Request\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: " +
                               std::to_string(response_body.size()) + "\r\n"
                                                                      "Connection: close\r\n\r\n" +
                               response_body;
        send(client_socket, response.c_str(), response.size(), 0);
    }
    close(client_socket);
}

// 사용자 이름이 데이터베이스에 있는지 확인하는 함수
bool is_username_taken(const std::string &username)
{
    const char *sql_select = "SELECT COUNT(*) FROM USERS WHERE USERNAME = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        int count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return count > 0;
    }

    sqlite3_finalize(stmt);
    return false;
}

// 아이디 중복 확인 요청을 처리하는 함수
void handle_check_username(int client_socket, const std::string &body)
{
    auto params = parse_urlencoded(body);
    if (params.find("username") != params.end())
    {
        std::string username = params["username"];

        if (is_username_taken(username))
        {
            std::string response_body = "Username is taken";
            std::string response = "HTTP/1.1 200 OK\r\n"
                                   "Content-Type: text/plain\r\n"
                                   "Content-Length: " +
                                   std::to_string(response_body.size()) + "\r\n"
                                                                          "Connection: close\r\n\r\n" +
                                   response_body;
            send(client_socket, response.c_str(), response.size(), 0);
        }
        else
        {
            std::string response_body = "Username is available";
            std::string response = "HTTP/1.1 200 OK\r\n"
                                   "Content-Type: text/plain\r\n"
                                   "Content-Length: " +
                                   std::to_string(response_body.size()) + "\r\n"
                                                                          "Connection: close\r\n\r\n" +
                                   response_body;
            send(client_socket, response.c_str(), response.size(), 0);
        }
    }
    else
    {
        std::string response_body = "Bad Request";
        std::string response = "HTTP/1.1 400 Bad Request\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: " +
                               std::to_string(response_body.size()) + "\r\n"
                                                                      "Connection: close\r\n\r\n" +
                               response_body;
        send(client_socket, response.c_str(), response.size(), 0);
    }
    close(client_socket);
}
// 사용자 수를 데이터베이스에서 가져오는 함수
int get_user_count()
{
    const char *sql_count = "SELECT COUNT(*) FROM USERS;";
    sqlite3_stmt *stmt;
    int user_count = 0;
    int rc = sqlite3_prepare_v2(db, sql_count, -1, &stmt, 0);
    if (rc == SQLITE_OK)
    {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            user_count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    else
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }
    return user_count;
}
// 사용자 수 요청을 처리하는 함수
void handle_user_count_request(int client_socket)
{
    int user_count = get_user_count();
    std::string response_body = std::to_string(user_count);
    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: " +
                           std::to_string(response_body.size()) + "\r\n"
                                                                  "Connection: close\r\n\r\n" +
                           response_body;
    send(client_socket, response.c_str(), response.size(), 0);
    close(client_socket);
}
// 파일 업로드 요청을 처리하는 함수
void handle_file_upload(int client_socket, const std::string &boundary, int bytes_received)
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

    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: 7\r\n"
                           "Connection: close\r\n\r\n"
                           "Success";
    send(client_socket, response.c_str(), response.size(), 0);
    close(client_socket);
}
// 파일 다운로드 요청을 처리하는 함수
void handle_file_download(int client_socket, const std::string &filename)
{
    std::ifstream infile(UPLOAD_DIR + filename, std::ios::binary);
    if (!infile)
    {
        std::string response = "HTTP/1.1 404 Not Found\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: 9\r\n"
                               "Connection: close\r\n\r\n"
                               "Not Found";
        send(client_socket, response.c_str(), response.size(), 0);
    }
    else
    {
        infile.seekg(0, std::ios::end);
        size_t file_size = infile.tellg();
        infile.seekg(0, std::ios::beg);

        std::string response = "HTTP/1.1 200 OK\r\n"
                               "Content-Type: application/octet-stream\r\n"
                               "Content-Length: " +
                               std::to_string(file_size) + "\r\n"
                                                           "Content-Disposition: attachment; filename=\"" +
                               filename + "\"\r\n"
                                          "Connection: close\r\n\r\n";
        send(client_socket, response.c_str(), response.size(), 0);

        char buffer[BUFFER_SIZE];
        while (infile.read(buffer, BUFFER_SIZE))
        {
            send(client_socket, buffer, BUFFER_SIZE, 0);
        }
        send(client_socket, buffer, infile.gcount(), 0);
    }

    infile.close();
    close(client_socket);
}
// 파일 목록 요청을 처리하는 함수
void handle_file_list_request(int client_socket)
{
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

    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < files.size(); ++i)
    {
        ss << "\"" << files[i] << "\"";
        if (i != files.size() - 1)
        {
            ss << ",";
        }
    }
    ss << "]";

    std::string response_body = ss.str();
    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Content-Length: " +
                           std::to_string(response_body.size()) + "\r\n"
                                                                  "Connection: close\r\n\r\n" +
                           response_body;
    send(client_socket, response.c_str(), response.size(), 0);
    close(client_socket);
}
void send_image(int client_socket, const std::string &file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::string not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                         "Content-Type: text/plain\r\n"
                                         "Content-Length: 13\r\n"
                                         "Connection: close\r\n\r\n"
                                         "404 Not Found";
        send(client_socket, not_found_response.c_str(), not_found_response.size(), 0);
        return;
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    std::string file_content = oss.str();

    std::string header = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "Content-Length: " +
                         std::to_string(file_content.size()) + "\r\n"
                                                               "Connection: close\r\n\r\n";
    send(client_socket, header.c_str(), header.size(), 0);
    send(client_socket, file_content.c_str(), file_content.size(), 0);

    file.close();
}
void send_js(int client_socket, const std::string &file_path)
{
    std::ifstream file(file_path);
    if (!file)
    {
        std::string not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                         "Content-Type: text/plain\r\n"
                                         "Content-Length: 13\r\n"
                                         "Connection: close\r\n\r\n"
                                         "404 Not Found";
        send(client_socket, not_found_response.c_str(), not_found_response.size(), 0);
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
    send(client_socket, header.c_str(), header.size(), 0);
    send(client_socket, file_content.c_str(), file_content.size(), 0);

    file.close();
}
void send_css(int client_socket, const std::string &file_path)
{
    std::ifstream file(file_path);
    if (!file)
    {
        std::string not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                         "Content-Type: text/plain\r\n"
                                         "Content-Length: 13\r\n"
                                         "Connection: close\r\n\r\n"
                                         "404 Not Found";
        send(client_socket, not_found_response.c_str(), not_found_response.size(), 0);
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
    send(client_socket, header.c_str(), header.size(), 0);
    send(client_socket, file_content.c_str(), file_content.size(), 0);

    file.close();
}
void send_font(int client_socket, const std::string &file_path, const std::string &content_type)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
    {
        std::string not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                         "Content-Type: text/plain\r\n"
                                         "Content-Length: 13\r\n"
                                         "Connection: close\r\n\r\n"
                                         "404 Not Found";
        send(client_socket, not_found_response.c_str(), not_found_response.size(), 0);
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
    send(client_socket, header.c_str(), header.size(), 0);
    send(client_socket, file_content.c_str(), file_content.size(), 0);

    file.close();
}
std::string get_font_content_type(const std::string &file_extension)
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
    return "application/octet-stream";
}
// JSON 파싱 함수
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
void handle_verify_token(int client_socket, const std::string &body)
{
    auto params = parse_urlencoded(body);

    std::string token = params.at("token");
    std::string username;
    std::ostringstream response;
    if (verify_jwt(token, SECRET_KEY, username))
    {
        response << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                 << "{\"success\": true, \"username\": \"" << username << "\"}";
    }
    else
    {
        response << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                 << "{\"success\": false}";
    }
    std::cerr << response.str() << std::endl;
    send(client_socket, response.str().c_str(), response.str().length(), 0);
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
// std::string process_content_and_save_images(const std::string &content, const std::string &output_path)
// {
//     std::regex base64_regex(R"(data/[^;]+;base64,([^>]+))");
//     std::string processed_content = content;
//     std::smatch match;
//     std::string::const_iterator searchStart(processed_content.cbegin());
//     while (std::regex_search(searchStart, processed_content.cend(), match, base64_regex))
//     {
//         std::string base64_data = match[1].str();
//         std::string file_path = save_image(base64_data, output_path);

//         std::string quoted_file_path = file_path + "\"";
//         // Replace the base64 data with the file path in processed_content
//         processed_content.replace(match.position(0), match.length(0), quoted_file_path);

//         // Update searchStart to continue searching after the replacement
//         searchStart = processed_content.begin() + match.position(0) + quoted_file_path.length();
//     }

//     return processed_content;
// }

// Function to process content and save images
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
// Function to process content and save images
// std::string process_content_and_save_images(const std::string &content, const std::string &output_path)
// {
//     std::regex base64_regex(R"(data:image\/([^;]+);base64,([^>]+))");
//     std::string processed_content = content;
//     std::smatch match;
//     std::string::const_iterator searchStart(processed_content.cbegin());

//     while (std::regex_search(searchStart, processed_content.cend(), match, base64_regex))
//     {
//         std::string extension = match[1].str();   // Extract image extension
//         std::string base64_data = match[2].str(); // Extract base64 data
//         std::string file_path = save_image(base64_data, output_path, extension);

//         // Create the replacement string with the file path
//         std::string quoted_file_path = file_path + "\"";

//         // Replace the base64 data with the file path in processed_content
//         processed_content.replace(match.position(0), match.length(0), quoted_file_path);

//         // Update searchStart to continue searching after the replacement
//         searchStart = processed_content.begin() + match.position(0) + quoted_file_path.length();
//     }

//     return processed_content;
// }
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
void save_post(int client_socket, const std::string &body)
{
    std::cout << "Received request body: " << body << std::endl; // 디버그 로그 추가

    Json::Value postData;
    Json::CharReaderBuilder reader;
    std::string errs;
    std::istringstream s(body);
    if (!Json::parseFromStream(reader, s, &postData, &errs))
    {
        std::cerr << "Failed to parse JSON: " << errs << std::endl;
        std::string response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    std::string title = postData["title"].asString();
    std::string content = postData["content"].asString();
    std::string author = postData["author"].asString();
    std::string timestamp = postData["timestamp"].asString();
    // Process the content and save images
    std::string output_path = "./images/"; // Ensure this directory exists and is writable
    std::string processed_content = process_content_and_save_images(content, output_path);

    sqlite3_stmt *stmt;
    std::string sql = "INSERT INTO posts (title, content, author, timestamp) VALUES (?, ?, ?, ?);";

    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        std::string response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    sqlite3_bind_text(stmt, 1, title.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, processed_content.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, author.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, timestamp.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db) << std::endl;
        std::string response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        sqlite3_finalize(stmt);
        return;
    }

    sqlite3_finalize(stmt);

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\": true}";
    std::cerr << "save_post success!" << std::endl;
    send(client_socket, response.c_str(), response.length(), 0);
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

void handle_get_posts(int client_socket)
{
    std::string sql = "SELECT id, title, content, author, timestamp FROM posts;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        std::string response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    Json::Value posts(Json::arrayValue);
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        Json::Value post;
        post["id"] = sqlite3_column_int(stmt, 0);
        post["title"] = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        post["content"] = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        post["author"] = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        post["timestamp"] = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
        posts.append(post);
    }
    sqlite3_finalize(stmt);

    Json::StreamWriterBuilder writer;
    // Adjust the Json::StreamWriterBuilder settings
    writer.settings_["indentation"] = "";             // No indentation
    writer.settings_["emitUTF8"] = true;              // Use UTF-8 encoding
    writer.settings_["escapeForwardSlashes"] = false; // Do not escape forward slashes

    std::string json_response = Json::writeString(writer, posts);
    // Replace \\\" with \"
    // replace_all(json_response, "\\\"", "\"");

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json_response;
    send(client_socket, response.c_str(), response.length(), 0);
}
void handle_delete_post(int client_socket, const std::string &request_body)
{
    Json::Value postData;
    Json::CharReaderBuilder reader;
    std::string errs;
    std::istringstream s(request_body);
    if (!Json::parseFromStream(reader, s, &postData, &errs))
    {
        std::cerr << "Failed to parse JSON: " << errs << std::endl;
        std::string response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    int post_id = postData["id"].asInt();
    std::string username = postData["username"].asString();

    sqlite3_stmt *stmt;
    std::string sql = "SELECT author FROM posts WHERE id = ?;";

    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        std::string response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    sqlite3_bind_int(stmt, 1, post_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW)
    {
        std::cerr << "Post not found: " << sqlite3_errmsg(db) << std::endl;
        std::string response = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        sqlite3_finalize(stmt);
        return;
    }

    std::string author = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);

    if (author != username)
    {
        std::cerr << "Unauthorized delete attempt by user: " << username << std::endl;
        std::string response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    sql = "DELETE FROM posts WHERE id = ?;";
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        std::string response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    sqlite3_bind_int(stmt, 1, post_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db) << std::endl;
        std::string response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"success\": false}";
        send(client_socket, response.c_str(), response.length(), 0);
        sqlite3_finalize(stmt);
        return;
    }

    sqlite3_finalize(stmt);

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\": true}";
    send(client_socket, response.c_str(), response.length(), 0);
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
void handleUploadImage(int client_socket, const std::string &request_body)
{
    // Parse the multipart data to extract the file content and filename
    std::string filename;
    std::string file_content = parseMultipartData(request_body, filename);

    if (filename.empty() || file_content.empty())
    {
        std::string response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_socket, response.c_str(), response.length(), 0);
        close(client_socket);
        return;
    }

    // Save the file to the upload folder
    std::string filepath = UPLOAD_IMAGE_DIR + filename;
    std::ofstream outfile(filepath, std::ios::binary);
    outfile.write(file_content.c_str(), file_content.size());
    outfile.close();

    // Send the response with the file URL
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Type: text/plain\r\n\r\n";
    response += "images/" + filename;
    send(client_socket, response.c_str(), response.length(), 0);

    close(client_socket);
}
std::unordered_map<std::string, std::function<void(int)>> get_routes = {
    {"/ws", [](int client_socket)
     {
         // Handle WebSocket connection
         // Extract Sec-WebSocket-Key and call handle_websocket_connection
     }},
    {"/usercount", handle_user_count_request},
    {"/filelist", handle_file_list_request},
    {"/posts", handle_get_posts},
    // Add other GET routes here
};

std::unordered_map<std::string, std::function<void(int, const std::string &)>> post_routes = {
    {"/signup", handle_signup},
    {"/login", handle_login},
    {"/verify-token", handle_verify_token},
    {"/check-username", handle_check_username},
    {"/save_post", save_post},
    {"/delete_post", handle_delete_post},
    {"upload_image", handleUploadImage},
    // Add other POST routes here
};

std::unordered_map<std::string, std::function<void(int, const std::string &)>> static_routes = {
    {"/images", send_image},
    {"/assets/js", send_js},
    {"/assets/css", send_css},
    // {"/assets/html/generic.html", send_html},
    {"/assets/html/elements.html", send_html},
    {"/assets/html/starMap.html", send_html},
    {"/assets/html/edit.html", send_html},
    {"/assets/html/index.html", send_html},
};

void handle_request(int client_socket, const std::string &request)
{
    std::istringstream request_stream(request);
    std::string method, path, version;
    request_stream >> method >> path >> version;

    if (method == "GET")
    {
        auto route = get_routes.find(path);
        if (route != get_routes.end())
        {
            route->second(client_socket);
        }
        else
        {
            // Check static routes
            for (const auto &entry : static_routes)
            {
                if (path.find(entry.first) == 0)
                {
                    entry.second(client_socket, path.substr(1));
                    return;
                }
            }
            // Special case for fonts
            if (path.find("/assets/fonts/") == 0)
            {
                std::string font_path = path.substr(1); // Remove leading '/'
                size_t query_pos = font_path.find("?");
                if (query_pos != std::string::npos)
                {
                    font_path = font_path.substr(0, query_pos);
                }
                std::string extension = font_path.substr(font_path.find_last_of("."));
                std::string content_type = get_font_content_type(extension);
                send_font(client_socket, font_path, content_type);
            }
            else
            {
                // Default route
                send_html(client_socket, "assets/html/index.html");
            }
            // Default route
            send_html(client_socket, "assets/html/index.html");
        }
    }
    else if (method == "POST")
    {
        size_t body_start = request.find("\r\n\r\n");
        if (body_start != std::string::npos)
        {
            body_start += 4;
            std::string body = request.substr(body_start);
            auto route = post_routes.find(path);
            if (route != post_routes.end())
            {
                route->second(client_socket, body);
            }
            else
            {
                std::cerr << "No route found for POST request to " << path << std::endl;
            }
        }
        else
        {
            std::cerr << "No body found in the POST request" << std::endl;
        }
    }
}
// void handle_client(int client_socket)
// {
//     char buffer[BUFFER_SIZE];
//     int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);

//     if (bytes_received > 0)
//     {
//         buffer[bytes_received] = '\0';
//         std::string request(buffer);
//         handle_request(client_socket, request);
//     }
//     if (bytes_received < 0)
//     {
//         perror("read failed");
//         close(client_socket);
//         return;
//     }
//     close(client_socket);
// }
void handle_client(int client_socket)
{
    std::vector<char> buffer(BUFFER_SIZE);
    std::string request;
    int bytes_received;

    while ((bytes_received = recv(client_socket, buffer.data(), buffer.size(), 0)) > 0)
    {
        request.append(buffer.data(), bytes_received);
        // Check if the full request has been received (i.e., we have received all the headers)
        if (request.find("\r\n\r\n") != std::string::npos)
        {
            break;
        }
    }

    if (bytes_received < 0)
    {
        perror("recv failed");
        close(client_socket);
        return;
    }

    // Extract Content-Length
    size_t content_length_pos = request.find("Content-Length:");
    if (content_length_pos != std::string::npos)
    {
        content_length_pos += 15; // Move past "Content-Length:"
        size_t end_pos = request.find("\r\n", content_length_pos);
        int content_length = std::stoi(request.substr(content_length_pos, end_pos - content_length_pos));

        // Read the body if it is not completely read yet
        size_t header_end_pos = request.find("\r\n\r\n");
        if (request.size() - (header_end_pos + 4) < content_length)
        {
            size_t bytes_remaining = content_length - (request.size() - (header_end_pos + 4));
            while (bytes_remaining > 0 && (bytes_received = recv(client_socket, buffer.data(), buffer.size(), 0)) > 0)
            {
                request.append(buffer.data(), bytes_received);
                bytes_remaining -= bytes_received;
            }

            if (bytes_received < 0)
            {
                perror("recv failed");
                close(client_socket);
                return;
            }
        }
    }

    handle_request(client_socket, request);
    close(client_socket);
}

void start_server()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Create socket file descriptor
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    // SO_REUSEADDR 옵션 설정
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 3) < 0)
    {
        perror("listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server started on port " << PORT << std::endl;

    while (true)
    {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0)
        {
            perror("accept");
            continue;
        }
        else
        {

            std::thread(handle_client, client_socket).detach();
        }
    }
}

int main()
{
    // SIGPIPE 시그널 무시
    signal(SIGPIPE, SIG_IGN);
    // 데이터베이스 초기화
    init_database();
    // 업로드 디렉토리 생성
    mkdir(UPLOAD_DIR.c_str(), 0777);

    start_server();

    sqlite3_close(db); // 서버 종료 시 데이터베이스 연결 닫기
    return 0;
}
