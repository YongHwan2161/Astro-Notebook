#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <openssl/sha.h>
#include <signal.h>
#include <errno.h> // errno 사용을 위해
#include <unordered_map>
#include <sqlite3.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <map>

const int PORT = 8080;
const int BUFFER_SIZE = 2048;
// 사용자 데이터를 저장할 간단한 해시맵
std::unordered_map<std::string, std::string> user_data;
// SQLite 데이터베이스 연결 객체
sqlite3 *db;
const std::string UPLOAD_DIR = "uploads/";

const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

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
    return base64_encode(reinterpret_cast<const unsigned char *>(hash.c_str()), hash.size());
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

    int sent_bytes = send(client_socket, response.c_str(), response.size(), 0);
    if (sent_bytes < 0)
    {
        perror("send failed");
    }

    // Ensure all data is sent before closing
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
void init_database() {
    int rc = sqlite3_open("users.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    } else {
        std::cout << "Opened database successfully" << std::endl;
    }

    const char* sql_create_users_table =
        "CREATE TABLE IF NOT EXISTS USERS ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "USERNAME TEXT NOT NULL, "
        "PASSWORD TEXT NOT NULL);";

    const char* sql_create_posts_table =
        "CREATE TABLE IF NOT EXISTS posts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "title TEXT NOT NULL, "
        "content TEXT NOT NULL, "
        "author TEXT NOT NULL);";

    char* err_msg = nullptr;

    rc = sqlite3_exec(db, sql_create_users_table, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        sqlite3_close(db);
        exit(1);
    } else {
        std::cout << "Users table created successfully" << std::endl;
    }

    rc = sqlite3_exec(db, sql_create_posts_table, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        sqlite3_close(db);
        exit(1);
    } else {
        std::cout << "Posts table created successfully" << std::endl;
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

// 로그인 요청을 처리하는 함수
void handle_login(int client_socket, const std::string &body)
{
    auto params = parse_urlencoded(body);
    if (params.find("username") != params.end() && params.find("password") != params.end())
    {
        std::string username = params["username"];
        std::string password = params["password"];

        if (verify_user(username, password))
        {
            std::string response_body = "Login successful";
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
            std::string response_body = "Login failed";
            std::string response = "HTTP/1.1 401 Unauthorized\r\n"
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
// Function to save the post to the database
void savePost(const std::string& title, const std::string& content, const std::string& author) {
    sqlite3* db;
    sqlite3_stmt* stmt;

    int rc = sqlite3_open("posts.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    const char* sql = "INSERT INTO posts (title, content, author) VALUES (?, ?, ?);";

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, title.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, content.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, author.c_str(), -1, SQLITE_STATIC);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            std::cerr << "Execution failed: " << sqlite3_errmsg(db) << std::endl;
        }
    } else {
        std::cerr << "Preparation failed: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// JSON 파싱 함수
std::map<std::string, std::string> parse_json(const std::string& json_str) {
    std::map<std::string, std::string> json_map;
    std::string key, value;
    bool in_key = false, in_value = false;
    bool is_escaped = false;
    
    for (size_t i = 0; i < json_str.length(); ++i) {
        char c = json_str[i];

        if (c == '\\' && !is_escaped) {
            is_escaped = true;
            continue;
        }

        if (c == '"' && !is_escaped) {
            if (in_key) {
                in_key = false;
            } else if (in_value) {
                in_value = false;
                json_map[key] = value;
                key.clear();
                value.clear();
            } else {
                if (key.empty()) {
                    in_key = true;
                } else {
                    in_value = true;
                }
            }
            is_escaped = false;
            continue;
        }

        if (in_key) {
            key += c;
        } else if (in_value) {
            value += c;
        }

        is_escaped = false;
    }

    return json_map;
}
void start_server()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

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

        std::thread([client_socket]()
                    {
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
                } else if (request.find("POST /signup") != std::string::npos) {
                    // Extract the body of the POST request
                    size_t body_start = request.find("\r\n\r\n");
                    if (body_start != std::string::npos) {
                        body_start += 4;
                        std::string body = request.substr(body_start);
                        handle_signup(client_socket, body);
                    } else {
                        std::cerr << "No body found in the POST request" << std::endl;
                    }
                } else if (request.find("POST /login") != std::string::npos) {
                    // Extract the body of the POST request
                    size_t body_start = request.find("\r\n\r\n");
                    if (body_start != std::string::npos) {
                        body_start += 4;
                        std::string body = request.substr(body_start);
                        handle_login(client_socket, body);
                    } else {
                        std::cerr << "No body found in the POST request" << std::endl;
                    }
                } else if (request.find("POST /check-username") != std::string::npos) {
                    // Extract the body of the POST request
                    size_t body_start = request.find("\r\n\r\n");
                    if (body_start != std::string::npos) {
                        body_start += 4;
                        std::string body = request.substr(body_start);
                        handle_check_username(client_socket, body);
                    } else {
                        std::cerr << "No body found in the POST request" << std::endl;
                    }
                } else if (request.find("GET /usercount") != std::string::npos) {
                    handle_user_count_request(client_socket);
                } else if (request.find("POST /upload") != std::string::npos) {
                    size_t boundary_pos = request.find("boundary=");
                    if (boundary_pos != std::string::npos) {
                        std::string boundary = request.substr(boundary_pos + 9);
        boundary = "--" + boundary;
                        handle_file_upload(client_socket, boundary, bytes_received);
                    } else {
                        std::cerr << "Boundary not found in the POST request" << std::endl;
                    }
                }  else if (request.find("GET /download") != std::string::npos) {
    size_t filename_pos = request.find("filename=");
    if (filename_pos != std::string::npos) {
        filename_pos += 9;
        size_t filename_end = request.find(' ', filename_pos);
        std::string filename = request.substr(filename_pos, filename_end - filename_pos);
        handle_file_download(client_socket, filename);
    } else {
        std::cerr << "Filename not found in the GET request" << std::endl;
    }
} else if (request.find("GET /filelist") != std::string::npos) {
                    handle_file_list_request(client_socket); 
                } else if (request.find("GET /images/") != std::string::npos) {
        size_t start_pos = request.find("GET /images/") + 5;
        size_t end_pos = request.find(" ", start_pos);
        std::string image_path = request.substr(start_pos, end_pos - start_pos);
        send_image(client_socket, image_path);
    } else if (request.find("GET /assets/js") != std::string::npos) {
        size_t start_pos = request.find("GET /assets/js") + 5;
        size_t end_pos = request.find(" ", start_pos);
        std::string js_path = request.substr(start_pos, end_pos - start_pos);
        send_js(client_socket, js_path);
    } else if (request.find("GET /assets/css") != std::string::npos) {
        size_t start_pos = request.find("GET /assets/css") + 5;
        size_t end_pos = request.find(" ", start_pos);
        std::string css_path = request.substr(start_pos, end_pos - start_pos);
        send_css(client_socket, css_path);
    } else if (request.find("GET /assets/fonts/") != std::string::npos) {
        size_t start_pos = request.find("GET /assets/fonts/") + 5;
        size_t end_pos = request.find(" ", start_pos);
        std::string font_path = request.substr(start_pos, end_pos - start_pos);
        // Remove the version query parameter if present
        size_t query_pos = font_path.find("?");
        if (query_pos != std::string::npos) {
            font_path = font_path.substr(0, query_pos);
        }
        std::string extension = font_path.substr(font_path.find_last_of("."));
        std::string content_type = get_font_content_type(extension);
        send_font(client_socket, font_path, content_type);
    } else if (request.find("GET /assets/html/generic.html") != std::string::npos) {
        send_html(client_socket, "assets/html/generic.html");
    } else if (request.find("GET /assets/html/elements.html") != std::string::npos) {
        send_html(client_socket, "assets/html/elements.html");
    } else if (request.find("GET /assets/html/starMap.html") != std::string::npos) {
        send_html(client_socket, "assets/html/starMap.html");
    } else if (request.find("GET /assets/html/edit.html") != std::string::npos) {
        send_html(client_socket, "assets/html/edit.html");
    } else {
                    send_html(client_socket, "assets/html/index.html");
                }
            } })
            .detach();
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
