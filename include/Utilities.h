#ifndef UTILITIES_H
#define UTILITIES_H

#include <string>
#include <vector>

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
std::string base64_url_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
std::string base64_decode(const char* encoded_string, unsigned int in_len);
std::vector<unsigned char> base64_decode_uchar(const std::string& encoded_string);
std::string base64_url_decode(const std::string& input);
std::string urlDecode(const std::string& encoded);
std::string url_decode(const std::string& encoded);
std::string sha1(const std::string& str);
std::string generate_salt(int length = 16);
std::string generate_websocket_accept_key(const std::string& client_key);
std::string read_file(const std::string& file_path);

#endif