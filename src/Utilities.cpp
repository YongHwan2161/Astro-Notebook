// #include "Utilities.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <fstream>
#include <string.h>
#include <openssl/rand.h>

// Base64 인코딩 테이블
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
std::string generate_salt(int length = 16)
{
    unsigned char salt[length];
    RAND_bytes(salt, length);
    std::stringstream ss;
    for (int i = 0; i < length; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }
    return ss.str();
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
