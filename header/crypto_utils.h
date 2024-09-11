#pragma once

#include <string>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>

// Function to generate a random salt
inline std::string generate_salt(int length = 16)
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

// Function to hash a password with a salt
inline std::string hash_password(const std::string &password, const std::string &salt)
{
    std::string salted_password = salt + password;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salted_password.c_str(), salted_password.length());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}