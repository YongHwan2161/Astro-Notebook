#pragma once

#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <cppconn/driver.h>
#include <cppconn/connection.h>

class ConnectionPool {
private:
    std::vector<std::unique_ptr<sql::Connection>> connections;
    std::mutex mutex;
    std::condition_variable cv;
    size_t pool_size;
    std::string server, username, password, database;
    sql::Driver *driver;

    std::unique_ptr<sql::Connection> createConnection();

public:
    ConnectionPool(size_t size, const std::string &server, const std::string &username,
                   const std::string &password, const std::string &database);

    std::unique_ptr<sql::Connection> getConnection();
    void releaseConnection(std::unique_ptr<sql::Connection> conn);
};

extern std::unique_ptr<ConnectionPool> connectionPool;

sql::Connection* get_connection();

void init_database();

template <typename Func>
auto withConnection(Func f) -> decltype(f(std::declval<sql::Connection&>()))
{
    auto conn = connectionPool->getConnection();
    try
    {
        if constexpr (std::is_void_v<decltype(f(*conn))>)
        {
            f(*conn);
            connectionPool->releaseConnection(std::move(conn));
        }
        else
        {
            auto result = f(*conn);
            connectionPool->releaseConnection(std::move(conn));
            return result;
        }
    }
    catch (...)
    {
        connectionPool->releaseConnection(std::move(conn));
        throw;
    }
}

// 기타 데이터베이스 관련 함수 선언
void migrate_passwords();
std::vector<std::string> extract_unique_categories();
void insert_categories(const std::vector<std::string> &categories);
void update_posts_table();
void migrate_categories();