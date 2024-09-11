#include "database.h"
#include "crypto_utils.h"
#include <stdexcept>
#include <iostream>
#include <cppconn/prepared_statement.h>
#include <cppconn/exception.h>

std::unique_ptr<ConnectionPool> connectionPool;

ConnectionPool::ConnectionPool(size_t size, const std::string &server, const std::string &username,
                               const std::string &password, const std::string &database)
    : pool_size(size), server(server), username(username), password(password), database(database)
{
    driver = get_driver_instance();
    for (size_t i = 0; i < pool_size; ++i)
    {
        connections.push_back(createConnection());
    }
}

std::unique_ptr<sql::Connection> ConnectionPool::createConnection()
{
    std::unique_ptr<sql::Connection> conn(driver->connect(server, username, password));
    conn->setSchema(database);
    return conn;
}

std::unique_ptr<sql::Connection> ConnectionPool::getConnection()
{
    std::unique_lock<std::mutex> lock(mutex);
    while (connections.empty())
    {
        cv.wait(lock);
    }
    auto conn = std::move(connections.back());
    connections.pop_back();
    return conn;
}

void ConnectionPool::releaseConnection(std::unique_ptr<sql::Connection> conn)
{
    std::unique_lock<std::mutex> lock(mutex);
    connections.push_back(std::move(conn));
    lock.unlock();
    cv.notify_one();
}

sql::Connection* get_connection()
{
    try
    {
        return connectionPool->getConnection().release();
    }
    catch (sql::SQLException &e)
    {
        std::cerr << "SQL Exception: " << e.what() << std::endl;
        return nullptr;
    }
}

// 데이터베이스 초기화 함수
void init_database()
{
    const char *db_host = std::getenv("DB_HOST");
    const char *db_port = std::getenv("DB_PORT");
    const char *db_user = std::getenv("DB_USER");
    const char *db_password = std::getenv("DB_PASSWORD");
    const char *db_name = std::getenv("DB_NAME");

    if (!db_host || !db_port || !db_user || !db_password || !db_name)
    {
        throw std::runtime_error("Database configuration not set in environment variables");
    }

    std::string connection_string = "tcp://" + std::string(db_host) + ":" + std::string(db_port);

    connectionPool = std::make_unique<ConnectionPool>(
        10, connection_string, db_user, db_password, db_name);
    sql::Connection *con = get_connection();
    if (!con)
    {
        std::cerr << "Failed to connect to database" << std::endl;
        exit(1);
    }

    try
    {
        sql::Statement *stmt = con->createStatement();

        stmt->execute("CREATE TABLE IF NOT EXISTS USERS ("
                      "ID INT AUTO_INCREMENT PRIMARY KEY, "
                      "USERNAME VARCHAR(255) NOT NULL UNIQUE, "
                      "PASSWORD VARCHAR(255) NOT NULL, "
                      "SALT VARCHAR(255))");

        stmt->execute("CREATE TABLE IF NOT EXISTS posts ("
                      "id INT AUTO_INCREMENT PRIMARY KEY, "
                      "title VARCHAR(255) NOT NULL, "
                      "content TEXT NOT NULL, "
                      "author VARCHAR(255) NOT NULL, "
                      "timestamp DATETIME NOT NULL,"
                      "category VARCHAR(255) NOT NULL DEFAULT 'Uncategorized')");

        stmt->execute("CREATE TABLE IF NOT EXISTS comments ("
                      "id INT AUTO_INCREMENT PRIMARY KEY, "
                      "post_id INT NOT NULL, "
                      "author VARCHAR(255) NOT NULL, "
                      "content TEXT NOT NULL, "
                      "timestamp DATETIME NOT NULL, "
                      "FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE)");

        stmt->execute("CREATE TABLE IF NOT EXISTS categories ("
                      "id INT AUTO_INCREMENT PRIMARY KEY, "
                      "name VARCHAR(255) NOT NULL UNIQUE)");

        // Check if is_active column exists in categories table
        std::unique_ptr<sql::ResultSet> res2(stmt->executeQuery(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_NAME = 'categories' AND COLUMN_NAME = 'is_active'"));

        if (res2->next() && res2->getInt(1) == 0)
        {
            // is_active column doesn't exist, so add it
            stmt->execute("ALTER TABLE categories ADD COLUMN is_active BOOLEAN DEFAULT TRUE");
            std::cout << "Added 'is_active' column to categories table." << std::endl;
        }
        else
        {
            std::cout << "'is_active' column already exists in categories table." << std::endl;
        }

        // Check if 'timestamp' column exists in posts table
        sql::ResultSet *res = stmt->executeQuery("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
                                                 "WHERE TABLE_NAME = 'posts' AND COLUMN_NAME = 'timestamp'");
        res->next();
        bool timestamp_exists = res->getInt(1) > 0;

        // Add 'timestamp' column if it does not exist
        if (!timestamp_exists)
        {
            stmt->execute("ALTER TABLE posts ADD COLUMN timestamp DATETIME");
        }

        // Check if we need to migrate passwords
        res = stmt->executeQuery("SELECT COUNT(*) FROM USERS WHERE SALT IS NULL");
        res->next();
        int count = res->getInt(1);
        delete res;

        if (count > 0)
        {
            std::cout << "Migrating " << count << " password(s) to new hashing scheme..." << std::endl;
            migrate_passwords(); // You'll need to implement this function for MySQL
        }

        // 카테고리 테이블이 비어있는지 확인
        bool categories_empty = false;
        withConnection([&categories_empty](sql::Connection &conn)
                       {
        std::unique_ptr<sql::Statement> stmt(conn.createStatement());
        std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT COUNT(*) FROM categories"));
        if (res->next() && res->getInt(1) == 0) {
            categories_empty = true;
        } });

        // 카테고리 테이블이 비어있다면 마이그레이션 실행
        if (categories_empty)
        {
            std::cout << "Migrating categories from posts table..." << std::endl;
            migrate_categories();
        }

        delete stmt;
        delete con;

        std::cout << "Database initialization completed." << std::endl;
    }
    catch (sql::SQLException &e)
    {
        std::cerr << "SQL Exception: " << e.what() << std::endl;
        delete con;
        exit(1);
    }
}

void migrate_passwords()
{
    try
    {
        withConnection([](sql::Connection &con)
                       {
            // Select users with null salt
            std::unique_ptr<sql::PreparedStatement> select_pstmt(con.prepareStatement(
                "SELECT ID, USERNAME, PASSWORD FROM USERS WHERE SALT IS NULL"));
            std::unique_ptr<sql::ResultSet> select_res(select_pstmt->executeQuery());

            // Prepare update statement
            std::unique_ptr<sql::PreparedStatement> update_pstmt(con.prepareStatement(
                "UPDATE USERS SET PASSWORD = ?, SALT = ? WHERE ID = ?"));

            while (select_res->next())
            {
                int id = select_res->getInt("ID");
                std::string username = select_res->getString("USERNAME");
                std::string old_password = select_res->getString("PASSWORD");

                std::string salt = generate_salt();
                std::string hashed_password = hash_password(old_password, salt);

                update_pstmt->setString(1, hashed_password);
                update_pstmt->setString(2, salt);
                update_pstmt->setInt(3, id);

                int affected_rows = update_pstmt->executeUpdate();

                if (affected_rows == 1)
                {
                    std::cout << "Successfully migrated password for user " << username << std::endl;
                }
                else
                {
                    std::cerr << "Failed to update password for user " << username << std::endl;
                }
            }

            std::cout << "Password migration completed." << std::endl; });
    }
    catch (const sql::SQLException &e)
    {
        std::cerr << "SQL Exception: " << e.what() << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}


std::vector<std::string> extract_unique_categories()
{
    std::vector<std::string> categories;

    withConnection([&categories](sql::Connection &conn)
                   {
        std::unique_ptr<sql::Statement> stmt(conn.createStatement());
        std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT DISTINCT category FROM posts"));
        
        while (res->next()) {
            categories.push_back(res->getString("category"));
        } });

    return categories;
}

void insert_categories(const std::vector<std::string> &categories)
{
    withConnection([&categories](sql::Connection &conn)
                   {
        std::unique_ptr<sql::PreparedStatement> pstmt(conn.prepareStatement(
            "INSERT IGNORE INTO categories (name) VALUES (?)"));
        
        for (const auto& category : categories) {
            pstmt->setString(1, category);
            pstmt->executeUpdate();
        } });
}
void update_posts_table()
{
    withConnection([](sql::Connection &conn)
                   {
        std::unique_ptr<sql::Statement> stmt(conn.createStatement());
        
        // 임시 컬럼 추가
        stmt->execute("ALTER TABLE posts ADD COLUMN category_id INT");
        
        // category_id 업데이트
        stmt->execute("UPDATE posts p JOIN categories c ON p.category = c.name "
                      "SET p.category_id = c.id");
        
        // 기존 category 컬럼 삭제
        stmt->execute("ALTER TABLE posts DROP COLUMN category");
        
        // category_id 컬럼 이름 변경
        stmt->execute("ALTER TABLE posts CHANGE category_id category INT");
        
        // 외래 키 제약 조건 추가
        stmt->execute("ALTER TABLE posts ADD CONSTRAINT fk_category "
                      "FOREIGN KEY (category) REFERENCES categories(id)"); });
}

void migrate_categories()
{
    try
    {
        std::vector<std::string> categories = extract_unique_categories();
        insert_categories(categories);
        update_posts_table();
        std::cout << "Category migration completed successfully." << std::endl;
    }
    catch (const sql::SQLException &e)
    {
        std::cerr << "SQL Exception: " << e.what() << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
// Implement other database-related functions as needed