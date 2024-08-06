#include <iostream>
#include <string>
#include <vector>
#include <sqlite3.h>
#include <mysql_driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <mysql_connection.h>
#include <mysql_driver.h>

void create_mysql_tables(sql::Connection *con)
{
    if (con == nullptr)
    {
        throw std::runtime_error("Database connection is null");
    }

    try
    {
        std::unique_ptr<sql::Statement> stmt(con->createStatement());

        // Users 테이블 생성
        stmt->execute("CREATE TABLE IF NOT EXISTS USERS ("
                      "ID INTEGER PRIMARY KEY AUTO_INCREMENT, "
                      "USERNAME VARCHAR(255) NOT NULL UNIQUE, "
                      "PASSWORD VARCHAR(255) NOT NULL, "
                      "SALT VARCHAR(255))");

        // Posts 테이블 생성
        stmt->execute("CREATE TABLE IF NOT EXISTS posts ("
                      "id INTEGER PRIMARY KEY AUTO_INCREMENT, "
                      "title VARCHAR(255) NOT NULL, "
                      "content TEXT NOT NULL, "
                      "author VARCHAR(255) NOT NULL, "
                      "timestamp DATETIME NOT NULL, "
                      "category VARCHAR(255) NOT NULL)");

        // Comments 테이블 생성
        stmt->execute("CREATE TABLE IF NOT EXISTS comments ("
                      "id INTEGER PRIMARY KEY AUTO_INCREMENT, "
                      "post_id INTEGER NOT NULL, "
                      "author VARCHAR(255) NOT NULL, "
                      "content TEXT NOT NULL, "
                      "timestamp DATETIME NOT NULL, "
                      "FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE)");

        std::cout << "Tables created successfully." << std::endl;
    }
    catch (sql::SQLException &e)
    {
        std::cerr << "SQL Exception: " << e.what() << std::endl;
        std::cerr << "MySQL error code: " << e.getErrorCode() << std::endl;
        std::cerr << "SQLState: " << e.getSQLState() << std::endl;
        throw;
    }
}

void migrate_data(sqlite3 *sqlite_db, sql::Connection *mysql_con, const std::string &table_name)
{
    sqlite3_stmt *stmt;
    std::string query = "SELECT * FROM " + table_name;

    if (sqlite3_prepare_v2(sqlite_db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    {
        std::cerr << "Failed to prepare SQLite statement: " << sqlite3_errmsg(sqlite_db) << std::endl;
        return;
    }

    std::vector<std::string> columns;
    int column_count = sqlite3_column_count(stmt);
    for (int i = 0; i < column_count; i++)
    {
        columns.push_back(sqlite3_column_name(stmt, i));
    }

    std::string insert_query = "INSERT INTO " + table_name + " (";
    for (size_t i = 0; i < columns.size(); i++)
    {
        insert_query += "`" + columns[i] + "`";
        if (i < columns.size() - 1)
            insert_query += ", ";
    }
    insert_query += ") VALUES (";
    for (size_t i = 0; i < columns.size(); i++)
    {
        insert_query += "?";
        if (i < columns.size() - 1)
            insert_query += ", ";
    }
    insert_query += ")";

    sql::PreparedStatement *pstat = mysql_con->prepareStatement(insert_query);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        for (int i = 0; i < column_count; i++)
        {
            switch (sqlite3_column_type(stmt, i))
            {
            case SQLITE_INTEGER:
                pstat->setInt(i + 1, sqlite3_column_int(stmt, i));
                break;
            case SQLITE_FLOAT:
                pstat->setDouble(i + 1, sqlite3_column_double(stmt, i));
                break;
            case SQLITE_TEXT:
                pstat->setString(i + 1, reinterpret_cast<const char *>(sqlite3_column_text(stmt, i)));
                break;
            case SQLITE_NULL:
                pstat->setNull(i + 1, sql::DataType::VARCHAR);
                break;
            default:
                std::cerr << "Unsupported SQLite data type" << std::endl;
                break;
            }
        }
        pstat->execute();
    }

    sqlite3_finalize(stmt);
    delete pstat;
}

int main()
{
    sqlite3 *sqlite_db;
    // sql::Driver *driver;
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *mysql_con;

    try
    {
        // SQLite connection
        if (sqlite3_open("users.db", &sqlite_db) != SQLITE_OK)
        {
            std::cerr << "Failed to open SQLite database: " << sqlite3_errmsg(sqlite_db) << std::endl;
            return 1;
        }

        // MySQL connection￦
        driver = sql::mysql::get_mysql_driver_instance();
        // driver = get_driver_instance();
        // mysql_con = driver->connect("database-1.chkaiiwsimts.us-east-2.rds.amazonaws.com:3306", "admin", "Yonghwan2161!");
        // mysql_con->setSchema("database-1");
        try
        {

            sql::Statement *stmt;
            mysql_con = driver->connect("tcp://database-1.chkaiiwsimts.us-east-2.rds.amazonaws.com:3306", "admin", "Yonghwan2161!");
            // mysql_con->setSchema("database-1");
            std::cout << "Successfully connected to MySQL database." << std::endl;
            // 방법 2: 새 데이터베이스 생성 및 사용
            stmt = mysql_con->createStatement();
            stmt->execute("CREATE DATABASE IF NOT EXISTS app_db");
            mysql_con->setSchema("app_db");
            std::cout << "Created and connected to 'app_db' database." << std::endl;

            // 여기에 데이터베이스 작업 코드를 추가하세요.
            // Create MySQL tables
            create_mysql_tables(mysql_con);
            delete stmt;
        }
        catch (sql::SQLException &e)
        {
            std::cerr << "SQL Exception: " << e.what() << std::endl;
            std::cerr << "MySQL error code: " << e.getErrorCode() << std::endl;
            std::cerr << "SQLState: " << e.getSQLState() << std::endl;
        }
        catch (std::runtime_error &e)
        {
            std::cerr << e.what() << std::endl;
        }

        // Migrate data
        std::vector<std::string> tables = {"USERS", "posts", "comments"};
        for (const auto &table : tables)
        {
            std::cout << "Migrating " << table << " table..." << std::endl;
            migrate_data(sqlite_db, mysql_con, table);
            std::cout << table << " table migration completed." << std::endl;
        }

        std::cout << "All data migration completed successfully." << std::endl;
    }
    catch (sql::SQLException &e)
    {
        std::cerr << "MySQL Error: " << e.what() << std::endl;
        return 1;
    }
    catch (std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    // Close connections
    sqlite3_close(sqlite_db);
    delete mysql_con;

    return 0;
}