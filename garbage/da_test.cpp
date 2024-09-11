#include <iostream>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

void printResultSet(sql::ResultSet *rs) {
    sql::ResultSetMetaData *res_meta = rs->getMetaData();
    int columns = res_meta->getColumnCount();

    for (int i = 1; i <= columns; i++) {
        std::cout << res_meta->getColumnName(i) << "\t";
    }
    std::cout << std::endl;

    while (rs->next()) {
        for (int i = 1; i <= columns; i++) {
            std::cout << rs->getString(i) << "\t";
        }
        std::cout << std::endl;
    }
}

int main() {
    const std::string server = "database-1.chkaiiwsimts.us-east-2.rds.amazonaws.com";
    const std::string username = "admin";
    const std::string password = "Yonghwan2161!";
    const std::string database = "app_db";

    try {
        sql::mysql::MySQL_Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;

        driver = sql::mysql::get_mysql_driver_instance();
        con = driver->connect(server, username, password);
        con->setSchema(database);

        stmt = con->createStatement();

        // USERS 테이블 데이터 확인
        res = stmt->executeQuery("SELECT * FROM USERS LIMIT 10");
        std::cout << "USERS Table:" << std::endl;
        printResultSet(res);
        delete res;

        // posts 테이블 데이터 확인
        res = stmt->executeQuery("SELECT * FROM posts LIMIT 10");
        std::cout << "\nposts Table:" << std::endl;
        printResultSet(res);
        delete res;

        // comments 테이블 데이터 확인
        res = stmt->executeQuery("SELECT * FROM comments LIMIT 10");
        std::cout << "\ncomments Table:" << std::endl;
        printResultSet(res);
        delete res;

        // 각 테이블의 레코드 수 확인
        res = stmt->executeQuery("SELECT COUNT(*) FROM USERS");
        res->next();
        std::cout << "\nTotal USERS: " << res->getInt(1) << std::endl;
        delete res;

        res = stmt->executeQuery("SELECT COUNT(*) FROM posts");
        res->next();
        std::cout << "Total posts: " << res->getInt(1) << std::endl;
        delete res;

        res = stmt->executeQuery("SELECT COUNT(*) FROM comments");
        res->next();
        std::cout << "Total comments: " << res->getInt(1) << std::endl;
        delete res;

        delete stmt;
        delete con;

    } catch (sql::SQLException &e) {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() << " )" << std::endl;
    }

    return 0;
}