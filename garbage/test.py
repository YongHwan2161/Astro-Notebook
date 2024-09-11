import sqlite3
import mysql.connector
from mysql.connector import Error

def create_mysql_tables(mysql_cursor):
    # Users 테이블 생성
    mysql_cursor.execute("""
    CREATE TABLE IF NOT EXISTS USERS (
        ID INTEGER PRIMARY KEY AUTO_INCREMENT,
        USERNAME TEXT NOT NULL UNIQUE,
        PASSWORD TEXT NOT NULL,
        SALT TEXT
    )
    """)

    # Posts 테이블 생성
    mysql_cursor.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        author TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL
    )
    """)

    # Comments 테이블 생성
    mysql_cursor.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        post_id INTEGER NOT NULL,
        author TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    )
    """)

def migrate_data(sqlite_cursor, mysql_cursor, table_name):
    sqlite_cursor.execute(f"SELECT * FROM {table_name}")
    rows = sqlite_cursor.fetchall()
    
    for row in rows:
        placeholders = ', '.join(['%s'] * len(row))
        columns = ', '.join(f"`{column[0]}`" for column in sqlite_cursor.description)
        sql = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
        mysql_cursor.execute(sql, row)

def main():
    # SQLite 연결
    sqlite_conn = sqlite3.connect('users.db')
    sqlite_cursor = sqlite_conn.cursor()

    try:
        # MySQL 연결
        mysql_conn = mysql.connector.connect(
            host="database-1.chkaiiwsimts.us-east-2.rds.amazonaws.com",
            user="admin",
            password="Yonghwan2161!",
            database="database-1"
        )
        mysql_cursor = mysql_conn.cursor()

        # MySQL 테이블 생성
        create_mysql_tables(mysql_cursor)

        # 데이터 마이그레이션
        tables = ['USERS', 'posts', 'comments']
        for table in tables:
            print(f"Migrating {table} table...")
            migrate_data(sqlite_cursor, mysql_cursor, table)
            print(f"{table} table migration completed.")

        # 변경사항 커밋
        mysql_conn.commit()
        print("All data migration completed successfully.")

    except Error as e:
        print(f"Error: {e}")
        mysql_conn.rollback()
    finally:
        # 연결 종료
        if sqlite_conn:
            sqlite_conn.close()
        if mysql_conn and mysql_conn.is_connected():
            mysql_cursor.close()
            mysql_conn.close()
        print("Database connections closed.")

if __name__ == "__main__":
    main()
