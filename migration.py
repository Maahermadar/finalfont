import sqlite3
import psycopg2

# 1. Connect to SQLite
sqlite_conn = sqlite3.connect('sec_videos.db')
sqlite_cursor = sqlite_conn.cursor()

# 2. Connect to Supabase PostgreSQL
pg_conn = psycopg2.connect(
    dbname='postgres',
    user='postgres',
    password='Maahir..,,11',  # <-- replace with your real password
    host='db.ollcvfshxrzbwhmuvrju.supabase.co',
    port='5432'
)
pg_cursor = pg_conn.cursor()

# 3. Define tables and fields
tables = {
    'editor': ['id', 'name', 'profile_picture'],
    'editor_handoff': ['id', 'subject', 'episode', 'editor_id', 'progress', 'date_assigned', 'chapter'],
    'raw_video': ['id', 'subject', 'chapter', 'episode', 'date', 'status', 'editor_id'],
    'subject': ['id', 'name'],
    '"user"': ['id', 'is_admin', 'username', 'password'],  # Quotes because 'user' is reserved word
    'video': ['id', 'subject', 'chapter', 'episode', 'status', 'date', 'file_path', 'editor_id']
}

# 4. Migrate data
for table_name, columns in tables.items():
    print(f"Migrating table {table_name}...")
    sqlite_cursor.execute(f"SELECT {', '.join(columns)} FROM {table_name.strip('\"')}")
    rows = sqlite_cursor.fetchall()

    for row in rows:
        placeholders = ', '.join(['%s'] * len(columns))
        insert_query = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"
        pg_cursor.execute(insert_query, row)

    pg_conn.commit()
    print(f"Table {table_name} migrated successfully!")

# 5. Close connections
sqlite_conn.close()
pg_conn.close()

print("✅ Migration completed successfully!")


