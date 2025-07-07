import sqlite3
import csv

# Connect to your SQLite database
conn = sqlite3.connect('sec_videos.db')
cursor = conn.cursor()

# Define tables to export
tables = [
    'editor',
    'editor_handoff',
    'raw_video',
    'subject',
    'user',
    'video'
]

# Export each table
for table in tables:
    cursor.execute(f"SELECT * FROM {table}")
    rows = cursor.fetchall()

    # Get column names
    column_names = [description[0] for description in cursor.description]

    # Write to CSV
    with open(f"{table}.csv", 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(column_names)  # Write header
        writer.writerows(rows)         # Write data

    print(f"✅ Exported {table} to {table}.csv")

# Close connection
conn.close()
print("✅✅ All tables exported successfully!")
