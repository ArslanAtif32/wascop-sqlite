import sqlite3

DB_PATH =r"D:\WAScope\data\wascope.sqlite3"


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Show how many requests were captured for each method
print("\n===== REQUEST METHODS =====")

cursor.execute("""
    SELECT method, COUNT(*)
    FROM request_record
    GROUP BY method
""")

for row in cursor.fetchall():
    print(row)

# Display every POST request
print("\n===== ALL POST REQUESTS =====")

cursor.execute("""
    SELECT id, method, url, content_type, post_params
    FROM request_record
    WHERE UPPER(TRIM(method)) = 'POST'
""")

rows = cursor.fetchall()

if rows:
    for row in rows:
        print("\nRequest ID:", row[0])
        print("Method:", row[1])
        print("URL:", row[2])
        print("Content Type:", row[3])
        print("POST Parameters:", row[4])
        print("-" * 60)
else:
    print("No POST requests found.")

# Display all captured URLs
print("\n===== ALL CAPTURED URLS =====")

cursor.execute("""
    SELECT id, method, url
    FROM request_record
""")

for row in cursor.fetchall():
    print(row)

conn.close()