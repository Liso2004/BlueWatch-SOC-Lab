import pymysql
import bcrypt

# Connect to MySQL
conn = pymysql.connect(
    host='mysql',            # Docker service name
    user='root',
    password='Liso1707',
    database='banking',
    cursorclass=pymysql.cursors.DictCursor
)
cur = conn.cursor()

# Users to reset
users = ['admin', 'jdoe', 'analyst']
for username in users:
    # Generate bcrypt hash
    hashed_pw = bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt())
    cur.execute("UPDATE users SET password=%s WHERE username=%s", (hashed_pw.decode('utf-8'), username))
    print(f"{username} password reset.")

conn.commit()
conn.close()
print("All user passwords updated successfully!")
