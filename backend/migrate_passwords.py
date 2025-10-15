#!/usr/bin/env python3
"""
Password Migration Script for Church Planner
This script will hash any plain text passwords in your database
"""

import mysql.connector
import bcrypt

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'church_planner_v2'
}

def migrate_passwords():
    """Migrate plain text passwords to bcrypt hashes"""
    try:
        # Connect to database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Get all users
        cursor.execute("SELECT id, email, password FROM users")
        users = cursor.fetchall()
        
        updated_count = 0
        
        for user_id, email, stored_password in users:
            # Convert bytes to string if needed
            if isinstance(stored_password, bytes):
                stored_password = stored_password.decode('utf-8')
            
            # Check if password is already hashed (bcrypt format)
            if not stored_password.startswith(('$2a$', '$2b$', '$2x$', '$2y$')):
                # It's plain text, hash it
                hashed_password = bcrypt.hashpw(stored_password.encode('utf-8'), bcrypt.gensalt())
                
                # Update the database
                cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
                updated_count += 1
                print(f"✓ Updated password for user: {email}")
            else:
                print(f"- Password already hashed for user: {email}")
        
        # Commit changes
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"\n✅ Migration completed successfully!")
        print(f"Updated {updated_count} passwords")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False
    
    return True

def create_default_superadmin():
    """Create a default superadmin user if none exists"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Check if superadmin exists
        cursor.execute("SELECT id FROM users WHERE role = 'superadmin'")
        if cursor.fetchone():
            print("✓ Superadmin user already exists")
            cursor.close()
            conn.close()
            return
        
        # Create default superadmin
        email = "admin@church.com"
        password = "admin123"  # Change this!
        name = "Super Admin"
        role = "superadmin"
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        cursor.execute("""
            INSERT INTO users (email, password, name, role) 
            VALUES (%s, %s, %s, %s)
        """, (email, hashed_password, name, role))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"✅ Created default superadmin user:")
        print(f"   Email: {email}")
        print(f"   Password: {password}")
        print(f"   ⚠️  IMPORTANT: Change this password after first login!")
        
    except Exception as e:
        print(f"❌ Failed to create superadmin: {e}")

if __name__ == "__main__":
    print("🔄 Starting password migration...")
    print("=" * 50)
    
    # Run migration
    if migrate_passwords():
        print("\n" + "=" * 50)
        print("🔄 Checking for superadmin user...")
        create_default_superadmin()
        print("\n✅ All done! You can now use the login system.")
    else:
        print("\n❌ Migration failed. Please check your database connection and try again.")