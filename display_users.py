"""
User Database Debugging Tool

This script displays all users in the SQLite database,
and optionally allows deletion of a user by username.

"""

import Database

def show_all_users():
    """
    Prints all user records in the database.
    """
    with Database.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT username, salt, hashcode, role FROM users")
        rows = cur.fetchall()

        if rows:
            print("\n✅ Users in Database:\n")
            for username, salt, hashcode, role in rows:
                print(f"Username:     {username}")
                print(f"Salt:         {salt}")
                print(f"Hashcode:     {hashcode}")
                print(f"Role:         {role}")
                print("─" * 52)
        else:
            print("⚠️ No users found.")

def delete_user(username: str) -> bool:
    """
    Deletes a user by username from the database.

    Args:
        username (str): The username to delete.

    Returns:
        bool: True if deletion occurred, False otherwise.
    """
    with Database.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return cur.rowcount > 0

if __name__ == "__main__":
    show_all_users()

    response = input("\nWould you like to delete a user? (yes/no): ").strip().lower()
    if response == "yes":
        username = input("Enter the username to delete: ").strip()
        if delete_user(username):
            print(f"✅ User '{username}' has been removed from the database.")
        else:
            print(f"❌ User '{username}' was not found or could not be removed.")

        print("\n🔄 Updated User List:")
        show_all_users()
    else:
        print("🛑 No changes made.")
