"""
Injector for 'badpasswords.txt' into the SQLite database.

Each time this script runs:
- The 'bad_passwords' table is cleared.
- The contents of 'badpasswords.txt' are reloaded from scratch.

"""

import Database


def clear_bad_passwords_table():
    """
    Removes all existing entries from the bad_passwords table.
    """
    with Database.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM bad_passwords")
        conn.commit()


if __name__ == "__main__":
    Database.init_db()
    clear_bad_passwords_table()
    Database.load_bad_passwords("badpasswords.txt")
    print("✅ Bad passwords table reset and reloaded successfully.")
