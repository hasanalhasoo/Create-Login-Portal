"""
Unit tests for the Password module (database-backed).

Tests include:
- Password policy checks
- Weak password detection
- Hashing consistency
- Database user operations

This test suite assumes a clean test environment.
"""

import unittest
import Password as p
import Database as db


class TestPasswordModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Initializes the test database and inserts test bad passwords.
        """
        db.init_db()
        # Add a known bad password to the database for testing
        db.load_bad_passwords("badpasswords.txt")

    def setUp(self):
        """
        Clears the users table before each test to ensure test isolation.
        """
        with db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM users")
            conn.commit()

    def test_check_uppercase(self):
        self.assertFalse(p.check_uppercase("test"))
        self.assertTrue(p.check_uppercase("TEST"))
        self.assertTrue(p.check_uppercase("tesT"))
        self.assertFalse(p.check_uppercase("123"))

    def test_check_lowercase(self):
        self.assertTrue(p.check_lowercase("TESt"))
        self.assertFalse(p.check_lowercase("NOLOWER1@"))

    def test_check_numericals(self):
        self.assertFalse(p.check_numericals("test"))
        self.assertTrue(p.check_numericals("test1"))

    def test_check_specials(self):
        self.assertFalse(p.check_specials("test"))
        self.assertTrue(p.check_specials("test!"))
        self.assertFalse(p.check_specials(""))

    def test_check_password_policy(self):
        self.assertFalse(p.check_password_policy("cool!"))               # Too short
        self.assertFalse(p.check_password_policy("cOol1!"))              # Too short
        self.assertTrue(p.check_password_policy("cooLpass@1"))           # Valid
        self.assertFalse(p.check_password_policy("cooLpassword@1"))      # Too long
        self.assertFalse(p.check_password_policy("COOLPASS1!"))          # No lowercase

    def test_check_weak_password(self):
        self.assertTrue(p.check_weak_password("testPassword!4"))  # Known weak (in list)
        self.assertFalse(p.check_weak_password("GoodPass4@"))     # Should not be in list

    def test_hash_password(self):
        self.assertEqual(
            p.hash_password("cOolPass1!", 4321),
            p.hash_password("cOolPass1!", 4321)
        )
        self.assertEqual(
            p.hash_password("TestPq@!", 31415),
            p.hash_password("TestPq@!", 31415)
        )

    def test_add_and_check_user_login(self):
        username = "cooluser"
        password = "Pass1word!"
        salt = p.generate_salt()
        hashcode = p.hash_password(password, salt)

        self.assertTrue(p.add_row(username, salt, hashcode, "client"))
        self.assertTrue(p.check_user_login(username, password))
        self.assertFalse(p.check_user_login("nonexistent", "whatever"))

    def test_check_username_availability(self):
        self.assertFalse(p.check_username_availability("cooluser"))
        p.add_row("cooluser", p.generate_salt(), "fakehash", "client")
        self.assertTrue(p.check_username_availability("cooluser"))

    def test_get_user_role(self):
        username = "client1"
        password = "ClientPass1!"
        salt = p.generate_salt()
        hashcode = p.hash_password(password, salt)

        p.add_row(username, salt, hashcode, "client")
        role = p.get_user_role(username, password)
        self.assertEqual(role, "client")


if __name__ == '__main__':
    unittest.main()
