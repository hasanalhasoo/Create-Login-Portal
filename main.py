"""
Main entry point for the Secure Role-Based Access System.

This module handles user interaction including:
- Creating user accounts
- Logging in
- Displaying permissions based on user roles

It interfaces with Password, Database, and UserPermissions modules
to manage authentication and access control logic.

"""

import Password
import UserPermissions
import Database

# Valid roles recognized by the system
roles = [
    "client", "premiumclient", "financialplanner", "financialadvisor",
    "investmentanalyst", "technicalsupport", "teller", "complianceofficer"
]


def create_user_flow() -> None:
    """
    Guides the user through the account creation process.
    - Prompts for a unique username.
    - Validates password against policy and weak list.
    - Prompts for a valid role.
    - Hashes and stores user credentials in the database.
    """
    username = input("Please Select A Username: ")
    while Password.check_username_availability(username):
        print("⚠️ Username is already taken. Please choose another.")
        username = input("Please Enter A Username: ")

    print("""
Password Requirements:
- At least 1 Uppercase Character
- At least 1 Lowercase Character
- At least 1 Special Character From: {'!', '@', '#', '$', '%', '?'}
- At least 1 Number Character
- Length between 8 and 12 characters
    """)

    password_input = input("Please Enter Your Password: ")
    while (
            Password.check_weak_password(password_input) or
            not Password.check_password_policy(password_input) or
            password_input == username
    ):
        print("❌ Password doesn't meet requirements or is too common. Try again.")
        password_input = input("Please Enter Your Password: ")

    # Role selection loop
    while True:
        role_input = input("Enter your role (e.g. Client, Financial Planner): ").replace(" ", "").lower()
        if role_input in roles:
            print("✅ Role entry successful. Redirecting to home...")
            break
        print("❌ Role not recognized. Please double-check your spelling.")

    # Store user in database
    salt = Password.generate_salt()
    hashcode = Password.hash_password(password_input, salt)
    Password.add_row(username, salt, hashcode, role_input)


def login_flow() -> str:
    """
    Handles user login.
    - Prompts for username and password.
    - Validates credentials.

    Returns:
        str: The role associated with the logged-in user.
    """
    while True:
        username = input("Enter Username: ")
        password = input("Enter Password: ")
        if Password.check_user_login(username, password):
            print(f"\n✅ Login Successful. Welcome, {username}!")
            role = Password.get_user_role(username, password)
            print(f"You are logged in as: {role}\n")
            return role
        else:
            print("❌ Incorrect username or password. Please try again.")


def display_permissions(role: str) -> None:
    """
    Displays all possible system permissions and highlights the current user's role-specific permissions.

    Args:
        role (str): The role of the logged-in user.
    """
    all_perms = [
        "View Account Balance", "View Investment Portfolio", "View Advisor Contact Information",
        "Modify Investment Portfolio", "View Financial Planner Contact Information",
        "View Investment Analyst Contact Information", "View Client Account Balance",
        "View Client Investment Portfolio", "Modify Client Investment Portfolio",
        "View Money Market Instruments", "View Private Consumer Instruments",
        "View Derivatives Trade", "View Interest Instruments", "View Client Information",
        "Request Client Account Access", "Validate Modifications To Investment Portfolio"
    ]

    print("🔐 All Available Permissions:")
    for perm in all_perms:
        print(f" - {perm}")
    print("\n🎯 Permissions Available to You:")
    UserPermissions.show_permissions_for_role(role)


def main() -> None:
    """
    Main application loop.
    - Initializes database.
    - Continuously prompts user to Login, Create, or Exit.
    - Delegates user actions to the appropriate flows.
    """
    Database.init_db()
    print("===============================================")
    print("  Welcome to the Secure Role-Based Access System")
    print("===============================================\n")

    while True:
        action = input("Type 'Login', 'Create', or 'Exit': ").lower()

        if action == "create":
            create_user_flow()

        elif action == "login":
            role = login_flow()
            display_permissions(role)

            while True:
                user_action = input("Enter an action from the list above (or type 'exit'): ").lower().replace(" ", "")
                if user_action == "exit":
                    break
                UserPermissions.check_user_permissions(role, user_action)

        elif action == "exit":
            print("\n👋 Goodbye! Thank you for using the system.\n")
            break

        else:
            print("❗ Invalid input. Please type 'Login', 'Create', or 'Exit'.")


if __name__ == '__main__':
    main()
