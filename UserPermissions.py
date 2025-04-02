"""
UserPermissions module for managing role-based access control (RBAC).

Each user role is mapped to a specific set of permissions.
This module:
- Checks if a user role has permission to perform a requested action.
- Displays the permissions available to each role.

Roles:
    client, premiumclient, financialplanner, financialadvisor,
    investmentanalyst, technicalsupport, teller, complianceofficer

"""

# Define all permission strings as constants
view_balance = "viewaccountbalance"
view_portfolio = "viewinvestmentportfolio"
view_contact_info_advisor = "viewadvisorcontactinformation"
modify_portfolio = "modifyinvestmentportfolio"
view_contact_info_planner = "viewfinancialplannercontactinformation"
view_contact_info_analyst = "viewinvestmentanalystcontactinformation"
view_client_balance = "viewclientaccountbalance"
view_client_portfolio = "viewclientinvestmentportfolio"
modify_client_portfolio = "modifyclientinvestmentportfolio"
view_money_instruments = "viewmoneymarketinstruments"
view_private_instruments = "viewprivateconsumerinstruments"
view_derivatives_trade = "viewderivativestrade"
view_interest_instruments = "viewinterestinstruments"
view_client_info = "viewclientinformation"
request_account_access = "requestclientaccountaccess"
validate_modifications = "validatemodificationstoinvestmentportfolio"

# List of all valid permissions
permissions = [
    view_balance, view_portfolio, view_contact_info_advisor, modify_portfolio,
    view_contact_info_planner, view_contact_info_analyst, view_client_balance,
    view_client_portfolio, modify_client_portfolio, view_money_instruments,
    view_private_instruments, view_derivatives_trade, view_interest_instruments,
    view_client_info, request_account_access, validate_modifications
]


def check_user_permissions(role: str, user_input: str) -> str:
    """
    Checks whether a given user role is authorized to perform the requested action.

    Args:
        role (str): The role of the user (e.g., "client", "investmentanalyst").
        user_input (str): The action the user wants to perform.

    Returns:
        str: One of the following:
            - "granted" if permission is allowed
            - "denied" if permission is known but disallowed
            - "unknown" if permission does not exist
    """
    # Role-based access control logic
    if role == "client":
        if user_input in [view_balance, view_portfolio, view_contact_info_advisor]:
            print("Access Granted!")
            return "granted"
        elif user_input in permissions:
            print("Access Denied")
            return "denied"
        else:
            print("No Such Permission Found")
            return "unknown"

    if role == "premiumclient":
        if user_input in [modify_portfolio, view_contact_info_planner, view_contact_info_analyst]:
            print("Access Granted!")
            return "granted"
        elif user_input in permissions:
            print("Access Denied")
            return "denied"
        else:
            print("No Such Permission Found")
            return "unknown"

    if role == "financialplanner":
        if user_input in [view_money_instruments, view_client_balance, view_client_portfolio,
                          modify_client_portfolio, view_private_instruments]:
            print("Access Granted")
            return "granted"
        elif user_input in permissions:
            print("Access Denied")
            return "denied"
        else:
            print("No Such Permission Found")
            return "unknown"

    if role == "financialadvisor":
        if user_input in [view_client_balance, view_client_portfolio,
                          modify_client_portfolio, view_private_instruments]:
            print("Access Granted")
            return "granted"
        elif user_input in permissions:
            print("Access Denied")
            return "denied"
        else:
            print("No Such Permission Found")
            return "unknown"

    if role == "investmentanalyst":
        if user_input in [view_money_instruments, view_derivatives_trade, view_interest_instruments,
                          view_private_instruments, view_client_balance,
                          view_client_portfolio, modify_client_portfolio]:
            print("Access Granted!")
            return "granted"
        elif user_input in permissions:
            print("Access Denied")
            return "denied"
        else:
            print("No Such Permission Found")
            return "unknown"

    if role == "technicalsupport":
        if user_input in [view_client_info, request_account_access]:
            print("Access Granted")
            return "granted"
        elif user_input in permissions:
            print("Access Denied")
            return "denied"
        else:
            print("No Such Permission Found")
            return "unknown"

    if role == "teller":
        try:
            hour, minute = map(int, user_input.split(":"))
        except ValueError:
            print("Please Check Your Input! Use HH:MM format.")
            return "denied"

        if 9 <= hour < 17 or (hour == 17 and minute == 0):
            print("Access Granted")
            return "granted"
        else:
            print("Access Denied")
            return "denied"

    if role == "complianceofficer":
        if user_input in [view_client_balance, view_client_portfolio, validate_modifications]:
            print("Access Granted")
            return "granted"
        elif user_input in permissions:
            print("Access Denied")
            return "denied"
        else:
            print("No Such Permission Found!")
            return "unknown"

    print("Unknown role. Access Denied.")
    return "unknown"


def show_permissions_for_role(role: str) -> None:
    """
    Displays the permissions available for a given user role.

    Args:
        role (str): The role to display permissions for.
    """
    print("\n📋 Permissions for Role:", role.capitalize())

    if role == "client":
        print(" - View Account Balance")
        print(" - View Investment Portfolio")
        print(" - View Advisor Contact Information")

    elif role == "premiumclient":
        print(" - Modify Investment Portfolio")
        print(" - View Financial Planner Contact Information")
        print(" - View Investment Analyst Contact Information")

    elif role == "financialplanner":
        print(" - View Money Market Instruments")
        print(" - View Client Account Balance")
        print(" - View Client Investment Portfolio")
        print(" - Modify Client Investment Portfolio")
        print(" - View Private Consumer Instruments")

    elif role == "financialadvisor":
        print(" - View Client Account Balance")
        print(" - View Client Investment Portfolio")
        print(" - Modify Client Investment Portfolio")
        print(" - View Private Consumer Instruments")

    elif role == "investmentanalyst":
        print(" - View Client Account Balance")
        print(" - View Client Investment Portfolio")
        print(" - Modify Client Investment Portfolio")
        print(" - View Money Market Instruments")
        print(" - View Derivatives Trade")
        print(" - View Interest Instruments")
        print(" - View Private Consumer Instruments")

    elif role == "technicalsupport":
        print(" - View Client Information")
        print(" - Request Client Account Access")

    elif role == "teller":
        print(" - Access allowed only between 09:00 and 17:00")

    elif role == "complianceofficer":
        print(" - View Client Account Balance")
        print(" - View Client Investment Portfolio")
        print(" - Validate Modifications To Investment Portfolio")

    else:
        print("❌ Unknown role. No permissions available.")
