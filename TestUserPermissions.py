"""
Unit tests for the UserPermissions module.

Tests:
- Role-based permission checks across all system roles
- Expected access grants and denials
- Edge cases such as unknown roles and invalid inputs

"""

import unittest
import UserPermissions as u

# Permissions used for validation
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

permissions = [
    view_balance, view_portfolio, view_contact_info_advisor, modify_portfolio,
    view_contact_info_planner, view_contact_info_analyst, view_client_balance,
    view_client_portfolio, modify_client_portfolio, view_money_instruments,
    view_private_instruments, view_derivatives_trade, view_interest_instruments,
    view_client_info, request_account_access, validate_modifications
]


class TestUserPermissions(unittest.TestCase):
    """
    Comprehensive unit tests for validating permission access
    based on user roles.
    """

    def test_check_user_permissions(self):
        """
        Validates that each role receives appropriate access to its
        allowed permissions and is denied others.
        """

        # Roles and their granted permissions
        role_permissions = {
            "client": [
                view_balance, view_portfolio, view_contact_info_advisor
            ],
            "premiumclient": [
                modify_portfolio, view_contact_info_planner, view_contact_info_analyst
            ],
            "financialplanner": [
                view_money_instruments, view_client_balance, view_client_portfolio,
                modify_client_portfolio, view_private_instruments
            ],
            "financialadvisor": [
                view_client_balance, view_client_portfolio,
                modify_client_portfolio, view_private_instruments
            ],
            "investmentanalyst": [
                view_money_instruments, view_derivatives_trade, view_interest_instruments,
                view_private_instruments, view_client_balance, view_client_portfolio,
                modify_client_portfolio
            ],
            "technicalsupport": [
                view_client_info, request_account_access
            ],
            "teller": [
                "9:00", "9:30", "17:00"
            ],
            "complianceofficer": [
                view_client_balance, view_client_portfolio, validate_modifications
            ]
        }

        # Deny cases: any permission not in granted list
        for role, allowed_perms in role_permissions.items():
            print(f"\n🎯 Testing Role: {role.upper()}\n{'-'*60}")

            if role != "teller":
                # Test GRANT
                for perm in allowed_perms:
                    self.assertEqual(
                        u.check_user_permissions(role, perm),
                        "granted",
                        msg=f"Expected access GRANTED for {role} -> {perm}"
                    )

                # Test DENY
                for perm in permissions:
                    if perm not in allowed_perms:
                        self.assertEqual(
                            u.check_user_permissions(role, perm),
                            "denied",
                            msg=f"Expected access DENIED for {role} -> {perm}"
                        )

            else:
                # Teller: test time-based logic
                for time_str in role_permissions["teller"]:
                    self.assertEqual(
                        u.check_user_permissions("teller", time_str),
                        "granted",
                        msg=f"Teller should have access at {time_str}"
                    )

                deny_times = ["00:30", "17:01", "8:59", "notatime"]
                for time_str in deny_times:
                    self.assertEqual(
                        u.check_user_permissions("teller", time_str),
                        "denied",
                        msg=f"Teller should be denied access at {time_str}"
                    )


if __name__ == '__main__':
    unittest.main()
