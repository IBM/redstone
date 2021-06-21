import unittest
from unittest.mock import patch

from redstone import auth


class TokenManagerTestCase(unittest.TestCase):
    def test_gettoken_expired_norefreshtoken(self):
        """
        When get_token is called, the current token is expired,
        and we are not using refresh tokens,
        then we should not call _refresh_token.
        """

        p1 = patch.object(auth.TokenManager, "is_token_expired", return_value=True)
        p2 = patch.object(auth.TokenManager, "_refresh_token")
        p3 = patch.object(auth.TokenManager, "_request_token")
        p4 = patch.object(
            auth.TokenManager, "is_refresh_token_expired", return_value=False
        )
        ite = p1.start()
        ref_tok = p2.start()
        req_tok = p3.start()
        _ = p4.start()
        self.addCleanup(p1.stop)
        self.addCleanup(p2.stop)
        self.addCleanup(p3.stop)
        self.addCleanup(p4.stop)

        tm = auth.TokenManager(api_key="TEST_KEY", use_refresh_token=False)
        tm._token_info["access_token"] = "MOCK_TOKEN"
        tm.get_token()

        ite.assert_called()
        ref_tok.assert_not_called()
        req_tok.assert_called()
