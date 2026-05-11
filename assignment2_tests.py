import os
import unittest
from typing import TYPE_CHECKING, Any

from ipv8.community import Community, CommunitySettings
from assignment2 import SubmissionCommunity
from ipv8.requestcache import NumberCache, RequestCache
from ipv8.test.base import TestBase
from ipv8.test.mocking.ipv8 import MockIPv8

if TYPE_CHECKING:
    from ipv8.messaging.payload import IntroductionRequestPayload
    from ipv8.messaging.payload_headers import GlobalTimeDistributionPayload
    from ipv8.peer import Peer

class MyTests(TestBase[SubmissionCommunity]):
    MAX_TEST_TIME = 10

    def setUp(self) -> None:
        super().setUp()

        # Create 1 MyCommunity
        self.initialize(SubmissionCommunity, 6)
        # Nodes are 0-indexed
        value = self.overlay(0).some_constant()
        self.server_key = self.overlay(0).my_peer.public_key.key_to_bin().hex()
        self.assertEqual(42, value)


    async def tearDown(self) -> None:
        await super().tearDown()
        

    # 
    def test_wrong_user(self):
        pass