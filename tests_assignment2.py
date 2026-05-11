import hashlib
import os
import unittest
from typing import TYPE_CHECKING, Any

from ipv8.community import Community, CommunitySettings
from ipv8.requestcache import NumberCache, RequestCache
from ipv8.test.base import TestBase
from ipv8.test.mocking.ipv8 import MockIPv8

from assignment2 import SubmissionCommunity
from assignment2 import SERVER_PUB_KEY, SERVER_PUB_KEY_SHA1, PUBLIC_KEYS, MEMBER_KEYS



if TYPE_CHECKING:
    from ipv8.messaging.payload import IntroductionRequestPayload
    from ipv8.messaging.payload_headers import GlobalTimeDistributionPayload
    from ipv8.peer import Peer

class SubmissionCommunityTests(TestBase[SubmissionCommunity]):
    MAX_TEST_TIME = 10

    def setUp(self) -> None:
        super().setUp()
        # Create 1 MyCommunity
        self.initialize(SubmissionCommunity, 6)
        # Nodes are 0-indexed
        SERVER_PUB_KEY = self.overlay(0).my_peer.public_key.key_to_bin().hex()

        for i in range(1, 4):
            MEMBER_KEYS[self.overlay(i).my_peer.public_key.key_to_bin().hex()] = i
            PUBLIC_KEYS[i] = self.overlay(i).my_peer.public_key.key_to_bin().hex()
        
        SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))

        print("server pub key:", SERVER_PUB_KEY)
        



    async def tearDown(self) -> None:
        
        await super().tearDown()
    

    async def test_intro_called(self) -> None:
        self.overlay(0).send_introduction_request(self.peer(1))
        await self.deliver_messages()
        self.assertEqual(self.peer(0).public_key.get_, SERVER_PUB_KEY)
        

    # 
    def test_wrong_user(self):
        pass