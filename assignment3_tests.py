import asyncio
import hashlib
import os
import unittest
from typing import TYPE_CHECKING, Any

from ipv8.community import Community, CommunitySettings
from ipv8.requestcache import NumberCache, RequestCache
from ipv8.test.base import TestBase
from ipv8.test.mocking.ipv8 import MockIPv8

from blockchain_community import BlockchainCommunity
from utils import *



if TYPE_CHECKING:
    from ipv8.messaging.payload import IntroductionRequestPayload
    from ipv8.messaging.payload_headers import GlobalTimeDistributionPayload
    from ipv8.peer import Peer

class SubmissionCommunityTests(TestBase[BlockchainCommunity]):
    MAX_TEST_TIME = 10

    def setUp(self) -> None:
        global SERVER_PUB_KEY, SERVER_PUB_KEY_SHA1, MEMBER_KEYS, PUBLIC_KEYS
        
        super().setUp()
        # Create 1 MyCommunity
        self.initialize(BlockchainCommunity, 5)

        

        # Nodes are 0-indexed
        SERVER_PUB_KEY = self.peer(0).public_key.key_to_bin().hex()
        SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))

        # Reset values in the dictionaries.
        MEMBER_KEYS.clear()
        PUBLIC_KEYS.clear()
        for i in range(1, 4):
            MEMBER_KEYS[self.overlay(i).my_peer.public_key.key_to_bin().hex()] = i
            PUBLIC_KEYS[i] = self.overlay(i).my_peer.public_key.key_to_bin().hex()
        

    async def tearDown(self) -> None:
        
        await super().tearDown()
    
    # Make sure all relevant global variable are overriden correctly.
    # along anything else that should be tested post setup.
    async def test_setup(self) -> None:
        self.assertEqual(
            self.key_bin(0).hex(), 
            SERVER_PUB_KEY
        )
        self.assertEqual(
            self.mid(0),
            SERVER_PUB_KEY_SHA1.digest()
        )

        # bijection testing
        [self.assertEqual(
            PUBLIC_KEYS[MEMBER_KEYS[pkey]],
            pkey
        ) for pkey in MEMBER_KEYS]

        [self.assertEqual(
            PUBLIC_KEYS[i],
            self.key_bin(i).hex()
        ) for i in range(1,4)]



        


    # Tests wether the server peer is initialized correctly for peer 1 after peer discovery.
    async def test_server_var_init(self) -> None:
        
        
        self.overlay(0).send_introduction_request(self.peer(1))
        await self.introduce_nodes()
        
        await self.deliver_messages()
        self.assertEqual(
            self.key_bin(0).hex(), 
            self.overlay(1).server_peer.public_key.key_to_bin().hex()
        )
        
        

    # 
    def test_wrong_user(self):
        pass