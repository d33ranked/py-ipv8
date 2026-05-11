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
        
        # Insert your setUp logic here

    async def tearDown(self) -> None:
        await super().tearDown()
        # Insert your tearDown logic here