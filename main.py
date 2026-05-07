from asyncio import run
from dataclasses import dataclass
import hashlib
from random import choice, random
import time
from typing import cast
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.chronos_payload import ChronosPayloadWID
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.messaging.serialization import Payload
from ipv8.peer import Peer
from ipv8.peerdiscovery.discovery import DiscoveryStrategy
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.requestcache import RandomNumberCacheWithName, RequestCache
from ipv8.util import run_forever
from ipv8_service import IPv8

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.keyvault.keys import PrivateKey

SERVER_PUB_KEY = "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))
COMMUNITY_ID = "4c61623247726f75705369676e696e6732303236"
REPLICATION_COMMUNITY_ID = "0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF"
DIFFICULTY = bytes.fromhex("0000000f" + "f" * 56)

MEMBER_KEYS = {
    "1": "4c69624e61434c504b3ab61e37a8692d6daa52ffadd042aa7b271121397fb2183b0690e3f29eb70d535ab3a5844182e0193bbda94b4007be5cc0f96aeadd130c6e48542c0109e5f18803",
    "2": "4c69624e61434c504b3acb4cf8cd94d4c0b6513dde5ac3e713421243fe03acd9f81c44a3c59d665af57e9372a84599691d8ca03efbe0095cc5eb4a14d68700ab81356a4da03be942c848",
    "3": "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176"
}

# Consts for replication
LASTSENT = "_lastsent"

IS_LEADER = True


@vp_compile
class RegistrationRequest(VariablePayload):
    msg_id=1
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]

@vp_compile
class RegistrationResponse(VariablePayload):
    msg_id=2
    format_list = ["?", "varlenHutf8", "varlenHutf8" ]
    names = ["success", "group_id", "message"]

@vp_compile
class ChallangeRequest(VariablePayload):
    msg_id=3
    format_list = ["varlenHutf8"]
    names = ["group_id"]

@vp_compile
class ChallangeResponse(VariablePayload):
    msg_id=4
    format_list = ["varlenH", "q", "d" ]
    names = ["nonce", "round_number", "deadline"]

@vp_compile
class BundleSubmission(VariablePayload):
    msg_id=5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]

@vp_compile
class RoundResult(VariablePayload):
    msg_id=6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]


class SubmissionCommunity(Community, PeerObserver):
    # community_id
    community_id = bytes.fromhex(COMMUNITY_ID)

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        # Register the handler for the server's response
       
        self.add_message_handler(RegistrationResponse, self.on_registration_response)
        self.add_message_handler(ChallangeResponse, self.on_challange_response)
        self.add_message_handler(RoundResult, self.on_round_result)



        
    def started(self) -> None:
        print("joining community")
        print("starting a peer listener")
        self.network.add_peer_observer(self)

        print("my key", self.my_peer.public_key.key_to_bin().hex())
        
        

    # Callbacks
    def on_peer_added(self, peer):
        print(f"FOUND PEER: {peer}")
        print(f"-> mid: {peer.mid.hex()}")
        print(f"-> pkeybin: {peer.public_key.key_to_bin().hex()}")

        if peer.mid == SERVER_PUB_KEY_SHA1 or peer.public_key.key_to_bin() == bytes.fromhex(SERVER_PUB_KEY):
            print("FOUND SERVER, SENDING REGISTRATION REQUEST")
            self.ez_send(peer, RegistrationRequest(MEMBER_KEYS["1"], MEMBER_KEYS["2"], MEMBER_KEYS["3"]))
    

    def on_peer_removed(self, peer) -> None:
        print(f"peer {peer} left")

    @lazy_wrapper(RegistrationResponse)
    def on_registration_response(self, peer, payload:RegistrationResponse):
        print("success", payload.success)
        print("msg", payload.message)

    # TODO: implement callbacks
    @lazy_wrapper(ChallangeResponse)
    def on_challange_response(self, peer, payload:ChallangeResponse):
        # Naive approach, just send the signed answer
        signed_payload = default_eccrypto.create_signature(cast("PrivateKey", self.my_peer.key), payload)
        peer.ez_send(signed_payload)

    def on_round_result(self, peer):
        pass





class Ping(VariablePayload):
    msg_id=10
    format_list = ["d"]
    names = ["timestamp"]

class Solution(VariablePayload):
    msg_id=11
    format_list = [""]
    names = ["pkey"]

class PingCache(RandomNumberCacheWithName):


    def __init__(self, request_cache: RequestCache, name: str, value:int) -> None:
        super().__init__(request_cache, self.name)
        self.value = value
        self.name = name

class ReplicationCommunity(Community):

    community_id = bytes.fromhex(REPLICATION_COMMUNITY_ID)

    timeout = 30
    ping_delay_min = 5
    ping_delay_max = 10

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        # Register the handler for the server's response
        
        self.add_message_handler(Ping, self.on_ping)

        self.request_cache = RequestCache()

    async def unload(self) -> None:
        await self.request_cache.shutdown()
        await super().unload()
        
    @lazy_wrapper(Ping)
    def on_ping(self, peer):
        self.cancel_pending_task(peer.mid.hex() + LASTSENT)
        self.register_task(peer.mid.hex() + LASTSENT, self.on_timeout, delay=self.timeout)
        self.request_cache.add(PingCache(self.request_cache, peer.mid.hex() + LASTSENT, time.time()))
        time.sleep(rand_in_range(self.ping_delay_min, self.ping_delay_max))
        peer.ez_send(Ping(time.time()))

    # after timeout remove peer
    def on_ping_timeout(self, peer):
        self.get_peers().remove(peer)
    def ez_send(self, peer: Peer, *payloads: Payload, sig: bool = True) -> None:
        for payload in payloads:
            # Only support VariablePayload convertion for now
            # TODO: Add support for other types of payloads.
            # They would need to be turned into 
            if (isinstance(payload, VariablePayload)):
                chronos_payload = ChronosPayloadWID(payload)
                chronos_payload.add_timestamp()
                payload = chronos_payload
            


        super().ez_send(peer, payloads, sig)

        
    def started(self) -> None:
        pass
        
        

    # Callbacks
    def on_peer_added(self, peer):
        print("Found a new peer", peer)

    def on_peer_removed(self, peer) -> None:
        print(f"peer {peer} left")

# time in ms between start and end
def rand_in_range(start, end) -> int:
    return random.random() * (end-start) + start

async def start_communities():
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key(UNI_EMAIL, "curve25519", "new_key.pem")
    builder.add_overlay(
        "SubmissionCommunity", 
        UNI_EMAIL,
        [
            WalkerDefinition
                (
                    Strategy.RandomWalk, 
                    10, 
                    {"timeout": 3.0}
                    
                )
        ],
        default_bootstrap_defs,
        {},
        [("started",)]
    )
    
    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={"SubmissionCommunity": SubmissionCommunity}
    )
    
    await ipv8.start()
    
    await run_forever()




def send_hash(hash):
    ...

def find_nonce(static_str):
    
    for i in range(0, 2**64):
        # only add nonce to the static part of the payload
        msg = static_str + i.to_bytes(8, byteorder='big')
        msg_hash = hashlib.sha256(msg).digest() 
        
        if check_zeros(msg_hash, DIFFICULTY):
            print(f"Found hash at nonce: {i}, with hash: {msg_hash.hex()}")
            exit(0)


def check_zeros(hash, difficulty):
    return hash < difficulty

def main():
    run(start_communities())

if __name__ == "__main__":
    main()