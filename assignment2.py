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

#CHANGE THIS TO YOUR OWN EMAIL
UNI_EMAIL = "danilvorotilov@tudelft.nl"

SERVER_PUB_KEY = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))
COMMUNITY_ID = "4c61623247726f75705369676e696e6732303236"
REPLICATION_COMMUNITY_ID = "0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF"

LEADER_ID = "1"
PUBLIC_KEYS = {
    "1": "4c69624e61434c504b3ab61e37a8692d6daa52ffadd042aa7b271121397fb2183b0690e3f29eb70d535ab3a5844182e0193bbda94b4007be5cc0f96aeadd130c6e48542c0109e5f18803",
    "2": "4c69624e61434c504b3acb4cf8cd94d4c0b6513dde5ac3e713421243fe03acd9f81c44a3c59d665af57e9372a84599691d8ca03efbe0095cc5eb4a14d68700ab81356a4da03be942c848",
    "3": "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176"
}

MEMBER_KEYS = {
    "4c69624e61434c504b3ab61e37a8692d6daa52ffadd042aa7b271121397fb2183b0690e3f29eb70d535ab3a5844182e0193bbda94b4007be5cc0f96aeadd130c6e48542c0109e5f18803": "1",
    "4c69624e61434c504b3acb4cf8cd94d4c0b6513dde5ac3e713421243fe03acd9f81c44a3c59d665af57e9372a84599691d8ca03efbe0095cc5eb4a14d68700ab81356a4da03be942c848": "2",
    "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176": "3"
}

LASTSENT = "_lastsent"

# Global variables
global to_send
global group_id
global solution_dict
global server_peer
global round_nr
global peers_connected


solution_dict = dict()
round_nr = 1
peers_connected = False



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
        self.register_task("check_solutions", self.check_solutions, interval = 0.1)
    



        
    def started(self) -> None:
        global peers_connected

        while not peers_connected:
            time.sleep(1.0)
        print("starting submition community")
        print("starting a peer listener")
        print("my key", self.my_peer.public_key.key_to_bin().hex())
        self.network.add_peer_observer(self)

        
        
        
    # --------------------
    # ------ Tasks -------
    # --------------------
    def check_solutions(self):
        global group_id, solution_dict, round_nr, to_send, server_peer
        ids = []
        sum = 0
        for key in list(solution_dict.keys()):
            args = key.split("_")
            if len(args) < 2:
                continue
            # TODO: Make sure temp_id is indeed in range [1..3]
            temp_id = args[0]
            curr_round_nr = args[1]
            
            if curr_round_nr == round_nr and temp_id not in ids:
                ids.append(temp_id)
                sum+=1
        
        if sum != 3:
            return
        # We know these exist
        sig1 = solution_dict["1_"+round_nr]
        sig2 = solution_dict["2_"+round_nr]
        sig3 = solution_dict["3_"+round_nr]
        # here sum is 3, so we are ready to send the packaged solution
        to_send = BundleSubmission(
            group_id,
            round_nr,
            sig1,
            sig2,
            sig3
        )

        if not server_peer:
            print("[WARNING] server was never found as a peer")

        server_peer.ez_send(to_send)





    # --------------------
    # ---- Callbacks -----
    # --------------------
    def on_peer_added(self, peer):
        global server_peer
        print(f"FOUND PEER: {peer}")
        print(f"-> mid: {peer.mid.hex()}")
        print(f"-> pkeybin: {peer.public_key.key_to_bin().hex()}")

        if not is_server(peer):
            return
        

        print("FOUND SERVER, SENDING REGISTRATION REQUEST")
        server_peer = peer
        self.ez_send(peer, RegistrationRequest(
            bytes.fromhex(PUBLIC_KEYS["1"]), 
            bytes.fromhex(PUBLIC_KEYS["2"]), 
            bytes.fromhex(PUBLIC_KEYS["3"])
        ))    

    def on_peer_removed(self, peer) -> None:
        print(f"peer {peer} left")

    @lazy_wrapper(RegistrationResponse)
    def on_registration_response(self, peer, payload:RegistrationResponse):
        global group_id
        if not is_server(peer):
            return
        group_id = payload.group_id
        print("success", payload.success)
        print("msg", payload.message)
        print("group_id: ", payload.group_id)
        
        

    @lazy_wrapper(ChallangeResponse)
    def on_challange_response(self, peer, payload:ChallangeResponse):
        global round_nr, solution_dict
        if not is_server(peer):
            return
       
        
        my_submition_id = MEMBER_KEYS[self.my_peer.mid]
        signed_nonce = default_eccrypto.create_signature(cast("PrivateKey", self.my_peer.key), payload.nonce).hex()
        solution_dict[my_submition_id + "_" + round_nr] = signed_nonce

    @lazy_wrapper(RoundResult)
    def on_round_result(self, peer):
        global round_nr
        if not is_server(peer):
            return 
        
        if not peer.payload.success:
            print("[SERVER]")


def is_server(peer):
    return peer.mid == SERVER_PUB_KEY_SHA1





class Ping(VariablePayload):
    msg_id=10
    format_list = ["d"]
    names = ["timestamp"]


class Solution(VariablePayload):
    msg_id=11
    format_list = ["varlenH", "q"]
    names = ["signed_nonce", "round_nr"]


class PingCache(RandomNumberCacheWithName):


    def __init__(self, request_cache: RequestCache, name: str, value:int) -> None:
        super().__init__(request_cache, self.name)
        self.value = value
        self.name = name

class ReplicationCommunity(Community, PeerObserver):

    community_id = bytes.fromhex(REPLICATION_COMMUNITY_ID)

    timeout = 30
    ping_delay_min = 5
    ping_delay_max = 10

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        # Register the handler for the server's response
        
        self.add_message_handler(Ping, self.on_ping)
        self.add_message_handler(Ping, self.on_solution)

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

    @lazy_wrapper(Solution)
    def on_solution(self, peer, payload:Solution):
        global solution_dict
        if not payload.signed_nonce:
            return
        # add a key:value pair of the members registered num and round as key [1..3] , and their signed_nonce as value.
        solution_dict[MEMBER_KEYS[peer.mid] + "_" + payload.round_nr] = payload.signed_nonce
        

    # after timeout remove peer
    def on_ping_timeout(self, peer):
        self.get_peers().remove(peer)


    # Ignore this for now
    # def ez_send(self, peer: Peer, *payloads: Payload, sig: bool = True) -> None:
    #     for payload in payloads:
    #         # Only support VariablePayload convertion for now
    #         # TODO: Add support for other types of payloads.
    #         # They would need to be turned into 
    #         if (isinstance(payload, VariablePayload)):
    #             chronos_payload = ChronosPayloadWID(payload)
    #             chronos_payload.add_timestamp()
    #             payload = chronos_payload
        


    #     super().ez_send(peer, payloads, sig)

    def started(self) -> None:
        pass
        
        

    # Callbacks
    def on_peer_added(self, peer):
        global peers_connected
        print("Found a new peer", peer)
        if MEMBER_KEYS.keys() not in map(lambda peer: peer.mid, all_peers(self)):
            print("still waiting on some members")
            
        print("all members connected, we can now start the submition community")
        peers_connected = True



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


def all_peers(community: Community) -> list[Peer]: 
    community.get_peers().append(community.my_peer())

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