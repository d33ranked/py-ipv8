from asyncio import run
from dataclasses import dataclass
from functools import reduce
import hashlib
import operator
import os
import time
from typing import cast
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile

from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.requestcache import RandomNumberCacheWithName, RequestCache
from ipv8.util import run_forever
from ipv8_service import IPv8

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.keyvault.keys import PrivateKey
from dotenv import load_dotenv

load_dotenv()

#CHANGE THIS TO YOUR OWN EMAIL
UNI_EMAIL = os.getenv("UNI_EMAIL")
KEY_PATH = os.getenv("KEY_PATH")


GROUP_ID = "814ee89d4621f005"
SERVER_PUB_KEY = "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))
COMMUNITY_ID = "4c616233426c6f636b636861696e323032365057"
BLOCKCHAIN_COMMUNITY_ID = "0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF"


PUBLIC_KEYS = {
    "1": "4c69624e61434c504b3aa3387dfd20b578dfce201978aea6f25dfa3b3127e6825ce7bd2fb8ce07797f7c8bf427fa376e6eaf58391430e63eb86dc93aebb3f68c89bc9d99c63882034a90",
    "2": "4c69624e61434c504b3acb4cf8cd94d4c0b6513dde5ac3e713421243fe03acd9f81c44a3c59d665af57e9372a84599691d8ca03efbe0095cc5eb4a14d68700ab81356a4da03be942c848",
    "3": "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176"
}

MEMBER_KEYS = {
    "4c69624e61434c504b3aa3387dfd20b578dfce201978aea6f25dfa3b3127e6825ce7bd2fb8ce07797f7c8bf427fa376e6eaf58391430e63eb86dc93aebb3f68c89bc9d99c63882034a90": "1",
    "4c69624e61434c504b3acb4cf8cd94d4c0b6513dde5ac3e713421243fe03acd9f81c44a3c59d665af57e9372a84599691d8ca03efbe0095cc5eb4a14d68700ab81356a4da03be942c848": "2",
    "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176": "3"
}

LASTSENT = "_lastsent"
LAST_N = 5


@vp_compile
class Register(VariablePayload):
    """
    Registration request sent by a group member to join the server.
    """
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]
    names = ["group_id", "community_id"]

@vp_compile
class RegisterResponse(VariablePayload):
    """
    Response from the server indicating if registration was successful.
    """
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]



        

#from ipv8.


class BlockchainCommunity(Community, PeerObserver):
    # -- Community-related constants here
    HEARTBEAT_INTERVAL = 30 # 30 seconds

    # -- Rest of the varialbes here
    community_id = bytes.fromhex(COMMUNITY_ID)
    server_peer = None
    


    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        # Register the handler for the server's response    

    def started(self) -> None:
        print("starting submition community")
        print("starting a peer listener")
        print("my key", pub_key(self.my_peer))
        self.network.add_peer_observer(self)
        self.add_message_handler(RegisterResponse, self.handle_regestration_response)
        

    def on_peer_added(self, peer):
        print("peer added: ", peer)
        print("Pkey ->", pub_key(peer, True))

        if pub_key(peer) == str(SERVER_PUB_KEY):
            self.send_register(peer)
        
        if pub_key(peer) in list(MEMBER_KEYS.keys()):
            self.handle_teammate(peer)

    def on_peer_removed(self, peer):
        print(f"PEER {pub_key(peer)} REMOVED")
    

    def send_register(self, peer: Peer):
        self.ez_send(peer, Register(
                GROUP_ID, 
                bytes.fromhex(BLOCKCHAIN_COMMUNITY_ID)
        ))

    @lazy_wrapper(RegisterResponse)
    def handle_regestration_response(self, peer, payload):
        if not payload.success:
            print("[SERVER] Registration Failed")

        print(f"[SERVER] msg: {payload.message}")
    def handle_teammate(self, peer):

        self.register_task("start_heartbeat", self.send_heartbeat, peer, interval=self.HEARTBEAT_INTERVAL)


    def send_heartbeat(self, peer: Peer):
        peer.ez_send()


    def hard_send(self, peer: Peer):
        pass







    # Helper functions
    def send_to_peers(self, payload):
        [self.ez_send(peer, payload) for peer in self.submission_peers]

# Helper functions

def all_peers(community: Community) -> list[Peer]:
    all_peers = community.get_peers()
    all_peers.append(community.my_peer)
    return all_peers

def pub_key(peer, short=False):
    key = peer.public_key.key_to_bin().hex()
    if short:
        key = key[-LAST_N:]


    return key

def is_server(peer):
    return peer.mid == SERVER_PUB_KEY_SHA1

async def start_communities():
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key(UNI_EMAIL, "curve25519", KEY_PATH)
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
        extra_communities={"SubmissionCommunity": BlockchainCommunity}
    )

    await ipv8.start()

    await run_forever()

def main():
    run(start_communities())

if __name__ == "__main__":
    main()