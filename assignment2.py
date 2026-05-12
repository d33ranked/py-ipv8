from asyncio import run
from dataclasses import dataclass
from functools import reduce
import hashlib
import operator
import os
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
from dotenv import load_dotenv

load_dotenv()

#CHANGE THIS TO YOUR OWN EMAIL
UNI_EMAIL = os.getenv("UNI_EMAIL")
KEY_PATH = os.getenv("KEY_PATH")

global SERVER_PUB_KEY
global SERVER_PUB_KEY_SHA1
global PUBLIC_KEYS
global MEMBER_KEYS

SERVER_PUB_KEY = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))
COMMUNITY_ID = "4c61623247726f75705369676e696e6732303236"
REPLICATION_COMMUNITY_ID = "0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF"


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

TAIL_N = 5

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


@vp_compile
class PeerRegistrationResponse(VariablePayload):
    msg_id=11
    format_list = ["?", "varlenHutf8", "varlenHutf8" ]
    names = ["success", "group_id", "message"]

@vp_compile
class PeerChallangeResponse(VariablePayload):
    msg_id=12
    format_list = ["varlenH", "q", "d" ]
    names = ["nonce", "round_number", "deadline"]

@vp_compile
class PeerSolution(VariablePayload):
    msg_id=13
    format_list = ["varlenH", "q"]
    names = ["signed_nonce", "round_nr"]


class SubmissionCommunity(Community, PeerObserver):
    # community_id
    community_id = bytes.fromhex(COMMUNITY_ID)
    # Global variables
    group_id = None
    solution_dict = dict()
    server_peer = None
    submission_peers = []
    round_nr = 1
    registration_sent = False


    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        # Register the handler for the server's response
       
        self.add_message_handler(RegistrationResponse, self.on_registration_response)
        self.add_message_handler(ChallangeResponse, self.on_challange_response)
        self.add_message_handler(RoundResult, self.on_round_result)
        self.add_message_handler(PeerRegistrationResponse, self.on_peer_registration_response)
        self.add_message_handler(PeerChallangeResponse, self.on_peer_challange_response)
        self.add_message_handler(PeerSolution, self.on_peer_solution_response)
        # self.register_task("check_solutions", self.check_solutions, interval = 0.1)
    



        
    def started(self) -> None:
        print("starting submition community")
        print("starting a peer listener")
        print("my key:", "..." + pub_key(self.my_peer)[-TAIL_N:])
        self.network.add_peer_observer(self)

        
        
        
    # --------------------
    # ------ Tasks -------
    # --------------------
    # depricated
    def check_solutions(self):
        global to_send
        ids = []
        sum = 0
        for key in list(self.solution_dict.keys()):
            args = key.split("_")
            if len(args) < 2:
                continue
            # TODO: Make sure temp_id is indeed in range [1..3]
            temp_id = args[0]
            curr_round_nr = args[1]
            
            if curr_round_nr == self.round_nr and temp_id not in ids:
                ids.append(temp_id)
                sum+=1
        
        if sum != 3:
            return
        # We know these exist
        sig1 = self.solution_dict["1"]
        sig2 = self.solution_dict["2"]
        sig3 = self.solution_dict["3"]
        # here sum is 3, so we are ready to send the packaged solution
        to_send = BundleSubmission(
            self.group_id,
            self.round_nr,
            sig1,
            sig2,
            sig3
        )

        if not self.server_peer:
            print("[WARNING] server was never found as a peer")

        self.server_peer.ez_send(to_send)





    # --------------------
    # ---- Callbacks -----
    # --------------------
    def on_peer_added(self, peer):
        
        print(f"FOUND PEER: {peer}")
        print(f"-> pkeybin: {"..." + pub_key(peer)[-TAIL_N:]}")

        if is_server(peer):
            self.server_peer = peer


        peers = all_peers(self)

        if not all(member in map(lambda peer: pub_key(peer), peers) for member in list(MEMBER_KEYS.keys())) or not self.server_peer:
            print("still waiting on some members and/or the server")
            return
            
        [self.submission_peers.append(peer) for peer in self.get_peers() if pub_key(peer) in MEMBER_KEYS.keys()]# append to submission_peers

        # Only peer 1 will send the registration request
        if MEMBER_KEYS[pub_key(self.my_peer)] == "1" and not self.registration_sent:
            print("sending RegistrationRequest")
            self.ez_send(self.server_peer, RegistrationRequest(
                bytes.fromhex(PUBLIC_KEYS["1"]),
                bytes.fromhex(PUBLIC_KEYS["2"]),
                bytes.fromhex(PUBLIC_KEYS["3"])
            ))
            self.registration_sent = True

            

    def on_peer_removed(self, peer) -> None:
        print(f"peer {peer} left")

    @lazy_wrapper(RegistrationResponse)
    def on_registration_response(self, peer, payload:RegistrationResponse):
        if not is_server(peer):
            return
        self.group_id = payload.group_id
        print("success", payload.success)
        print("group_id: ", payload.group_id)
        print("msg", payload.message)

        self.send_to_peers(PeerRegistrationResponse(payload.success, payload.group_id, payload.message))

        # send challenge request
        get_challenge = ChallangeRequest(group_id = self.group_id)
        self.ez_send(self.server_peer, get_challenge)

    @lazy_wrapper(ChallangeResponse)
    def on_challange_response(self, peer, payload:ChallangeResponse):
        if not is_server(peer):
            return
       
        print(f"[SERVER] - round {payload.round_number} challange with nonce: {payload.nonce.hex()}")
        
        my_submition_id = MEMBER_KEYS[pub_key(self.my_peer)]
        signed_nonce = default_eccrypto.create_signature(cast("PrivateKey", self.my_peer.key), payload.nonce).hex()

        # if our turn to submit collect signatures
        if self.round_nr == MEMBER_KEYS[pub_key(self.my_peer)]: #should always be true anyway
            self.solution_dict[my_submition_id] = signed_nonce
            self.send_to_peers(PeerChallangeResponse(
                nonce = payload.nonce, 
                round_number = payload.round_number, 
                deadline=payload.deadline)
            )
        
        

    


    @lazy_wrapper(RoundResult)
    def on_round_result(self, peer):

        if not is_server(peer):
            return 
        
        if not peer.payload.success:
            print("[SERVER]")

    # ---------------------
    # ---group callbacks---
    # ---------------------

    @lazy_wrapper(PeerRegistrationResponse)
    def on_peer_registration_response(self, peer, payload: PeerRegistrationResponse):
        if not peer in self.submission_peers:
            return
        if payload.success:
            print(f"[PEER] - Recieved Registration Response, group_id: {payload.group_id}")
            self.group_id = payload.group_id

    @lazy_wrapper(PeerChallangeResponse)
    def on_peer_challange_response(self, peer, payload: PeerChallangeResponse):
        if not peer in self.submission_peers:
            return

        signed_nonce = default_eccrypto.create_signature(cast("PrivateKey", self.my_peer.key), payload.nonce).hex()
        payload = PeerSolution(signed_nonce, self.round_nr)

        for p in self.submission_peers:
            if pub_key(p) == PUBLIC_KEYS[self.round_nr]:
                self.ez_send(p, payload)

    @lazy_wrapper(PeerSolution)
    def on_peer_solution_response(self, peer, payload: PeerSolution):
        if not peer in self.submission_peers:
            return
        if not payload.signed_nonce:
            return

        peer_id = MEMBER_KEYS[pub_key(peer)]
        self.solution_dict[peer_id] = payload.signed_nonce

        if len(self.solution_dict) == 3:
            to_send = BundleSubmission(
                self.group_id,
                self.round_nr,
                self.solution_dict["1"],
                self.solution_dict["2"],
                self.solution_dict["3"]
            )
            self.ez_send(self.server_peer, to_send)

    # Helper functions
    def send_to_peers(self, payload):
        [self.ez_send(peer, payload) for peer in self.submission_peers]

# Helper functions

def all_peers(community: Community) -> list[Peer]:
    all_peers = community.get_peers()
    all_peers.append(community.my_peer)
    return all_peers

def pub_key(peer):
    return peer.public_key.key_to_bin().hex()

def is_server(peer: Peer):
    return peer.public_key.key_to_bin().hex() == SERVER_PUB_KEY

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
        extra_communities={"SubmissionCommunity": SubmissionCommunity}
    )

    await ipv8.start()

    await run_forever()

def main():
    run(start_communities())

if __name__ == "__main__":
    main()