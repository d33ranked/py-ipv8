from asyncio import run
from dataclasses import dataclass
import hashlib
from random import choice
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.peer import Peer
from ipv8.peerdiscovery.discovery import DiscoveryStrategy
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.util import run_forever
from ipv8_service import IPv8

REPO_LINK = "https://github.com/d33ranked/py-ipv8"
UNI_EMAIL = "danilvorotilov@tudelft.nl"
SERVER_PUB_KEY = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))
COMMUNITY_ID = "4c61623247726f75705369676e696e6732303236"
DIFFICULTY = bytes.fromhex("0000000f" + "f" * 56)

MEMBER_KEYS = {
    "1": "4c69624e61434c504b3ab61e37a8692d6daa52ffadd042aa7b271121397fb2183b0690e3f29eb70d535ab3a5844182e0193bbda94b4007be5cc0f96aeadd130c6e48542c0109e5f18803",
    "2": "3076301006072a8648ce3d020106052b8104002203620004476536525c76fad241495e7698044494f9b0341377093c66dad4c7660123aec53d71e62879efe82bb1b71d8b890c77c9592b04c56de9788ded6e66ac2338577db72e9477018fc3f7f9e190ebcbce390c46a970271b5668fc999881b76612434b",
    "3": "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176"
}




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
        print("------------------FOUND PEER-----------------------")
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
    def on_challange_response(self, peer):
        pass

    def on_round_result(self, peer):
        pass



async def start_communities():
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key(UNI_EMAIL, "medium", "uni_email_ipv8_key.pem")
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