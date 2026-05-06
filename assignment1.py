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
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY)).hexdigest()
COMMUNITY_ID = "2c1cc6e35ff484f99ebdfb6108477783c0102881"
DIFFICULTY = bytes.fromhex("0000000f" + "f" * 56)
NONCE_SOLUTION = 51200215

PEDRO = "WrK1wzoSk2lrmKAnQymmAI4krMc"

global i

@vp_compile
class SubmissionMessage(VariablePayload):
    msg_id=1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]

@vp_compile
class ServerResponse(VariablePayload):
    msg_id=2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

class SubmissionCommunity(Community, PeerObserver):
    # community_id
    community_id = bytes.fromhex(COMMUNITY_ID)

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        global i
        i = 0
        # Register the handler for the server's response
        self.add_message_handler(SubmissionMessage, self.on_request)
        self.add_message_handler(ServerResponse, self.on_response)
        self.register_task("find_server", self.find_server, interval=1.0)

        

    def find_server(self):
        for peer in self.get_peers():
            if peer.mid.hex() != SERVER_PUB_KEY_SHA1:
                print("Found NOT the server, ignoring")
                continue
            print("Found THE SERVER, sending submission")
            self.ez_send(peer, SubmissionMessage(UNI_EMAIL, REPO_LINK, NONCE_SOLUTION))
    def on_peer_added(self, peer):
        global i
        print("------------------FOUND PEER-----------------------")
        print("Found", peer, "mid:", peer.mid.hex())
        print("pubkey_ser: ", peer.public_key.key_to_bin().hex() )

        if peer.mid.hex() != SERVER_PUB_KEY_SHA1:
            print("Found NOT the server, ignoring")
            return
        print("Found THE SERVER, sending submission")
        self.ez_send(peer, SubmissionMessage(UNI_EMAIL, REPO_LINK, NONCE_SOLUTION))
        # self.register_task(f"spam_peer{i}", self.spam_peer, peer, interval=0.2 )
        #self.ez_send(peer, ServerResponse(True, "YOU JUST WON $100000000000000"))
        i+=1
        
    """ def on_peer_added(self, peer):
        print(peer, "mid:", peer.mid.hex())
        if peer.mid == PEDRO:
            self.register_task("spam_peer", self.spam_peer, peer, interval=0.1, ) """

    def spam_peer(self, peer):
        print("SPAMMING PEDRO")
        self.ez_send(peer, ServerResponse(True, "YOU JUST WON $100000000000000"))

    def on_peer_removed(self, peer) -> None:
        print(f"peer {peer} left")

    def started(self) -> None:
        print("joining community")
        print("starting a peer listener")
        print("looking for", SERVER_PUB_KEY_SHA1)
        self.network.add_peer_observer(self)


           
    @lazy_wrapper(SubmissionMessage)
    def on_request(self, peer, payload:SubmissionMessage) -> None:
        print(f"peer {peer} is submitting {payload}")

        print("Their submission")
        print("email:", payload.email)
        print("github:", payload.github_url)
        print("nonce:", payload.nonce)
        self.ez_send(peer, ServerResponse(False, "Bro, I am not the server, but nice try :)"))
    
    @lazy_wrapper(ServerResponse)
    def on_response(self, peer, payload:ServerResponse) -> None:
        print("success: ", payload.success)
        print(peer, "responsed to us with ", payload.message)

    def polling_peers(self):
        print(self.get_peers())



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
    
    # run for 8 bytes
    static = UNI_EMAIL + "\n" + REPO_LINK + "\n" 
    static = static.encode("utf-8")
    # NONCE_SOLUTION was retrieved with find_nonce func
    full_msg = static + NONCE_SOLUTION.to_bytes(8, byteorder='big') 
    hash_digest = hashlib.sha256(full_msg).digest()
    if not check_zeros(hash_digest, DIFFICULTY):
        print("invalid hash, exiting")
        exit(1)

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

