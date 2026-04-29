from asyncio import run
from dataclasses import dataclass
import hashlib
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.util import run_forever
from ipv8_service import IPv8

REPO_LINK = "https://github.com/d33ranked/py-ipv8"
UNI_EMAIL = "danilvorotilov@tudelft.nl"
SERVER_PUB_KEY = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
COMMUNITY_ID = "2c1cc6e35ff484f99ebdfb6108477783c0102881"
DIFFICULTY = bytes.fromhex("0000000f" + "f" * 56)
NONCE_SOLUTION = 51200215

class SubmissionCommunity(Community, PeerObserver):
    # This ID must match the hex ID of the community you want to join
    community_id = bytes.fromhex(COMMUNITY_ID)

        

    def on_peer_added(self, peer):
        print(f"I am: {self.my_peer}, found: {peer}")

    def on_peer_removed(self, peer) -> None:
        print(f"peer {peer} left")

    def started(self) -> None:
        print("joining community")
        self.network.add_peer_observer(self)
        for p in self.get_peers():
            print(p.address)
            


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

def main():
    # run for 8 bytes
    static = UNI_EMAIL + "\n" + REPO_LINK + "\n" 
    static = static.encode("utf-8")
    # NONCE_SOLUTION was retrieved with find_nonce func
    full_msg = static + NONCE_SOLUTION.to_bytes(8, byteorder='big') 
    hash_digest = hashlib.sha256(full_msg).digest()
    if not check_zeros(hash_digest, DIFFICULTY):
        print("invalid hash, exiting")
        exit(1)

    send_hash(hash_digest)


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

if __name__ == "__main__":
    run(start_communities())

