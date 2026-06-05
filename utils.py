import hashlib
import os

from ipv8.community import Community
from ipv8.peer import Peer

#CHANGE THIS TO YOUR OWN EMAIL
UNI_EMAIL = os.getenv("UNI_EMAIL")
KEY_PATH = os.getenv("KEY_PATH")

GROUP_ID = "814ee89d4621f005"
SERVER_PUB_KEY = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))

BLOCKCHAIN_COMMUNITY_ID = "0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF"
COMMUNITY_ID = "4c61623247726f75705369676e696e6732303236"
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


# Helper functions
def group_send(community, group: list[Peer], payload) -> None:
    [community.ez_send(peer, payload) for peer in group]

def all_peers(community: Community) -> list[Peer]:
    all_peers = community.get_peers()
    all_peers.append(community.my_peer)
    return all_peers

def pub_key(peer, short=False):
    p_key = peer.public_key.key_to_bin().hex()
    if short:
        p_key = p_key[-LAST_N:]
    return p_key

def is_server(peer):
    return pub_key(peer) == SERVER_PUB_KEY