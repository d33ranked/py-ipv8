import hashlib
import os

from ipv8.community import Community
from ipv8.peer import Peer

#CHANGE THIS TO YOUR OWN EMAIL
UNI_EMAIL = os.getenv("UNI_EMAIL")
KEY_PATH = os.getenv("KEY_PATH")

global SERVER_PUB_KEY, SERVER_PUB_KEY_SHA1, MEMBER_KEYS, PUBLIC_KEYS

GROUP_ID = "814ee89d4621f005"
SERVER_PUB_KEY = "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))

BLOCKCHAIN_COMMUNITY_ID = b"QuickFoxJumpsLazyDog"
COMMUNITY_ID = "4c616233426c6f636b636861696e323032365057"
LEADER_ID = "1"
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
    try:
        return pub_key(peer) == SERVER_PUB_KEY
    except Exception:
        return False

def is_leader(peer):
    try:
        return MEMBER_KEYS[pub_key(peer)] == LEADER_ID
    except Exception:
        return False

def is_teammate(peer):
    return pub_key(peer) in list(MEMBER_KEYS.keys())

def log_info(logger, peer):
    peer_obj = {"peer_name": "UNKNOWN"}
    if is_server(peer):
        peer_obj["peer_name"]="SERVER"
    if is_teammate(peer):
        peer_obj["peer_name"] ="TEAMMATE"
    if is_leader(peer):
        peer_obj["peer_name"] ="LEADER"
        
    logger.info("User logged in successfully", extra=peer_obj)