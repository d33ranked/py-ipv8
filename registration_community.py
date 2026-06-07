from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver

from utils import *


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

@vp_compile
class ReadyMessage(VariablePayload):
    """
    Response from the server indicating if registration was successful.
    """
    msg_id = 3
    format_list = ["?"]
    names = ["ready"]

# RegistrationCommunity
class RegistrationCommunity(Community, PeerObserver):
    # -- Rest of the varialbes here
    community_id=bytes.fromhex(COMMUNITY_ID)
    HEARTBEAT_INTERVAL = 30

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)

        self.server_peer = getattr(settings, "server_peer")
        self.team_peers = getattr(settings, "team_peers")
        self.registration_complete = getattr(settings, "registration_complete")

        # add our own peer
        our_id = MEMBER_KEYS[pub_key(self.my_peer)]
        self.team_peers[our_id] = self.my_peer
        self.team_ready = []
        self.all_ready = False
        # Register the handler for the server's response
        self.add_message_handler(RegisterResponse, self.handle_regestration_response)  
        self.add_message_handler(ReadyMessage, self.on_ready)

    def started(self) -> None:
        print("Started Registration Community.")
        self.register_task("check_ready", self.check_ready, interval=2.0)
        self.network.add_peer_observer(self)

    def check_ready(self):
        print("READYS: ", [MEMBER_KEYS[ready] for ready in self.team_ready])
        # early return if readys are not recieved or server is not yet found
        if not self.server_peer or len(self.team_ready) != 3:
            return

        print("READYS collected")
        

        if is_leader(self.my_peer):
            print("SENDING REGISTRATION REQUEST")
            self.ez_send(self.server_peer, Register(
                GROUP_ID,
                bytes.fromhex(BLOCKCHAIN_COMMUNITY_ID)
            ))
            #self.send_register(self.server_peer)
        self.cancel_pending_task("check_ready")

    def on_peer_added(self, peer):
        print("peer added: ", peer)
        print("Pkey ->", pub_key(peer, short=True))

        if is_server(peer):
            self.server_peer = peer

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
    def handle_regestration_response(self, peer, payload: RegisterResponse):
        if not payload.success:
            print("[SERVER] Registration Failed")

        print(f"[SERVER] msg: {payload.message}")
        self.registration_complete = True

    @lazy_wrapper(ReadyMessage)
    def on_ready(self, peer, payload: ReadyMessage):
        if pub_key(peer) not in self.team_ready and pub_key(peer) in MEMBER_KEYS:
            self.team_ready.append(pub_key(peer))


    def handle_teammate(self, peer):
        
        self.team_peers[MEMBER_KEYS[pub_key(peer)]] = peer
        if len(self.team_peers) == 3:
            group_send(self, list(self.team_peers.values()), ReadyMessage(True))
        #self.register_task("send_heartbeat", self.send_heartbeat, peer, interval=self.HEARTBEAT_INTERVAL)


    def send_heartbeat(self, peer: Peer):
        peer.ez_send()


    def hard_send(self, peer: Peer):
        pass