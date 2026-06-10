import asyncio
from dataclasses import dataclass
import hashlib

import time

from ipv8.community import Community, CommunitySettings

from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.requestcache import RandomNumberCacheWithName, RequestCache



from dotenv import load_dotenv

from utils import *

load_dotenv()

import logging

# Create a logger specific to this file/module
logger = logging.getLogger(__name__)

@dataclass
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: bytes
    signature: bytes
    tx_hash: bytes
    status: str

@dataclass
class BlockHeader:
    prev_hash: bytes
    txs_hash: bytes
    timestamp: bytes
    difficulty: bytes
    nonce: bytes

@dataclass
class Block:
    header: BlockHeader
    block_hash: bytes
    tx_hashes: tuple[bytes]
    n_txs: int



@vp_compile
class SubmitTransaction(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "q", "varlenH"]
    names = ["sender_key", "data", "timestamp", "signature"]

@vp_compile
class SubmitTransactionResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenH", "varlenHutf8"]
    names = ["success", "tx_hash", "message"]

@vp_compile
class GetChainHeight(VariablePayload):
    msg_id = 3
    format_list = ["q"]
    names = ["request_id"]

@vp_compile
class ChainHeightResponse(VariablePayload):
    msg_id = 4
    format_list = ["q", "q", "varlenH"]
    names = ["request_id", "height", "tip_hash"]

@vp_compile
class GetBlock(VariablePayload):
    msg_id = 5
    format_list = ["q"]
    names = ["height"]

@vp_compile
class BlockResponse(VariablePayload):
    msg_id = 6
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = [
        "height", "prev_hash", "txs_hash", "timestamp", 
        "difficulty", "nonce", "block_hash", "tx_hashes"
    ]

@vp_compile
class BlockMined(VariablePayload):
    msg_id = 7
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = [
        "height", "prev_hash", "txs_hash", "timestamp",
        "difficulty", "nonce", "block_hash", "tx_hashes"
    ]

@vp_compile
class HeartbeatRequest(VariablePayload):
    msg_id = 8
    format_list = ["q"]
    names = ["default"]

@vp_compile
class HeartbeatResponse(VariablePayload):
    msg_id = 9
    format_list = ["q"]
    names = ["default"]

@vp_compile
class ReadyMessage(VariablePayload):
    """
    Message which appears from a peer if all team mate peers have been discovered
    """
    msg_id = 10
    format_list = ["?"]
    names = ["ready"]

@vp_compile
class NewBlock(VariablePayload):
    msg_id = 100
    
    # format_list defines the byte-structure for each field
    # Q = 64-bit unsigned int
    # varlenH = variable length bytes (prefixed with 2-byte length)
    # I = 32-bit unsigned int
    format_list = ["Q", "varlenH", "varlenH", "Q", "I", "I", "varlenH"]
    
    names = [
        "height",
        "prev_hash",
        "txs_hash",
        "timestamp",
        "difficulty",
        "nonce",
        "tx_hashes"
    ]

GENESIS_BLOCK = Block(
    BlockHeader(b"", hashlib.sha256(b"").digest(), b"", b"", b""),
    b"",
    b"",
    0
)

DIFFICULTY = bytes.fromhex("0000000f" + "f" * 56)


class BlockchainCommunity(Community, PeerObserver):
    # -- Community-related constants here
    HEARTBEAT_INTERVAL = 15 # 15 seconds
    HEARTBEAT_TIMEOUT = 30

    # -- Rest of the varialbes here
    community_id = BLOCKCHAIN_COMMUNITY_ID


    def __init__(self, settings: CommunitySettings, *args, **kwargs):
        super().__init__(settings, *args, **kwargs)

        #shared vars
        self.server_peer = getattr(settings, "server_peer")
        self.team_peers = getattr(settings, "team_peers")

        # add our own peer
        our_id = MEMBER_KEYS[pub_key(self.my_peer)]
        self.team_peers[our_id] = self.my_peer

        self.team_ready = []

        self.mempool = dict()
        self.txs_per_block = 0 # 0 first because it's the genesis block, this is later changed

        # Q: Should the chain be saved and loaded from disk?
        # ANS: No,
        # the idea is that the chain would only be kept alive in an actual blockchain by at least one living peer.
        # Could be a cool extension idea though.

        self.blockchain = [GENESIS_BLOCK]
        self.next_block = GENESIS_BLOCK

        # Register the handler for the server's response
        self.add_message_handler(SubmitTransaction, self.on_submit_tx)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockMined, self.on_block_mined)

        # Heartbeats
        self.add_message_handler(HeartbeatRequest, self.on_heartbeat_request)
        self.add_message_handler(HeartbeatResponse, self.on_heartbeat_response)

        self.add_message_handler(NewBlock, self.on_new_block)
        self.add_message_handler(ReadyMessage, self.on_ready)


    def started(self) -> None:
        print("starting blockchain community")
        print("starting a peer listener")
        print("my key", pub_key(self.my_peer))
        self.network.add_peer_observer(self)

        

    def on_peer_added(self, peer):
        super().on_peer_added(peer)
        print("Pkey ->", pub_key(peer, True))



    # here we register a task which will be monitor heartbeats.
    def handle_teammate(self, peer):
        peer_id = MEMBER_KEYS[pub_key(peer)]
        self.team_peers[peer_id] = peer
        print("team_peers: ", self.team_peers)
        if len(self.team_peers) == 3:
            group_send(self, list(self.team_peers.values()), ReadyMessage(True))


    def on_peer_removed(self, peer):
        return super().on_peer_removed(peer)
    

    @lazy_wrapper(ReadyMessage)
    def on_ready(self, peer, payload: ReadyMessage):
        if pub_key(peer) not in self.team_ready and pub_key(peer) in MEMBER_KEYS:
            self.team_ready.append(pub_key(peer))

    
    def send_heartbeat(self, peer: Peer):
        peer.ez_send(HeartbeatRequest(0))

    @lazy_wrapper(HeartbeatRequest)
    def on_heartbeat_request(self, peer: Peer, payload: HeartbeatRequest):
        peer.ez_send(HeartbeatResponse(0))

    @lazy_wrapper(HeartbeatResponse)
    def on_heartbeat_response(self, peer: Peer, payload: HeartbeatResponse):
        peer_id = MEMBER_KEYS[pub_key(peer)]
        task_id = f"heartbeat_timeout_{peer_id}"
        heartbeat_task = self.get_task(task_id)
        if heartbeat_task:
            heartbeat_task.cancel()

        self.register_task(task_id, self.on_heartbeat_expired, peer, interval=self.HEARTBEAT_TIMEOUT)
        
    @lazy_wrapper(NewBlock)
    def on_new_block(self, peer, payload: NewBlock):
        print(payload)


            
    def on_heartbeat_expired(self, peer):
        # Log the warning using lazy evaluation
        logger.warning(f"heartbeat of {pub_key(peer)} expired, deleting peer.")
        self.team_peers.pop(MEMBER_KEYS[pub_key(peer)], None)



    def mine_block(self):
        self.next_block.header.txs_hash = hashlib.sha256(self.next_block.tx_hashes).digest()
        timestamp_int = int(time.time())
        self.next_block.header.timestamp = timestamp_int.to_bytes(length=8, byteorder="big")
        self.next_block.header.prev_hash = self.blockchain[-1].block_hash
        nonce = 0

        while True:
            self.next_block.header.nonce = nonce.to_bytes(length=8, byteorder="big")
            self.next_block.block_hash = hashlib.sha256(self.next_block.header).digest() # Q: does this get header bytes as it should?

            if self.next_block.block_hash < self.next_block.header.difficulty:
                # Mined!

                # Now this can go to the real number because we're sure the genesis block was mined
                self.txs_per_block = 4

                self.blockchain.append(self.next_block)

                for tx in self.mempool.values():
                    if tx.hash in self.next_block.tx_hashes:
                        tx.status = "IN-MINED-BLOCK" # Or, could delete, but need to be careful because maybe the final chain will not have it

                block_mined_res = BlockMined(
                    height=self.next_block.header.height,
                    prev_hash=self.next_block.header.prev_hash,
                    txs_hash=self.next_block.header.txs_hash,
                    timestamp=self.next_block.header.timestamp,
                    difficulty=self.next_block.header.difficulty,
                    nonce=self.next_block.header.nonce,
                    block_hash=self.next_block.block_hash,
                    tx_hash=self.next_block.tx_hashes
                )

                
                group_send(self, self.team_peers.values(), block_mined_res)
                self.next_block = self.gen_next_block()

            nonce += 1

    # Handlers

    @lazy_wrapper(SubmitTransaction)
    def on_submit_tx(self, peer, payload: SubmitTransaction) -> None:
        if not is_server(peer):
            return

        # Reconstruct the public key object
        pk_bytes = payload.sender_key
        data_bytes = payload.data
        timestamp_bytes = int.to_bytes(payload.timestamp, length=8, byteorder="big")
        sig_bytes = payload.signature
        public_key_obj = self.crypto.key_from_public_bin(payload.sender_key)

        # Verify the signature
        is_valid = self.crypto.is_valid_signature(
            public_key_obj,
            pk_bytes + data_bytes + timestamp_bytes,
            sig_bytes
        )

        response = None
        hash = hashlib.sha256(pk_bytes + data_bytes + timestamp_bytes + sig_bytes).digest()

        if is_valid:
            print("✓ Valid signature")
            tx = Transaction(pk_bytes, data_bytes, timestamp_bytes, sig_bytes, hash, "IN-POOL")
            self.mempool[hash] = tx
            
            response = SubmitTransactionResponse(success=True, tx_hash=hash, message="Added transaction to pool")
        else:
            print("✗ Invalid signature")
            response = SubmitTransactionResponse(success=False, tx_hash=hash, message="Invalid signature")

        self.ez_send(peer, response)

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer, payload: GetChainHeight) -> None:
        if not is_server(peer):
            return

        height = len(self.blockchain) - 1
        tip_hash = self.blockchain[-1].block_hash
        response = ChainHeightResponse(payload.request_id, height, tip_hash)

        self.ez_send(peer, response)

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer, payload: GetBlock) -> None:
        if not is_server(peer):
            return

        height = payload.height

        if height < 0 or height >= len(self.blockchain):
            return

        block = self.blockchain[height]
        response = BlockResponse(
            height = height,
            prev_hash = block.header.prev_hash,
            txs_hash = block.header.txs_hash,
            timestamp = block.header.timestamp,
            difficulty = block.header.difficulty,
            nonce = block.header.nonce,
            block_hash = block.block_hash,
            tx_hash = block.tx_hashes
        )

        self.ez_send(peer, response)

    @lazy_wrapper(BlockMined)
    def on_block_mined(self, peer, payload: BlockMined) -> None:
        # if not coming from group, early return

        # Now this can go to the real number because we're sure the genesis block was mined
        self.txs_per_block = 4

        # Reset txs from mempool back to IN-POOL

        self.next_block = self.gen_next_block()

        pass


    # Helper functions
    def gen_next_block(self):
        tx_hashes = b""
        n_txs = 0

        # Add txs from mempool
        for tx in self.mempool.values():
            if n_txs >= self.txs_per_block:
                break

            if tx.status == "IN-POOL":
                tx_hashes += tx.hash
                tx.status = "IN-PENDING-BLOCK"
                n_txs += 1

        return (
            Block(
                BlockHeader(
                    prev_hash=self.blockchain[-1].block_hash,
                    txs_hash=b"",
                    timestamp=b"",
                    difficulty=DIFFICULTY,
                    nonce=b""
                ),
                block_hash=b"",
                tx_hashes=tx_hashes,
                n_txs = n_txs
            ))
