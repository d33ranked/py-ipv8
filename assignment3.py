import asyncio
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

SERVER_PUB_KEY = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
SERVER_PUB_KEY_SHA1 = hashlib.sha1(bytes.fromhex(SERVER_PUB_KEY))
COMMUNITY_ID = "4c61623247726f75705369676e696e6732303236"
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
    tx_hashes: bytes
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

GENESIS_BLOCK = Block(
    BlockHeader(b"", hashlib.sha256(b"").digest(), b"", b"", b""),
    b"",
    b"",
    0
)

DIFFICULTY = bytes.fromhex("0000000f" + "f" * 56)


class BlockchainCommunity(Community, PeerObserver):
    # -- Community-related constants here
    HEARTBEAT_INTERVAL = 30 # 30 seconds

    # -- Rest of the varialbes here
    community_id = bytes.fromhex(COMMUNITY_ID)
    server_peer = None


    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)

        self.mempool = []
        self.txs_per_block = 0 # 0 first because it's the genesis block, this is later changed

        # TODO: Should the chain be saved and loaded from disk?
        self.blockchain = []
        self.next_block = GENESIS_BLOCK

        # Register the handler for the server's response
        self.add_message_handler(SubmitTransaction, self.on_submit_tx)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockMined, self.on_block_mined)

    def started(self) -> None:
        print("starting submition community")
        print("starting a peer listener")
        print("my key", pub_key(self.my_peer))
        self.network.add_peer_observer(self)
        

    def on_peer_added(self, peer):
        print("peer added: ", peer)
        print("Pkey ->", pub_key(peer, True))

        if pub_key(peer) in list(MEMBER_KEYS.keys()):
            self.handle_teammate(peer)

        # TODO Find the server and the other 2 group members -> Danil
        # Then we can start
        # Q: Or can we start only knowing the server and not the other miners?

        

    def handle_teammate(self, peer):

        self.register_task("start_heartbeat", self.send_heartbeat, peer, interval=self.HEARTBEAT_INTERVAL)


    def send_heartbeat(self, peer: Peer):
        peer.ez_send()


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

                for tx in self.mempool:
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

                # TODO Tell my peers that I mined it -> Danil

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
            self.mempool.append(tx)

            if self.next_block.n_txs < self.txs_per_block:
                tx.status = "IN-PENDING-BLOCK"
                self.next_block.tx_hashes += hash
                self.next_block.n_txs += 1

                if self.next_block.n_txs == self.txs_per_block:
                    task = asyncio.create_task(self.mine_block()) # TODO Not sure about this

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
            height = block.header.height,
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
    def send_to_peers(self, payload):
        [self.ez_send(peer, payload) for peer in self.submission_peers]

    def gen_next_block(self):
        tx_hashes = b""
        n_txs = 0

        # Add txs from mempool
        for tx in self.mempool:
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

# Helper functions

def all_peers(community: Community) -> list[Peer]:
    all_peers = community.get_peers()
    all_peers.append(community.my_peer)
    return all_peers

def pub_key(peer, short=False):
    return not short and peer.public_key.key_to_bin().hex() or short and peer.public_key.key_to_bin().hex()[-LAST_N:]

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