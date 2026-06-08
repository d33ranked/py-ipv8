import asyncio
from asyncio import run

from registration_community import RegistrationCommunity
from blockchain_community import BlockchainCommunity
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs

from ipv8.util import run_forever
from ipv8_service import IPv8

from dotenv import load_dotenv

from utils import *

load_dotenv()

import logging

logger = logging.getLogger(__name__)


async def start_communities():

    shared_state = {
        "server_peer" : None,
        "team_peers": {}
    }

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key(UNI_EMAIL, "curve25519", KEY_PATH)
    builder.add_overlay(
        "RegistrationCommunity",
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
        {
            **shared_state
        },
        [("started",)]
    )
    builder.add_overlay(    
        "BlockchainCommunity",
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
        {
            **shared_state
        },
        [("started",)]        

    )

    

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "RegistrationCommunity": RegistrationCommunity,
            "BlockchainCommunity": BlockchainCommunity
            
        }
    )

    await ipv8.start()

    await run_forever()

def main():
    run(start_communities())

if __name__ == "__main__":
    main()