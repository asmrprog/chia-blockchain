from __future__ import annotations

from secrets import token_bytes
from typing import Any, Dict, Optional

import pytest

from chia.consensus.block_rewards import calculate_base_farmer_reward, calculate_pool_reward
from chia.simulator.full_node_simulator import FullNodeSimulator
from chia.simulator.simulator_protocol import FarmNewBlockProtocol
from chia.simulator.time_out_assert import time_out_assert, time_out_assert_not_none
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.peer_info import PeerInfo
from chia.util.ints import uint16, uint32, uint64
from chia.wallet.cat_wallet.cat_wallet import CATWallet
from chia.wallet.nft_wallet.nft_wallet import NFTWallet
from chia.wallet.outer_puzzles import create_asset_id, match_puzzle
from chia.wallet.puzzle_drivers import PuzzleInfo
from chia.wallet.trading.offer import Offer
from chia.wallet.trading.trade_status import TradeStatus
from chia.wallet.uncurried_puzzle import uncurry_puzzle
from chia.wallet.util.debug_spend_bundle import disassemble
from tests.wallet.nft_wallet.test_nft_1_offers import mempool_not_empty


async def get_trade_and_status(trade_manager, trade) -> TradeStatus:  # type: ignore
    trade_rec = await trade_manager.get_trade_by_id(trade.trade_id)
    return TradeStatus(trade_rec.status)


@pytest.mark.parametrize(
    "trusted",
    [False],
)
@pytest.mark.parametrize(
    "forwards_compat",
    [True, False],
)
@pytest.mark.parametrize(
    "reuse_puzhash",
    [True, False],
)
@pytest.mark.asyncio
async def test_nft_offer_with_fee(
    self_hostname: str, two_wallet_nodes: Any, trusted: Any, forwards_compat: bool, reuse_puzhash: bool
) -> None:
    full_nodes, wallets, _ = two_wallet_nodes
    full_node_api: FullNodeSimulator = full_nodes[0]
    full_node_server = full_node_api.server
    wallet_node_0, server_0 = wallets[0]
    wallet_node_1, server_1 = wallets[1]
    wallet_maker = wallet_node_0.wallet_state_manager.main_wallet
    wallet_taker = wallet_node_1.wallet_state_manager.main_wallet

    maker_ph = await wallet_maker.get_new_puzzlehash()
    taker_ph = await wallet_taker.get_new_puzzlehash()
    token_ph = bytes32(token_bytes())

    if trusted:
        wallet_node_0.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
        wallet_node_1.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
    else:
        wallet_node_0.config["trusted_peers"] = {}
        wallet_node_1.config["trusted_peers"] = {}

    await server_0.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)
    await server_1.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(maker_ph))
    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(taker_ph))

    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    funds = sum([calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i)) for i in range(1, 2)])

    await time_out_assert(20, wallet_maker.get_unconfirmed_balance, funds)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, funds)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    nft_wallet_maker = await NFTWallet.create_new_nft_wallet(
        wallet_node_0.wallet_state_manager, wallet_maker, name="NFT WALLET 1"
    )

    nft_wallet_taker = await NFTWallet.create_new_nft_wallet(
        wallet_node_1.wallet_state_manager, wallet_taker, name="NFT WALLET 2"
    )

    trade_manager_maker = wallet_maker.wallet_state_manager.trade_manager
    trade_manager_taker = wallet_taker.wallet_state_manager.trade_manager

    metadata = Program.to(
        [
            ("u", ["https://www.chia.net/img/branding/chia-logo.svg"]),
            ("h", "0xD4584AD463139FA8C0D9F68F4B59F185"),
        ]
    )

    sb = await nft_wallet_maker.generate_new_nft(metadata)
    assert sb
    await time_out_assert_not_none(20, full_node_api.full_node.mempool_manager.get_spendbundle, sb.name())

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)
    coins_maker = await nft_wallet_maker.get_current_nfts()
    assert len(coins_maker) == 1

    assert await nft_wallet_taker.get_nft_count() == 0
    # MAKE FIRST TRADE: 1 NFT for 100 xch
    maker_balance_pre = await wallet_maker.get_confirmed_balance()
    taker_balance_pre = await wallet_taker.get_confirmed_balance()

    nft_to_offer = coins_maker[0]
    nft_info: Optional[PuzzleInfo] = match_puzzle(uncurry_puzzle(nft_to_offer.full_puzzle))
    nft_asset_id: bytes32 = create_asset_id(nft_info)  # type: ignore
    driver_dict: Dict[bytes32, Optional[PuzzleInfo]] = {nft_asset_id: nft_info}

    xch_request = 100
    maker_fee = uint64(10)
    offer_nft_for_xch = {wallet_maker.id(): xch_request, nft_asset_id: -1}
    maker_unused_index = (
        await wallet_maker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(uint32(1))
    ).index
    taker_unused_index = (
        await wallet_taker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(uint32(1))
    ).index

    if forwards_compat:
        old_maker_offer = Offer.from_bytes(
            bytes.fromhex(
                "000000030000000000000000000000000000000000000000000000000000000000000000bae24162efbd568f89bc7a340798a6118df0189eb9e3f8697bcea27af99f8f790000000000000000ff02ffff01ff02ff0affff04ff02ffff04ff03ff80808080ffff04ffff01ffff333effff02ffff03ff05ffff01ff04ffff04ff0cffff04ffff02ff1effff04ff02ffff04ff09ff80808080ff808080ffff02ff16ffff04ff02ffff04ff19ffff04ffff02ff0affff04ff02ffff04ff0dff80808080ff808080808080ff8080ff0180ffff02ffff03ff05ffff01ff04ffff04ff08ff0980ffff02ff16ffff04ff02ffff04ff0dffff04ff0bff808080808080ffff010b80ff0180ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff1effff04ff02ffff04ff09ff80808080ffff02ff1effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffffa00605d20b106c9c91eb25b25725265f1a1fdb5c2a1de2664a639c3f40857bd57affffa066f9d0199a23435445559963348176a0f30cd62bb94e39076478947da01fae2aff64ff808080805d89ea82434984abc9111a9c33fddd38e391f7dac92ffacdad90a80735f62bfc265445599b4e4242d845fb085dee29fda21ad5614d65fc46b27f8065eac140f70000000000000001ff02ffff01ff02ffff01ff02ffff03ffff18ff2fff3480ffff01ff04ffff04ff20ffff04ff2fff808080ffff04ffff02ff3effff04ff02ffff04ff05ffff04ffff02ff2affff04ff02ffff04ff27ffff04ffff02ffff03ff77ffff01ff02ff36ffff04ff02ffff04ff09ffff04ff57ffff04ffff02ff2effff04ff02ffff04ff05ff80808080ff808080808080ffff011d80ff0180ffff04ffff02ffff03ff77ffff0181b7ffff015780ff0180ff808080808080ffff04ff77ff808080808080ffff02ff3affff04ff02ffff04ff05ffff04ffff02ff0bff5f80ffff01ff8080808080808080ffff01ff088080ff0180ffff04ffff01ffffffff4947ff0233ffff0401ff0102ffffff20ff02ffff03ff05ffff01ff02ff32ffff04ff02ffff04ff0dffff04ffff0bff3cffff0bff34ff2480ffff0bff3cffff0bff3cffff0bff34ff2c80ff0980ffff0bff3cff0bffff0bff34ff8080808080ff8080808080ffff010b80ff0180ffff02ffff03ffff22ffff09ffff0dff0580ff2280ffff09ffff0dff0b80ff2280ffff15ff17ffff0181ff8080ffff01ff0bff05ff0bff1780ffff01ff088080ff0180ff02ffff03ff0bffff01ff02ffff03ffff02ff26ffff04ff02ffff04ff13ff80808080ffff01ff02ffff03ffff20ff1780ffff01ff02ffff03ffff09ff81b3ffff01818f80ffff01ff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff34ff808080808080ffff01ff04ffff04ff23ffff04ffff02ff36ffff04ff02ffff04ff09ffff04ff53ffff04ffff02ff2effff04ff02ffff04ff05ff80808080ff808080808080ff738080ffff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff34ff8080808080808080ff0180ffff01ff088080ff0180ffff01ff04ff13ffff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff17ff8080808080808080ff0180ffff01ff02ffff03ff17ff80ffff01ff088080ff018080ff0180ffffff02ffff03ffff09ff09ff3880ffff01ff02ffff03ffff18ff2dffff010180ffff01ff0101ff8080ff0180ff8080ff0180ff0bff3cffff0bff34ff2880ffff0bff3cffff0bff3cffff0bff34ff2c80ff0580ffff0bff3cffff02ff32ffff04ff02ffff04ff07ffff04ffff0bff34ff3480ff8080808080ffff0bff34ff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff03ffff21ff17ffff09ff0bff158080ffff01ff04ff30ffff04ff0bff808080ffff01ff088080ff0180ff018080ffff04ffff01ffa07faa3253bfddd1e0decb0906b2dc6247bbc4cf608f58345d173adb63e8b47c9fffa0a14daf55d41ced6419bcd011fbc1f74ab9567fe55340d88435aa6493d628fa47a0eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9ffff04ffff01ff02ffff01ff02ffff01ff02ff3effff04ff02ffff04ff05ffff04ffff02ff2fff5f80ffff04ff80ffff04ffff04ffff04ff0bffff04ff17ff808080ffff01ff808080ffff01ff8080808080808080ffff04ffff01ffffff0233ff04ff0101ffff02ff02ffff03ff05ffff01ff02ff1affff04ff02ffff04ff0dffff04ffff0bff12ffff0bff2cff1480ffff0bff12ffff0bff12ffff0bff2cff3c80ff0980ffff0bff12ff0bffff0bff2cff8080808080ff8080808080ffff010b80ff0180ffff0bff12ffff0bff2cff1080ffff0bff12ffff0bff12ffff0bff2cff3c80ff0580ffff0bff12ffff02ff1affff04ff02ffff04ff07ffff04ffff0bff2cff2c80ff8080808080ffff0bff2cff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff03ff0bffff01ff02ffff03ffff09ff23ff1880ffff01ff02ffff03ffff18ff81b3ff2c80ffff01ff02ffff03ffff20ff1780ffff01ff02ff3effff04ff02ffff04ff05ffff04ff1bffff04ff33ffff04ff2fffff04ff5fff8080808080808080ffff01ff088080ff0180ffff01ff04ff13ffff02ff3effff04ff02ffff04ff05ffff04ff1bffff04ff17ffff04ff2fffff04ff5fff80808080808080808080ff0180ffff01ff02ffff03ffff09ff23ffff0181e880ffff01ff02ff3effff04ff02ffff04ff05ffff04ff1bffff04ff17ffff04ffff02ffff03ffff22ffff09ffff02ff2effff04ff02ffff04ff53ff80808080ff82014f80ffff20ff5f8080ffff01ff02ff53ffff04ff818fffff04ff82014fffff04ff81b3ff8080808080ffff01ff088080ff0180ffff04ff2cff8080808080808080ffff01ff04ff13ffff02ff3effff04ff02ffff04ff05ffff04ff1bffff04ff17ffff04ff2fffff04ff5fff80808080808080808080ff018080ff0180ffff01ff04ffff04ff18ffff04ffff02ff16ffff04ff02ffff04ff05ffff04ff27ffff04ffff0bff2cff82014f80ffff04ffff02ff2effff04ff02ffff04ff818fff80808080ffff04ffff0bff2cff0580ff8080808080808080ff378080ff81af8080ff0180ff018080ffff04ffff01a0a04d9f57764f54a43e4030befb4d80026e870519aaa66334aef8304f5d0393c2ffff04ffff01ffff75ffaf68747470733a2f2f7777772e636869612e6e65742f696d672f6272616e64696e672f636869612d6c6f676f2e73766780ffff68a23078443435383441443436333133394641384330443946363846344235394631383580ffff04ffff01a0fe8a4b4e27a2e29a4d3fc7ce9d527adbcaccbab6ada3903ccf3ba9a769d2d78bffff04ffff01ff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b0a3b0219722055ac0a66cd9de5cd3e86962d8c8ec6abb801b57e5c77ed98453b02ceae0e19548f6d4fc20b3a2ec82aa90ff018080ff018080808080ff01808080ffffa0a14daf55d41ced6419bcd011fbc1f74ab9567fe55340d88435aa6493d628fa47ffa014fb5148d6add7dcc06610a9b42ee0dcd0e1fe8b569bc0ac7399ece54d0f231cff0180ff01ffffff80ffff01ffff33ffa0bae24162efbd568f89bc7a340798a6118df0189eb9e3f8697bcea27af99f8f79ff01ffffa0bae24162efbd568f89bc7a340798a6118df0189eb9e3f8697bcea27af99f8f798080ffff3cffa02bbcc5211c70ae28112d7e656a2ac5f5f59cd9c79c605e3a46f014c5b326343480ffff3fffa00740c6d197f7526a49240a15eb7c5db8182b7340d52b096488b6dbf9603e43d48080ff808080809563629e653a9fc3c65f55947883a47e062e6b67394091228ec01352ff78f333e4fb5940aef16e2c6cfed28ea3934dada96f4ce2b629b17cd482eb31f6a6c5590000003a352943ffff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b080399dec21ec7ab66ed0b43811652c2c27c16e2f304b8e2900d7f510448675ef9d8be70ba19e6b6675c4d9bb5f75ced4ff018080ff80ffff01ffff33ffa0b48f3fccb3bbfe6a91496634bede07814b8e5a96a8c4779785398f0ca15f63dbff853a352943f580ffff34ff0a80ffff3cffa077abcb346d27a62c9ddbc65b749e329f07e6912d9c0811962cf148c3cfb6990280ffff3dffa0ba338627c171c11df8cc29435c86a1a45398d11770a63d46bdab9b7dc03701118080ff80808f9d4da9391b8d32dcc12832d511608e244c74719e20e7e004f4220d7c28f568559a7aeed3ccb048e7f54635f1b0fa4201d42d87bb241286eda440e6de027cbe66f6e177bd2335c7e054c760a191dce813c2261cc90fc887b81d543e7f695f15"  # noqa: E501
            )
        )
    else:
        success, trade_make, error = await trade_manager_maker.create_offer_for_ids(
            offer_nft_for_xch, driver_dict, fee=maker_fee, reuse_puzhash=reuse_puzhash
        )
        assert success is True
        assert error is None
        assert trade_make is not None

    taker_fee = uint64(1)

    peer = wallet_node_1.get_full_node_peer()
    trade_take, tx_records = await trade_manager_taker.respond_to_offer(
        old_maker_offer if forwards_compat else Offer.from_bytes(trade_make.offer),
        peer,
        fee=taker_fee,
        reuse_puzhash=reuse_puzhash and not forwards_compat,
    )
    assert trade_take is not None
    assert tx_records is not None

    await full_node_api.process_transaction_records(records=tx_records)
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    if not forwards_compat:
        await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_maker, trade_make)
    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_taker, trade_take)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, maker_balance_pre + xch_request - maker_fee)
    await time_out_assert(20, wallet_taker.get_confirmed_balance, taker_balance_pre - xch_request - taker_fee)
    coins_taker = await nft_wallet_taker.get_current_nfts()
    assert len(coins_taker) == 1

    assert await nft_wallet_maker.get_nft_count() == 0
    if not forwards_compat:
        if reuse_puzhash:
            # Check if unused index changed
            assert (
                maker_unused_index
                == (
                    await wallet_maker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(
                        uint32(1)
                    )
                ).index
            )
            assert (
                taker_unused_index
                == (
                    await wallet_taker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(
                        uint32(1)
                    )
                ).index
            )
        else:
            assert (
                maker_unused_index
                < (
                    await wallet_maker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(
                        uint32(1)
                    )
                ).index
            )
            assert (
                taker_unused_index
                < (
                    await wallet_taker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(
                        uint32(1)
                    )
                ).index
            )
    # MAKE SECOND TRADE: 100 xch for 1 NFT

    maker_balance_pre = await wallet_maker.get_confirmed_balance()
    taker_balance_pre = await wallet_taker.get_confirmed_balance()

    nft_to_buy = coins_taker[0]
    nft_to_buy_info: Optional[PuzzleInfo] = match_puzzle(uncurry_puzzle(nft_to_buy.full_puzzle))
    nft_to_buy_asset_id: bytes32 = create_asset_id(nft_to_buy_info)  # type: ignore
    driver_dict_to_buy: Dict[bytes32, Optional[PuzzleInfo]] = {nft_to_buy_asset_id: nft_to_buy_info}

    xch_offered = 1000
    maker_fee = uint64(10)
    offer_xch_for_nft = {wallet_maker.id(): -xch_offered, nft_to_buy_asset_id: 1}

    if forwards_compat:
        old_maker_offer = Offer.from_bytes(
            bytes.fromhex(
                "0000000200000000000000000000000000000000000000000000000000000000000000002db044f007e82a3146f47c2273954ce81da226888ea1c4f2f0f36d305cedaad80000000000000000ff02ffff01ff02ffff01ff02ffff03ffff18ff2fff3480ffff01ff04ffff04ff20ffff04ff2fff808080ffff04ffff02ff3effff04ff02ffff04ff05ffff04ffff02ff2affff04ff02ffff04ff27ffff04ffff02ffff03ff77ffff01ff02ff36ffff04ff02ffff04ff09ffff04ff57ffff04ffff02ff2effff04ff02ffff04ff05ff80808080ff808080808080ffff011d80ff0180ffff04ffff02ffff03ff77ffff0181b7ffff015780ff0180ff808080808080ffff04ff77ff808080808080ffff02ff3affff04ff02ffff04ff05ffff04ffff02ff0bff5f80ffff01ff8080808080808080ffff01ff088080ff0180ffff04ffff01ffffffff4947ff0233ffff0401ff0102ffffff20ff02ffff03ff05ffff01ff02ff32ffff04ff02ffff04ff0dffff04ffff0bff3cffff0bff34ff2480ffff0bff3cffff0bff3cffff0bff34ff2c80ff0980ffff0bff3cff0bffff0bff34ff8080808080ff8080808080ffff010b80ff0180ffff02ffff03ffff22ffff09ffff0dff0580ff2280ffff09ffff0dff0b80ff2280ffff15ff17ffff0181ff8080ffff01ff0bff05ff0bff1780ffff01ff088080ff0180ff02ffff03ff0bffff01ff02ffff03ffff02ff26ffff04ff02ffff04ff13ff80808080ffff01ff02ffff03ffff20ff1780ffff01ff02ffff03ffff09ff81b3ffff01818f80ffff01ff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff34ff808080808080ffff01ff04ffff04ff23ffff04ffff02ff36ffff04ff02ffff04ff09ffff04ff53ffff04ffff02ff2effff04ff02ffff04ff05ff80808080ff808080808080ff738080ffff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff34ff8080808080808080ff0180ffff01ff088080ff0180ffff01ff04ff13ffff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff17ff8080808080808080ff0180ffff01ff02ffff03ff17ff80ffff01ff088080ff018080ff0180ffffff02ffff03ffff09ff09ff3880ffff01ff02ffff03ffff18ff2dffff010180ffff01ff0101ff8080ff0180ff8080ff0180ff0bff3cffff0bff34ff2880ffff0bff3cffff0bff3cffff0bff34ff2c80ff0580ffff0bff3cffff02ff32ffff04ff02ffff04ff07ffff04ffff0bff34ff3480ff8080808080ffff0bff34ff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff03ffff21ff17ffff09ff0bff158080ffff01ff04ff30ffff04ff0bff808080ffff01ff088080ff0180ff018080ffff04ffff01ffa07faa3253bfddd1e0decb0906b2dc6247bbc4cf608f58345d173adb63e8b47c9fffa0a14daf55d41ced6419bcd011fbc1f74ab9567fe55340d88435aa6493d628fa47a0eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9ffff04ffff01ff02ffff01ff02ffff01ff02ff3effff04ff02ffff04ff05ffff04ffff02ff2fff5f80ffff04ff80ffff04ffff04ffff04ff0bffff04ff17ff808080ffff01ff808080ffff01ff8080808080808080ffff04ffff01ffffff0233ff04ff0101ffff02ff02ffff03ff05ffff01ff02ff1affff04ff02ffff04ff0dffff04ffff0bff12ffff0bff2cff1480ffff0bff12ffff0bff12ffff0bff2cff3c80ff0980ffff0bff12ff0bffff0bff2cff8080808080ff8080808080ffff010b80ff0180ffff0bff12ffff0bff2cff1080ffff0bff12ffff0bff12ffff0bff2cff3c80ff0580ffff0bff12ffff02ff1affff04ff02ffff04ff07ffff04ffff0bff2cff2c80ff8080808080ffff0bff2cff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff03ff0bffff01ff02ffff03ffff09ff23ff1880ffff01ff02ffff03ffff18ff81b3ff2c80ffff01ff02ffff03ffff20ff1780ffff01ff02ff3effff04ff02ffff04ff05ffff04ff1bffff04ff33ffff04ff2fffff04ff5fff8080808080808080ffff01ff088080ff0180ffff01ff04ff13ffff02ff3effff04ff02ffff04ff05ffff04ff1bffff04ff17ffff04ff2fffff04ff5fff80808080808080808080ff0180ffff01ff02ffff03ffff09ff23ffff0181e880ffff01ff02ff3effff04ff02ffff04ff05ffff04ff1bffff04ff17ffff04ffff02ffff03ffff22ffff09ffff02ff2effff04ff02ffff04ff53ff80808080ff82014f80ffff20ff5f8080ffff01ff02ff53ffff04ff818fffff04ff82014fffff04ff81b3ff8080808080ffff01ff088080ff0180ffff04ff2cff8080808080808080ffff01ff04ff13ffff02ff3effff04ff02ffff04ff05ffff04ff1bffff04ff17ffff04ff2fffff04ff5fff80808080808080808080ff018080ff0180ffff01ff04ffff04ff18ffff04ffff02ff16ffff04ff02ffff04ff05ffff04ff27ffff04ffff0bff2cff82014f80ffff04ffff02ff2effff04ff02ffff04ff818fff80808080ffff04ffff0bff2cff0580ff8080808080808080ff378080ff81af8080ff0180ff018080ffff04ffff01a0a04d9f57764f54a43e4030befb4d80026e870519aaa66334aef8304f5d0393c2ffff04ffff01ffff75ffaf68747470733a2f2f7777772e636869612e6e65742f696d672f6272616e64696e672f636869612d6c6f676f2e73766780ffff68a23078443435383441443436333133394641384330443946363846344235394631383580ffff04ffff01a0fe8a4b4e27a2e29a4d3fc7ce9d527adbcaccbab6ada3903ccf3ba9a769d2d78bffff04ffff01ff02ffff01ff02ff0affff04ff02ffff04ff03ff80808080ffff04ffff01ffff333effff02ffff03ff05ffff01ff04ffff04ff0cffff04ffff02ff1effff04ff02ffff04ff09ff80808080ff808080ffff02ff16ffff04ff02ffff04ff19ffff04ffff02ff0affff04ff02ffff04ff0dff80808080ff808080808080ff8080ff0180ffff02ffff03ff05ffff01ff04ffff04ff08ff0980ffff02ff16ffff04ff02ffff04ff0dffff04ff0bff808080808080ffff010b80ff0180ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff1effff04ff02ffff04ff09ff80808080ffff02ff1effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ff018080808080ff01808080ffffa05840dd0327a2dd8ec33c800bcb67c0c3dffe5c0cfd6bb379c2ce88d76fa31111ffffa08a66292fde9ef08198d996eae0ea21677eb478afeabed8030b1bf42c728f7dccff01ffffa08a66292fde9ef08198d996eae0ea21677eb478afeabed8030b1bf42c728f7dcc808080800b886a919fb63febbe6e515a17917e83893887fec7f96bcdf5f45d245ff25aa4b48f3fccb3bbfe6a91496634bede07814b8e5a96a8c4779785398f0ca15f63db0000003a352943f5ff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b08acbcdc220408ab0065b3d77eab2d15ea7ab6de0765287f64d97b203ff9823d4cc8dde13239531d199de4269ba7e04f6ff018080ff80ffff01ffff33ffa0bae24162efbd568f89bc7a340798a6118df0189eb9e3f8697bcea27af99f8f79ff8203e880ffff33ffa0c842b1a384b8633ac25d0f12bd7b614f86a77642ab6426418750f2b0b86bab2aff853a3529400380ffff34ff0a80ffff3cffa0745e2949ebff7f90fd8adff6d7eac296cada1a9dfee72833fc461c5524ca3c8d80ffff3fffa022ec568790be5ab8181365930907c3089d8af1d0ff6c0aa46e53f03f044685258080ff808084ff176c54138529f96bd332a12a9d7f54b3dad48e91daaa4cb1b41d283de47bf48e0eda97a8e889981b033549fb13670f80f19685101573a6c040f3bae001afadee91b9777c2def763c4645b0ea2235af876bf6f3fbb4c9198a8f6d8846f1ef"  # noqa: E501
            )
        )
    else:
        success, trade_make, error = await trade_manager_maker.create_offer_for_ids(
            offer_xch_for_nft, driver_dict_to_buy, fee=maker_fee
        )
        assert success is True
        assert error is None
        assert trade_make is not None

    taker_fee = uint64(1)

    trade_take, tx_records = await trade_manager_taker.respond_to_offer(
        old_maker_offer if forwards_compat else Offer.from_bytes(trade_make.offer), peer, fee=taker_fee
    )

    assert trade_take is not None
    assert tx_records is not None

    await full_node_api.process_transaction_records(records=tx_records)
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    if not forwards_compat:
        await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_maker, trade_make)
    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_taker, trade_take)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, maker_balance_pre - xch_offered - maker_fee)
    await time_out_assert(20, wallet_taker.get_confirmed_balance, taker_balance_pre + xch_offered - taker_fee)

    assert await nft_wallet_maker.get_nft_count() == 1
    assert await nft_wallet_taker.get_nft_count() == 0


@pytest.mark.parametrize(
    "trusted",
    [False],
)
@pytest.mark.asyncio
async def test_nft_offer_cancellations(self_hostname: str, two_wallet_nodes: Any, trusted: Any) -> None:
    full_nodes, wallets, _ = two_wallet_nodes
    full_node_api: FullNodeSimulator = full_nodes[0]
    full_node_server = full_node_api.server
    wallet_node_0, server_0 = wallets[0]
    wallet_node_1, server_1 = wallets[1]
    wallet_maker = wallet_node_0.wallet_state_manager.main_wallet
    wallet_taker = wallet_node_1.wallet_state_manager.main_wallet

    maker_ph = await wallet_maker.get_new_puzzlehash()
    taker_ph = await wallet_taker.get_new_puzzlehash()
    token_ph = bytes32(token_bytes())

    if trusted:
        wallet_node_0.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
        wallet_node_1.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
    else:
        wallet_node_0.config["trusted_peers"] = {}
        wallet_node_1.config["trusted_peers"] = {}

    await server_0.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)
    await server_1.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(maker_ph))
    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(taker_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    funds = sum([calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i)) for i in range(1, 2)])

    await time_out_assert(20, wallet_maker.get_unconfirmed_balance, funds)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, funds)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    nft_wallet_maker = await NFTWallet.create_new_nft_wallet(
        wallet_node_0.wallet_state_manager, wallet_maker, name="NFT WALLET 1"
    )

    nft_wallet_taker = await NFTWallet.create_new_nft_wallet(
        wallet_node_1.wallet_state_manager, wallet_taker, name="NFT WALLET 2"
    )

    trade_manager_maker = wallet_maker.wallet_state_manager.trade_manager
    # trade_manager_taker = wallet_taker.wallet_state_manager.trade_manager

    metadata = Program.to(
        [
            ("u", ["https://www.chia.net/img/branding/chia-logo.svg"]),
            ("h", "0xD4584AD463139FA8C0D9F68F4B59F185"),
        ]
    )

    sb = await nft_wallet_maker.generate_new_nft(metadata)
    assert sb
    await time_out_assert_not_none(20, full_node_api.full_node.mempool_manager.get_spendbundle, sb.name())

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)
    coins_maker = await nft_wallet_maker.get_current_nfts()
    assert len(coins_maker) == 1
    assert await nft_wallet_taker.get_nft_count() == 0
    # maker creates offer and cancels
    maker_balance_pre = await wallet_maker.get_confirmed_balance()
    # taker_balance_pre = await wallet_taker.get_confirmed_balance()

    nft_to_offer = coins_maker[0]
    nft_info: Optional[PuzzleInfo] = match_puzzle(uncurry_puzzle(nft_to_offer.full_puzzle))
    nft_asset_id: bytes32 = create_asset_id(nft_info)  # type: ignore
    driver_dict: Dict[bytes32, Optional[PuzzleInfo]] = {nft_asset_id: nft_info}

    xch_request = 100
    maker_fee = uint64(10)
    offer_nft_for_xch = {wallet_maker.id(): xch_request, nft_asset_id: -1}

    success, trade_make, error = await trade_manager_maker.create_offer_for_ids(
        offer_nft_for_xch, driver_dict, fee=maker_fee
    )
    assert success is True
    assert error is None
    assert trade_make is not None

    # await trade_manager_maker.cancel_pending_offer(trade_make.trade_id)
    # await time_out_assert(20, get_trade_and_status, TradeStatus.CANCELLED, trade_manager_maker, trade_make)

    cancel_fee = uint64(10)

    txs = await trade_manager_maker.cancel_pending_offer_safely(trade_make.trade_id, fee=cancel_fee)

    await time_out_assert(20, get_trade_and_status, TradeStatus.PENDING_CANCEL, trade_manager_maker, trade_make)
    await full_node_api.process_transaction_records(records=txs)
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    await time_out_assert(20, get_trade_and_status, TradeStatus.CANCELLED, trade_manager_maker, trade_make)

    maker_balance = await wallet_maker.get_confirmed_balance()
    assert maker_balance == maker_balance_pre - cancel_fee
    assert await nft_wallet_maker.get_nft_count() == 1


@pytest.mark.parametrize(
    "trusted",
    [False],
)
@pytest.mark.asyncio
async def test_nft_offer_with_metadata_update(self_hostname: str, two_wallet_nodes: Any, trusted: Any) -> None:
    full_nodes, wallets, _ = two_wallet_nodes
    full_node_api: FullNodeSimulator = full_nodes[0]
    full_node_server = full_node_api.server
    wallet_node_0, server_0 = wallets[0]
    wallet_node_1, server_1 = wallets[1]
    wallet_maker = wallet_node_0.wallet_state_manager.main_wallet
    wallet_taker = wallet_node_1.wallet_state_manager.main_wallet

    maker_ph = await wallet_maker.get_new_puzzlehash()
    taker_ph = await wallet_taker.get_new_puzzlehash()
    token_ph = bytes32(token_bytes())

    if trusted:
        wallet_node_0.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
        wallet_node_1.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
    else:
        wallet_node_0.config["trusted_peers"] = {}
        wallet_node_1.config["trusted_peers"] = {}

    await server_0.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)
    await server_1.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(maker_ph))
    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(taker_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    funds = sum([calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i)) for i in range(1, 2)])

    await time_out_assert(20, wallet_maker.get_unconfirmed_balance, funds)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, funds)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    nft_wallet_maker = await NFTWallet.create_new_nft_wallet(
        wallet_node_0.wallet_state_manager, wallet_maker, name="NFT WALLET 1"
    )

    nft_wallet_taker = await NFTWallet.create_new_nft_wallet(
        wallet_node_1.wallet_state_manager, wallet_taker, name="NFT WALLET 2"
    )

    trade_manager_maker = wallet_maker.wallet_state_manager.trade_manager
    trade_manager_taker = wallet_taker.wallet_state_manager.trade_manager

    metadata = Program.to(
        [
            ("u", ["https://www.chia.net/img/branding/chia-logo.svg"]),
            ("h", "0xD4584AD463139FA8C0D9F68F4B59F185"),
            ("mu", []),
            ("lu", []),
            ("sn", uint64(1)),
            ("st", uint64(1)),
        ]
    )

    sb = await nft_wallet_maker.generate_new_nft(metadata)
    assert sb
    await time_out_assert_not_none(20, full_node_api.full_node.mempool_manager.get_spendbundle, sb.name())

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)
    coins_maker = await nft_wallet_maker.get_current_nfts()
    assert len(coins_maker) == 1
    assert await nft_wallet_taker.get_nft_count() == 0

    # Maker updates metadata:
    nft_to_update = coins_maker[0]
    url_to_add = "https://new_url.com"
    key = "mu"
    fee_for_update = uint64(10)
    update_sb = await nft_wallet_maker.update_metadata(nft_to_update, key, url_to_add, fee=fee_for_update)
    mempool_mgr = full_node_api.full_node.mempool_manager
    await time_out_assert_not_none(20, mempool_mgr.get_spendbundle, update_sb.name())  # type: ignore

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    coins_maker = await nft_wallet_maker.get_current_nfts()
    updated_nft = coins_maker[0]
    updated_nft_info = match_puzzle(uncurry_puzzle(updated_nft.full_puzzle))

    assert url_to_add in disassemble(updated_nft_info.also().info["metadata"])  # type: ignore

    # MAKE FIRST TRADE: 1 NFT for 100 xch
    maker_balance_pre = await wallet_maker.get_confirmed_balance()
    taker_balance_pre = await wallet_taker.get_confirmed_balance()

    nft_to_offer = coins_maker[0]
    nft_info: Optional[PuzzleInfo] = match_puzzle(uncurry_puzzle(nft_to_offer.full_puzzle))
    nft_asset_id: bytes32 = create_asset_id(nft_info)  # type: ignore
    driver_dict: Dict[bytes32, Optional[PuzzleInfo]] = {nft_asset_id: nft_info}

    xch_request = 100
    maker_fee = uint64(10)
    offer_nft_for_xch = {wallet_maker.id(): xch_request, nft_asset_id: -1}

    success, trade_make, error = await trade_manager_maker.create_offer_for_ids(
        offer_nft_for_xch, driver_dict, fee=maker_fee
    )
    assert success is True
    assert error is None
    assert trade_make is not None

    taker_fee = uint64(1)

    peer = wallet_node_1.get_full_node_peer()
    trade_take, tx_records = await trade_manager_taker.respond_to_offer(
        Offer.from_bytes(trade_make.offer), peer, fee=taker_fee
    )

    assert trade_take is not None
    assert tx_records is not None

    await full_node_api.process_transaction_records(records=tx_records)
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_maker, trade_make)
    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_taker, trade_take)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, maker_balance_pre + xch_request - maker_fee)
    await time_out_assert(20, wallet_taker.get_confirmed_balance, taker_balance_pre - xch_request - taker_fee)

    assert await nft_wallet_maker.get_nft_count() == 0
    assert await nft_wallet_taker.get_nft_count() == 1


@pytest.mark.parametrize(
    "trusted",
    [False],
)
@pytest.mark.parametrize(
    "reuse_puzhash",
    [True, False],
)
@pytest.mark.asyncio
async def test_nft_offer_nft_for_cat(
    self_hostname: str,
    two_wallet_nodes: Any,
    trusted: Any,
    reuse_puzhash: bool,
) -> None:
    full_nodes, wallets, _ = two_wallet_nodes
    full_node_api: FullNodeSimulator = full_nodes[0]
    full_node_server = full_node_api.server
    wallet_node_0, server_0 = wallets[0]
    wallet_node_1, server_1 = wallets[1]
    wallet_maker = wallet_node_0.wallet_state_manager.main_wallet
    wallet_taker = wallet_node_1.wallet_state_manager.main_wallet

    maker_ph = await wallet_maker.get_new_puzzlehash()
    taker_ph = await wallet_taker.get_new_puzzlehash()
    token_ph = bytes32(token_bytes())

    if trusted:
        wallet_node_0.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
        wallet_node_1.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
    else:
        wallet_node_0.config["trusted_peers"] = {}
        wallet_node_1.config["trusted_peers"] = {}

    await server_0.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)
    await server_1.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(maker_ph))
    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(taker_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    funds = sum([calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i)) for i in range(1, 2)])

    await time_out_assert(20, wallet_maker.get_unconfirmed_balance, funds)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, funds)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    # Create NFT wallets and nfts for maker and taker
    nft_wallet_maker = await NFTWallet.create_new_nft_wallet(
        wallet_node_0.wallet_state_manager, wallet_maker, name="NFT WALLET 1"
    )

    nft_wallet_taker = await NFTWallet.create_new_nft_wallet(
        wallet_node_1.wallet_state_manager, wallet_taker, name="NFT WALLET 2"
    )

    trade_manager_maker = wallet_maker.wallet_state_manager.trade_manager
    trade_manager_taker = wallet_taker.wallet_state_manager.trade_manager

    metadata = Program.to(
        [
            ("u", ["https://www.chia.net/img/branding/chia-logo.svg"]),
            ("h", "0xD4584AD463139FA8C0D9F68F4B59F185"),
        ]
    )

    sb = await nft_wallet_maker.generate_new_nft(metadata)
    assert sb
    await time_out_assert_not_none(20, full_node_api.full_node.mempool_manager.get_spendbundle, sb.name())

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    coins_maker = await nft_wallet_maker.get_current_nfts()
    assert len(coins_maker) == 1
    assert await nft_wallet_taker.get_nft_count() == 0
    # Create two new CATs and wallets for maker and taker
    cats_to_mint = 10000
    async with wallet_node_0.wallet_state_manager.lock:
        cat_wallet_maker: CATWallet = await CATWallet.create_new_cat_wallet(
            wallet_node_0.wallet_state_manager, wallet_maker, {"identifier": "genesis_by_id"}, uint64(cats_to_mint)
        )
        await time_out_assert(20, mempool_not_empty, True, full_node_api)
    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    async with wallet_node_1.wallet_state_manager.lock:
        cat_wallet_taker: CATWallet = await CATWallet.create_new_cat_wallet(
            wallet_node_1.wallet_state_manager, wallet_taker, {"identifier": "genesis_by_id"}, uint64(cats_to_mint)
        )
        await time_out_assert(20, mempool_not_empty, True, full_node_api)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    await time_out_assert(20, cat_wallet_maker.get_confirmed_balance, cats_to_mint)
    await time_out_assert(20, cat_wallet_maker.get_unconfirmed_balance, cats_to_mint)
    await time_out_assert(20, cat_wallet_taker.get_confirmed_balance, cats_to_mint)
    await time_out_assert(20, cat_wallet_taker.get_unconfirmed_balance, cats_to_mint)

    wallet_maker_for_taker_cat: CATWallet = await CATWallet.get_or_create_wallet_for_cat(
        wallet_node_0.wallet_state_manager, wallet_maker, cat_wallet_taker.get_asset_id()
    )

    wallet_taker_for_maker_cat: CATWallet = await CATWallet.get_or_create_wallet_for_cat(
        wallet_node_1.wallet_state_manager, wallet_taker, cat_wallet_maker.get_asset_id()
    )

    assert wallet_taker_for_maker_cat
    # MAKE FIRST TRADE: 1 NFT for 10 taker cats
    maker_balance_pre = await wallet_maker.get_confirmed_balance()
    taker_balance_pre = await wallet_taker.get_confirmed_balance()
    taker_cat_maker_balance_pre = await wallet_maker_for_taker_cat.get_confirmed_balance()
    taker_cat_taker_balance_pre = await cat_wallet_taker.get_confirmed_balance()

    nft_to_offer = coins_maker[0]
    nft_info: Optional[PuzzleInfo] = match_puzzle(uncurry_puzzle(nft_to_offer.full_puzzle))
    nft_asset_id: bytes32 = create_asset_id(nft_info)  # type: ignore
    driver_dict: Dict[bytes32, Optional[PuzzleInfo]] = {nft_asset_id: nft_info}

    maker_fee = uint64(10)
    taker_cat_offered = 2500
    offer_nft_for_cat = {nft_asset_id: -1, wallet_maker_for_taker_cat.id(): taker_cat_offered}
    maker_unused_index = (
        await wallet_maker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(uint32(1))
    ).index
    taker_unused_index = (
        await wallet_taker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(uint32(1))
    ).index

    success, trade_make, error = await trade_manager_maker.create_offer_for_ids(
        offer_nft_for_cat, driver_dict, fee=maker_fee, reuse_puzhash=reuse_puzhash
    )
    assert success is True
    assert error is None
    assert trade_make is not None

    taker_fee = uint64(1)

    peer = wallet_node_1.get_full_node_peer()
    trade_take, tx_records = await trade_manager_taker.respond_to_offer(
        Offer.from_bytes(trade_make.offer),
        peer,
        fee=taker_fee,
        reuse_puzhash=reuse_puzhash,
    )

    assert trade_take is not None
    assert tx_records is not None

    await full_node_api.process_transaction_records(records=tx_records)
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_maker, trade_make)
    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_taker, trade_take)

    taker_cat_maker_balance_post = await wallet_maker_for_taker_cat.get_confirmed_balance()
    taker_cat_taker_balance_post = await cat_wallet_taker.get_confirmed_balance()
    assert taker_cat_maker_balance_post == taker_cat_maker_balance_pre + taker_cat_offered
    assert taker_cat_taker_balance_post == taker_cat_taker_balance_pre - taker_cat_offered
    maker_balance_post = await wallet_maker.get_confirmed_balance()
    taker_balance_post = await wallet_taker.get_confirmed_balance()
    assert maker_balance_post == maker_balance_pre - maker_fee
    assert taker_balance_post == taker_balance_pre - taker_fee
    coins_taker = await nft_wallet_taker.get_current_nfts()
    assert len(coins_taker) == 1

    assert await nft_wallet_maker.get_nft_count() == 0
    if reuse_puzhash:
        # Check if unused index changed
        assert (
            maker_unused_index
            == (
                await wallet_maker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(uint32(1))
            ).index
        )
        assert (
            taker_unused_index
            == (
                await wallet_taker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(uint32(1))
            ).index
        )
    else:
        assert (
            maker_unused_index
            < (
                await wallet_maker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(uint32(1))
            ).index
        )
        assert (
            taker_unused_index
            < (
                await wallet_taker.wallet_state_manager.puzzle_store.get_current_derivation_record_for_wallet(uint32(1))
            ).index
        )
    # Make an offer for taker NFT for multiple cats
    maker_cat_amount = 400
    taker_cat_amount = 500

    nft_to_buy = coins_taker[0]
    nft_to_buy_info: Optional[PuzzleInfo] = match_puzzle(uncurry_puzzle(nft_to_buy.full_puzzle))
    nft_to_buy_asset_id: bytes32 = create_asset_id(nft_to_buy_info)  # type: ignore

    driver_dict_to_buy: Dict[bytes32, Optional[PuzzleInfo]] = {
        nft_to_buy_asset_id: nft_to_buy_info,
    }

    maker_fee = uint64(10)
    offer_multi_cats_for_nft = {
        nft_to_buy_asset_id: 1,
        wallet_maker_for_taker_cat.id(): -taker_cat_amount,
        cat_wallet_maker.id(): -maker_cat_amount,
    }

    success, trade_make, error = await trade_manager_maker.create_offer_for_ids(
        offer_multi_cats_for_nft, driver_dict_to_buy, fee=maker_fee
    )
    assert success is True
    assert error is None
    assert trade_make is not None

    taker_fee = uint64(1)

    trade_take, tx_records = await trade_manager_taker.respond_to_offer(
        Offer.from_bytes(trade_make.offer), peer, fee=taker_fee
    )

    assert trade_take is not None
    assert tx_records is not None

    await full_node_api.process_transaction_records(records=tx_records)
    # check balances: taker wallet down an NFT, up cats
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_maker, trade_make)
    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_taker, trade_take)

    taker_cat_maker_balance_post_2 = await wallet_maker_for_taker_cat.get_confirmed_balance()
    taker_cat_taker_balance_post_2 = await cat_wallet_taker.get_confirmed_balance()
    assert taker_cat_maker_balance_post_2 == taker_cat_maker_balance_post - taker_cat_amount
    assert taker_cat_taker_balance_post_2 == taker_cat_taker_balance_post + taker_cat_amount
    maker_balance_post_2 = await wallet_maker.get_confirmed_balance()
    taker_balance_post_2 = await wallet_taker.get_confirmed_balance()
    assert maker_balance_post_2 == maker_balance_post - maker_fee
    assert taker_balance_post_2 == taker_balance_post - taker_fee
    assert await nft_wallet_maker.get_nft_count() == 1
    assert await nft_wallet_taker.get_nft_count() == 0


@pytest.mark.parametrize(
    "trusted",
    [False],
)
@pytest.mark.asyncio
async def test_nft_offer_nft_for_nft(self_hostname: str, two_wallet_nodes: Any, trusted: Any) -> None:
    full_nodes, wallets, _ = two_wallet_nodes
    full_node_api: FullNodeSimulator = full_nodes[0]
    full_node_server = full_node_api.server
    wallet_node_0, server_0 = wallets[0]
    wallet_node_1, server_1 = wallets[1]
    wallet_maker = wallet_node_0.wallet_state_manager.main_wallet
    wallet_taker = wallet_node_1.wallet_state_manager.main_wallet

    maker_ph = await wallet_maker.get_new_puzzlehash()
    taker_ph = await wallet_taker.get_new_puzzlehash()
    token_ph = bytes32(token_bytes())

    if trusted:
        wallet_node_0.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
        wallet_node_1.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
    else:
        wallet_node_0.config["trusted_peers"] = {}
        wallet_node_1.config["trusted_peers"] = {}

    await server_0.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)
    await server_1.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(maker_ph))
    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(taker_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    funds = sum([calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i)) for i in range(1, 2)])

    await time_out_assert(20, wallet_maker.get_unconfirmed_balance, funds)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, funds)

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    # Create NFT wallets and nfts for maker and taker
    nft_wallet_maker = await NFTWallet.create_new_nft_wallet(
        wallet_node_0.wallet_state_manager, wallet_maker, name="NFT WALLET 1"
    )

    nft_wallet_taker = await NFTWallet.create_new_nft_wallet(
        wallet_node_1.wallet_state_manager, wallet_taker, name="NFT WALLET 2"
    )

    trade_manager_maker = wallet_maker.wallet_state_manager.trade_manager
    trade_manager_taker = wallet_taker.wallet_state_manager.trade_manager

    metadata = Program.to(
        [
            ("u", ["https://www.chia.net/img/branding/chia-logo.svg"]),
            ("h", "0xD4584AD463139FA8C0D9F68F4B59F185"),
        ]
    )

    sb = await nft_wallet_maker.generate_new_nft(metadata)
    assert sb
    await time_out_assert_not_none(20, full_node_api.full_node.mempool_manager.get_spendbundle, sb.name())

    metadata_2 = Program.to(
        [
            ("u", ["https://www.chia.net/image2.html"]),
            ("h", "0xD4584AD463139FA8C0D9F68F4B59F183"),
        ]
    )
    sb_2 = await nft_wallet_taker.generate_new_nft(metadata_2)
    assert sb_2
    await time_out_assert_not_none(20, full_node_api.full_node.mempool_manager.get_spendbundle, sb_2.name())

    await full_node_api.farm_new_transaction_block(FarmNewBlockProtocol(token_ph))
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    coins_maker = await nft_wallet_maker.get_current_nfts()
    assert len(coins_maker) == 1
    coins_taker = await nft_wallet_taker.get_current_nfts()
    assert len(coins_taker) == 1

    maker_balance_pre = await wallet_maker.get_confirmed_balance()
    taker_balance_pre = await wallet_taker.get_confirmed_balance()

    nft_to_offer = coins_maker[0]
    nft_to_offer_info: Optional[PuzzleInfo] = match_puzzle(uncurry_puzzle(nft_to_offer.full_puzzle))
    nft_to_offer_asset_id: bytes32 = create_asset_id(nft_to_offer_info)  # type: ignore

    nft_to_take = coins_taker[0]
    nft_to_take_info: Optional[PuzzleInfo] = match_puzzle(uncurry_puzzle(nft_to_take.full_puzzle))
    nft_to_take_asset_id: bytes32 = create_asset_id(nft_to_take_info)  # type: ignore

    driver_dict: Dict[bytes32, Optional[PuzzleInfo]] = {
        nft_to_offer_asset_id: nft_to_offer_info,
        nft_to_take_asset_id: nft_to_take_info,
    }

    maker_fee = uint64(10)
    offer_nft_for_nft = {nft_to_take_asset_id: 1, nft_to_offer_asset_id: -1}

    success, trade_make, error = await trade_manager_maker.create_offer_for_ids(
        offer_nft_for_nft, driver_dict, fee=maker_fee
    )
    assert success is True
    assert error is None
    assert trade_make is not None

    taker_fee = uint64(1)

    peer = wallet_node_1.get_full_node_peer()
    trade_take, tx_records = await trade_manager_taker.respond_to_offer(
        Offer.from_bytes(trade_make.offer), peer, fee=taker_fee
    )

    assert trade_take is not None
    assert tx_records is not None

    await full_node_api.process_transaction_records(records=tx_records)
    await full_node_api.wait_for_wallets_synced(wallet_nodes=[wallet_node_0, wallet_node_1], timeout=20)

    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_maker, trade_make)
    await time_out_assert(20, get_trade_and_status, TradeStatus.CONFIRMED, trade_manager_taker, trade_take)
    await time_out_assert(20, wallet_maker.get_confirmed_balance, maker_balance_pre - maker_fee)
    await time_out_assert(20, wallet_taker.get_confirmed_balance, taker_balance_pre - taker_fee)

    assert await nft_wallet_maker.get_nft_count() == 1
    assert await nft_wallet_taker.get_nft_count() == 1
