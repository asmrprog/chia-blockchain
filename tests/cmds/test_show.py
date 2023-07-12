from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.full_block import FullBlock
from chia.util.byte_types import hexstr_to_bytes
from tests.cmds.cmd_test_utils import GlobalTestRpcClients, TestFullNodeRpcClient, cli_assert_shortcut, run_cli_command
from tests.cmds.test_classes import height_hash

BASE_LIST = ["show"]

full_block_bytes = hexstr_to_bytes(
    "0000000000000000000000000000000000000c000000000200000000000000000000000000002f310946c1a3a6deab21e451717264ac5dd66a7b398d0743c9ae982485cce1c44db2ca88c05567ba85d60b4b639064a01070096ef8bf66b642ec0ad6726f190f4317f90181fcb6d215887f694516d3d478253f61e017d20b06b4a7d761c5e63775ce25ec56ca6f9f1adc737a75f38eefd2305fbc00aa35f3f6c49d74e43a1dc8faa1be9ce8adfa6e3c7c0b0b7373aaf2499079afaff346c8fe05ef7eded352b20af66188611300000098de98a766330c493b3c5ea633d614387e3bdc76cc56822551c73e58a8fe640fe23d52860d95665c8402dac1031db42ae683e1c7c8b79ec379ce8f4d1feb94af5eac10c8ab4d3d797bdaf42f7f29503a3d7c1f9a57ffa9eb3594db90ab3daa4c5283a5daa2c3984f5c6e9c406a41b919bf042ecf7cd0ff8e4ba3ef2f52502ae20f9f511439a4c316d1a4ebda4c69ae8e46cef804ca193804d10146c1a3a6deab21e451717264ac5dd66a7b398d0743c9ae982485cce1c44db2ca00000000000002400800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099daf41cfd356d0e166c1a543b78ab1f808b064465df5448478f593d35145712296c8c9f630e4c9676c377e06fbf353c189abdd26db78e8bb81d86ac8adf8bfcfa3942c2070710053290aef712587ee4faea11a60d08ed3be2d3231bb6fc077346c1a3a6deab21e451717264ac5dd66a7b398d0743c9ae982485cce1c44db2ca00000000000003310200200005010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d2d1a5d02523b253f6d5f821e07a68cc6f9542510ab2b98d5c1e71496b9601db000000000000012802003b00040201000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000928fefdd6e5ed147e3d2ce1ef47238e1ab95986b66312d55f15f82a5d43a5ce8b66fcc01b0ff38713ecafbb3a932bb6311c02277c390457d5c97707fd446005976a3b93dde9d27f65ec99fa68c4c26809013652ceec8e149b1ebe95b2c31d718d2d1a5d02523b253f6d5f821e07a68cc6f9542510ab2b98d5c1e71496b9601db0000000000000219030073000201000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000121b65d5fa4f58c5e78190a62cc1f2ea259757a793ee3a4aed137cb2b8d5576120000000000000219000015000203020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000006402001a00030100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000064030017000104020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000006401000a0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006403003300010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000640300070002010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a3fa1d045a172db146ee123d678dfdaa0fcd2182733caacd9e0aef0974dd3683b53f26d33bf5ed96ebd32435014a6b4acec9855ff9fb47f7d99eecf6fa2971b1aeef7da5f68d5c71d78f4677b68e283c9bd23b1d7727a1a82d243b658c7ffb6369b52da8f9fa786c54a07c149f43e8970493cfa5420e20be4bd90ed9a7410b080000000001a425f95b6a2b883fcd0ea85947547d4444b23fff465e119404e0e6550d6d6b8d9211546c0933b76c202c30105876f9630e2c259bbda7469e71353dbf94503731bcf0aeac3e29d19fd16fe37c8384ec9e72df9573554037cd46e107f3679caeec69b52da8f9fa786c54a07c149f43e8970493cfa5420e20be4bd90ed9a7410b080000000000000000000000000000000000000000000000000000000003a2c7c9a8c98aadddf1c94377a491dcf390cb19e33e118cdf33f8b48c9c0bc4f690dbcf0f571d653622399db537c2ad277806331973c444800800fb6a268a7e524d0823455b4c2fd964bdaee8f865e597edc91cb25e719103256cabdde5c9be680ab00a014546771679b0c4c18dc392867a5ebd03594476cd3e5d355c68c7967444631fbb01933f46b1b434ff0b0313e0497beaa39c7f28c699dab32af97e7dd2986fe56a44160fb87bc28f798c75fc13f6db179bda114b997ed972b18fd69b8fec5f96b6ae29d7a891ebea80b0b5a6dab9d9a3ed6fa538a6075d9eb937161d99ede0f5a96001a3fa1d045a172db146ee123d678dfdaa0fcd2182733caacd9e0aef0974dd36830000000064601feab27a3acd8736fdb7288dc29d28df4183dda259e0e067bcdb35f4ac500bebf661f13d815d2bc2ee636864e26a9bdef36e6aab42db931eeeae1f001aa2cd2b0840b2652a803fb7bd375e4b4859b41c4afa4098376e7aecd02d0b22cfe80874ff88cda01d7021810c968040c00c84b0a44ece97ca419512cf9488ab976309e42ffb01eaecb131f18372c6316273523b99474e2176cd5c7ea43361b2cdad315ca8f169010101010101010101010101010101010101010101010101010101010101010199a1501cc845ccf25f3061899dae925c05151b4c1740c8e535619b78ec3977120b20e5447b6043d60c803f005f5e224f10968c3b5f28679195ad4881e60152e463791c45eb4ad603842c647e433bb5687e903f5ddb069587db99148549b193f30000000000000000000000000400159b00000002eb8c4d20b322be8d9fddbf9412016bdf0000000000000000000000000000000169b52da8f9fa786c54a07c149f43e8970493cfa5420e20be4bd90ed9a7410b08000001977420dc00fe9a2901d7edb0e364e94266d0e095f70000000000000000000000000000000169b52da8f9fa786c54a07c149f43e8970493cfa5420e20be4bd90ed9a7410b080000003a3529440001ff01ffffffa0a2fda775e51a4d99a683780224a710ca8ceddcb8380f222154eac4ea697b1732ffff02ffff01ff04ffff04ff04ffff04ff05ffff04ff0bff80808080ffff04ffff04ff0affff04ffff02ff0effff04ff02ffff04ffff04ff05ffff04ff0bffff04ff17ff80808080ff80808080ff808080ff808080ffff04ffff01ff33ff3cff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff0effff04ff02ffff04ff09ff80808080ffff02ff0effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ff01ffffa0fab2c3e50526b8bb6e24e97f36a52f73c251b71aeff8a6b5240a8b15ea91ed70ff01ffffff856f776e657286504552534f4e808080ffffa0a2ff26e55a515c32ac8771ba3a193839def4adcc7f80eea8b1e9f6ae8487a9e9ffff02ffff01ff02ffff01ff02ffff03ffff18ff2fff3480ffff01ff04ffff04ff20ffff04ff2fff808080ffff04ffff02ff3effff04ff02ffff04ff05ffff04ffff02ff2affff04ff02ffff04ff27ffff04ffff02ffff03ff77ffff01ff02ff36ffff04ff02ffff04ff09ffff04ff57ffff04ffff02ff2effff04ff02ffff04ff05ff80808080ff808080808080ffff011d80ff0180ffff04ffff02ffff03ff77ffff0181b7ffff015780ff0180ff808080808080ffff04ff77ff808080808080ffff02ff3affff04ff02ffff04ff05ffff04ffff02ff0bff5f80ffff01ff8080808080808080ffff01ff088080ff0180ffff04ffff01ffffffff4947ff0233ffff0401ff0102ffffff20ff02ffff03ff05ffff01ff02ff32ffff04ff02ffff04ff0dffff04ffff0bff3cffff0bff34ff2480ffff0bff3cffff0bff3cffff0bff34ff2c80ff0980ffff0bff3cff0bffff0bff34ff8080808080ff8080808080ffff010b80ff0180ffff02ffff03ffff22ffff09ffff0dff0580ff2280ffff09ffff0dff0b80ff2280ffff15ff17ffff0181ff8080ffff01ff0bff05ff0bff1780ffff01ff088080ff0180ff02ffff03ff0bffff01ff02ffff03ffff02ff26ffff04ff02ffff04ff13ff80808080ffff01ff02ffff03ffff20ff1780ffff01ff02ffff03ffff09ff81b3ffff01818f80ffff01ff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff34ff808080808080ffff01ff04ffff04ff23ffff04ffff02ff36ffff04ff02ffff04ff09ffff04ff53ffff04ffff02ff2effff04ff02ffff04ff05ff80808080ff808080808080ff738080ffff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff34ff8080808080808080ff0180ffff01ff088080ff0180ffff01ff04ff13ffff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff17ff8080808080808080ff0180ffff01ff02ffff03ff17ff80ffff01ff088080ff018080ff0180ffffff02ffff03ffff09ff09ff3880ffff01ff02ffff03ffff18ff2dffff010180ffff01ff0101ff8080ff0180ff8080ff0180ff0bff3cffff0bff34ff2880ffff0bff3cffff0bff3cffff0bff34ff2c80ff0580ffff0bff3cffff02ff32ffff04ff02ffff04ff07ffff04ffff0bff34ff3480ff8080808080ffff0bff34ff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff03ffff21ff17ffff09ff0bff158080ffff01ff04ff30ffff04ff0bff808080ffff01ff088080ff0180ff018080ffff04ffff01ffa07faa3253bfddd1e0decb0906b2dc6247bbc4cf608f58345d173adb63e8b47c9fffa0a2ff26e55a515c32ac8771ba3a193839def4adcc7f80eea8b1e9f6ae8487a9e9a0eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9ffff04ffff01ff02ffff01ff02ffff01ff02ffff01ff02ffff01ff02ffff03ff8205ffffff01ff04ffff04ff10ffff04ff2fffff04ffff02ff3effff04ff02ffff04ff8205ffffff04ff8202ffff8080808080ff80808080ffff04ffff04ff34ffff04ffff02ff36ffff04ff02ffff04ff17ffff04ffff02ff3effff04ff02ffff04ff17ff80808080ffff04ffff02ff3effff04ff02ffff04ff8202ffff80808080ffff04ffff02ff3effff04ff02ffff04ff8205ffff80808080ff80808080808080ffff01ff01808080ff808080ffff01ff02ffff03ff82017fffff01ff04ffff04ff10ffff04ff2fffff04ffff02ff3effff04ff02ffff04ff81bfffff04ffff02ffff03ff8202ffffff018202ffffff015f80ff0180ff8080808080ff80808080ffff04ffff04ff28ffff04ff81bfff808080ffff04ffff04ff2cffff04ffff0bff0bff81bf80ff808080ffff04ffff04ff38ffff04ffff0bff05ffff0bff0bff81bf8080ff808080ffff04ffff04ff34ffff04ffff02ff36ffff04ff02ffff04ff17ffff04ffff02ff3effff04ff02ffff04ff17ff80808080ffff04ffff02ff3effff04ff02ffff04ffff02ffff03ff8202ffffff018202ffffff015f80ff0180ff80808080ffff04ffff02ff3effff04ff02ffff04ff2fff80808080ff80808080808080ffff01ff01808080ff808080808080ffff01ff04ffff04ff10ffff04ff2fffff04ffff02ff3effff04ff02ffff04ff8202ffff80808080ff80808080ffff04ffff04ff2cffff04ffff0bff0bff81bf80ff808080ffff04ffff04ff34ffff04ffff02ff36ffff04ff02ffff04ff17ffff04ffff02ff3effff04ff02ffff04ff17ff80808080ffff04ffff02ff3effff04ff02ffff04ff8202ffff80808080ffff04ffff02ff3effff04ff02ffff04ff2fff80808080ff80808080808080ffff01ff01808080ff8080808080ff018080ff0180ffff04ffff01ffffff32ff473fffff0233ff3e04ffff01ff0102ffffff02ffff03ff05ffff01ff02ff26ffff04ff02ffff04ff0dffff04ffff0bff3affff0bff12ff3c80ffff0bff3affff0bff3affff0bff12ff2a80ff0980ffff0bff3aff0bffff0bff12ff8080808080ff8080808080ffff010b80ff0180ff02ff2effff04ff02ffff04ff05ffff04ff17ffff04ff2fffff04ff0bff80808080808080ffff0bff3affff0bff12ff2480ffff0bff3affff0bff3affff0bff12ff2a80ff0580ffff0bff3affff02ff26ffff04ff02ffff04ff07ffff04ffff0bff12ff1280ff8080808080ffff0bff12ff8080808080ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff3effff04ff02ffff04ff09ff80808080ffff02ff3effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01a07bb18ebcdbee14e01c44110f46c439bc96d155406e39a0adc3b21b41d49c79a2ff018080ffff04ffff018a4a61636b31792e786368ff018080ffff04ffff01a04eece8333f1e46e6307061256cb179e46dab770a319e4a2f8d3f482fbbf2c733ffff04ffff01b0b094f390a391d10eda509f3f8fade8e3e432a6f0d1ad078108814fdfc43f81f6efd714692450c4f75228b9746eef4095ffff04ffff01ffff856f776e657286504552534f4e80ff0180808080ff01808080ff01ffffffa0a2fda775e51a4d99a683780224a710ca8ceddcb8380f222154eac4ea697b1732ff0180ff01ffffa0a2ff26e55a515c32ac8771ba3a193839def4adcc7f80eea8b1e9f6ae8487a9e9ff01ff80ff80808080ffffa0a2fda775e51a4d99a683780224a710ca8ceddcb8380f222154eac4ea697b1732ffff02ffff01ff02ffff01ff02ff3effff04ff02ffff04ff05ffff04ff0bffff04ff17ffff04ff2fffff04ff5fffff04ff81bfffff04ffff0bff2fff82017f80ff80808080808080808080ffff04ffff01ffffff3f02ff33ff3e04ffff01ff0102ffff02ffff03ff05ffff01ff02ff16ffff04ff02ffff04ff0dffff04ffff0bff3affff0bff12ff3c80ffff0bff3affff0bff3affff0bff12ff2a80ff0980ffff0bff3aff0bffff0bff12ff8080808080ff8080808080ffff010b80ff0180ffff0bff3affff0bff12ff1880ffff0bff3affff0bff3affff0bff12ff2a80ff0580ffff0bff3affff02ff16ffff04ff02ffff04ff07ffff04ffff0bff12ff1280ff8080808080ffff0bff12ff8080808080ff04ffff04ff10ffff04ffff0bff5fff82017f80ff808080ffff04ffff04ff2cffff04ff82017fff808080ffff04ffff04ff14ffff04ff0bffff04ff17ff80808080ffff04ffff04ff14ffff04ffff02ff2effff04ff02ffff04ff05ffff04ffff0bffff0101ff2f80ff8080808080ffff04ffff0101ffff04ffff04ff81bfff8080ff8080808080ff8080808080ff018080ffff04ffff01a0989379ca2baa34863789a365b20764bd6aae0b7c72f5dca9de6ca1cf132d5abeffff04ffff01a0b0046b08ca25e28f947d1344b2ccc983be7fc8097a8f353cca43f2c54117a429ffff04ffff018502540be400ff0180808080ff8502540be401ffff8a4a61636b31792e786368ffa0fab2c3e50526b8bb6e24e97f36a52f73c251b71aeff8a6b5240a8b15ea91ed70ffa0a2ff26e55a515c32ac8771ba3a193839def4adcc7f80eea8b1e9f6ae8487a9e9ffa0a2ff26e55a515c32ac8771ba3a193839def4adcc7f80eea8b1e9f6ae8487a9e98080ffffa0fe9a2901d7edb0e364e94266d0e095f700000000000000000000000000000000ffff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b0a3b18f823c5d6b0aa443b4e10451f1a8b2dc0f9cb71d9dfd08de5d87999142057025853ae9c50e34ae43af8758accd7bff018080ff88246ddf9797668000ffff80ffff01ffff33ffa0eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9ff0180ffff33ffa07bb18ebcdbee14e01c44110f46c439bc96d155406e39a0adc3b21b41d49c79a2ff8502540be40180ffff33ffa0da03aeeab792425415eb348363eb6aee945fdc4489dbc73a757f5fa7ae81da4cff88246ddf95435a9bfe80ffff3cffa03a443244caebc9782f8f0efb113a6e6acd5c931e1538944cfebba1e561077e7580ffff3dffa03d8e44161d71d2dd5f0907adb08d21a8d7eb9427e6e2d0d46320383289ee3b2b80ffff3fffa0e0e24248e67e067df2d5ae59cd1e63e5279e2076670c9f87427bc04be6cda8558080ff808080808000000000"  # noqa: E501
)


@dataclass
class ShowFullNodeRpcClient(TestFullNodeRpcClient):
    async def get_fee_estimate(self, target_times: Optional[List[int]], cost: Optional[int]) -> Dict[str, Any]:
        response: Dict[str, Any] = {
            "current_fee_rate": 0,
            "estimates": [0, 0, 0],
            "fee_rate_last_block": 30769.681426718744,
            "fees_last_block": 500000000000,
            "full_node_synced": True,
            "last_block_cost": 16249762,
            "last_peak_timestamp": 1688858763,
            "last_tx_block_height": 32,
            "mempool_fees": 0,
            "mempool_max_size": 0,
            "mempool_size": 0,
            "node_time_utc": 1689187617,
            "num_spends": 0,
            "peak_height": 32,
            "success": True,
            "target_times": target_times,
        }
        self.rpc_log["get_fee_estimate"] = (target_times, cost)
        return response

    async def get_block(self, header_hash: bytes32) -> Optional[FullBlock]:
        # we return a block with height 2
        self.rpc_log["get_block"] = (header_hash,)
        return FullBlock.from_bytes(full_block_bytes)


RPC_CLIENT_TO_USE = ShowFullNodeRpcClient()  # pylint: disable=no-value-for-parameter


def test_chia_show(capsys: Any, get_global_cli_clients: GlobalTestRpcClients) -> None:
    # set RPC Client
    get_global_cli_clients.full_node_rpc_client = RPC_CLIENT_TO_USE
    # get output with all options
    command_args = ["-s", "-f", "-bh 1", "-b 0000000000000000000000000000000000000000000000000000000000000002"]
    success, output = run_cli_command(capsys, BASE_LIST + command_args)
    assert success
    # these are various things that should be in the output
    assert_list = [
        "Current Blockchain Status: Full Node Synced",
        "Estimated network space: 25.647 EiB",
        "Block fees: 500000000000 mojos",
        "Fee rate:    3.077e+04 mojos per CLVM cost",
        "Tx Filter Hash         b27a3acd8736fdb7288dc29d28df4183dda259e0e067bcdb35f4ac500bebf661",
    ]
    cli_assert_shortcut(output, assert_list)
    expected_calls: dict[str, Optional[tuple[Any, ...]]] = {  # name of rpc: (args)
        "get_blockchain_state": None,
        "get_block_record": (height_hash(1),),
        "get_fee_estimate": ([60, 120, 300], 1),
        "get_block": (height_hash(2),),
    }  # these RPC's should be called with these variables.
    get_global_cli_clients.full_node_rpc_client.check_log(expected_calls)
