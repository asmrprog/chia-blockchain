# this file is generated by build_network_protocol_files.py

from __future__ import annotations

from tests.util.network_protocol_data import *  # noqa: F403
from tests.util.protocol_messages_json import *  # noqa: F403


def test_protocol_json() -> None:
    assert str(new_signage_point_json) == str(new_signage_point.to_json_dict())
    assert type(new_signage_point).from_json_dict(new_signage_point_json) == new_signage_point
    assert str(declare_proof_of_space_json) == str(declare_proof_of_space.to_json_dict())
    assert type(declare_proof_of_space).from_json_dict(declare_proof_of_space_json) == declare_proof_of_space
    assert str(request_signed_values_json) == str(request_signed_values.to_json_dict())
    assert type(request_signed_values).from_json_dict(request_signed_values_json) == request_signed_values
    assert str(farming_info_json) == str(farming_info.to_json_dict())
    assert type(farming_info).from_json_dict(farming_info_json) == farming_info
    assert str(signed_values_json) == str(signed_values.to_json_dict())
    assert type(signed_values).from_json_dict(signed_values_json) == signed_values
    assert str(new_peak_json) == str(new_peak.to_json_dict())
    assert type(new_peak).from_json_dict(new_peak_json) == new_peak
    assert str(new_transaction_json) == str(new_transaction.to_json_dict())
    assert type(new_transaction).from_json_dict(new_transaction_json) == new_transaction
    assert str(request_transaction_json) == str(request_transaction.to_json_dict())
    assert type(request_transaction).from_json_dict(request_transaction_json) == request_transaction
    assert str(respond_transaction_json) == str(respond_transaction.to_json_dict())
    assert type(respond_transaction).from_json_dict(respond_transaction_json) == respond_transaction
    assert str(request_proof_of_weight_json) == str(request_proof_of_weight.to_json_dict())
    assert type(request_proof_of_weight).from_json_dict(request_proof_of_weight_json) == request_proof_of_weight
    assert str(respond_proof_of_weight_json) == str(respond_proof_of_weight.to_json_dict())
    assert type(respond_proof_of_weight).from_json_dict(respond_proof_of_weight_json) == respond_proof_of_weight
    assert str(request_block_json) == str(request_block.to_json_dict())
    assert type(request_block).from_json_dict(request_block_json) == request_block
    assert str(reject_block_json) == str(reject_block.to_json_dict())
    assert type(reject_block).from_json_dict(reject_block_json) == reject_block
    assert str(request_blocks_json) == str(request_blocks.to_json_dict())
    assert type(request_blocks).from_json_dict(request_blocks_json) == request_blocks
    assert str(respond_blocks_json) == str(respond_blocks.to_json_dict())
    assert type(respond_blocks).from_json_dict(respond_blocks_json) == respond_blocks
    assert str(reject_blocks_json) == str(reject_blocks.to_json_dict())
    assert type(reject_blocks).from_json_dict(reject_blocks_json) == reject_blocks
    assert str(respond_block_json) == str(respond_block.to_json_dict())
    assert type(respond_block).from_json_dict(respond_block_json) == respond_block
    assert str(new_unfinished_block_json) == str(new_unfinished_block.to_json_dict())
    assert type(new_unfinished_block).from_json_dict(new_unfinished_block_json) == new_unfinished_block
    assert str(request_unfinished_block_json) == str(request_unfinished_block.to_json_dict())
    assert type(request_unfinished_block).from_json_dict(request_unfinished_block_json) == request_unfinished_block
    assert str(respond_unfinished_block_json) == str(respond_unfinished_block.to_json_dict())
    assert type(respond_unfinished_block).from_json_dict(respond_unfinished_block_json) == respond_unfinished_block
    assert str(new_signage_point_or_end_of_subslot_json) == str(new_signage_point_or_end_of_subslot.to_json_dict())
    assert (
        type(new_signage_point_or_end_of_subslot).from_json_dict(new_signage_point_or_end_of_subslot_json)
        == new_signage_point_or_end_of_subslot
    )
    assert str(request_signage_point_or_end_of_subslot_json) == str(
        request_signage_point_or_end_of_subslot.to_json_dict()
    )
    assert (
        type(request_signage_point_or_end_of_subslot).from_json_dict(request_signage_point_or_end_of_subslot_json)
        == request_signage_point_or_end_of_subslot
    )
    assert str(respond_signage_point_json) == str(respond_signage_point.to_json_dict())
    assert type(respond_signage_point).from_json_dict(respond_signage_point_json) == respond_signage_point
    assert str(respond_end_of_subslot_json) == str(respond_end_of_subslot.to_json_dict())
    assert type(respond_end_of_subslot).from_json_dict(respond_end_of_subslot_json) == respond_end_of_subslot
    assert str(request_mempool_transaction_json) == str(request_mempool_transaction.to_json_dict())
    assert (
        type(request_mempool_transaction).from_json_dict(request_mempool_transaction_json)
        == request_mempool_transaction
    )
    assert str(new_compact_vdf_json) == str(new_compact_vdf.to_json_dict())
    assert type(new_compact_vdf).from_json_dict(new_compact_vdf_json) == new_compact_vdf
    assert str(request_compact_vdf_json) == str(request_compact_vdf.to_json_dict())
    assert type(request_compact_vdf).from_json_dict(request_compact_vdf_json) == request_compact_vdf
    assert str(respond_compact_vdf_json) == str(respond_compact_vdf.to_json_dict())
    assert type(respond_compact_vdf).from_json_dict(respond_compact_vdf_json) == respond_compact_vdf
    assert str(request_peers_json) == str(request_peers.to_json_dict())
    assert type(request_peers).from_json_dict(request_peers_json) == request_peers
    assert str(respond_peers_json) == str(respond_peers.to_json_dict())
    assert type(respond_peers).from_json_dict(respond_peers_json) == respond_peers
    assert str(request_puzzle_solution_json) == str(request_puzzle_solution.to_json_dict())
    assert type(request_puzzle_solution).from_json_dict(request_puzzle_solution_json) == request_puzzle_solution
    assert str(puzzle_solution_response_json) == str(puzzle_solution_response.to_json_dict())
    assert type(puzzle_solution_response).from_json_dict(puzzle_solution_response_json) == puzzle_solution_response
    assert str(respond_puzzle_solution_json) == str(respond_puzzle_solution.to_json_dict())
    assert type(respond_puzzle_solution).from_json_dict(respond_puzzle_solution_json) == respond_puzzle_solution
    assert str(reject_puzzle_solution_json) == str(reject_puzzle_solution.to_json_dict())
    assert type(reject_puzzle_solution).from_json_dict(reject_puzzle_solution_json) == reject_puzzle_solution
    assert str(send_transaction_json) == str(send_transaction.to_json_dict())
    assert type(send_transaction).from_json_dict(send_transaction_json) == send_transaction
    assert str(transaction_ack_json) == str(transaction_ack.to_json_dict())
    assert type(transaction_ack).from_json_dict(transaction_ack_json) == transaction_ack
    assert str(new_peak_wallet_json) == str(new_peak_wallet.to_json_dict())
    assert type(new_peak_wallet).from_json_dict(new_peak_wallet_json) == new_peak_wallet
    assert str(request_block_header_json) == str(request_block_header.to_json_dict())
    assert type(request_block_header).from_json_dict(request_block_header_json) == request_block_header
    assert str(request_block_headers_json) == str(request_block_headers.to_json_dict())
    assert type(request_block_headers).from_json_dict(request_block_headers_json) == request_block_headers
    assert str(respond_header_block_json) == str(respond_header_block.to_json_dict())
    assert type(respond_header_block).from_json_dict(respond_header_block_json) == respond_header_block
    assert str(respond_block_headers_json) == str(respond_block_headers.to_json_dict())
    assert type(respond_block_headers).from_json_dict(respond_block_headers_json) == respond_block_headers
    assert str(reject_header_request_json) == str(reject_header_request.to_json_dict())
    assert type(reject_header_request).from_json_dict(reject_header_request_json) == reject_header_request
    assert str(request_removals_json) == str(request_removals.to_json_dict())
    assert type(request_removals).from_json_dict(request_removals_json) == request_removals
    assert str(respond_removals_json) == str(respond_removals.to_json_dict())
    assert type(respond_removals).from_json_dict(respond_removals_json) == respond_removals
    assert str(reject_removals_request_json) == str(reject_removals_request.to_json_dict())
    assert type(reject_removals_request).from_json_dict(reject_removals_request_json) == reject_removals_request
    assert str(request_additions_json) == str(request_additions.to_json_dict())
    assert type(request_additions).from_json_dict(request_additions_json) == request_additions
    assert str(respond_additions_json) == str(respond_additions.to_json_dict())
    assert type(respond_additions).from_json_dict(respond_additions_json) == respond_additions
    assert str(reject_additions_json) == str(reject_additions.to_json_dict())
    assert type(reject_additions).from_json_dict(reject_additions_json) == reject_additions
    assert str(request_header_blocks_json) == str(request_header_blocks.to_json_dict())
    assert type(request_header_blocks).from_json_dict(request_header_blocks_json) == request_header_blocks
    assert str(reject_header_blocks_json) == str(reject_header_blocks.to_json_dict())
    assert type(reject_header_blocks).from_json_dict(reject_header_blocks_json) == reject_header_blocks
    assert str(respond_header_blocks_json) == str(respond_header_blocks.to_json_dict())
    assert type(respond_header_blocks).from_json_dict(respond_header_blocks_json) == respond_header_blocks
    assert str(coin_state_json) == str(coin_state.to_json_dict())
    assert type(coin_state).from_json_dict(coin_state_json) == coin_state
    assert str(register_for_ph_updates_json) == str(register_for_ph_updates.to_json_dict())
    assert type(register_for_ph_updates).from_json_dict(register_for_ph_updates_json) == register_for_ph_updates
    assert str(reject_block_headers_json) == str(reject_block_headers.to_json_dict())
    assert type(reject_block_headers).from_json_dict(reject_block_headers_json) == reject_block_headers
    assert str(respond_to_ph_updates_json) == str(respond_to_ph_updates.to_json_dict())
    assert type(respond_to_ph_updates).from_json_dict(respond_to_ph_updates_json) == respond_to_ph_updates
    assert str(register_for_coin_updates_json) == str(register_for_coin_updates.to_json_dict())
    assert type(register_for_coin_updates).from_json_dict(register_for_coin_updates_json) == register_for_coin_updates
    assert str(respond_to_coin_updates_json) == str(respond_to_coin_updates.to_json_dict())
    assert type(respond_to_coin_updates).from_json_dict(respond_to_coin_updates_json) == respond_to_coin_updates
    assert str(coin_state_update_json) == str(coin_state_update.to_json_dict())
    assert type(coin_state_update).from_json_dict(coin_state_update_json) == coin_state_update
    assert str(request_children_json) == str(request_children.to_json_dict())
    assert type(request_children).from_json_dict(request_children_json) == request_children
    assert str(respond_children_json) == str(respond_children.to_json_dict())
    assert type(respond_children).from_json_dict(respond_children_json) == respond_children
    assert str(request_ses_info_json) == str(request_ses_info.to_json_dict())
    assert type(request_ses_info).from_json_dict(request_ses_info_json) == request_ses_info
    assert str(respond_ses_info_json) == str(respond_ses_info.to_json_dict())
    assert type(respond_ses_info).from_json_dict(respond_ses_info_json) == respond_ses_info
    assert str(pool_difficulty_json) == str(pool_difficulty.to_json_dict())
    assert type(pool_difficulty).from_json_dict(pool_difficulty_json) == pool_difficulty
    assert str(harvester_handhsake_json) == str(harvester_handhsake.to_json_dict())
    assert type(harvester_handhsake).from_json_dict(harvester_handhsake_json) == harvester_handhsake
    assert str(new_signage_point_harvester_json) == str(new_signage_point_harvester.to_json_dict())
    assert (
        type(new_signage_point_harvester).from_json_dict(new_signage_point_harvester_json)
        == new_signage_point_harvester
    )
    assert str(new_proof_of_space_json) == str(new_proof_of_space.to_json_dict())
    assert type(new_proof_of_space).from_json_dict(new_proof_of_space_json) == new_proof_of_space
    assert str(request_signatures_json) == str(request_signatures.to_json_dict())
    assert type(request_signatures).from_json_dict(request_signatures_json) == request_signatures
    assert str(respond_signatures_json) == str(respond_signatures.to_json_dict())
    assert type(respond_signatures).from_json_dict(respond_signatures_json) == respond_signatures
    assert str(plot_json) == str(plot.to_json_dict())
    assert type(plot).from_json_dict(plot_json) == plot
    assert str(request_plots_json) == str(request_plots.to_json_dict())
    assert type(request_plots).from_json_dict(request_plots_json) == request_plots
    assert str(respond_plots_json) == str(respond_plots.to_json_dict())
    assert type(respond_plots).from_json_dict(respond_plots_json) == respond_plots
    assert str(request_peers_introducer_json) == str(request_peers_introducer.to_json_dict())
    assert type(request_peers_introducer).from_json_dict(request_peers_introducer_json) == request_peers_introducer
    assert str(respond_peers_introducer_json) == str(respond_peers_introducer.to_json_dict())
    assert type(respond_peers_introducer).from_json_dict(respond_peers_introducer_json) == respond_peers_introducer
    assert str(authentication_payload_json) == str(authentication_payload.to_json_dict())
    assert type(authentication_payload).from_json_dict(authentication_payload_json) == authentication_payload
    assert str(get_pool_info_response_json) == str(get_pool_info_response.to_json_dict())
    assert type(get_pool_info_response).from_json_dict(get_pool_info_response_json) == get_pool_info_response
    assert str(post_partial_payload_json) == str(post_partial_payload.to_json_dict())
    assert type(post_partial_payload).from_json_dict(post_partial_payload_json) == post_partial_payload
    assert str(post_partial_request_json) == str(post_partial_request.to_json_dict())
    assert type(post_partial_request).from_json_dict(post_partial_request_json) == post_partial_request
    assert str(post_partial_response_json) == str(post_partial_response.to_json_dict())
    assert type(post_partial_response).from_json_dict(post_partial_response_json) == post_partial_response
    assert str(get_farmer_response_json) == str(get_farmer_response.to_json_dict())
    assert type(get_farmer_response).from_json_dict(get_farmer_response_json) == get_farmer_response
    assert str(post_farmer_payload_json) == str(post_farmer_payload.to_json_dict())
    assert type(post_farmer_payload).from_json_dict(post_farmer_payload_json) == post_farmer_payload
    assert str(post_farmer_request_json) == str(post_farmer_request.to_json_dict())
    assert type(post_farmer_request).from_json_dict(post_farmer_request_json) == post_farmer_request
    assert str(post_farmer_response_json) == str(post_farmer_response.to_json_dict())
    assert type(post_farmer_response).from_json_dict(post_farmer_response_json) == post_farmer_response
    assert str(put_farmer_payload_json) == str(put_farmer_payload.to_json_dict())
    assert type(put_farmer_payload).from_json_dict(put_farmer_payload_json) == put_farmer_payload
    assert str(put_farmer_request_json) == str(put_farmer_request.to_json_dict())
    assert type(put_farmer_request).from_json_dict(put_farmer_request_json) == put_farmer_request
    assert str(put_farmer_response_json) == str(put_farmer_response.to_json_dict())
    assert type(put_farmer_response).from_json_dict(put_farmer_response_json) == put_farmer_response
    assert str(error_response_json) == str(error_response.to_json_dict())
    assert type(error_response).from_json_dict(error_response_json) == error_response
    assert str(new_peak_timelord_json) == str(new_peak_timelord.to_json_dict())
    assert type(new_peak_timelord).from_json_dict(new_peak_timelord_json) == new_peak_timelord
    assert str(new_unfinished_block_timelord_json) == str(new_unfinished_block_timelord.to_json_dict())
    assert (
        type(new_unfinished_block_timelord).from_json_dict(new_unfinished_block_timelord_json)
        == new_unfinished_block_timelord
    )
    assert str(new_infusion_point_vdf_json) == str(new_infusion_point_vdf.to_json_dict())
    assert type(new_infusion_point_vdf).from_json_dict(new_infusion_point_vdf_json) == new_infusion_point_vdf
    assert str(new_signage_point_vdf_json) == str(new_signage_point_vdf.to_json_dict())
    assert type(new_signage_point_vdf).from_json_dict(new_signage_point_vdf_json) == new_signage_point_vdf
    assert str(new_end_of_sub_slot_bundle_json) == str(new_end_of_sub_slot_bundle.to_json_dict())
    assert (
        type(new_end_of_sub_slot_bundle).from_json_dict(new_end_of_sub_slot_bundle_json) == new_end_of_sub_slot_bundle
    )
    assert str(request_compact_proof_of_time_json) == str(request_compact_proof_of_time.to_json_dict())
    assert (
        type(request_compact_proof_of_time).from_json_dict(request_compact_proof_of_time_json)
        == request_compact_proof_of_time
    )
    assert str(respond_compact_proof_of_time_json) == str(respond_compact_proof_of_time.to_json_dict())
    assert (
        type(respond_compact_proof_of_time).from_json_dict(respond_compact_proof_of_time_json)
        == respond_compact_proof_of_time
    )
