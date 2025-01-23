pub const VerifyError = error{
    invalid_token_data,
    invalid_version,
    excessive_standard_unlocking_bytecode_length,
    no_inputs,
    no_outputs,
    output_input_mismatch,
    insufficient_length,
    max_tx_length_exceeded,
    max_tx_standard_length_exceeded,
    input_exceeds_max_money,
    output_exceeds_max_money,
    output_value_exceeds_inputs_value,
    nonstandard_utxo_locking_bytecode,
    nonstandard_ouput_locking_bytecode,
    non_truthy_stack_top_item,
    operation_cost_exceeded,
    hashing_limit_exceeded,
    non_empty_control_stack,
    invalid_sighash_type,
    non_null_signature_failure,
    maximum_control_stack_depth,
    empty_stack_on_lockscript_eval,
};
pub const StackError = error{
    reserved_opcode,
    unassigned_opcode,
    requires_clean_stack_redeem_bytecode,
    requires_clean_stack,
    unsatisfied_locktime,
    negative_locktime,
    invalid_bit_range,
    invalid_script_int,
    invalid_bit_count,
    multisig_sig_and_pubkey_missmatch,
    max_pubkey_mulsig,
    max_push_element,
    bitwise_stack_item_size_mismatch,
    invalid_stack_op,
    op_return,
    verify,
    non_minimal,
    non_push,
    read_empty_stack,
    div_zero,
    equal_verify_fail,
    unbalanced_stack,
    unbalanced_conditional,
    invalid_split_range,
    impossible_encoding,
    invalid_tx_output_index,
    invalid_tx_input_index,
    exceeded_max_bytecode_length,
    requires_push_only,
    non_schnorr_signature_in_schnorr_multisig,
    schnorr_signature_in_legacy_multisig,
    arithmetic_operation_exceeds_vm_limits_range,
};
