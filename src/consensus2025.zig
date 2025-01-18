const std = @import("std");

pub const MAX_PUBKEYS_MULTISIG = 20;
pub const MAX_COINS: u64 = 21_000_000;
pub const SATOSHI_PER_COIN: u64 = 100_000_000;
pub const MAX_MONEY: u64 = MAX_COINS * SATOSHI_PER_COIN;

pub const ConsensusBch2025 = struct {
    /// Base instruction cost
    base_instruction_cost: u32 = 100,

    /// The constant added to the unlocking bytecode length to determine a
    /// contract's density control length (for operation cost and hashing budgets)
    density_control_base_length: u32 = 41,

    /// Hash digest iteration cost for consensus
    hash_digest_iteration_cost_consensus: u32 = 64,

    /// Hash digest iteration cost for standard operations
    hash_digest_iteration_cost_standard: u32 = 192,

    /// Hash digest iterations per byte for non-standard operations
    hash_digest_iterations_per_byte_nonstandard: f32 = 3.5,

    /// Hash digest iterations per byte for standard operations
    hash_digest_iterations_per_byte_standard: f32 = 0.5,

    /// Maximum bytecode length (MAX_SCRIPT_SIZE)
    maximum_bytecode_length: u32 = 10000,

    /// Maximum commitment length
    maximum_commitment_length: u32 = 40,

    /// Maximum consensus version (MAX_CONSENSUS_VERSION)
    maximum_consensus_version: u32 = 2,

    /// Maximum control stack depth
    maximum_control_stack_depth: u32 = 100,

    /// Maximum data carrier bytes (MAX_OP_RETURN_RELAY)
    maximum_data_carrier_bytes: u16 = 223,

    /// Maximum fungible token amount
    maximum_fungible_token_amount: i64 = 9_223_372_036_854_775_807,

    /// Maximum operation count per script (MAX_OPS_PER_SCRIPT)
    maximum_operation_count: u16 = 201,

    /// Maximum stack depth (MAX_STACK_SIZE)
    maximum_stack_depth: u32 = 1000,

    /// Maximum stack item length (MAX_SCRIPT_ELEMENT_SIZE)
    maximum_stack_item_length: u16 = 10_000,

    /// Maximum standard transaction size
    maximum_standard_transaction_size: u32 = 100_000,

    /// Maximum standard unlocking bytecode length (MAX_TX_IN_SCRIPT_SIG_SIZE)
    maximum_standard_unlocking_bytecode_length: u16 = 1650,

    /// Maximum transaction length in bytes (MAX_TX_SIZE)
    maximum_transaction_length_bytes: u32 = 1_000_000,

    /// Maximum transaction signature checks (MAX_TX_SIGCHECKS)
    maximum_transaction_signature_checks: u32 = 3_000,

    /// Maximum VM number byte length (nMaxNumSize)
    maximum_vm_number_byte_length: u16 = 10_000,

    /// Minimum consensus version (MIN_CONSENSUS_VERSION)
    minimum_consensus_version: u8 = 1,

    /// Minimum transaction length in bytes (MIN_TX_SIZE)
    minimum_transaction_length_bytes: u8 = 65,

    /// Operation cost budget per byte
    operation_cost_budget_per_byte: u32 = 800,

    /// Schnorr signature length
    schnorr_signature_length: u8 = 64,

    /// Signature check cost
    signature_check_cost: u32 = 26_000,

    // Optional method to create a default instance
    pub fn init() ConsensusBch2025 {
        return ConsensusBch2025{};
    }
};
