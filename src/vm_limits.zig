const std = @import("std");
const assert = std.debug.assert;

// Pre May 2025 Legacy Constants
pub const MAX_SCRIPT_ELEMENT_SIZE_LEGACY: u32 = 520;
pub const MAX_OPS_PER_SCRIPT_LEGACY: i32 = 201;
pub const MAX_PUBKEYS_PER_MULTISIG: i32 = 20;
pub const MAX_SCRIPT_SIZE: i32 = 10000;
pub const MAX_STACK_SIZE: i32 = 1000;
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

pub const May2025 = struct {
    // Post May 2025 Upgrade Constants
    pub const MAX_SCRIPT_ELEMENT_SIZE: u32 = MAX_SCRIPT_SIZE;
    pub const OPCODE_COST: u32 = 100;
    pub const MAX_CONDITIONAL_STACK_DEPTH: u32 = 100;
    pub const SIG_CHECK_COST_FACTOR: u32 = 26_000;

    // Detailed Constants and Utility Functions
    pub const detail = struct {
        pub const HASH_ITER_BONUS_FOR_NONSTD_TXNS: u32 = 7;
        pub const OP_COST_BUDGET_PER_INPUT_BYTE: u32 = 800;
        pub const HASH_COST_PENALTY_FOR_STD_TXNS: u32 = 3;
        pub const HASH_BLOCK_SIZE: u32 = 64;
        pub const INPUT_SCRIPT_SIZE_FIXED_CREDIT: u32 = 41;

        pub fn getInputHashItersLimit(standard: bool, script_sig_size: u64) i64 {
            const factor = if (standard) @as(u32, 1) else detail.HASH_ITER_BONUS_FOR_NONSTD_TXNS;
            const ret = ((script_sig_size + detail.INPUT_SCRIPT_SIZE_FIXED_CREDIT) * factor) / 2;
            assert(ret >= 0);
            return @intCast(ret);
        }

        pub fn getInputOpCostLimit(script_sig_size: u64) i64 {
            const ret = (script_sig_size + detail.INPUT_SCRIPT_SIZE_FIXED_CREDIT) * detail.OP_COST_BUDGET_PER_INPUT_BYTE;
            assert(ret >= 0);
            return @intCast(ret);
        }
    };

    pub fn getHashIterOpCostFactor(standard: bool) i64 {
        return if (standard)
            @as(i64, detail.HASH_BLOCK_SIZE * detail.HASH_COST_PENALTY_FOR_STD_TXNS)
        else
            @as(i64, detail.HASH_BLOCK_SIZE);
    }

    pub fn calcHashIters(message_length: u32, is_two_round_hash_op: bool) i64 {
        return @intCast(@as(u64, @intFromBool(is_two_round_hash_op)) + 1 +
            ((message_length + 8) / detail.HASH_BLOCK_SIZE));
    }

    pub const ScriptLimits = struct {
        op_cost_limit: i64,
        hash_iters_limit: i64,

        pub fn init(standard: bool, script_sig_size: u64) ScriptLimits {
            return ScriptLimits{
                .op_cost_limit = detail.getInputOpCostLimit(script_sig_size),
                .hash_iters_limit = detail.getInputHashItersLimit(standard, script_sig_size),
            };
        }

        pub fn getOpCostLimit(self: ScriptLimits) i64 {
            return self.op_cost_limit;
        }

        pub fn getHashItersLimit(self: ScriptLimits) i64 {
            return self.hash_iters_limit;
        }
    };
};
