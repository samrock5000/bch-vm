const std = @import("std");
const May2025 = @import("vm_limits.zig").May2025;

pub const ScriptExecutionMetrics = struct {
    sig_checks: i32 = 0,
    op_cost: i64 = 0,
    hash_digest_iterations: i64 = 0,
    script_limits: ?May2025.ScriptLimits = null,
    operations: usize,

    pub fn init() ScriptExecutionMetrics {
        return ScriptExecutionMetrics{
            .sig_checks = 0,
            .op_cost = 0,
            .hash_digest_iterations = 0,
            .operations = 0,
            .script_limits = null,
        };
    }

    pub fn getSigChecks(self: *const ScriptExecutionMetrics) i32 {
        return self.sig_checks;
    }

    pub fn getCompositeOpCost(self: *const ScriptExecutionMetrics, standard: bool) i64 {
        const hash_iter_op_cost_factor = May2025.getHashIterOpCostFactor(standard);
        return self.op_cost +
            self.hash_digest_iterations *
            hash_iter_op_cost_factor +
            @as(i64, self.sig_checks) * May2025.SIG_CHECK_COST_FACTOR;
    }

    pub fn getBaseOpCost(self: *const ScriptExecutionMetrics) i64 {
        return self.op_cost;
    }

    pub fn getHashDigestIterations(self: *const ScriptExecutionMetrics) i64 {
        return self.hash_digest_iterations;
    }

    pub fn tallyOp(self: *ScriptExecutionMetrics, cost: u32) void {
        self.op_cost += @as(i64, cost);
    }

    pub fn tallyHashOp(self: *ScriptExecutionMetrics, message_length: u32, is_two_round_hash_op: bool) void {
        self.hash_digest_iterations += May2025.calcHashIters(message_length, is_two_round_hash_op);
    }

    pub fn tallyPushOp(self: *ScriptExecutionMetrics, stack_item_length: u32) void {
        self.op_cost += @as(i64, stack_item_length);
    }

    pub fn tallySigChecks(self: *ScriptExecutionMetrics, n_checks: i32) void {
        self.sig_checks += n_checks;
    }

    pub fn isOverOpCostLimit(self: *const ScriptExecutionMetrics, standard: bool) bool {
        return if (self.script_limits) |limits|
            self.getCompositeOpCost(standard) > limits.getOpCostLimit()
        else
            false;
    }

    pub fn isOverHashItersLimit(self: *const ScriptExecutionMetrics) bool {
        return if (self.script_limits) |limits|
            self.getHashDigestIterations() > limits.getHashItersLimit()
        else
            false;
    }

    pub fn hasScriptLimits(self: *const ScriptExecutionMetrics) bool {
        return self.script_limits != null;
    }

    pub fn setScriptLimits(self: *ScriptExecutionMetrics, standard: bool, script_sig_size: u64) void {
        self.script_limits = May2025.ScriptLimits.init(standard, script_sig_size);
    }
};
