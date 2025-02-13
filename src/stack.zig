/// `Stack` is a bounded array that holds `StackValue` elements, with a maximum capacity defined by
/// `ConsensusBch2026.maximum_bytecode_length`. This type is used to represent the stack during the
/// execution of a script in a transaction. The stack is a fundamental data structure in script
/// execution, used to store intermediate values, operands, and results of operations.
///
/// The `Stack` type is implemented as a `std.BoundedArray`, which ensures that the stack cannot
/// exceed the predefined maximum size, preventing potential memory overflows or excessive resource
/// usage during script execution.
const Stack = std.BoundedArray(StackValue, ConsensusBch2026.maximum_bytecode_length);

/// `StackValue` represents a single value on the stack. It is a struct that contains a byte slice
/// (`bytes`), which holds the actual data of the stack value. The byte slice can represent various
/// types of data, such as numbers, cryptographic keys, or other script-related information.
///
/// During script execution, `StackValue` instances are pushed onto and popped from the stack as
/// the script is processed. The flexibility of the `bytes` field allows it to accommodate different
/// types of data required by the script operations.
pub const StackValue = struct {
    bytes: []u8,
};
/// `ScriptExecutionContext` represents the execution context for a script in a transaction.
/// It encapsulates all the necessary data and state required to execute and validate
/// a script within the context of a specific transaction input. This includes:
/// - The index of the input being processed (`input_index`).
/// - The set of Unspent Transaction Outputs (UTXOs) referenced by the transaction (`utxo`).
/// - The transaction itself (`tx`), which contains the script being executed.
/// - A cache for precomputed signing data (`signing_cache`), which optimizes script execution
///   by avoiding redundant computations.
///
/// This struct is typically used during the execution of Bitcoin Cash (or similar) scripts
/// to ensure that all relevant data is available for validation, signing, and execution.
pub const ScriptExecutionContext = struct {
    /// The index of the transaction input being processed. This is used to identify
    /// which input's script is currently being executed.
    input_index: u32,
    /// The set of Unspent Transaction Outputs (UTXOs) referenced by the transaction.
    /// These outputs are used to validate the transaction's inputs and ensure that
    /// the script has access to the necessary data for execution.
    utxo: []Transaction.Output,
    /// The transaction being validated. This contains the script being executed,
    /// as well as other metadata required for validation.
    tx: Transaction,
    /// A cache for precomputed signing data. This is used to optimize script execution
    /// by storing intermediate results that can be reused during the signing process.
    signing_cache: SigningCache,
    /// Initializes a new `ScriptExecContext` with default values.
    /// This is typically used to create a clean context before script execution begins.
    pub fn init() ScriptExecutionContext {
        return ScriptExecutionContext{
            .input_index = 0,
            .utxo = &[_]Transaction.Output{},
            .tx = Transaction.init(),
            .signing_cache = SigningCache.init(),
        };
    }
    pub fn computeSigningCache(self: *ScriptExecutionContext, buf: []u8) !void {
        return try self.signing_cache.compute(self, buf);
    }
};
/// `Program` represents the state of a script during execution.
/// It includes the main stack, alternate stack, instruction bytecode, and other
/// metadata required to execute and validate the script.
pub const Program = struct {
    /// The main stack used during script execution. This stack holds values that
    /// are manipulated by the script's instructions.
    stack: std.BoundedArray(StackValue, ConsensusBch2026.maximum_bytecode_length),

    /// The alternate stack used during script execution. This stack is used for
    /// temporary storage of values that need to be preserved across operations.
    alt_stack: std.BoundedArray(StackValue, ConsensusBch2026.maximum_bytecode_length),

    /// The bytecode of the script being executed. This contains the instructions
    /// that define the script's logic.
    instruction_bytecode: []const u8,

    /// The current position in the instruction bytecode. This is used to track
    /// which instruction is being executed.
    instruction_pointer: usize,

    /// The position of the last `OP_CODESEPARATOR` instruction encountered.
    /// This is used to handle script segmentation during execution.
    code_separator: usize,

    /// The allocator used for dynamic memory allocation during script execution.
    allocator: Allocator,

    /// The control stack used to manage flow control structures (e.g., loops,
    /// conditionals) during script execution.
    control_stack: ControlStack,

    /// Metrics collected during script execution. These can be used for debugging
    /// or performance analysis.
    metrics: Metrics,

    /// A reference to the `ScriptExecContext` associated with this program.
    /// This provides access to the transaction and UTXO data required for execution.
    context: *ScriptExecutionContext,
    pub fn init(
        alloc: Allocator,
        context: *ScriptExecutionContext,
    ) !Program {
        return Program{
            .stack = try std.BoundedArray(StackValue, ConsensusBch2026.maximum_bytecode_length).init(0),
            .alt_stack = try std.BoundedArray(StackValue, ConsensusBch2026.maximum_bytecode_length).init(0),
            .control_stack = ControlStack.init(alloc),
            .instruction_bytecode = undefined,
            .instruction_pointer = 0,
            .code_separator = 0,
            .allocator = alloc,
            .context = context,
            .metrics = Metrics.init(),
        };
    }
    pub fn deinit(self: *Program) void {
        self.stack_frames.deinit();
    }
};

pub const VirtualMachine = struct {
    pub fn execute(program: *Program) anyerror!void {
        const operation = getOperation(program);
        try @call(.auto, VirtualMachine.opcodeLookup(operation), .{program});
    }
    fn opcodeLookup(op: Opcode) Instruction {
        return opcodeToFuncTable[@intFromEnum(op)];
    }
    fn getCodepoint(program: *Program) u8 {
        return program.instruction_bytecode[program.instruction_pointer];
    }
    fn getOperation(program: *Program) Opcode {
        const operation: Opcode = @enumFromInt(getCodepoint(program));
        return operation;
    }
    pub fn advancePointer(p: *Program) void {
        p.instruction_pointer += 1;
    }
    fn afterOperation(program: *Program) !void {
        //TODO
        _ = &program;
    }
    fn pushOperation(program: *Program) !void {
        const ip = program.instruction_pointer;
        const push_res = try readPush(
            program.instruction_bytecode[ip..],
            program.allocator,
        );
        if (!isMinimalDataPush(
            program.instruction_bytecode[ip],
            push_res.data,
        )) return StackError.non_minimal;
        // std.debug.print("OPPUSH  {any}\n", .{push_res.data});
        try program.stack.append(StackValue{ .bytes = push_res.data });
        program.instruction_pointer += push_res.bytes_read;
    }
    pub fn evaluate(p: *Program) !void {
        const unlock_code = p.context.tx.inputs[p.context.input_index].script;
        const lock_code = p.context.utxo[p.context.input_index].script;

        if (unlock_code.len > ConsensusBch2026.maximum_bytecode_length)
            return VerifyError.excessive_standard_unlocking_bytecode_length;
        if (lock_code.len > ConsensusBch2026.maximum_bytecode_length)
            return VerifyError.maximum_bytecode_length_lockscript;
        p.instruction_bytecode = unlock_code;

        // Unlocking eval
        _ = try executeProgram(p);
        // std.debug.print("Unlock post {any}\n", .{p.stack.slice()});
        if (!p.control_stack.empty()) return VerifyError.non_empty_control_stack_unlocking;

        var stack_clone = try std.BoundedArray(StackValue, 10_000).init(0);
        _ = try stack_clone.appendSlice(p.stack.slice());

        p.instruction_bytecode = lock_code;
        p.instruction_pointer = 0;

        // Locking eval
        _ = try executeProgram(p);
        // std.debug.print("lock post {any}\n", .{p.stack.slice()});
        const lockscript_eval = readScriptBool(p.stack.get(p.stack.len - 1).bytes);
        if (!lockscript_eval) return VerifyError.non_truthy_stack_top_item_locking_eval;
        if (!p.control_stack.empty()) return VerifyError.non_empty_control_stack_locking;

        const is_p2sh = Script.isP2SH(lock_code);
        if (!is_p2sh) {
            if (p.stack.len != 1) {
                return StackError.requires_clean_stack_lockingbytecode;
            }
        }
        if (is_p2sh) {
            p.instruction_bytecode = if (stack_clone.popOrNull()) |p2sh_stack|
                p2sh_stack.bytes
            else
                &[_]u8{};
            p.instruction_pointer = 0;
            p.stack.clear();
            try p.stack.appendSlice(stack_clone.slice());

            // P2SH eval
            _ = try executeProgram(p);
            // std.debug.print("p2sh post {any}\n", .{p.stack.slice()});
            if (!p.control_stack.empty()) return VerifyError.non_empty_control_stack_redeem;
            if (p.stack.len != 1) {
                return StackError.requires_clean_stack_redeem_bytecode;
            }
        }
    }

    const tail = if (native_os == .wasi) .auto else .always_tail;

    pub fn executeProgram(p: *Program) !void {
        if (!hasMoreInstructions(p)) return;
        if (debug) {
            try debugStep(p);
        }
        const op_cost_exceeded = p.metrics.isOverOpCostLimit(true);
        var control_stack = p.control_stack;
        if (op_cost_exceeded) {
            return VerifyError.operation_cost_exceeded;
        }
        if (control_stack.size() > ConsensusBch2026.maximum_control_stack_depth) {
            return StackError.maximum_control_stack_depth;
        }
        const execution_state = control_stack.allTrue();
        const operation = getOperation(p);

        // std.debug.print("{any}\n", .{operation});

        // Skip disabled opcodes
        if (operation.isDisabled()) {
            return StackError.disabled_opcode;
        }

        // Handle push operations
        if (isPushOp(operation)) {
            if (!execution_state) {
                const push_data = try readPush(
                    p.instruction_bytecode[p.instruction_pointer..],
                    p.allocator,
                );
                p.instruction_pointer += push_data.bytes_read;
                return try @call(tail, executeProgram, .{p});
            } else {
                p.metrics.operations += 1;
                p.metrics.tallyOp(May2025.OPCODE_COST);
                // Execute the push operation if the control stack allows it.
                try pushOperation(p);
                return try @call(tail, executeProgram, .{p});
            }
        }

        // Handle conditional and non-conditional operations
        if (execution_state or operation.isConditional()) {
            try VirtualMachine.execute(p);
            advancePointer(p);
            p.metrics.operations += 1;
            p.metrics.tallyOp(May2025.OPCODE_COST);
            return try @call(tail, executeProgram, .{p});
        } else {
            advancePointer(p);
            return try @call(tail, executeProgram, .{p});
        }
    }
    pub fn verify(
        program: *Program,
    ) !bool {
        const context = program.context;
        const tx = context.tx;

        if (context.tx.inputs.len == 0) {
            return VerifyError.no_inputs;
        }
        if (context.tx.outputs.len == 0) {
            return VerifyError.no_outputs;
        }
        if (context.tx.inputs.len != context.utxo.len) {
            return VerifyError.output_input_mismatch;
        }
        var counting_writer = std.io.countingWriter(std.io.null_writer);
        _ = try context.tx.encode(counting_writer.writer());

        if (counting_writer.bytes_written > ConsensusBch2026.maximum_transaction_length_bytes) {
            return VerifyError.max_tx_length_exceeded;
        }
        if (counting_writer.bytes_written < ConsensusBch2026.minimum_transaction_length_bytes) {
            return VerifyError.minimun_transaction_length;
        }

        const input_value = totalOutputValue(context.utxo);
        const output_value = totalOutputValue(context.tx.outputs);

        if (input_value > Consensus.MAX_MONEY) {
            return VerifyError.input_exceeds_max_money;
        }
        if (output_value > Consensus.MAX_MONEY) {
            return VerifyError.output_exceeds_max_money;
        }
        if (output_value > input_value) {
            return VerifyError.output_value_exceeds_inputs_value;
        }
        if (context.tx.version < ConsensusBch2026.minimum_consensus_version or
            context.tx.version > ConsensusBch2026.maximum_consensus_version)
        {
            return VerifyError.invalid_version;
        }
        const standard = true;
        if (standard) {
            if (counting_writer.bytes_written > ConsensusBch2026.maximum_standard_transaction_size) {
                return VerifyError.max_tx_standard_length_exceeded;
            }
            for (context.utxo) |ouput| {
                if (ouput.script.len > ConsensusBch2026.maximum_operation_count) {
                    return VerifyError.nonstandard_ouput_locking_bytecode;
                }
            }
            for (context.tx.outputs) |ouput| {
                if (ouput.script.len > ConsensusBch2026.maximum_operation_count) {
                    return VerifyError.nonstandard_ouput_locking_bytecode;
                }
            }
            for (tx.inputs) |input| {
                if (!isPushOnly(input.script, program.allocator)) return StackError.requires_push_only;
            }
            //TODO arbritary outputs
            //TODO handle dust
            _ = try verifyTransactionTokens(context.tx, context.utxo, program.allocator);

            for (context.tx.inputs) |input| {
                if (input.script.len > ConsensusBch2026.maximum_standard_unlocking_bytecode_length) {
                    return VerifyError.excessive_standard_unlocking_bytecode_length;
                }
            }
        }

        // program.metrics.op_cost
        _ = try VirtualMachine.evaluate(program);

        const op_cost_exceeded = program.metrics.isOverOpCostLimit(true);
        const hash_iterations_exceeded = program.metrics.isOverHashItersLimit();
        if (op_cost_exceeded) {
            return VerifyError.operation_cost_exceeded;
        }
        if (hash_iterations_exceeded) {
            return VerifyError.hashing_limit_exceeded;
        }
        // if (!program.control_stack.empty()) {
        //     return VerifyError.non_empty_control_stack;
        // }
        const eval = readScriptBool(program.stack.get(program.stack.len - 1).bytes);
        return eval;
    }

    fn isPushOp(op: Opcode) bool {
        return @intFromEnum(op) <= @intFromEnum(Opcode.op_16);
    }

    pub fn hasMoreInstructions(p: *Program) bool {
        const ip = p.instruction_pointer;
        const len = p.instruction_bytecode.len;
        return ip < len;
    }
    pub fn debugStep(program: *Program) !void {
        const operation = getOperation(program);
        std.debug.print(ANSI.bold ++ ANSI.yellow ++ "*****************************************" ++ ANSI.reset ++ "\n", .{});
        // Print current operation with color
        std.debug.print(ANSI.bold ++ ANSI.cyan ++ "Next Operation: {any}" ++ ANSI.reset ++ "\n", .{operation});

        // Print instruction pointer with color
        std.debug.print(ANSI.bold ++ ANSI.green ++ "Instruction Pointer: {}" ++ ANSI.reset ++ "\n", .{program.instruction_pointer});

        // Print stack with color
        std.debug.print(ANSI.bold ++ ANSI.yellow ++ "Stack:" ++ ANSI.reset ++ "\n", .{});
        for (program.stack.slice(), 0..) |item, idx| {
            std.debug.print(ANSI.blue ++ "Index: {}" ++ ANSI.reset ++ "\nValue: {any}\n", .{ idx, item.bytes });
        }

        // Print alt stack with color
        std.debug.print(ANSI.bold ++ ANSI.yellow ++ "Alt Stack:" ++ ANSI.reset ++ "\n", .{});
        for (program.alt_stack.slice(), 0..) |item, idx| {
            std.debug.print(ANSI.blue ++ "Index: {}" ++ ANSI.reset ++ "\nValue: {any}\n", .{ idx, item.bytes });
        }

        // Print control stack with color
        std.debug.print(ANSI.bold ++ ANSI.magenta ++ "Control Stack length: {any}" ++ ANSI.reset ++ "\n", .{program.control_stack.values.items.len});

        // Print metrics with color
        std.debug.print(ANSI.bold ++ ANSI.yellow ++ "Metrics:" ++ ANSI.reset ++ "\n", .{});
        std.debug.print(ANSI.green ++ "sig checks: {}" ++ ANSI.reset ++ "\n" ++
            ANSI.green ++ "op cost: {}" ++ ANSI.reset ++ "\n" ++
            ANSI.green ++ "hash iterations: {}" ++ ANSI.reset ++ "\n" ++
            ANSI.green ++ "Over operation limit: {}" ++ ANSI.reset ++ "\n" ++
            ANSI.green ++ "Over hash limit: {}" ++ ANSI.reset ++ "\n" ++
            ANSI.green ++ "Composite op cost: {}" ++ ANSI.reset ++ "\n", .{
            program.metrics.sig_checks,
            program.metrics.op_cost,
            program.metrics.hash_digest_iterations,
            program.metrics.isOverOpCostLimit(true),
            program.metrics.isOverHashItersLimit(),
            program.metrics.getCompositeOpCost(true),
        });

        std.debug.print(ANSI.bold ++ ANSI.yellow ++ "*****************************************" ++ ANSI.reset ++ "\n", .{});
        // Wait for user input to continue
        std.debug.print(ANSI.bold ++ ANSI.red ++ "Press Enter to continue..." ++ ANSI.reset ++ "\n", .{});
        var buf: [1]u8 = undefined;
        _ = try std.io.getStdIn().read(buf[0..]);
    }
};
pub const ControlStackValue = union(enum) {
    boolean: bool,
    integer: usize,
    frame: StackFrame,
};

pub const StackFrame = struct {
    instruction_bytecode: []const u8,
    instruction_pointer: usize,
    code_separator: usize,
};
pub const ControlStack = struct {
    values: std.ArrayList(ControlStackValue),
    allocator: Allocator,

    pub fn init(allocator: Allocator) @This() {
        return ControlStack{
            .values = std.ArrayList(ControlStackValue).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn empty(self: *ControlStack) bool {
        return self.values.items.len == 0;
    }

    pub fn size(self: *ControlStack) usize {
        return self.values.items.len;
    }

    pub fn allTrue(self: *ControlStack) bool {
        for (self.values.items) |value| {
            if (value == .boolean and !value.boolean) {
                return false;
            }
        }
        return true;
    }

    pub fn pushBool(self: *ControlStack, v: bool) !void {
        try self.values.append(.{ .boolean = v });
    }

    pub fn pushInteger(self: *ControlStack, v: usize) !void {
        try self.values.append(.{ .integer = v });
    }

    pub fn pushFrame(self: *ControlStack, frame: StackFrame) !void {
        if (self.values.items.len >= ConsensusBch2026.maximum_control_stack_depth) {
            return StackError.maximum_control_stack_depth;
        }
        try self.values.append(.{ .frame = frame });
    }

    pub fn pop(self: *ControlStack) ?ControlStackValue {
        if (self.values.items.len == 0) return null;
        return self.values.pop();
    }

    pub fn popFrame(self: *ControlStack) ?StackFrame {
        if (self.values.items.len == 0) return null;

        const value = self.values.pop();
        return switch (value) {
            .frame => |frame| frame,
            else => null, // Invalid state; control stack should only contain frames here
        };
    }

    pub fn toggleTop(self: *ControlStack) void {
        if (self.values.items.len == 0) return;

        const top_index = self.values.items.len - 1;
        const top_value = &self.values.items[top_index];

        switch (top_value.*) {
            .boolean => |*b| {
                b.* = !b.*;
            },
            else => {}, // Only boolean values can be toggled
        }
    }
};
const std = @import("std");
const BigInt = std.math.big.int.Managed;
const Opcode = @import("opcodes.zig").Opcodes;
const ConsensusBch2026 = @import("consensus2026.zig").ConsensusBch2026.init();
const Consensus = @import("consensus2026.zig");
// const Curosr = @import("encoding.zig").Cursor;
const Allocator = std.mem.Allocator;
const readScriptBool = @import("script.zig").readScriptBool;
const isStandard = @import("script.zig").isStandard;
const isPushOnly = @import("push.zig").isPushOnly;
const Transaction = @import("transaction.zig").Transaction;
const verifyTransactionTokens = @import("token.zig").verifyTransactionTokens;
const totalOutputValue = @import("transaction.zig").totalOutputValue;
const Token = @import("token.zig");
const Script = @import("script.zig");
const SigningCache = @import("sigser.zig").SigningCache;
const Metrics = @import("metrics.zig").ScriptExecutionMetrics;
const May2025 = @import("vm_limits.zig").May2025;
const VerifyError = @import("error.zig").VerifyError;
const StackError = @import("error.zig").StackError;
const isMinimalDataPush = @import("push.zig").isMinimalDataPush;
const Instruction = @import("opfuncs.zig").Instruction;
const opcodeToFuncTable = @import("opfuncs.zig").opcodeToFuncTable;
const readPush = @import("push.zig").readPushData;
const freePushResult = @import("push.zig").freePushResult;
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const build_options = @import("build_options");
const debug = build_options.debug;
// ANSI escape codes for colors and styles
const ANSI = struct {
    const reset = "\x1b[0m";
    const bold = "\x1b[1m";
    const underline = "\x1b[4m";
    const red = "\x1b[31m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const blue = "\x1b[34m";
    const magenta = "\x1b[35m";
    const cyan = "\x1b[36m";
    const white = "\x1b[37m";
};
