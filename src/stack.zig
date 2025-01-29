const std = @import("std");
const BigInt = std.math.big.int.Managed;
const Opcode = @import("opcodes.zig").Opcodes;
const ConsensusBch2025 = @import("consensus2025.zig").ConsensusBch2025.init();
const Consensus = @import("consensus2025.zig");
const Encoder = @import("encoding.zig").Cursor;
const Allocator = std.mem.Allocator;
const readScriptBool = @import("script.zig").readScriptBool;
const isStandard = @import("script.zig").isStandard;
const isPushOnly = @import("push.zig").isPushOnly;
const Transaction = @import("transaction.zig").Transaction;
const verifyTransactionTokens = @import("token.zig").verifyTransactionTokens;
const totalOutputValue = @import("transaction.zig").totalOutputValue;
const Token = @import("token.zig");
const Script = @import("script.zig");
const SigningContextCache = @import("sigser.zig").SigningContextCache;
const Metrics = @import("metrics.zig").ScriptExecutionMetrics;
const May2025 = @import("vm_limits.zig").May2025;
const VerifyError = @import("error.zig").VerifyError;
const StackError = @import("error.zig").StackError;
const isMinimalDataPush = @import("push.zig").isMinimalDataPush;
const Instruction = @import("opfuncs.zig").Instruction;
const opcodeToFuncTable = @import("opfuncs.zig").opcodeToFuncTable;
const readPush = @import("push.zig").readPushData;

const Stack = std.BoundedArray(StackValue, ConsensusBch2025.maximum_bytecode_length);
pub const StackValue = struct {
    bytes: []u8,
};
pub const ScriptExecContext = struct {
    input_index: u32,
    utxo: []Transaction.Output,
    tx: Transaction,
    signing_cache: SigningContextCache,
    pub fn init() ScriptExecContext {
        return ScriptExecContext{
            .input_index = 0,
            .utxo = &[_]Transaction.Output{},
            .tx = Transaction.init(),
            .signing_cache = SigningContextCache.init(),
        };
    }
    pub fn computeSigningCache(self: *ScriptExecContext, buf: []u8) !void {
        return try self.signing_cache.compute(self, buf);
    }
};

pub const Program = struct {
    stack: std.BoundedArray(StackValue, ConsensusBch2025.maximum_bytecode_length),
    alt_stack: std.BoundedArray(StackValue, ConsensusBch2025.maximum_bytecode_length),
    instruction_bytecode: []u8,
    instruction_pointer: usize,
    code_seperator: usize,
    allocator: Allocator,
    control_stack: ConditionalStack,
    metrics: Metrics,
    context: *ScriptExecContext,
    // has_error: ?anyerror!void,
    pub fn init(
        gpa: Allocator,
        context: *ScriptExecContext,
    ) !Program {
        return Program{
            .stack = try std.BoundedArray(StackValue, ConsensusBch2025.maximum_bytecode_length).init(0),
            .alt_stack = try std.BoundedArray(StackValue, ConsensusBch2025.maximum_bytecode_length).init(0),
            .control_stack = ConditionalStack.init(),
            .instruction_bytecode = undefined,
            .instruction_pointer = 0,
            .code_seperator = 0,
            .allocator = gpa,
            .context = context,
            .metrics = Metrics.init(),
            // .has_error = null,
        };
    }
};

pub const VirtualMachine = struct {
    pub fn execute(program: *Program) anyerror!void {
        // const ip = program.instruction_pointer;
        const operation = getOperation(program);
        try @call(.auto, VirtualMachine.opcodeLookup(operation), .{program});
    }
    fn opcodeLookup(op: Opcode) Instruction {
        // std.debug.print("OP {any}\n", .{op});
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
        // std.debug.print("Push Result {any}\n", .{push_res.data});
        if (!isMinimalDataPush(
            program.instruction_bytecode[ip],
            push_res.data,
        )) return StackError.non_minimal;
        try program.stack.append(StackValue{ .bytes = push_res.data });
        program.instruction_pointer += push_res.bytes_read;
    }

    pub fn evaluateProto(p: *Program) !void {
        const unlock_code = p.context.tx.inputs[p.context.input_index].script;
        const lock_code = p.context.utxo[p.context.input_index].script;

        if (unlock_code.len > ConsensusBch2025.maximum_bytecode_length)
            return VerifyError.excessive_standard_unlocking_bytecode_length;
        if (lock_code.len > ConsensusBch2025.maximum_bytecode_length)
            return VerifyError.maximum_bytecode_length_lockscript;
        p.instruction_bytecode = unlock_code;

        // Unlocking eval
        _ = try executeProgram(p);
        if (!p.control_stack.empty()) return VerifyError.non_empty_control_stack;

        var stack_clone = try std.BoundedArray(StackValue, 10_000).init(0);
        _ = try stack_clone.appendSlice(p.stack.slice());

        p.instruction_bytecode = lock_code;
        p.instruction_pointer = 0;

        // Locking eval
        _ = try executeProgram(p);
        const lockscript_eval = readScriptBool(p.stack.get(p.stack.len - 1).bytes);
        if (!lockscript_eval) return VerifyError.non_truthy_stack_top_item_locking_eval;
        if (!p.control_stack.empty()) return VerifyError.non_empty_control_stack;
        // std.debug.print("POST LOCK STACK {any}\n", .{p.stack.get(p.stack.len - 1)});

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
            // std.debug.print("POST P2SH STACK {any}\n", .{p.stack.slice()});
            if (!p.control_stack.empty()) return VerifyError.non_empty_control_stack;
            if (p.stack.len != 1) {
                return StackError.requires_clean_stack_redeem_bytecode;
            }
            // std.debug.print("STACK {any}\n", .{p.stack.slice()});
        }
    }

    pub fn executeProgram(p: *Program) !void {
        if (!hasMoreInstructions(p)) return;

        const operation = getOperation(p);
        const execution_state = p.control_stack.allTrue();

        if (execution_state) {
            if (operation.isUnknownOpcode()) {
                return StackError.unassigned_opcode;
            }
            if (operation.isDisabled()) {
                return StackError.disabled_opcode;
            }
        }

        if (!operation.isConditional() and !p.control_stack.isBranchExecuting()) {
            advancePointer(p);
            try @call(.always_tail, executeProgram, .{p});
        }

        if (isPushOp(operation) and execution_state) {
            try pushOperation(p);
            return try @call(.always_tail, executeProgram, .{p});
        }

        if (execution_state or operation.isConditional()) {
            try VirtualMachine.execute(p);
            advancePointer(p);
            try @call(.always_tail, executeProgram, .{p});
        } else {
            advancePointer(p);
            return try @call(.always_tail, executeProgram, .{p});
        }
    }

    fn verify(
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

        if (counting_writer.bytes_written > ConsensusBch2025.maximum_transaction_length_bytes) {
            return VerifyError.max_tx_length_exceeded;
        }
        if (counting_writer.bytes_written < ConsensusBch2025.minimum_transaction_length_bytes) {
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
        if (context.tx.version < ConsensusBch2025.minimum_consensus_version or
            context.tx.version > ConsensusBch2025.maximum_consensus_version)
        {
            return VerifyError.invalid_version;
        }
        const standard = true;
        if (standard) {
            if (counting_writer.bytes_written > ConsensusBch2025.maximum_standard_transaction_size) {
                return VerifyError.max_tx_standard_length_exceeded;
            }
            for (context.utxo) |ouput| {
                if (!isStandard(ouput.script, program.allocator)) {
                    return VerifyError.nonstandard_utxo_locking_bytecode;
                }
            }
            for (context.tx.outputs) |ouput| {
                if (!isStandard(ouput.script, program.allocator)) {
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
                if (input.script.len > ConsensusBch2025.maximum_standard_unlocking_bytecode_length) {
                    return VerifyError.excessive_standard_unlocking_bytecode_length;
                }
            }
        }

        _ = try VirtualMachine.evaluateProto(program);
        // for (tx.inputs) |i| {
        //     context.input_index = @intCast(i.index);
        //     _ = try VirtualMachine.evaluateProto(program);
        // }

        const op_cost_exceeded = program.metrics.isOverOpCostLimit(true);
        const hash_iterations_exceeded = program.metrics.isOverHashItersLimit();

        if (op_cost_exceeded) {
            return VerifyError.operation_cost_exceeded;
        }
        if (hash_iterations_exceeded) {
            return VerifyError.hashing_limit_exceeded;
        }
        if (!program.control_stack.empty()) {
            return VerifyError.non_empty_control_stack;
        }
        const eval = readScriptBool(program.stack.get(program.stack.len - 1).bytes);
        return eval;
    }

    fn isPushOp(op: Opcode) bool {
        return @intFromEnum(op) <= @intFromEnum(Opcode.op_16);
    }

    pub fn hasMoreInstructions(p: *Program) bool {
        const ip = p.instruction_pointer;
        const len = p.instruction_bytecode.len;
        return if (ip < len) true else false;
    }
};

pub const ConditionalStack = struct {
    size: usize,
    first_false_pos: usize,

    const NO_FALSE: usize = std.math.maxInt(u32);

    pub fn init() @This() {
        return ConditionalStack{
            .size = 0,
            .first_false_pos = NO_FALSE,
        };
    }
    pub fn empty(self: *ConditionalStack) bool {
        return self.size == 0;
    }
    pub fn allTrue(self: *ConditionalStack) bool {
        return self.first_false_pos == NO_FALSE;
    }
    pub fn push(self: *ConditionalStack, v: bool) void {
        if (self.first_false_pos == NO_FALSE and !v) {
            // The stack consists of all true values, and a false is added.
            // The first false value will appear at the current size.
            self.first_false_pos = self.size;
        }
        self.size += 1;
    }
    pub fn pop(self: *ConditionalStack) void {
        self.size -= 1;
        if (self.first_false_pos == self.size) {
            // When popping off the first false value, everything becomes true.
            self.first_false_pos = NO_FALSE;
        }
    }
    pub fn toggleTop(self: *ConditionalStack) void {
        if (self.first_false_pos == NO_FALSE) {
            // The current stack is all true values; the first false will be the top.
            self.first_false_pos = self.size - 1;
        } else if (self.first_false_pos == self.size - 1) {
            // The top is the first false value; toggling it will make everything true.
            self.first_false_pos = NO_FALSE;
        } else {
            // There is a false value, but not on top. No action is needed as toggling
            // anything but the first false value is unobservable.
        }
    }
    pub fn isBranchExecuting(self: *ConditionalStack) bool {
        if (self.empty()) {
            return true;
        }
        return self.allTrue();
    }
};

test "simple" {
    var genp_alloc = std.heap.GeneralPurposeAllocator(.{}){};
    const ally = genp_alloc.allocator();

    var code = [_]u8{ 0x51, 0x51, 0x93, 0x51, 0x93, 0x51, 0x93 };

    var script_exec = ScriptExecContext.init();
    const tx = Transaction.init();
    script_exec.tx = tx;
    var program = try Program.init(&code, ally, &script_exec);
    // var pgrm = try Program.init(instruction_funcs.items.ptr, &code, ally);
    try VirtualMachine.run(&program);
    // std.debug.print("STACKPOST {any}\n", .{program.stack.slice()});
}
test "vmbtests" {
    var genp_alloc = std.heap.GeneralPurposeAllocator(.{}){};
    // defer {
    //     const check = genp_alloc.detectLeaks();
    //     std.debug.print("LEAKED {any}", .{check});
    // }
    const ally = genp_alloc.allocator();

    // const path = "bch_2025_standard";
    const path = "bch_2025_invalid";
    const base_url = try std.fmt.allocPrint(std.heap.page_allocator, "../vmb_tests/{s}", .{path});

    var current_dir = try std.fs.cwd().openDir(base_url, .{ .iterate = true });
    defer current_dir.close();

    // Pre-allocate and read all test files
    var test_files = std.ArrayList(struct { filename: []const u8, contents: []const u8, parsed_data: std.json.Parsed(std.json.Value) }).init(ally);
    defer {
        for (test_files.items) |*file| {
            ally.free(file.filename);
            ally.free(file.contents);
            file.parsed_data.deinit();
        }
        test_files.deinit();
    }

    // Collect all test files first
    var dir_iterator = current_dir.iterate();
    while (try dir_iterator.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".vmb_tests.json")
        // and !std.mem.startsWith(u8, entry.name, "core.bigint-limits.unary")
        ) {
            // Allocate and copy the filename
            const filename = try ally.dupe(u8, entry.name);
            const all = filename;
            _ = &all;

            const test_match_file = std.mem.eql(u8, all, filename);
            // const test_match = std.mem.eql(u8, all, "core.push.data.vmb_tests.json");
            // Add to our list of test files
            if (test_match_file) {
                const file = try current_dir.openFile(entry.name, .{});
                const bytes_read = try file.getEndPos();

                // Read file contents
                const file_contents = try current_dir.readFileAlloc(ally, entry.name, bytes_read);

                // Parse JSON
                const parsed = try std.json.parseFromSlice(std.json.Value, ally, file_contents, .{ .allocate = .alloc_if_needed });
                try test_files.append(.{ .filename = filename, .contents = file_contents, .parsed_data = parsed });
            }
        }
    }

    const start_time = std.time.nanoTimestamp();
    var verify_start: i128 = 0;
    var verify_end: i128 = 0;
    var verification_count: usize = 0;
    var failed_verifications: usize = 0;
    var total_verification_time: i128 = 0;
    var end_time: i128 = 0;
    // Process all collected test files
    for (test_files.items, 0..) |*test_file, i| {
        const json_data = test_file.parsed_data.value.array.items;
        _ = i;
        var passed_count: usize = 0;
        for (json_data[0..]) |item| {
            // _ = i;
            const identifier = item.array.items[0].string;
            const description = item.array.items[1].string;
            const skip = blk: {
                const phrases = [_][]const u8{ "authorization", "before upgrade", "benchmark" };

                for (phrases) |phrase| {
                    var it = std.mem.window(u8, description, phrase.len, 1);
                    while (it.next()) |slice| {
                        if (std.mem.eql(u8, slice, phrase)) {
                            break :blk true;
                        }
                    }
                }

                break :blk false;
            };
            const specific_test = "qwqmel";
            const all = identifier;
            _ = &all;
            _ = &specific_test;
            const test_match = std.mem.eql(u8, identifier, specific_test);
            _ = &test_match;
            // const test_match_file = std.mem.eql(u8, "core.cashtokens.vmb_tests.json", test_file.filename);
            const test_match_file = std.mem.eql(u8, "core.signing-serialization.vmb_tests.json", test_file.filename);
            _ = &test_match_file;

            if (test_match and !skip) {
                // Allocate buffers for each iteration to avoid reusing potentially modified buffers
                var tx_buff = std.ArrayList(u8).init(ally);
                defer tx_buff.deinit();

                var utxo_buff = std.ArrayList(u8).init(ally);
                defer utxo_buff.deinit();

                const tx = item.array.items[4].string;

                const input_index = if (item.array.items.len == 7) item.array.items[6].integer else 0;
                _ = &tx;
                const src_outs = item.array.items[5].string;

                try utxo_buff.resize(src_outs.len);
                const utxos_slice = try std.fmt.hexToBytes(utxo_buff.items, src_outs);

                var utxo_writer = Encoder.init(utxos_slice);

                // std.debug.print("Testing {s}\nID {s}\n", .{ test_file.filename, identifier });
                const utxos = Transaction.readOutputs(&utxo_writer, ally) catch |err| {
                    std.debug.print("UTXO decoding error {any}\n", .{err});
                    failed_verifications += 1;
                    continue;
                };

                try tx_buff.resize(tx.len);
                const tx_slice = try std.fmt.hexToBytes(tx_buff.items, tx);

                var tx_reader = Encoder.init(tx_slice);
                const tx_decoded = Transaction.decode(&tx_reader, ally) catch |err| {
                    std.debug.print("Transaction decoding error {any}\n", .{err});

                    failed_verifications += 1;
                    continue;
                };
                // std.debug.print("ID {s}\n", .{identifier});
                // const sig_cache = SigningContextCache.init();
                var script_exec = ScriptExecContext{
                    .input_index = @intCast(input_index),
                    .utxo = utxos,
                    .tx = tx_decoded,
                    .signing_cache = SigningContextCache.init(),
                };
                var sigser_buff = [_]u8{0} ** (ConsensusBch2025.maximum_standard_transaction_size * 2);
                try script_exec.computeSigningCache(&sigser_buff);

                var program = try Program.init(ally, &script_exec);
                const unlock_code = program.context.tx.inputs[program.context.input_index].script;
                program.metrics.setScriptLimits(true, unlock_code.len);

                verify_start = std.time.microTimestamp();
                // _ = try evaluateProto(&program);
                const res = VirtualMachine.verify(&program) catch |err| {
                    _ = &err;
                    // std.debug.print("ID {s}\n", .{identifier});
                    // std.debug.print("Failed verification  {any}\n", .{err});
                    failed_verifications += 1;
                    verification_count += 1;
                    continue;
                };
                if (!res) {
                    //     std.debug.print("ID {s}\n", .{identifier});
                    //     std.debug.print("Failed non truthy stack top item {any}\n", .{res});
                    failed_verifications += 1;
                }

                // if (program.has_error) |err| {
                //     std.debug.print("ID {s}\n", .{identifier});
                //     std.debug.print("Contains error {any}\n", .{err});
                // }
                verify_end = std.time.microTimestamp();
                if (res) {
                    std.debug.print("ID {s}\n", .{identifier});
                    // std.debug.print("Testing {s}\nID {s}\n", .{ test_file.filename, identifier });
                    passed_count += 1;
                }
                // verification_count += 1;

                // std.debug.print("Testing: {s}\n", .{
                //     test_file.filename,
                // });
                std.debug.print("Metrics\n" ++
                    "Sig checks: {}\n" ++
                    "Op Cost: {}\n" ++
                    "Hash iterations: {}\n" ++
                    "Is over cost limit: {}\n" ++
                    "Is Over Hash {}\n" ++
                    // "Has Limits {}\n" ++
                    "Composite Op Cost: {}\n", .{
                    program.metrics.sig_checks,
                    program.metrics.op_cost,
                    program.metrics.hash_digest_iterations,
                    program.metrics.isOverOpCostLimit(true),
                    program.metrics.isOverHashItersLimit(),
                    // program.metrics.hasValidScriptLimits(),
                    program.metrics.getCompositeOpCost(true),
                });
                // std.debug.print("Verify  {any}\n\n", .{res});
                end_time = std.time.nanoTimestamp();
                const verification_duration = verify_end - verify_start;
                total_verification_time += verification_duration;
                verification_count += 1;
            }
        }
    }
    const total_execution_time = end_time - start_time;
    const average_verification_time = if (verification_count > 0)
        @divTrunc(total_verification_time, @as(i128, @intCast(verification_count)))
    else
        0;
    std.debug.print("\nPerformance Statistics:\n" ++
        "Total Execution Time: {d} ns\n" ++
        "Total Verification Time: {d} ns\n" ++
        "Average Verification Time: {d} ns\n" ++
        "Number of Verifications: {d}\n" ++
        "Failed Verifications: {d}\n" ++
        "Verification Rate: {d} ops/sec\n", .{
        total_execution_time,
        total_verification_time,
        average_verification_time,
        verification_count,
        failed_verifications,
        // 0,
        @divTrunc(@as(i128, 1_000_000_000), average_verification_time),
    });
}

const evaluateProto = @import("protoype.zig").evaluateProto;

test "tag" {
    // var it = std.mem.splitScalar(u8, name, "op_unknown");
    // var it = std.mem.splitScalar(u8, name, "op_unknown");
    // std.ascii.isDigit()
    // std.debug.print("OP {s}", .{it.first()});
    // while (it.next()) |op| {
    //     std.debug.print("OP {s}", .{op});
    // }
}
