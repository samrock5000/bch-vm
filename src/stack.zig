const std = @import("std");
const Opcode = @import("opcodes.zig").Opcodes;
const ConsensusBch2025 = @import("consensus2025.zig").ConsensusBch2025.init();
const readPush = @import("push.zig").readPushData;
const Allocator = std.mem.Allocator;

const Stack = std.BoundedArray(StackValue, ConsensusBch2025.maximum_bytecode_length);
pub const StackValue = struct {
    bytes: []u8,
};
pub const Program = struct {
    stack: std.BoundedArray(StackValue, ConsensusBch2025.maximum_bytecode_length),
    alt_stack: std.BoundedArray(StackValue, ConsensusBch2025.maximum_bytecode_length),
    instruction_funcs: [*]const Instruction,
    instruction_bytecode: []u8,
    instruction_pointer: usize,
    // control_stack: ConditionalStack,
    // metrics: Metrics,
    // context: *ScriptExecContext,
    pub fn init(
        instruction_funcs: [*]const Instruction,
        instruction_bytecode: []u8,
    ) !Program {
        return Program{
            .stack = try std.BoundedArray(StackValue, 10_000).init(0),
            .alt_stack = try std.BoundedArray(StackValue, 10_000).init(0),
            // .control_stack = ConditionalStack.init(),
            .instruction_funcs = instruction_funcs,
            .instruction_bytecode = instruction_bytecode,
            .instruction_pointer = 0,
            // .context = context,
            // .metrics = Metrics.init(),
        };
    }
};

pub const Instruction = struct {
    opcode: u8,
};
const InstructionFunc = *const fn (program: *Program) anyerror!void;

const InstructionFuncs = struct {
    const opcodeToFuncTable = [256]InstructionFunc{
        &op_0,
        &op_pushbytes_1,
        &op_pushbytes_2,
        &op_pushbytes_3,
        &op_pushbytes_4,
        &op_pushbytes_5,
        &op_pushbytes_6,
        &op_pushbytes_7,
        &op_pushbytes_8,
        &op_pushbytes_9,
        &op_pushbytes_10,
        &op_pushbytes_11,
        &op_pushbytes_12,
        &op_pushbytes_13,
        &op_pushbytes_14,
        &op_pushbytes_15,
        &op_pushbytes_16,
        &op_pushbytes_17,
        &op_pushbytes_18,
        &op_pushbytes_19,
        &op_pushbytes_20,
        &op_pushbytes_21,
        &op_pushbytes_22,
        &op_pushbytes_23,
        &op_pushbytes_24,
        &op_pushbytes_25,
        &op_pushbytes_26,
        &op_pushbytes_27,
        &op_pushbytes_28,
        &op_pushbytes_29,
        &op_pushbytes_30,
        &op_pushbytes_31,
        &op_pushbytes_32,
        &op_pushbytes_33,
        &op_pushbytes_34,
        &op_pushbytes_35,
        &op_pushbytes_36,
        &op_pushbytes_37,
        &op_pushbytes_38,
        &op_pushbytes_39,
        &op_pushbytes_40,
        &op_pushbytes_41,
        &op_pushbytes_42,
        &op_pushbytes_43,
        &op_pushbytes_44,
        &op_pushbytes_45,
        &op_pushbytes_46,
        &op_pushbytes_47,
        &op_pushbytes_48,
        &op_pushbytes_49,
        &op_pushbytes_50,
        &op_pushbytes_51,
        &op_pushbytes_52,
        &op_pushbytes_53,
        &op_pushbytes_54,
        &op_pushbytes_55,
        &op_pushbytes_56,
        &op_pushbytes_57,
        &op_pushbytes_58,
        &op_pushbytes_59,
        &op_pushbytes_60,
        &op_pushbytes_61,
        &op_pushbytes_62,
        &op_pushbytes_63,
        &op_pushbytes_64,
        &op_pushbytes_65,
        &op_pushbytes_66,
        &op_pushbytes_67,
        &op_pushbytes_68,
        &op_pushbytes_69,
        &op_pushbytes_70,
        &op_pushbytes_71,
        &op_pushbytes_72,
        &op_pushbytes_73,
        &op_pushbytes_74,
        &op_pushbytes_75,
        &op_pushdata_1,
        &op_pushdata_2,
        &op_pushdata_4,
        &op_1negate,
        &op_reserved,
        &op_1,
        &op_2,
        &op_3,
        &op_4,
        &op_5,
        &op_6,
        &op_7,
        &op_8,
        &op_9,
        &op_10,
        &op_11,
        &op_12,
        &op_13,
        &op_14,
        &op_15,
        &op_16,
        &op_nop,
        &op_ver,
        &op_if,
        &op_notif,
        &op_verif,
        &op_vernotif,
        &op_else,
        &op_endif,
        &op_verify,
        &op_return,
        &op_toaltstack,
        &op_fromaltstack,
        &op_2drop,
        &op_2dup,
        &op_3dup,
        &op_2over,
        &op_2rot,
        &op_2swap,
        &op_ifdup,
        &op_depth,
        &op_drop,
        &op_dup,
        &op_nip,
        &op_over,
        &op_pick,
        &op_roll,
        &op_rot,
        &op_swap,
        &op_tuck,
        &op_cat,
        &op_split,
        &op_num2bin,
        &op_bin2num,
        &op_size,
        &op_invert,
        &op_and,
        &op_or,
        &op_xor,
        &op_equal,
        &op_equalverify,
        &op_reserved1,
        &op_reserved2,
        &op_1add,
        &op_1sub,
        &op_2mul,
        &op_2div,
        &op_negate,
        &op_abs,
        &op_not,
        &op_0notequal,
        &op_add,
        &op_sub,
        &op_mul,
        &op_div,
        &op_mod,
        &op_lshift,
        &op_rshift,
        &op_booland,
        &op_boolor,
        &op_numequal,
        &op_numequalverify,
        &op_numnotequal,
        &op_lessthan,
        &op_greaterthan,
        &op_lessthanorequal,
        &op_greaterthanorequal,
        &op_min,
        &op_max,
        &op_within,
        &op_ripemd160,
        &op_sha1,
        &op_sha256,
        &op_hash160,
        &op_hash256,
        &op_codeseparator,
        &op_checksig,
        &op_checksigverify,
        &op_checkmultisig,
        &op_checkmultisigverify,
        &op_nop1,
        &op_checklocktimeverify,
        &op_checksequenceverify,
        &op_nop4,
        &op_nop5,
        &op_nop6,
        &op_nop7,
        &op_nop8,
        &op_nop9,
        &op_nop10,
        &op_checkdatasig,
        &op_checkdatasigverify,
        &op_reversebytes,
        // * First CODEPOINT left undefined before nullary introspection operations.
        &op_unknown189,
        &op_unknown190,
        // * Last CODEPOINT left undefined before nullary introspection operations.
        &op_unknown191,
        &op_inputindex,
        &op_activebytecode,
        &op_txversion,
        &op_txinputcount,
        &op_txoutputcount,
        &op_txlocktime,
        &op_utxovalue,
        &op_utxobytecode,
        &op_outpointtxhash,
        &op_outpointindex,
        &op_inputbytecode,
        &op_inputsequencenumber,
        &op_outputvalue,
        &op_outputbytecode,
        &op_utxotokencategory,
        &op_utxotokencommitment,
        &op_utxotokenamount,
        &op_outputtokencategory,
        &op_outputtokencommitment,
        &op_outputtokenamount,
        &op_unknown212,
        &op_unknown213,
        &op_unknown214,
        &op_unknown215,
        &op_unknown216,
        &op_unknown217,
        &op_unknown218,
        &op_unknown219,
        &op_unknown220,
        &op_unknown221,
        &op_unknown222,
        &op_unknown223,
        &op_unknown224,
        &op_unknown225,
        &op_unknown226,
        &op_unknown227,
        &op_unknown228,
        &op_unknown229,
        &op_unknown230,
        &op_unknown231,
        &op_unknown232,
        &op_unknown233,
        &op_unknown234,
        &op_unknown235,
        &op_unknown236,
        &op_unknown237,
        &op_unknown238,
        &op_unknown239,
        // * A.K.A. `OP_PREFIX_BE
        &op_unknown240,
        &op_unknown241,
        &op_unknown242,
        &op_unknown243,
        &op_unknown244,
        &op_unknown245,
        &op_unknown246,
        &op_unknown247,
        &op_unknown248,
        &op_unknown249,
        &op_unknown250,
        &op_unknown251,
        &op_unknown252,
        &op_unknown253,
        &op_unknown254,
        &op_unknown255,
    };
    fn indexFromOpcode(opcode: Opcode) usize {
        opcodeToFuncTable[opcode];
    }
    fn execute(program: *Program) anyerror!void {
        // try @call(.always_tail, InstructionFuncs.lookup(@as(Opcode, @enumFromInt(program.instruction_pointer))), .{program});
        try @call(.always_tail, InstructionFuncs.lookup(@as(
            Opcode,
            @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
        )), .{program});
    }

    fn lookup(opcode: Opcode) InstructionFunc {
        // return opcodeToFuncTable[@intFromEnum(@as(Opcode, @enumFromInt(0)))];
        // std.debug.print("OPCODE {any}\n", .{@intFromEnum(opcode)});

        return opcodeToFuncTable[@intFromEnum(opcode)];
    }
};

test {
    var funcs = std.ArrayList(Instruction).init(std.testing.allocator);
    defer funcs.deinit();
    // for (0..255) |i| {
    //     try funcs.append(Instruction{ .opcode = @intCast(i) });
    // }
    var code = [_]u8{75} ++ .{255} ** 75;
    for (code) |ins| {
        try funcs.append(Instruction{ .opcode = @intCast(ins) });
    }
    var pgrm = try Program.init(funcs.items.ptr, &code);
    try InstructionFuncs.execute(&pgrm);
    // for (0..code.len) |i| {}
    // try funcs.append(x);
    // var s = [_]u8{1};
    // try stack.append(StackValue{ .bytes = &s });
    // try stack.append(StackValue{ .bytes = &s });
    // try InstructionFuncs.run(@intFromEnum(x.opcode), funcs.items.ptr, &stack);
    // _ = InstructionFuncs.lookup(x.opcode);
    // const items = InstructionFuncs.opcodeToFuncTable;
    // for (items, 0..) |i, idx| {
    //     std.debug.print("item {} index {} \n", .{ i, idx });
    // }
}
pub fn op_0(program: *Program) anyerror!void {
    try program.stack.append(StackValue{ .bytes = &.{} });
    // const push_value = try readPush(code[ip..], gpa);

    std.debug.print("OP_0 STACK {any}\n", .{program.stack.slice()});
    std.debug.print("OP_0 ip {any}\n", .{program.instruction_pointer});

    program.instruction_pointer += 1;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}
pub fn op_pushbytes_1(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    // std.debug.print("op_pushbytes_1 {any}\n", .{program.instruction_bytecode});
    std.debug.print("op_pushbytes_1 STACK {any}\n", .{program.stack.slice()});
    std.debug.print("op_pushbytes_1 ip {any}\n", .{program.instruction_pointer});
    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}
pub fn op_pushbytes_2(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_3(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_4(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_5(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_6(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_7(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_8(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_9(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_10(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_11(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_12(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_13(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_14(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_15(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_16(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_17(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_18(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_19(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_20(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_21(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_22(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_23(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_24(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_25(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_26(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_27(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_28(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_29(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_30(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_31(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_32(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_33(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_34(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_35(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_36(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_37(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_38(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_39(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_40(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_41(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_42(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_43(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_44(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_45(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_46(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_47(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_48(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_49(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_50(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_51(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_52(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_53(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_54(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_55(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_56(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_57(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_58(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_59(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_60(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_61(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_62(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_63(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_64(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_65(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_66(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_67(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_68(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_69(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_70(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_71(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_72(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_73(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_74(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    program.instruction_pointer += 1 + length;
    try @call(.always_tail, InstructionFuncs.lookup(@as(
        Opcode,
        @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    )), .{program});
}

pub fn op_pushbytes_75(program: *Program) anyerror!void {
    const length = program.instruction_bytecode[program.instruction_pointer];
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < length + 1) return error.InsufficientData;
    try program.stack.append(StackValue{ .bytes = data[0..length] });

    // std.debug.print("STACK {any}", .{program.stack.slice()});
    program.instruction_pointer += 1 + length;
    // try @call(.always_tail, InstructionFuncs.lookup(@as(
    //     Opcode,
    //     @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    // )), .{program});
}

pub fn op_pushdata_1(program: *Program) anyerror!void {
    const data = program.instruction_bytecode[program.instruction_pointer..];
    if (data.len < 2) return error.InsufficientData;
    const length: u16 = data[1];
    if (length > data.len - 2) return error.InsufficientData;

    try program.stack.append(StackValue{ .bytes = data[2..][0..length] });
    // _ = program;
}

pub fn op_pushdata_2(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_pushdata_4(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_1negate(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_reserved(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_1(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_2(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_3(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_4(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_5(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_6(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_7(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_8(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_9(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_10(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_11(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_12(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_13(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_14(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_15(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_16(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_ver(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_if(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_notif(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_verif(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_vernotif(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_else(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_endif(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_verify(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_return(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_toaltstack(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_fromaltstack(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_2drop(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_2dup(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_3dup(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_2over(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_2rot(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_2swap(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_ifdup(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_depth(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_drop(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_dup(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nip(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_over(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_pick(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_roll(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_rot(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_swap(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_tuck(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_cat(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_split(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_num2bin(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_bin2num(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_size(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_invert(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_and(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_or(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_xor(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_equal(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_equalverify(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_reserved1(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_reserved2(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_1add(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_1sub(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_2mul(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_2div(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_negate(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_abs(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_not(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_0notequal(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_add(program: *Program) anyerror!void {
    std.debug.print("OP_ADD {any}\n ", .{program});
}

pub fn op_sub(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_mul(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_div(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_mod(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_lshift(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_rshift(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_booland(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_boolor(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_numequal(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_numequalverify(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_numnotequal(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_lessthan(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_greaterthan(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_lessthanorequal(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_greaterthanorequal(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_min(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_max(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_within(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_ripemd160(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_sha1(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_sha256(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_hash160(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_hash256(program: *Program) anyerror!void {
    _ = program;
}
pub fn op_codeseparator(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_checksig(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_checksigverify(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_checkmultisig(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_checkmultisigverify(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop1(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_checklocktimeverify(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_checksequenceverify(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop4(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop5(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop6(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop7(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop8(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop9(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_nop10(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_checkdatasig(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_checkdatasigverify(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_reversebytes(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown189(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown190(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown191(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_inputindex(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_activebytecode(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_txversion(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_txinputcount(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_txoutputcount(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_txlocktime(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_utxovalue(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_utxobytecode(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_outpointtxhash(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_outpointindex(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_inputbytecode(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_inputsequencenumber(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_outputvalue(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_outputbytecode(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_utxotokencategory(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_utxotokencommitment(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_utxotokenamount(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_outputtokencategory(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_outputtokencommitment(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_outputtokenamount(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown212(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown213(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown214(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown215(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown216(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown217(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown218(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown219(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown220(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown221(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown222(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown223(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown224(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown225(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown226(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown227(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown228(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown229(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown230(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown231(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown232(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown233(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown234(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown235(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown236(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown237(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown238(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown239(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown240(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown241(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown242(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown243(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown244(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown245(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown246(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown247(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown248(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown249(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown250(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown251(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown252(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown253(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown254(program: *Program) anyerror!void {
    _ = program;
}

pub fn op_unknown255(program: *Program) anyerror!void {
    _ = program;
}
