const std = @import("std");
const Opcode = @import("opcodes.zig").Opcodes;
const InstructionFunc = *const fn (pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void;
const readPush = @import("push.zig").readPushData;

pub const StackValue = struct {
    bytes: []u8,
};

const Stack = std.BoundedArray(StackValue, 10_000);

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
    fn run(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        // std.debug.print("PC {any}\n", .{@as(Opcode, @enumFromInt(pc))});
        std.debug.print("PC {any}\n", .{code[pc].opcode});
        // std.debug.print("FIELD {any}\n", .{@field(Opcode, "op_add") });
        try @call(.always_tail, InstructionFuncs.lookup(code[pc].opcode), .{ pc, code, stack });
    }

    fn lookup(opcode: Opcode) InstructionFunc {
        // return opcodeToFuncTable[@intFromEnum(@as(Opcode, @enumFromInt(0)))];
        std.debug.print("OPCODE {any}\n", .{@intFromEnum(opcode)});

        return opcodeToFuncTable[@intFromEnum(opcode)];
    }
    fn op_add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        const item_lhs = stack.get(stack.len - 2);
        const item_rhs = stack.get(stack.len - 1);
        // const res = item_lhs.bytes + item_rhs;
        // _ = pc;
        std.debug.print("OP_ADD {any} {any} {any} {}\n ", .{ item_lhs, item_rhs, code, pc });
    }
    // fn push_op(pc: u32, code: [*]const Instruction, stack: *Stack) !void {
    // const push_val = c
    // }
};

pub const Instruction = struct {
    opcode: Opcode,
};
// fn getEnumOrdinal(comptime T: type, value: T) usize {
//     const fields = @typeInfo(T).Enum.fields;
//     for (fields, 0..) |field, i| {
//         if (@intFromEnum(value) == field.value) {
//             return i;
//         }
//     }
//     unreachable;
// }
// const OpcodeToOrdinal = struct {
//     // Create a lookup table at comptime
//     const table = block: {
//         const fields = @typeInfo(Opcode).Enum.fields;
//         var map: [256]u8 = undefined;
//         for (fields, 0..) |field, i| {
//             map[field.value] = @intCast(i);
//         }
//         break :block map;
//     };

//     // Function to get ordinal at runtime
//     pub fn getOrdinal(opcode: Opcode) u8 {
//         return table[@intFromEnum(opcode)];
//     }
// };
test {
    var funcs = std.ArrayList(Instruction).init(std.testing.allocator);
    defer funcs.deinit();
    const x = Instruction{ .opcode = Opcode.op_add };
    try funcs.append(x);
    // var stack = try Stack.init(5);
    // var s = [_]u8{1};
    // try stack.append(StackValue{ .bytes = &s });
    // try stack.append(StackValue{ .bytes = &s });
    // try InstructionFuncs.run(@intFromEnum(x.opcode), funcs.items.ptr, &stack);
    // try InstructionFuncs.run(0x93, funcs.items.ptr, &stack);
    // _ = InstructionFuncs.lookup(x.opcode);
    const items = InstructionFuncs.opcodeToFuncTable;
    for (items, 0..) |i, idx| {
        std.debug.print("item {} index {} \n", .{ i, idx });
    }
}
pub fn op_0(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_1(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_2(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_3(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_4(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_5(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_6(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_7(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_8(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_9(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_10(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_11(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_12(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_13(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_14(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_15(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_16(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_17(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_18(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_19(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_20(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_21(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_22(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_23(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_24(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_25(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_26(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_27(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_28(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_29(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_30(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_31(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_33(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_34(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_35(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_36(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_37(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_38(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_39(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_40(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_41(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_42(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_43(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_44(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_45(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_46(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_47(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_48(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_49(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_50(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_51(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_52(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_53(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_54(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_55(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_56(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_57(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_58(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_59(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_60(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_61(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_62(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_63(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_65(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_66(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_67(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_68(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_69(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_70(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_71(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_72(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_73(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_74(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushbytes_75(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushdata_1(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushdata_2(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pushdata_4(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_1negate(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_reserved(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_1(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_2(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_3(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_4(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_5(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_6(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_7(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_8(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_9(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_10(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_11(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_12(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_13(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_14(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_15(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_16(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_ver(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_if(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_notif(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_verif(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_vernotif(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_else(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_endif(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_verify(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_return(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_toaltstack(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_fromaltstack(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_2drop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_2dup(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_3dup(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_2over(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_2rot(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_2swap(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_ifdup(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_depth(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_drop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_dup(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nip(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_over(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_pick(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_roll(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_rot(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_swap(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_tuck(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_cat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_split(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_num2bin(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_bin2num(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_size(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_invert(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_and(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_or(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_xor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_equal(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_equalverify(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_reserved1(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_reserved2(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_1add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_1sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_2mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_2div(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_negate(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_not(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_0notequal(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}

pub fn op_sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_div(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_mod(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_lshift(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_rshift(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_booland(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_boolor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_numequal(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_numequalverify(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_numnotequal(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_lessthan(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_greaterthan(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_lessthanorequal(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_greaterthanorequal(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_min(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_max(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_within(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_ripemd160(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_sha1(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_sha256(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_hash160(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_hash256(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    std.debug.print("HASH256\n", .{});
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_codeseparator(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_checksig(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_checksigverify(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_checkmultisig(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_checkmultisigverify(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop1(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_checklocktimeverify(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_checksequenceverify(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop4(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop5(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop6(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop7(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop8(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop9(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_nop10(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_checkdatasig(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_checkdatasigverify(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_reversebytes(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown189(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown190(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown191(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_inputindex(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_activebytecode(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_txversion(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_txinputcount(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_txoutputcount(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_txlocktime(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_utxovalue(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_utxobytecode(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_outpointtxhash(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_outpointindex(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_inputbytecode(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_inputsequencenumber(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_outputvalue(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_outputbytecode(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_utxotokencategory(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_utxotokencommitment(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_utxotokenamount(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_outputtokencategory(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_outputtokencommitment(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_outputtokenamount(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown212(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown213(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown214(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown215(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown216(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown217(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown218(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown219(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown220(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown221(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown222(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown223(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown224(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown225(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown226(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown227(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown228(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown229(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown230(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown231(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown232(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown233(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown234(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown235(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown236(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown237(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown238(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown239(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown240(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown241(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown242(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown243(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown244(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown245(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown246(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown247(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown248(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown249(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown250(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown251(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown252(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown253(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown254(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
pub fn op_unknown255(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    _ = pc;
    _ = code;
    _ = stack;
}
