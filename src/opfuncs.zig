pub const Instruction = *const fn (program: *Program) anyerror!void;

pub const opcodeToFuncTable = [256]Instruction{
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
    &op_eval,
    &op_if,
    &op_notif,
    &op_begin,
    &op_until,
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
pub fn op_0(program: *Program) anyerror!void {
    _ = &program;
}
pub fn op_pushbytes_1(program: *Program) anyerror!void {
    _ = &program;
}
pub fn op_pushbytes_2(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_3(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_4(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_5(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_6(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_7(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_8(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_9(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_10(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_11(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_12(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_13(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_14(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_15(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_16(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_17(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_18(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_19(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_20(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_21(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_22(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_23(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_24(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_25(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_26(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_27(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_28(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_29(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_30(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_31(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_32(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_33(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_34(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_35(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_36(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_37(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_38(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_39(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_40(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_41(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_42(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_43(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_44(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_45(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_46(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_47(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_48(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_49(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_50(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_51(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_52(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_53(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_54(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_55(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_56(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_57(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_58(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_59(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_60(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_61(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_62(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_63(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_64(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_65(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_66(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_67(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_68(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_69(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_70(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_71(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_72(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_73(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_74(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushbytes_75(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushdata_1(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushdata_2(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_pushdata_4(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_1negate(program: *Program) anyerror!void {
    const code = program.instruction_bytecode[program.instruction_pointer..];
    const push_value = try readPush(code, program.allocator);
    try program.stack.append(StackValue{ .bytes = push_value.data });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_reserved(program: *Program) anyerror!void {
    _ = program;
    return error.reserved;
}

pub fn op_1(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_2(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_3(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_4(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_5(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_6(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_7(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_8(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_9(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_10(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_11(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_12(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_13(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_14(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_15(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_16(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_nop(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_ver(program: *Program) anyerror!void {
    // _ = pc;
    _ = program;
    return error.DisabledOpcode;
}

pub fn op_if(program: *Program) anyerror!void {
    var b = false;

    if (program.control_stack.allTrue()) {
        if (program.stack.len < 1) {
            return error.unbalanced_conditional;
        }
        const top = program.stack.get(program.stack.len - 1);

        b = readScriptBool(top.bytes);
    }
    _ = program.stack.pop();

    try program.control_stack.pushBool(b);
    // std.debug.print("control stack  {} {any}\n", .{ program.control_stack.size, program.stack.slice() });
}

pub fn op_notif(program: *Program) anyerror!void {
    var b = false;

    if (program.control_stack.allTrue()) {
        if (program.stack.len < 1) {
            return error.unbalanced_conditional;
        }
        const top = program.stack.get(program.stack.len - 1);

        b = !readScriptBool(top.bytes);
    }
    _ = program.stack.pop();

    try program.control_stack.pushBool(b);
}
pub fn op_eval(program: *Program) !void {
    const execution_state = program.control_stack.allTrue();
    if (execution_state) {
        if (program.stack.len == 0) {
            return error.empty_stack;
        }

        const bytecode = program.stack.pop().bytes;

        // Check for malformed bytecode (e.g., incomplete push operations)
        // if (!isValidBytecode(bytecode)) {
        //     return error.malformed_bytecode;
        // }

        const stack_frame = StackFrame{
            .instruction_bytecode = program.instruction_bytecode,
            .instruction_pointer = program.instruction_pointer,
            .code_separator = program.code_separator,
        };
        try program.control_stack.pushFrame(stack_frame);

        // std.debug.print("EVAL FRAME {any}\n", .{bytecode});
        program.instruction_bytecode = bytecode;
        program.instruction_pointer = 0;
        program.code_separator = 0;

        try VirtualMachine.executeProgram(program);
        if (program.control_stack.values.getLast() == .frame) {
            const frame = program.control_stack.popFrame() orelse return error.control_stack_corrupted;
            program.instruction_bytecode = frame.instruction_bytecode;
            program.instruction_pointer = frame.instruction_pointer;
            program.code_separator = frame.code_separator;
        }
    }
}

pub fn op_begin(program: *Program) anyerror!void {
    var control_stack = program.control_stack;
    const execution_state = control_stack.allTrue();
    if (execution_state) {
        try program.control_stack.pushInteger(program.instruction_pointer);
    } else {
        try control_stack.pushBool(false);
    }
}

pub fn op_until(program: *Program) anyerror!void {
    var control_stack = &program.control_stack;
    const execution_state = control_stack.allTrue();

    // Pop the top item from the control stack
    const top_value = control_stack.pop() orelse return error.control_stack_underflow;
    if (top_value != .integer) {
        return error.unexpected_until;
    }
    if (!execution_state) {
        if (!top_value.boolean) {
            return;
        } else {
            return error.unexpected_until_missing_endif;
        }
    }

    // Ensure the top value is an integer (as per the specification)
    const begin_ip = switch (top_value) {
        .integer => |ip| ip,
        else => return error.invalid_control_stack_value, // Error if not an integer
    };

    // Pop the top value from the stack to check if it's 0 (similar to OP_NOTIF)
    const stack_value = program.stack.pop().bytes;
    const value = readScriptBool(stack_value); // Convert stack value to an integer

    // If the value is 0, jump back to the instruction pointer stored in the control stack
    if (value) {
        // program.instruction_pointer = begin_ip;
        return;
    }
    program.instruction_pointer = begin_ip - 1;
}

pub fn op_else(program: *Program) anyerror!void {
    if (program.control_stack.values.getLast() != .boolean) {
        return error.unexpected_else;
    }
    program.control_stack.toggleTop();
}

pub fn op_endif(program: *Program) anyerror!void {
    if (program.control_stack.values.getLast() != .boolean) {
        return error.unexpected_endif;
    }
    _ = program.control_stack.pop();
}

pub fn op_verify(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const top = program.stack.get(program.stack.len - 1);
    const b = readScriptBool(top.bytes);
    if (b) {
        _ = program.stack.pop();
    } else {
        return error.verify;
    }
}

pub fn op_return(program: *Program) anyerror!void {
    // _ = pc;
    _ = program;
    return error.op_return;
}

pub fn op_toaltstack(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    try program.alt_stack.append(program.stack.pop());
}

pub fn op_fromaltstack(program: *Program) anyerror!void {
    if (program.alt_stack.len < 1) {
        return error.read_empty_stack;
    }
    try program.stack.append(program.alt_stack.pop());
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_2drop(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    _ = program.stack.pop();
    _ = program.stack.pop();
}

pub fn op_2dup(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const item1 = program.stack.get(program.stack.len - 2);
    const item2 = program.stack.get(program.stack.len - 1);
    const item1_copy = try program.allocator.dupe(u8, item1.bytes);
    const item2_copy = try program.allocator.dupe(u8, item2.bytes);
    try program.stack.append(StackValue{ .bytes = item1_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    try program.stack.append(StackValue{ .bytes = item2_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    // std.debug.print("OP_2DUP {any}\n", .{program.stack.get(program.stack.len - 1)});
}

pub fn op_3dup(program: *Program) anyerror!void {
    if (program.stack.len < 3) {
        return error.read_empty_stack;
    }
    const item1 = program.stack.get(program.stack.len - 3);
    const item2 = program.stack.get(program.stack.len - 2);
    const item3 = program.stack.get(program.stack.len - 1);

    const item1_copy = try program.allocator.dupe(u8, item1.bytes);
    const item2_copy = try program.allocator.dupe(u8, item2.bytes);
    const item3_copy = try program.allocator.dupe(u8, item3.bytes);
    try program.stack.append(StackValue{ .bytes = item1_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    try program.stack.append(StackValue{ .bytes = item2_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    try program.stack.append(StackValue{ .bytes = item3_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_2over(program: *Program) anyerror!void {
    if (program.stack.len < 4) {
        return error.read_empty_stack;
    }
    const item1 = program.stack.get(program.stack.len - 4);
    const item2 = program.stack.get(program.stack.len - 3);
    const item1_copy = try program.allocator.dupe(u8, item1.bytes);
    const item2_copy = try program.allocator.dupe(u8, item2.bytes);
    try program.stack.append(StackValue{ .bytes = item1_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    try program.stack.append(StackValue{ .bytes = item2_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_2rot(program: *Program) anyerror!void {
    if (program.stack.len < 6) {
        return error.read_empty_stack;
    }
    // Save copies of first two items (a, b)
    const item1 = program.stack.get(program.stack.len - 6);
    const item2 = program.stack.get(program.stack.len - 5);
    const item1_copy = try program.allocator.dupe(u8, item1.bytes);
    const item2_copy = try program.allocator.dupe(u8, item2.bytes);

    // Remove the original first two items
    _ = program.stack.orderedRemove(program.stack.len - 6);
    _ = program.stack.orderedRemove(program.stack.len - 5);

    // Append the copies at the end to complete rotation
    try program.stack.append(StackValue{ .bytes = item1_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    try program.stack.append(StackValue{ .bytes = item2_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    // if (!stateContinue(pc, program)) return;
}

pub fn op_2swap(program: *Program) anyerror!void {
    if (program.stack.len < 4) {
        return error.read_empty_stack;
    }

    // Save copies of first pair (a, b)
    const item1 = program.stack.get(program.stack.len - 4);
    const item2 = program.stack.get(program.stack.len - 3);
    const item1_copy = try program.allocator.dupe(u8, item1.bytes);
    const item2_copy = try program.allocator.dupe(u8, item2.bytes);

    // Remove the first pair
    _ = program.stack.orderedRemove(program.stack.len - 4);
    _ = program.stack.orderedRemove(program.stack.len - 3);

    // Append the copies to complete the swap
    try program.stack.append(StackValue{ .bytes = item1_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    try program.stack.append(StackValue{ .bytes = item2_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_ifdup(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const top = program.stack.get(program.stack.len - 1);
    const b = readScriptBool(top.bytes);
    if (b) {
        try program.stack.append(top);
        program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    }
}

pub fn op_depth(program: *Program) anyerror!void {
    const len = program.stack.len;
    var num = try BigInt.initSet(program.allocator, len);
    var minimally_encoded = try encodeScriptIntMininal(&num, program.allocator);
    try program.stack.append(StackValue{ .bytes = minimally_encoded[0..] });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_drop(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    _ = program.stack.pop();
}

pub fn op_dup(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item1 = program.stack.get(program.stack.len - 1);
    const item1_copy = try program.allocator.dupe(u8, item1.bytes);
    try program.stack.append(StackValue{ .bytes = item1_copy });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_nip(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    _ = program.stack.orderedRemove(program.stack.len - 2);
}

pub fn op_over(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    _ = try program.stack.append(program.stack.get(program.stack.len - 2));

    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_pick(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }

    const item = program.stack.get(program.stack.len - 1);
    var n = try readScriptInt(item.bytes, program.allocator);

    const script_num = try n.to(i64);
    _ = program.stack.pop();
    if (script_num < 0 or script_num >= program.stack.len) {
        return error.invalid_stack_op;
    }
    const it = @as(i64, @intCast(program.stack.len)) - script_num - 1;
    const picked = program.stack.get(@as(usize, @intCast(it)));
    try program.stack.append(StackValue{ .bytes = picked.bytes });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_roll(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }

    const item = program.stack.get(program.stack.len - 1);
    var n = try readScriptInt(item.bytes, program.allocator);

    const script_num = try n.to(i64);
    _ = program.stack.pop();
    if (script_num < 0 or script_num >= program.stack.len) {
        return error.invalid_stack_op;
    }
    const it = @as(i64, @intCast(program.stack.len)) - script_num - 1;
    const rolled = program.stack.orderedRemove(@intCast(it));
    try program.stack.append(StackValue{ .bytes = rolled.bytes });
    program.metrics.tallyOp(@intCast(script_num));
}

pub fn op_rot(program: *Program) anyerror!void {
    if (program.stack.len < 3) {
        return error.read_empty_stack;
    }
    const a = program.stack.get(program.stack.len - 3);
    const b = program.stack.get(program.stack.len - 2);
    const c = program.stack.get(program.stack.len - 1);

    program.stack.set(program.stack.len - 3, b);
    program.stack.set(program.stack.len - 2, c);
    program.stack.set(program.stack.len - 1, a);
}

pub fn op_swap(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const a = program.stack.get(program.stack.len - 2);
    const b = program.stack.get(program.stack.len - 1);

    // Swap them (a b -> b a)
    program.stack.set(program.stack.len - 2, b);
    program.stack.set(program.stack.len - 1, a);
}

pub fn op_tuck(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const top = program.stack.get(program.stack.len - 1);
    program.metrics.tallyPushOp(@intCast(top.bytes.len));
    try program.stack.insert(program.stack.len - 2, top);
}

pub fn op_cat(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }

    const item1 = program.stack.get(program.stack.len - 2);
    const item2 = program.stack.get(program.stack.len - 1);

    if (item1.bytes.len + item2.bytes.len > ConsensusBch2026.maximum_bytecode_length) {
        return error.max_push_element;
    }

    var cat_buff = try program.allocator.alloc(u8, item1.bytes.len + item2.bytes.len);

    @memcpy(cat_buff[0..item1.bytes.len], item1.bytes);
    @memcpy(cat_buff[item1.bytes.len..], item2.bytes);

    _ = program.stack.pop();
    _ = program.stack.pop();

    try program.stack.append(StackValue{ .bytes = cat_buff });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_split(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }

    const data = program.stack.get(program.stack.len - 2);
    const split_value = program.stack.get(program.stack.len - 1);

    const split_position = try readScriptIntI64(split_value.bytes);
    if (split_position < 0 or split_position > data.bytes.len) {
        return error.invalid_split_range;
    }

    const range1 = data.bytes[0..@intCast(split_position)];
    const range2 = data.bytes[@intCast(split_position)..];

    program.stack.set(program.stack.len - 2, StackValue{ .bytes = range1 });
    program.stack.set(program.stack.len - 1, StackValue{ .bytes = range2 });

    program.metrics.tallyPushOp(@intCast(range1.len + range2.len));
}

pub fn op_num2bin(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const num_size = program.stack.get(program.stack.len - 1);
    const size = try readScriptIntI64(num_size.bytes);

    if (size > ConsensusBch2026.maximum_bytecode_length) {
        return error.max_push_element;
    }

    _ = program.stack.pop();

    const raw = program.stack.get(program.stack.len - 1).bytes;

    var script_num = try scriptIntParse(raw, program.allocator);
    // std.debug.print("STACK {any}\n", .{stack.buffer[0..stack.len]});
    var raw_num = try encodeScriptIntMininal(&script_num, program.allocator);
    // std.debug.print("RAW {any} size {any}\n", .{ raw_num, size });
    if (raw_num.len > size) {
        return error.impossible_encoding;
    }

    // Check if the requested size is too small to encode the number

    var list = std.ArrayList(u8).init(program.allocator);
    try list.resize(@intCast(@abs(size)));

    list.clearAndFree();
    try list.appendSlice(raw_num);

    if (list.items.len == size) {
        program.stack.set(program.stack.len - 1, StackValue{ .bytes = list.items });
        return;
    }
    list.clearAndFree();
    var signbit: u8 = 0x00;
    if (raw_num.len > 0) {
        signbit = raw_num[raw_num.len - 1] & 0x80;
        raw_num[raw_num.len - 1] &= 0x7f;
    }

    try list.ensureTotalCapacity(@intCast(size));
    try list.appendSlice(raw_num);
    while (list.items.len < size - 1) {
        try list.append(0x00);
    }

    try list.append(signbit);
    program.stack.set(program.stack.len - 1, StackValue{ .bytes = list.items });
    // program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    program.metrics.tallyPushOp(@intCast(raw_num.len));
}

pub fn op_bin2num(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const number = program.stack.get(program.stack.len - 1);
    var num_big = try scriptIntParse(number.bytes, program.allocator);
    const num = try encodeScriptIntMininal(&num_big, program.allocator);

    _ = program.stack.pop();
    try program.stack.append(StackValue{ .bytes = num });

    program.metrics.tallyPushOp(@intCast(number.bytes.len));
}

pub fn op_size(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item = program.stack.get(program.stack.len - 1);
    const size = item.bytes.len;
    var num = try BigInt.initSet(program.allocator, size);
    const minimally_encoded = try encodeScriptIntMininal(&num, program.allocator);
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_invert(program: *Program) anyerror!void {
    _ = program;
    return error.DisabledOpcode;
}

pub fn op_and(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.invalid_stack_op;
    }
    const item1 = program.stack.get(program.stack.len - 2);
    const item2 = program.stack.get(program.stack.len - 1);
    if (item1.bytes.len != item2.bytes.len) {
        return error.bitwise_stack_item_size_mismatch;
    }
    for (0..item1.bytes.len) |i| {
        item1.bytes[i] &= item2.bytes[i];
    }

    _ = program.stack.pop();
    program.metrics.tallyOp(@intCast(item1.bytes.len));
}

pub fn op_or(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.invalid_stack_op;
    }
    const item1 = program.stack.get(program.stack.len - 2);
    const item2 = program.stack.get(program.stack.len - 1);
    if (item1.bytes.len != item2.bytes.len) {
        return error.bitwise_stack_item_size_mismatch;
    }
    for (0..item1.bytes.len) |i| {
        item1.bytes[i] |= item2.bytes[i];
    }
    _ = program.stack.pop();
    program.metrics.tallyOp(@intCast(item1.bytes.len));
}

pub fn op_xor(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.invalid_stack_op;
    }
    const item1 = program.stack.get(program.stack.len - 2);
    const item2 = program.stack.get(program.stack.len - 1);
    if (item1.bytes.len != item2.bytes.len) {
        return error.bitwise_stack_item_size_mismatch;
    }
    for (0..item1.bytes.len) |i| {
        item1.bytes[i] ^= item2.bytes[i];
    }
    _ = program.stack.pop();
    program.metrics.tallyOp(@intCast(item1.bytes.len));
}

pub fn op_equal(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const item1 = program.stack.get(program.stack.len - 2);
    const item2 = program.stack.get(program.stack.len - 1);
    const is_equal = std.mem.eql(u8, item1.bytes, item2.bytes);
    // std.debug.print("OPEQUAL {}\n{any}\n{any}\n", .{ is_equal, item1, item2 });

    // Allocate  only if needed, and ensure it's always freed
    if (is_equal) {
        var allocated_res: []u8 = try program.allocator.alloc(u8, 1);
        // defer gpa.free(allocated_res);
        _ = program.stack.pop();
        _ = program.stack.pop();
        allocated_res[0] = @as(u8, @intFromBool(is_equal));
        try program.stack.append(StackValue{ .bytes = allocated_res });
    } else {
        _ = program.stack.pop();
        _ = program.stack.pop();
        try program.stack.append(StackValue{ .bytes = &.{} });
    }
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_equalverify(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const item2 = program.stack.pop();
    const item1 = program.stack.pop();

    const is_equal = std.mem.eql(u8, item1.bytes, item2.bytes);
    // Allocate  only if needed, and ensure it's always freed
    // std.debug.print("OPEQUAL {}\n{any}\n{any}\n", .{ is_equal, item1, item2 });
    if (!is_equal) {
        return error.equal_verify_fail;
    }
}

pub fn op_reserved1(program: *Program) anyerror!void {
    // _ = pc;
    _ = program;
    return error.reserved_opcode;
}

pub fn op_reserved2(program: *Program) anyerror!void {
    // _ = pc;
    _ = program;
    return error.reserved_opcode;
}

pub fn op_1add(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item = program.stack.get(program.stack.len - 1);
    var script_num = try readScriptInt(item.bytes, program.allocator);
    try script_num.addScalar(&script_num, 1);
    _ = program.stack.pop();
    const val = try encodeScriptIntMininal(&script_num, program.allocator);

    if (val.len > ConsensusBch2026.maximum_bytecode_length) {
        return error.arithmetic_operation_exceeds_vm_limits_range;
    }
    const res = try program.allocator.dupe(u8, val);
    _ = try program.stack.append(StackValue{ .bytes = res });
}

pub fn op_1sub(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const push_cost_factor = 2;
    const item = program.stack.get(program.stack.len - 1);
    var script_num = try readScriptInt(item.bytes, program.allocator);
    const one = try BigInt.initSet(program.allocator, 1);
    try script_num.sub(&script_num, &one);

    _ = program.stack.pop();
    const val = try encodeScriptIntMininal(&script_num, program.allocator);

    if (val.len > ConsensusBch2026.maximum_bytecode_length) {
        return error.arithmetic_operation_exceeds_vm_limits_range;
    }
    const res = try program.allocator.dupe(u8, val);
    _ = try program.stack.append(StackValue{ .bytes = res });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_2mul(program: *Program) anyerror!void {
    _ = program;
    return error.DisabledOpcode;
}

pub fn op_2div(program: *Program) anyerror!void {
    _ = program;
    return error.DisabledOpcode;
}

pub fn op_negate(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const push_cost_factor = 2;
    const item = program.stack.get(program.stack.len - 1);
    var script_num = try readScriptInt(item.bytes, program.allocator);
    script_num.negate();

    _ = program.stack.pop();
    const val = try encodeScriptIntMininal(&script_num, program.allocator);

    if (val.len > ConsensusBch2026.maximum_bytecode_length) {
        return error.arithmetic_operation_exceeds_vm_limits_range;
    }
    const res = try program.allocator.dupe(u8, val);
    _ = try program.stack.append(StackValue{ .bytes = res });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_abs(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const push_cost_factor = 2;
    const item = program.stack.get(program.stack.len - 1);
    var script_num = try readScriptInt(item.bytes, program.allocator);
    if (!script_num.isPositive()) {
        script_num.negate();
    }
    _ = program.stack.pop();
    const val = try encodeScriptIntMininal(&script_num, program.allocator);

    if (val.len > ConsensusBch2026.maximum_bytecode_length) {
        return error.arithmetic_operation_exceeds_vm_limits_range;
    }
    const res = try program.allocator.dupe(u8, val);
    _ = try program.stack.append(StackValue{ .bytes = res });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_not(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const push_cost_factor = 1;
    const item = program.stack.pop();
    var script_num = try readScriptInt(item.bytes, program.allocator);
    _ = try script_num.set(@intFromBool(script_num.eqlZero()));

    const val = try encodeScriptIntMininal(&script_num, program.allocator);

    if (val.len > ConsensusBch2026.maximum_bytecode_length) {
        return error.arithmetic_operation_exceeds_vm_limits_range;
    }
    const res = try program.allocator.dupe(u8, val);
    _ = try program.stack.append(StackValue{ .bytes = res });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_0notequal(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const push_cost_factor = 1;
    const item = program.stack.get(program.stack.len - 1);
    var script_num = try readScriptInt(item.bytes, program.allocator);
    _ = try script_num.set(@intFromBool(!script_num.eqlZero()));

    _ = program.stack.pop();
    const val = try encodeScriptIntMininal(&script_num, program.allocator);

    if (val.len > ConsensusBch2026.maximum_bytecode_length) {
        return error.arithmetic_operation_exceeds_vm_limits_range;
    }
    const res = try program.allocator.dupe(u8, val);
    _ = try program.stack.append(StackValue{ .bytes = res });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_add(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 2;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    var int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    try int_l.add(&int_l, &int_r);
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_sub(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 2;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    var int_r = try readScriptInt(item_rhs.bytes, program.allocator);

    try int_l.sub(&int_l, &int_r);
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_mul(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    // var quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 2;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    var int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    try int_l.mul(&int_l, &int_r);
    const quadratic_op_cost: u32 = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_div(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    //quotient
    var q = try BigInt.init(program.allocator);
    defer q.deinit();
    //remainder
    var r = try BigInt.init(program.allocator);
    defer r.deinit();
    // var quadratic_op_cost: u32 = 0;
    // var push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    var int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    if (int_r.eqlZero()) {
        return error.div_zero;
    }
    _ = try BigInt.divTrunc(&q, &r, &int_l, &int_r);
    int_l.swap(&q);
    const quadratic_op_cost: u32 = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    const push_cost_factor: u32 = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_mod(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    //quotient
    var q = try BigInt.init(program.allocator);
    defer q.deinit();
    //remainder
    var r = try BigInt.init(program.allocator);
    defer r.deinit();
    // var quadratic_op_cost: u32 = 0;
    // var push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    var int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    if (int_r.eqlZero()) {
        return error.div_zero;
    }
    _ = try BigInt.divTrunc(&q, &r, &int_l, &int_r);
    int_l.swap(&r);
    const quadratic_op_cost: u32 = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    const push_cost_factor: u32 = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_lshift(program: *Program) anyerror!void {
    // _ = pc;
    _ = program;
    return error.DisabledOpcode;
}

pub fn op_rshift(program: *Program) anyerror!void {
    // _ = pc;
    _ = program;
    return error.DisabledOpcode;
}

pub fn op_booland(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    var int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = !int_l.eqlZero() and !int_r.eqlZero();
    try int_l.set(@intFromBool(op_res));
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_boolor(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    var int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = !int_l.eqlZero() or !int_r.eqlZero();
    try int_l.set(@intFromBool(op_res));
    // quadratic_op_cost = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    // push_cost_factor = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_numequal(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = int_l.eql(int_r);
    try int_l.set(@intFromBool(op_res));
    // quadratic_op_cost = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    // push_cost_factor = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_numequalverify(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = int_l.eql(int_r);
    if (!op_res) {
        return error.equal_verify_fail;
    }
    try int_l.set(@intFromBool(op_res));
    _ = program.stack.pop();
    _ = program.stack.pop();
    program.metrics.tallyOp(quadratic_op_cost);
    // program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_numnotequal(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = !int_l.eql(int_r);
    try int_l.set(@intFromBool(op_res));
    // quadratic_op_cost = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    // push_cost_factor = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_lessthan(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = int_l.order(int_r).compare(.lt);
    try int_l.set(@intFromBool(op_res));
    // quadratic_op_cost = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    // push_cost_factor = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_greaterthan(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = int_l.order(int_r).compare(.gt);
    try int_l.set(@intFromBool(op_res));
    // quadratic_op_cost = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    // push_cost_factor = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_lessthanorequal(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = int_l.order(int_r).compare(.lte);
    try int_l.set(@intFromBool(op_res));
    // quadratic_op_cost = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    // push_cost_factor = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
    // if (!stateContinue(pc, program)) return;
    // try @call(.always_tail, InstructionFuncs.lookup(@as(
    //     Opcode,
    //     @enumFromInt(program.instruction_bytecode[program.instruction_pointer]),
    // )), .{ pc + 1, program });
}

pub fn op_greaterthanorequal(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 1;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    const op_res = int_l.order(int_r).compare(.gte);
    try int_l.set(@intFromBool(op_res));
    // quadratic_op_cost = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    // push_cost_factor = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_min(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 2;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    // std.debug.print("ADD {any} {any}\n", .{ item_lhs.bytes.len, item_rhs.bytes.len });
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    var res = if (int_l.order(int_r).compare(.lt)) int_l else int_r;
    int_l.swap(&res);
    // quadratic_op_cost = @intCast(item_lhs.bytes.len * item_rhs.bytes.len);
    // push_cost_factor = 2;
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_max(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    const quadratic_op_cost: u32 = 0;
    const push_cost_factor: u32 = 2;

    const item_lhs = program.stack.get(program.stack.len - 2);
    const item_rhs = program.stack.get(program.stack.len - 1);
    var int_l = try readScriptInt(item_lhs.bytes, program.allocator);
    const int_r = try readScriptInt(item_rhs.bytes, program.allocator);
    var res = if (int_l.order(int_r).compare(.gt)) int_l else int_r;
    int_l.swap(&res);
    _ = program.stack.pop();
    _ = program.stack.pop();
    const minimally_encoded = try encodeScriptIntMininal(&int_l, program.allocator);
    if (minimally_encoded.len > ConsensusBch2026.maximum_stack_item_length) return error.max_push_element;
    try program.stack.append(StackValue{ .bytes = minimally_encoded });
    program.metrics.tallyOp(quadratic_op_cost);
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len * push_cost_factor));
}

pub fn op_within(program: *Program) anyerror!void {
    if (program.stack.len < 3) {
        return error.read_empty_stack;
    }

    const a = try scriptIntParse(program.stack.get(program.stack.len - 3).bytes, program.allocator);
    const b = try scriptIntParse(program.stack.get(program.stack.len - 2).bytes, program.allocator);
    const c = try scriptIntParse(program.stack.get(program.stack.len - 1).bytes, program.allocator);

    const result = b.order(a).compare(.lte) and a.order(c).compare(.lt);
    _ = program.stack.pop();
    _ = program.stack.pop();
    _ = program.stack.pop();

    if (result) {
        const res = try program.allocator.dupe(u8, &[_]u8{1});
        try program.stack.append(StackValue{ .bytes = res });
    } else {
        try program.stack.append(StackValue{ .bytes = &.{} });
    }

    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_ripemd160(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item = program.stack.pop();
    var buff = try program.allocator.alloc(u8, 32);
    const is_two_rounds = false;
    const hash_len: usize = 20;
    ripemd160.Ripemd160.hash(item.bytes, buff[0..20], .{});
    try program.stack.append(StackValue{ .bytes = buff[0..hash_len] });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    program.metrics.tallyHashOp(@intCast(item.bytes.len), is_two_rounds);
}

pub fn op_sha1(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item = program.stack.pop();
    var buff = try program.allocator.alloc(u8, 32);
    const is_two_rounds = false;
    const hash_len: usize = 20;
    std.crypto.hash.Sha1.hash(item.bytes, buff[0..20], .{});
    try program.stack.append(StackValue{ .bytes = buff[0..hash_len] });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    program.metrics.tallyHashOp(@intCast(item.bytes.len), is_two_rounds);
}

pub fn op_sha256(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item = program.stack.pop();
    var buff = try program.allocator.alloc(u8, 32);
    const is_two_rounds = false;
    const hash_len = 32;
    std.crypto.hash.sha2.Sha256.hash(item.bytes, buff[0..32], .{});
    try program.stack.append(StackValue{ .bytes = buff[0..hash_len] });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    program.metrics.tallyHashOp(@intCast(item.bytes.len), is_two_rounds);
}

pub fn op_hash160(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item = program.stack.pop();
    var buff = try program.allocator.alloc(u8, 32);
    const is_two_rounds = true;
    const hash_len: usize = 20;
    std.crypto.hash.sha2.Sha256.hash(item.bytes, buff[0..32], .{});
    ripemd160.Ripemd160.hash(buff[0..32], buff[0..20], .{});
    try program.stack.append(StackValue{ .bytes = buff[0..hash_len] });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    program.metrics.tallyHashOp(@intCast(item.bytes.len), is_two_rounds);
}

pub fn op_hash256(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item = program.stack.pop();
    var buff = try program.allocator.alloc(u8, 32);
    const is_two_rounds = true;
    const hash_len: usize = 32;
    // hash_len = 32;
    std.crypto.hash.sha2.Sha256.hash(item.bytes, buff[0..32], .{});
    std.crypto.hash.sha2.Sha256.hash(buff[0..32], buff[0..32], .{});
    try program.stack.append(StackValue{ .bytes = buff[0..hash_len] });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
    program.metrics.tallyHashOp(@intCast(item.bytes.len), is_two_rounds);
}
pub fn op_codeseparator(program: *Program) anyerror!void {
    program.code_separator = program.instruction_pointer + 1;
    // if (!stateContinue(pc, program)) return;
}

pub fn op_checksig(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    var bytes_hashed: usize = 0;
    const sig = program.stack.get(program.stack.len - 2);
    // std.debug.print("OP_CHECK SIG {any} PUB KEY {any}\n", .{ program.stack.get(program.stack.len - 2), program.stack.get(program.stack.len - 1) });
    // std.debug.print("SIGNATURE {any}\n", .{sig.bytes});
    const publickey = program.stack.get(program.stack.len - 1);
    // std.debug.print("PUBKEY {any}\n", .{publickey.bytes});
    const is_valid_sig = try checkSig(
        program.context,
        sig.bytes,
        publickey.bytes,
        program.instruction_bytecode[0..],
        &bytes_hashed,
        program.allocator,
    );
    program.metrics.tallySigChecks(1);
    program.metrics.tallyHashOp(@intCast(bytes_hashed), true);

    _ = program.stack.pop();
    _ = program.stack.pop();

    const val = &[_]u8{@intCast(@intFromBool(is_valid_sig))};
    const res = try program.allocator.dupe(u8, val);
    try program.stack.append(StackValue{ .bytes = res });

    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_checksigverify(program: *Program) anyerror!void {
    if (program.stack.len < 2) {
        return error.read_empty_stack;
    }
    var bytes_hashed: usize = 0;
    const sig = program.stack.get(program.stack.len - 2);
    const publickey = program.stack.get(program.stack.len - 1);
    const is_valid_sig = try checkSig(
        program.context,
        sig.bytes,
        publickey.bytes,
        program.instruction_bytecode[0..][0..],
        &bytes_hashed,
        program.allocator,
    );
    program.metrics.tallySigChecks(1);
    program.metrics.tallyHashOp(@intCast(bytes_hashed), true);
    if (!is_valid_sig) {
        return error.verify;
    }
    _ = program.stack.pop();
    _ = program.stack.pop();
}

pub fn op_checkmultisig(program: *Program) anyerror!void {
    var success = true;
    var bytes_hashed: usize = 0;

    const index_key_count: usize = 1; // Position of N
    if (program.stack.len < index_key_count) {
        return error.invalid_stack_op;
    }
    var n = try readScriptInt(program.stack.get(program.stack.len - index_key_count).bytes, program.allocator);
    const num_pubkeys = try n.to(u64);

    if (num_pubkeys < 0 or num_pubkeys > Consensus.MAX_PUBKEYS_MULTISIG) {
        return error.max_pubkey_mulsig;
    }

    // First pushed pubkey is num_pubkeys positions before N
    const index_first_pubkey: usize = @intCast(index_key_count + num_pubkeys);
    const index_sig_count = index_first_pubkey + 1;
    if (program.stack.len < index_sig_count) {
        return error.invalid_stack_op;
    }
    var read_sig_counts = try readScriptInt(program.stack.get(program.stack.len - index_sig_count).bytes, program.allocator);

    const sig_count = try read_sig_counts.to(u64);

    if (sig_count < 0 or sig_count > num_pubkeys) {
        return error.multisig_sig_and_pubkey_missmatch;
    }

    // First pushed signature is sig_count positions before M
    const index_first_sig: usize = @intCast(index_sig_count + sig_count);
    const index_dummy: usize = index_first_sig + 1;

    if (program.stack.len < index_dummy) {
        return error.invalid_stack_op;
    }

    var checkbits: u32 = 0;
    var i_key: u5 = 0;

    if (program.stack.get(program.stack.len - index_dummy).bytes.len != 0) {
        const dummy_item = program.stack.get(program.stack.len - index_dummy);
        _ = try decodeBitfield(dummy_item.bytes, @intCast(num_pubkeys), &checkbits);

        if (@popCount(checkbits) != @as(u32, @truncate(@abs(sig_count)))) {
            return error.invalid_bit_count;
        }

        for (0..@intCast(sig_count)) |i_sig| {
            if (checkbits >> i_key == 0) {
                return error.invalid_bit_range;
            }
            if (i_key >= num_pubkeys) {
                return error.max_pubkey_mulsig;
            }
            while (((checkbits >> i_key) & 0x01) == 0) {
                i_key += 1;
            }

            // Get signature in original push order - subtract i_sig from index_first_sig
            const sig = program.stack.get(program.stack.len - (index_first_sig - i_sig));

            // Get pubkey in original push order - subtract i_key from index_first_pubkey
            const pubkey = program.stack.get(program.stack.len - (index_first_pubkey - i_key));
            var tmp_bytes_hashed: usize = 0;
            // std.debug.print("CHECK MULTI SIG SCHNORR {any}\n ", .{sig.bytes.len});
            if (sig.bytes.len > 65 or sig.bytes.len == 0) {
                return error.non_schnorr_signature_in_schnorr_multisig;
            }
            success = try checkSig(
                program.context,
                sig.bytes,
                pubkey.bytes,
                program.instruction_bytecode[0..][0..],
                &tmp_bytes_hashed,
                program.allocator,
            );

            if (!success) {
                return error.non_null_signature_failure;
            }
            // std.debug.print("CHECK MULTI SIG SCHNORR {any}\n ", .{success});
            if (tmp_bytes_hashed > bytes_hashed) {
                bytes_hashed = tmp_bytes_hashed;
            }
            program.metrics.tallySigChecks(1);
            i_key += 1;
        }

        if (bytes_hashed > 0) {
            program.metrics.tallyHashOp(@intCast(bytes_hashed), true);
        }
        if ((checkbits >> i_key) != 0) {
            return error.invalid_bit_count;
        }
    } else {
        var remaining_sigs = sig_count;
        var remaining_keys = num_pubkeys;
        var all_signatures_null = true;
        while (success and remaining_sigs > 0) {
            // Calculate indices for the current signature and pubkey we're checking
            // For signatures: we start at first_sig and work backwards
            const sig_index = index_first_sig - (sig_count - remaining_sigs);
            // For pubkeys: we start at first_pubkey and work backwards
            const pubkey_index = index_first_pubkey - (num_pubkeys - remaining_keys);

            const sig = program.stack.get(@intCast(program.stack.len - sig_index));
            if (sig.bytes.len == 65) {
                return error.schnorr_signature_in_legacy_multisig;
            }
            const pubkey = program.stack.get(@intCast(program.stack.len - pubkey_index));

            var tmp_bytes_hashed: usize = 0;
            const is_valid_sig = try checkSig(
                program.context,
                sig.bytes,
                pubkey.bytes,
                program.instruction_bytecode[0..],
                &tmp_bytes_hashed,
                program.allocator,
            );
            if (tmp_bytes_hashed > bytes_hashed) {
                bytes_hashed = tmp_bytes_hashed;
            }
            for (0..@intCast(sig_count)) |i| {
                if (program.stack.get(@intCast(program.stack.len - sig_index + i)).bytes.len > 0) {
                    all_signatures_null = false;
                }
            }

            if (is_valid_sig) {
                remaining_sigs -= 1;
            }
            remaining_keys -= 1;

            if (remaining_sigs > remaining_keys) {
                success = false;
            }
        }
        if (!all_signatures_null) {
            program.metrics.tallySigChecks(@intCast(num_pubkeys));
            if (bytes_hashed > 0) {
                program.metrics.tallyHashOp(@intCast(bytes_hashed), true);
            }
        }
    }
    for (0..index_dummy) |_| {
        _ = program.stack.pop();
    }
    // const val = &[_]u8{@intCast(@intFromBool(success))};
    // const res = try program.allocator.dupe(u8, val);
    // try program.stack.append(StackValue{ .bytes = res });
    if (success) {
        const val = &[_]u8{1};
        const res = try program.allocator.dupe(u8, val);
        try program.stack.append(StackValue{ .bytes = res });
    } else {
        const empty = &[_]u8{};
        // const res = try program.allocator.dupe(u8, empty);
        try program.stack.append(StackValue{ .bytes = empty });
    }
    // std.debug.print("CHECK MULTI SIG RES {any}\n", .{success});

    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_checkmultisigverify(program: *Program) anyerror!void {
    _ = try op_checkmultisig(program);
    const top = program.stack.get(program.stack.len - 1);
    const res = readScriptBool(top.bytes);
    if (!res) return error.verify else _ = program.stack.pop();
}

pub fn op_nop1(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_checklocktimeverify(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const item = program.stack.get(program.stack.len - 1);
    const lock_time_num = scriptIntParseI64(item.bytes);
    if (lock_time_num < 0) {
        return error.negative_locktime;
    }
    if (!checkLockTime(lock_time_num, program.context)) {
        return error.read_empty_stack;
    }
}

pub fn op_checksequenceverify(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const item = program.stack.get(program.stack.len - 1);
    const sequence_num = scriptIntParseI64(item.bytes);

    if (sequence_num < 0) {
        return error.negative_locktime;
    }

    if (!checkSequence(sequence_num, program.context.*)) {
        return error.unsatisfied_locktime;
    }
}

pub fn op_nop4(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_nop5(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_nop6(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_nop7(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_nop8(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_nop9(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_nop10(program: *Program) anyerror!void {
    _ = &program;
}

pub fn op_checkdatasig(program: *Program) anyerror!void {
    if (program.stack.len < 3) {
        return error.read_empty_stack;
    }
    const sig = program.stack.get(program.stack.len - 3);
    // std.debug.print("CHECKDATA SIG {any} \n", .{sig});
    const message = program.stack.get(program.stack.len - 2);
    // std.debug.print("CHECKDATA SIG MSG {any} \n", .{message});
    const publickey = program.stack.get(program.stack.len - 1);
    // std.debug.print("CHECKDATA SIG PUBKEY {any} \n", .{publickey});
    var success = false;
    if (sig.bytes.len > 0) {
        success = try checkDataSig(
            sig.bytes,
            message.bytes,
            publickey.bytes,
            program.allocator,
        );
        program.metrics.tallySigChecks(1);
        program.metrics.tallyHashOp(@intCast(message.bytes.len), true);
    }

    _ = program.stack.pop();
    _ = program.stack.pop();
    _ = program.stack.pop();

    const val = &[_]u8{@intCast(@intFromBool(success))};
    const res = try program.allocator.dupe(u8, val);
    try program.stack.append(StackValue{ .bytes = res });

    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_checkdatasigverify(program: *Program) anyerror!void {
    if (program.stack.len < 3) {
        return error.read_empty_stack;
    }
    const sig = program.stack.get(program.stack.len - 3);
    // std.debug.print("CHECKDATA SIG {any} \n", .{sig});
    const message = program.stack.get(program.stack.len - 2);
    // std.debug.print("CHECKDATA SIG MSG {any} \n", .{message});
    const publickey = program.stack.get(program.stack.len - 1);
    // std.debug.print("CHECKDATA SIG PUBKEY {any} \n", .{publickey});
    var success = false;
    if (sig.bytes.len > 0) {
        success = try checkDataSig(
            sig.bytes,
            message.bytes,
            publickey.bytes,
            program.allocator,
        );
        program.metrics.tallySigChecks(1);
        program.metrics.tallyHashOp(@intCast(message.bytes.len), true);
    }

    _ = program.stack.pop();
    _ = program.stack.pop();
    _ = program.stack.pop();

    if (!success) {
        return error.op_checkdatasigverify;
    }
}

pub fn op_reversebytes(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }
    const stack_top = program.stack.get(program.stack.len - 1);

    _ = std.mem.reverse(u8, stack_top.bytes);

    program.stack.set(program.stack.len - 1, StackValue{ .bytes = stack_top.bytes });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_unknown189(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown190(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown191(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_inputindex(program: *Program) anyerror!void {
    var index = try BigInt.initSet(program.allocator, program.context.input_index);
    const num = try encodeScriptIntMininal(&index, program.allocator);
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_activebytecode(program: *Program) anyerror!void {
    const code = program.instruction_bytecode[program.code_separator..][0..];
    const copy = try program.allocator.dupe(u8, code);
    try program.stack.append(StackValue{ .bytes = copy });

    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_txversion(program: *Program) anyerror!void {
    const tx_version = program.context.tx.version;
    var index = try BigInt.initSet(program.allocator, tx_version);
    const num = try encodeScriptIntMininal(
        &index,
        program.allocator,
    );
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_txinputcount(program: *Program) anyerror!void {
    const input_count = program.context.tx.inputs.len;
    var count = try BigInt.initSet(program.allocator, input_count);
    const num = try encodeScriptIntMininal(&count, program.allocator);
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_txoutputcount(program: *Program) anyerror!void {
    const output_count = program.context.tx.outputs.len;
    var count = try BigInt.initSet(program.allocator, output_count);
    const num = try encodeScriptIntMininal(&count, program.allocator);
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_txlocktime(program: *Program) anyerror!void {
    const lockime = program.context.tx.locktime;
    var lock_time = try BigInt.initSet(program.allocator, lockime);
    const num = try encodeScriptIntMininal(&lock_time, program.allocator);
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_utxovalue(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();

    const is_valid_input_index = validInputIndex(program.context, index);
    const is_valid_output_index = validOutputIndex(program.context, index);
    _ = &is_valid_output_index;

    var bytecode = std.ArrayList(u8).init(program.allocator);
    defer bytecode.deinit();

    _ = try is_valid_input_index;

    const utxo_value = program.context.utxo[@intCast(index)].satoshis;
    if (utxo_value > Consensus.MAX_MONEY) {
        return error.input_exceeds_max_money;
    }
    var utxo_value_bytes = try BigInt.initSet(program.allocator, utxo_value);
    const num = try encodeScriptIntMininal(&utxo_value_bytes, program.allocator);
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_utxobytecode(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();

    const is_valid_input_index = validInputIndex(program.context, index);
    const is_valid_output_index = validOutputIndex(program.context, index);
    _ = &is_valid_output_index;

    var bytecode = std.ArrayList(u8).init(program.allocator);
    defer bytecode.deinit();

    _ = try is_valid_input_index;
    const utxo_script = program.context.utxo[@intCast(index)].script;
    const utxo_bytecode = try bytecode.allocator.dupe(u8, utxo_script);
    try program.stack.append(StackValue{ .bytes = utxo_bytecode });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_outpointtxhash(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();

    const is_valid_input_index = validInputIndex(program.context, index);
    const is_valid_output_index = validOutputIndex(program.context, index);
    _ = &is_valid_output_index;

    var bytecode = std.ArrayList(u8).init(program.allocator);
    defer bytecode.deinit();

    _ = try is_valid_input_index;
    const outpoint_txid = program.context.tx.inputs[@intCast(index)].txid;
    try bytecode.writer().writeInt(u256, outpoint_txid, .big);
    const outpoint_txid_bytecode = try bytecode.allocator.dupe(u8, bytecode.items);
    try program.stack.append(StackValue{ .bytes = outpoint_txid_bytecode });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_outpointindex(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();

    const is_valid_input_index = validInputIndex(program.context, index);
    const is_valid_output_index = validOutputIndex(program.context, index);
    _ = &is_valid_output_index;

    var bytecode = std.ArrayList(u8).init(program.allocator);
    defer bytecode.deinit();

    _ = try is_valid_input_index;
    const outpoint_index = program.context.tx.inputs[@intCast(index)].index;
    var outpoint_index_bytes = try BigInt.initSet(program.allocator, outpoint_index);
    const num = try encodeScriptIntMininal(&outpoint_index_bytes, program.allocator);
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_inputbytecode(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();

    const is_valid_input_index = validInputIndex(program.context, index);
    const is_valid_output_index = validOutputIndex(program.context, index);
    _ = &is_valid_output_index;

    var bytecode = std.ArrayList(u8).init(program.allocator);
    defer bytecode.deinit();

    _ = try is_valid_input_index;
    const input_script = program.context.tx.inputs[@intCast(index)].script;
    const input_bytecode = try bytecode.allocator.dupe(u8, input_script);
    try program.stack.append(StackValue{ .bytes = input_bytecode });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_inputsequencenumber(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();

    const is_valid_input_index = validInputIndex(program.context, index);
    const is_valid_output_index = validOutputIndex(program.context, index);
    _ = &is_valid_output_index;

    var bytecode = std.ArrayList(u8).init(program.allocator);
    defer bytecode.deinit();

    _ = try is_valid_input_index;
    const input_sequence = program.context.tx.inputs[@intCast(index)].sequence;
    var input_sequence_bytes = try BigInt.initSet(program.allocator, input_sequence);
    const num = try encodeScriptIntMininal(&input_sequence_bytes, program.allocator);
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_outputvalue(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();

    // const is_valid_input_index = validInputIndex(program.context, index);
    const is_valid_output_index = validOutputIndex(program.context, index);
    _ = &is_valid_output_index;

    var bytecode = std.ArrayList(u8).init(program.allocator);
    defer bytecode.deinit();

    _ = try is_valid_output_index;
    const output_value = program.context.tx.outputs[@intCast(index)].satoshis;
    var output_value_bytes = try BigInt.initSet(program.allocator, output_value);
    const num = try encodeScriptIntMininal(&output_value_bytes, program.allocator);
    try program.stack.append(StackValue{ .bytes = num });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_outputbytecode(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();

    const is_valid_output_index = validOutputIndex(program.context, index);

    var bytecode = std.ArrayList(u8).init(program.allocator);
    defer bytecode.deinit();
    _ = try is_valid_output_index;

    const output_script = program.context.tx.outputs[@intCast(index)].script;
    const txo_bytecode = try bytecode.allocator.dupe(u8, output_script);
    try program.stack.append(StackValue{ .bytes = txo_bytecode });

    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_utxotokencategory(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();
    const is_valid_input_index = validInputIndex(program.context, index);
    _ = try is_valid_input_index;
    const has_token = program.context.utxo[@intCast(@abs(index))].token;
    if (has_token == null) {
        try program.stack.append(StackValue{ .bytes = &.{} });
        return;
    }

    var bytecode = std.ArrayList(u8).init(program.allocator);
    const token = program.context.utxo[@intCast(index)].token.?;
    try bytecode.writer().writeInt(u256, token.id, .big);
    const capability = token.capability;
    const push_cap_byte = (Token.isMinting(capability) or Token.isMutable(capability));
    if (push_cap_byte) {
        try bytecode.writer().writeInt(u8, Token.getCapabilityByte(token.capability), .little);
    }
    const cat_id = try bytecode.allocator.dupe(u8, bytecode.items);
    try program.stack.append(StackValue{ .bytes = cat_id });
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_utxotokencommitment(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();
    const is_valid_input_index = validInputIndex(program.context, index);
    _ = try is_valid_input_index;
    const has_token = program.context.utxo[@intCast(@abs(index))].token;
    if (has_token == null) {
        try program.stack.append(StackValue{ .bytes = &.{} });
        return;
    }

    var bytecode = std.ArrayList(u8).init(program.allocator);
    const token = program.context.utxo[@intCast(index)].token;
    // const has_token = context.tx.outputs[@intCast(index)].token;
    if (token.?.nft == null) {
        try program.stack.append(StackValue{ .bytes = &.{} });
    } else {
        const commitment_data = token.?.nft.?.commitment;
        try bytecode.appendSlice(commitment_data);
        const capability = try bytecode.allocator.dupe(u8, bytecode.items);
        try program.stack.append(StackValue{ .bytes = capability });
    }
    bytecode.clearAndFree();
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_utxotokenamount(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();
    const is_valid_input_index = validInputIndex(program.context, index);
    _ = try is_valid_input_index;
    const has_token = program.context.utxo[@intCast(@abs(index))].token;
    if (has_token == null) {
        try program.stack.append(StackValue{ .bytes = &.{} });
        return;
    }

    var bytecode = std.ArrayList(u8).init(program.allocator);
    const token = program.context.utxo[@intCast(index)].token;
    const n = token.?.amount;
    var utxo_token_amount = try BigInt.initSet(program.allocator, n);
    const num = try encodeScriptIntMininal(&utxo_token_amount, program.allocator);
    try bytecode.appendSlice(num);

    const amount = try bytecode.allocator.dupe(u8, bytecode.items);
    try program.stack.append(StackValue{ .bytes = amount });
    bytecode.clearAndFree();
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_outputtokencategory(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();
    const is_valid_output_index = validOutputIndex(program.context, index);
    const has_token = program.context.tx.outputs[@intCast(@abs(index))].token;
    if (has_token == null) {
        try program.stack.append(StackValue{ .bytes = &.{} });
        return;
    }
    _ = try is_valid_output_index;

    var bytecode = std.ArrayList(u8).init(program.allocator);
    const token = program.context.tx.outputs[@intCast(index)].token.?;
    try bytecode.writer().writeInt(u256, token.id, .big);
    const capability = token.capability;
    const push_cap_byte = (Token.isMinting(capability) or Token.isMutable(capability));
    // std.debug.print("TOKEN CAT {any}\n", .{cat_id});
    if (push_cap_byte) {
        try bytecode.writer().writeInt(u8, Token.getCapabilityByte(token.capability), .little);
    }
    const cat_id = try bytecode.allocator.dupe(u8, bytecode.items);
    try program.stack.append(StackValue{ .bytes = cat_id });

    bytecode.clearAndFree();
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_outputtokencommitment(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();
    const is_valid_output_index = validOutputIndex(program.context, index);
    const has_token = program.context.tx.outputs[@intCast(@abs(index))].token;
    if (has_token == null) {
        try program.stack.append(StackValue{ .bytes = &.{} });
        return;
    }
    _ = try is_valid_output_index;

    const token = program.context.tx.outputs[@intCast(index)].token;
    var bytecode = std.ArrayList(u8).init(program.allocator);

    if (token.?.nft == null) {
        try program.stack.append(StackValue{ .bytes = &.{} });
    } else {
        const commitment_data = token.?.nft.?.commitment;
        try bytecode.appendSlice(commitment_data);
        const capability = try bytecode.allocator.dupe(u8, bytecode.items);
        try program.stack.append(StackValue{ .bytes = capability });
    }
    bytecode.clearAndFree();
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_outputtokenamount(program: *Program) anyerror!void {
    if (program.stack.len < 1) {
        return error.read_empty_stack;
    }

    const number = program.stack.get(program.stack.len - 1);
    const index = try readScriptIntI64(number.bytes);
    _ = program.stack.pop();
    const is_valid_output_index = validOutputIndex(program.context, index);
    const has_token = program.context.tx.outputs[@intCast(@abs(index))].token;
    if (has_token == null) {
        try program.stack.append(StackValue{ .bytes = &.{} });
        return;
    }
    _ = try is_valid_output_index;

    const token = program.context.tx.outputs[@intCast(index)].token;
    var bytecode = std.ArrayList(u8).init(program.allocator);
    const n = token.?.amount;
    var utxo_token_amount = try BigInt.initSet(program.allocator, n);
    const num = try encodeScriptIntMininal(&utxo_token_amount, program.allocator);
    try bytecode.appendSlice(num);

    const amount = try bytecode.allocator.dupe(u8, bytecode.items);
    try program.stack.append(StackValue{ .bytes = amount });
    bytecode.clearAndFree();
    program.metrics.tallyPushOp(@intCast(program.stack.get(program.stack.len - 1).bytes.len));
}

pub fn op_unknown212(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown213(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown214(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown215(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown216(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown217(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown218(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown219(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown220(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown221(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown222(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown223(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown224(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown225(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown226(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown227(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown228(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown229(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown230(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown231(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown232(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown233(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown234(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown235(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown236(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown237(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown238(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown239(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown240(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown241(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown242(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown243(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown244(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown245(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown246(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown247(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown248(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown249(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown250(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown251(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown252(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown253(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown254(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}

pub fn op_unknown255(program: *Program) anyerror!void {
    _ = program;
    return error.unassigned_opcode;
}
fn validInputIndex(ctx: *ScriptExecContext, index: i64) anyerror!bool {
    if (index < 0 or index >= ctx.tx.inputs.len or index >= ctx.utxo.len) {
        return error.invalid_tx_input_index;
    } else {
        return true;
    }
}
fn validOutputIndex(ctx: *ScriptExecContext, index: i64) anyerror!bool {
    if (index < 0 or index >= ctx.tx.outputs.len) {
        return error.invalid_tx_output_index;
    } else {
        return true;
    }
}
pub fn checkLockTime(time: i64, ctx: *ScriptExecContext) bool {
    const input_index = ctx.*.input_index;
    const tx_locktime: u32 = ctx.*.tx.locktime;
    const locktime: u32 = @intCast(time);

    // (tx_locktime < LOCKTIME_THRESHOLD and locktime < LOCKTIME_THRESHOLD ) {}
    if (!((tx_locktime < LOCKTIME_THRESHOLD and locktime < LOCKTIME_THRESHOLD) or
        (tx_locktime >= LOCKTIME_THRESHOLD and locktime >= LOCKTIME_THRESHOLD)))
    {
        return false;
    }

    if (locktime > tx_locktime) {
        return false;
    }
    if (0xffffffff == ctx.tx.inputs[input_index].sequence) {
        return false;
    }

    return true;
}
pub fn includesFlag(value: u32, flag: u32) bool {
    return (value & flag) == 0;
}
const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 0x80000000;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 0x00400000;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
pub fn checkSequence(sequence: i64, ctx: ScriptExecContext) bool {
    const input_index = ctx.input_index;
    const tx_sequence: u32 = ctx.tx.inputs[input_index].sequence;

    // Check if transaction version supports BIP 68
    if (ctx.tx.version < 2) {
        return false;
    }

    // Check if sequence locktime is disabled
    if ((tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return false;
    }

    // Mask off bits that don't have consensus-enforced meaning
    const locktime_mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
    const tx_sequence_masked = tx_sequence & locktime_mask;
    const sequence_masked: u32 = @intCast(sequence & locktime_mask);

    // Compare lock-by-blockheight vs lock-by-blocktime
    if (!((tx_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG and
        sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG) or
        (tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG and
        sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG)))
    {
        return false;
    }

    // Simple numeric comparison
    if (sequence_masked > tx_sequence_masked) {
        return false;
    }

    return true;
}
pub fn checkDataSig(
    sig: []const u8,
    message: []const u8,
    pubkey: []const u8,
    gpa: std.mem.Allocator,
) !bool {
    _ = &gpa;
    if ((sig.len > 65)) {
        // _ = &message;
        const publickey = try EcdsaDataSig.PublicKey.fromSec1(pubkey);
        const sig_ecdsa = try EcdsaDataSig.Signature.fromDer(sig);
        _ = sig_ecdsa.verify(message, publickey) catch |err| {
            // std.debug.print("DATASIG VERIF ECDSA ERR {any}\n", .{err});
            _ = &err;
            return false;
        };
    } else {
        // std.debug.print("CHECK DATA SIG {any}", .{pubkey});
        const publickey = try Schnorr.PublicKey.fromSec1(pubkey);
        var signature = Schnorr.Signature.fromBytes(sig[0..64].*);
        _ = signature.verify(message, publickey) catch |err| {
            // std.debug.print("DATASIG VERIF SCHNORR ERR {any}\n", .{err});
            _ = &err;
            return false;
        };
    }
    return true;
}
pub fn getHashType(signature: []const u8) u8 {
    if (signature.len == 0) return 0;
    return signature[signature.len - 1];
}
pub fn checkSig(
    context: *ScriptExecContext,
    sig: []const u8,
    pubkey: []const u8,
    script: []const u8,
    bytes_hashed: *usize,
    alloc: std.mem.Allocator,
) !bool {
    const tx_size = Transaction.getTransactionSize(context.tx);
    const utxo_size = Transaction.calculateOutputsSize(context.utxo);
    // var serialized_tx_data = try std.ArrayList(u8).initCapacity(alloc, tx_size + utxo_size);
    const overhead = 1024;
    var serialized_tx_data = std.ArrayList(u8).init(alloc);
    defer serialized_tx_data.deinit();

    try serialized_tx_data.resize(tx_size + utxo_size + overhead);

    // std.debug.print("TX SIZE {} UTXO SIZE {}\n", .{ tx_size, utxo_size });

    //TODO validate signiature
    if (sig.len == 0) return false;
    const hashtype = getHashType(sig);
    if (!validSigHashType(hashtype)) {
        return error.invalid_sighash_type;
    }

    var sigser_writer = Encoder.init(serialized_tx_data.items);
    // bytes_hashed.* = try SigSer.encode(
    //     &context.tx,
    //     &context.utxo,
    //     @intCast(hashtype),
    //     script,
    //     context.input_index,
    //     &sigser_writer,
    //     alloc,
    // );

    bytes_hashed.* = try SigSer.encodeWithPrecompute(
        &context.tx,
        &context.utxo,
        @intCast(hashtype),
        script,
        context.input_index,
        &sigser_writer,
        alloc,
        &context.signing_cache,
    );

    var sighash = try std.ArrayList(u8).initCapacity(alloc, 32);
    defer sighash.deinit();
    try sighash.resize(32);
    _ = sha256(sigser_writer.fbs.getWritten(), sighash.items[0..32], .{});
    _ = sha256(sighash.items[0..32], sighash.items[0..32], .{});

    if ((sig.len > 65)) {
        const publickey = try Ecdsa.PublicKey.fromSec1(pubkey);
        const sig_ecdsa = try Ecdsa.Signature.fromDer(sig[0 .. sig.len - 1]);

        var verifier = try sig_ecdsa.verifier(publickey);
        _ = verifier.update(sigser_writer.fbs.getWritten());
        _ = verifier.verify() catch |err| {
            _ = &err;
            return false;
        };
    } else {
        const publickey = try Schnorr.PublicKey.fromSec1(pubkey);
        var signature = Schnorr.Signature.fromBytes(sig[0..64].*);

        var verifier = try signature.verifier(publickey);
        _ = verifier.verifyMessageHash(sighash.items[0..32].*) catch |err| {
            _ = &err;
            return false;
        };
    }
    return true;
}
fn decodeBitfield(vch: []const u8, size: u32, bitfield: *u32) anyerror!bool {
    if (size > 32) return error.invalid_bit_count;

    const bitfield_size = (size + 7) / 8;
    if (vch.len != bitfield_size) return error.invalid_bit_range;

    bitfield.* = 0;
    var i: usize = 0;
    while (i < bitfield_size) : (i += 1) {
        // Decode the bitfield as little endian
        bitfield.* |= @as(u32, vch[i]) << @intCast(8 * i);
    }

    const mask = (@as(u64, 1) << @as(u6, @intCast(size))) - 1;
    if ((bitfield.* & mask) != bitfield.*) {
        return error.invalid_bit_range;
    }

    return true;
}

const Program = @import("stack.zig").Program;
const Encoder = @import("encoding.zig").Cursor;
const Transaction = @import("transaction.zig").Transaction;
const VirtualMachine = @import("stack.zig").VirtualMachine;
const validSigHashType = @import("sigser.zig").validSigHashType;
const ripemd160 = @import("ripemd160.zig");
const scriptIntParse = @import("script.zig").scriptIntParse;
const scriptIntParseI64 = @import("script.zig").scriptIntParseI64;
const Token = @import("token.zig");
const encodeScriptIntMininal = @import("script.zig").encodeScriptIntMininal;
const readScriptInt = @import("script.zig").readScriptInt;
const readScriptBool = @import("script.zig").readScriptBool;
const readScriptIntI64 = @import("script.zig").readScriptIntI64;
const readPush = @import("push.zig").readPushData;
const BigInt = std.math.big.int.Managed;
const std = @import("std");
const StackValue = @import("stack.zig").StackValue;
const ScriptExecContext = @import("stack.zig").ScriptExecutionContext;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256;
const EcdsaDataSig = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Schnorr = @import("schnorr.zig").SchnorrBCH;
const SigSer = @import("sigser.zig").SigningSer;
const sha256 = std.crypto.hash.sha2.Sha256.hash;
const ConsensusBch2026 = @import("consensus2026.zig").ConsensusBch2026.init();
const Consensus = @import("consensus2026.zig");
const StackFrame = @import("stack.zig").StackFrame;
const ControlStackValue = @import("stack.zig").ControlStackValue;
