const Program = @import("stack.zig").Program;
const ScriptExecCtx = @import("stack.zig").ScriptExecContext;
const std = @import("std");
const Opcode = @import("opcodes.zig").Opcodes;
const VirtualMachine = @import("stack.zig").VirtualMachine;
const readPush = @import("push.zig").readPushData;
const StackValue = @import("stack.zig").StackValue;
const Script = @import("script.zig");
// const ProgramState = *const fn (program: *Program) void;

pub fn nextInstruction(p: *Program) void {
    p.instruction_pointer += 1;
}
pub fn hasMoreInstructions(p: *Program) bool {
    const ip = p.instruction_pointer;
    const len = p.instruction_bytecode.len;
    return if (ip < len) true else false;
}
fn pushOperation(p: *Program) !void {
    const ip = p.instruction_pointer;
    const push_res = try readPush(
        p.instruction_bytecode[ip..],
        p.allocator,
    );
    try p.stack.append(StackValue{ .bytes = push_res.data });
    p.instruction_pointer += push_res.bytes_read;
}
pub fn executeProgram(p: *Program) !void {
    if (!hasMoreInstructions(p)) return;

    const operation = getOperation(p);
    const execution_state = p.control_stack.allTrue();

    if (isPushOp(operation) and execution_state) {
        try pushOperation(p);
        return try @call(.always_tail, executeProgram, .{p});
    }

    if (execution_state or operation.isConditional()) {
        try VirtualMachine.execute(p);
        nextInstruction(p);
        try @call(.always_tail, executeProgram, .{p});
    } else {
        nextInstruction(p);
        return try @call(.always_tail, executeProgram, .{p});
    }
}

fn isPushOp(op: Opcode) bool {
    return @intFromEnum(op) <= @intFromEnum(Opcode.op_16);
}

fn getCodepoint(program: *Program) u8 {
    return program.instruction_bytecode[program.instruction_pointer];
}

fn getOperation(program: *Program) Opcode {
    const operation: Opcode = @enumFromInt(getCodepoint(program));
    return operation;
}
pub fn evaluateProto(p: *Program) !void {
    const unlock_code = p.context.tx.inputs[p.context.input_index].script;
    const lock_code = p.context.utxo[p.context.input_index].script;
    p.instruction_bytecode = unlock_code;

    _ = try executeProgram(p);
    var stack_clone = try std.BoundedArray(StackValue, 10_000).init(0);
    _ = try stack_clone.appendSlice(p.stack.slice());
    const p2sh_code = stack_clone.get(stack_clone.len - 1).bytes;
    // std.debug.print("P2SH code {any}\n", .{p2sh_code});

    p.instruction_bytecode = lock_code;

    p.instruction_pointer = 0;
    _ = try executeProgram(p);
    // std.debug.print("POST LOCK STACK {any}\n", .{p.stack.get(p.stack.len - 1)});

    const is_p2sh = Script.isP2SH(lock_code);
    if (is_p2sh) {
        p.instruction_bytecode = p2sh_code;
        p.instruction_pointer = 0;
        _ = stack_clone.pop();
        p.stack.clear();
        try p.stack.appendSlice(stack_clone.slice());
        _ = try executeProgram(p);
        // std.debug.print("STACK {any}\n", .{p.stack.slice()});
    }
}

test "proto" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const ally = gpa.allocator();

    var ctx = ScriptExecCtx.init();
    var p = try Program.init(ally, &ctx);
    var code = [_]u8{ 0x51, 0x51, 0x93, 0x51, 0x93, 0x51, 0x93 }; // Creates array of 10 zeros

    p.instruction_bytecode = code[0..];
    _ = try executeProgram(&p);
    std.debug.print("STACK {any}\n", .{p.stack.pop()});
}
