//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;
const Transaction = @import("transaction.zig").Transaction;
const Encoder = @import("encoding.zig").Cursor;
const VirtualMachine = @import("stack.zig").VirtualMachine;
const Program = @import("stack.zig").Program;
const walloc = std.heap.wasm_allocator;
const SigningCache = @import("sigser.zig").SigningCache;
const ScriptExecutionContext = @import("stack.zig").ScriptExecutionContext;

export fn verify(s: [*]u8, length: usize, utxo_idx: usize, index: usize) i32 {
    const input_tx = s[0..length];
    const input_utxos = s[length .. length + utxo_idx][0..];
    if (s[length] == 1) return @intCast(111);

    const input_tx_buff = walloc.dupe(u8, input_tx) catch return -1;
    const input_utxo_buff = walloc.dupe(u8, input_utxos) catch return -2;
    defer walloc.free(input_tx_buff);
    defer walloc.free(input_utxo_buff);

    var tx_reader = Encoder.init(input_tx_buff);
    var utxo_reader = Encoder.init(input_utxo_buff);
    const tx = Transaction.decode(&tx_reader, walloc) catch return -3;

    if (tx.version == 0) return @intCast(45);
    // _ = &tx_reader;
    // _ = &utxo_reader;
    // _ = &tx;
    // _ = &index;

    const utxos = Transaction.readOutputs(&utxo_reader, walloc) catch return -4;
    // if (utxos.len == 0) return @intCast(input_utxos[0]);
    var script_exec = ScriptExecutionContext{
        .input_index = @intCast(index),
        .utxo = utxos,
        .tx = tx,
        .signing_cache = SigningCache.init(),
    };
    var program = Program.init(walloc, &script_exec) catch return -6;
    const unlock_code = program.context.tx.inputs[program.context.input_index].script;
    program.metrics.setScriptLimits(true, unlock_code.len);

    const res = VirtualMachine.verify(&program) catch return -5;

    if (res) return 1 else return 0;
}
