const std = @import("std");
const Transaction = @import("transaction.zig");
const Allocator = std.mem.Allocator;
const sha256 = std.crypto.hash.sha2.Sha256.hash;
const Cursor = @import("encoding.zig");
const ScriptExecContext = @import("stack.zig").ScriptExecutionContext;
pub const SigningSer = @This();

tx: Transaction,
outpoint: []Transaction.Output,
idx: usize,

pub fn encode(
    ctx: *Transaction,
    src_outs: *[]Transaction.Output,
    hashflag: i32,
    script: []const u8,
    idx: usize,
    sigser_writer: *Cursor,
    alloc: Allocator,
) !usize {
    const flag = std.mem.toBytes(hashflag);
    // std.debug.print("FLAG {any}\n", .{hashflag});
    var hash_prev_out: [32]u8 = undefined;
    var hash_utxos: [32]u8 = undefined;
    var hash_sequence: [32]u8 = undefined;
    var hash_ouputs: [32]u8 = undefined;
    const emptyhash: [32]u8 = .{0x00} ** 32;
    var buff = std.ArrayList(u8).init(alloc);
    defer buff.deinit();
    try buff.resize(sigser_writer.fbs.buffer.len);
    @memset(buff.items, 0); // Ensure buffer is initialized
    var encoder = Cursor.init(buff.items);
    const script_slice = try alloc.alloc(u8, script.len);
    defer alloc.free(script_slice);
    @memcpy(script_slice, script);
    var len: usize = 0;

    try sigser_writer.fbs.writer().writeInt(u32, ctx.version, .little);
    len += 4;

    //Hash PrevOuts
    if (shouldSerializeSingleInput(flag[0])) {
        len += try sigser_writer.fbs.writer().write(&emptyhash);
    } else {
        _ = try SigningSer.encodeOutpoints(ctx, encoder.fbs.writer());
        _ = sha256(encoder.fbs.getWritten(), &hash_prev_out, .{});
        _ = sha256(&hash_prev_out, &hash_prev_out, .{});
        // std.debug.print("sigser Single: {x}\n", .{out});
        len += try sigser_writer.fbs.writer().write(&hash_prev_out);
        _ = encoder.fbs.reset();
    }
    // SIGHASH_UTXOS
    if (shouldSerializeUtxos(flag[0])) {
        _ = try SigningSer.encodeUtxos(src_outs.*, encoder.fbs.writer());

        _ = sha256(encoder.fbs.getWritten(), &hash_utxos, .{});
        _ = sha256(&hash_utxos, &hash_utxos, .{});
        len += try sigser_writer.fbs.writer().write(&hash_utxos);
        _ = encoder.fbs.reset();
    }

    if (!shouldSerializeSingleInput(flag[0]) and
        !shouldSerializeCorrespondingOutput(flag[0]) and
        !shouldSerializeNoOutputs(flag[0]))
    {
        _ = try SigningSer.encodeSequence(ctx, encoder.fbs.writer());

        _ = sha256(encoder.fbs.getWritten(), &hash_sequence, .{});
        _ = sha256(&hash_sequence, &hash_sequence, .{});
        len += try sigser_writer.fbs.writer().write(&hash_sequence);
        _ = encoder.fbs.reset();
    } else {
        len += try sigser_writer.fbs.writer().write(&emptyhash);
    }

    try sigser_writer.fbs.writer().writeInt(u256, ctx.inputs[idx].txid, .big);
    len += 32;
    try sigser_writer.fbs.writer().writeInt(u32, ctx.inputs[idx].index, .little);
    len += 4;

    if (src_outs.len > idx) {
        if (src_outs.*[idx].token) |*token| {
            len += try token.encode(&sigser_writer.fbs.writer());
        }
    }

    len += try Cursor.writeVarBytes(sigser_writer.fbs.writer(), script_slice);
    // std.debug.dumpHex(sigser_writer.fbs.getWritten());
    try sigser_writer.fbs.writer().writeInt(u64, src_outs.*[idx].satoshis, .little);
    len += 8;
    try sigser_writer.fbs.writer().writeInt(u32, ctx.inputs[idx].sequence, .little);
    len += 4;

    if (!shouldSerializeCorrespondingOutput(flag[0]) and
        !shouldSerializeNoOutputs(flag[0]))
    {
        _ = try SigningSer.encodeOutputs(ctx, encoder.fbs.writer());
        _ = sha256(encoder.fbs.getWritten(), &hash_ouputs, .{});
        _ = sha256(&hash_ouputs, &hash_ouputs, .{});

        len += try sigser_writer.fbs.writer().write(&hash_ouputs);
        _ = encoder.fbs.reset();
    } else if (shouldSerializeCorrespondingOutput(flag[0])) {
        // SINGLE case
        if (idx < ctx.outputs.len) {
            // Hash corresponding output
            _ = try ctx.outputs[idx].encode(encoder.fbs.writer());
            _ = sha256(encoder.fbs.getWritten(), &hash_ouputs, .{});
            _ = sha256(&hash_ouputs, &hash_ouputs, .{});
            len += try sigser_writer.fbs.writer().write(&hash_ouputs);
            _ = encoder.fbs.reset();
        } else {
            len += try sigser_writer.fbs.writer().write(&emptyhash);
        }
    } else {
        len += try sigser_writer.fbs.writer().write(&emptyhash);
    }

    try sigser_writer.fbs.writer().writeInt(u32, ctx.locktime, .little);
    len += 4;
    try sigser_writer.fbs.writer().writeInt(i32, hashflag, .little);
    len += 4;
    return len;
}

pub fn isLegacy(flag: i32) bool {
    const forkValue = flag >> 8;
    const newForkValue = (forkValue ^ 0xdead) | 0xff0000;
    const sighashType = (newForkValue << 8) | (flag & 0xff);
    return (sighashType & 0x40) == 0;
}
// A.K.A. `sighash` flags
pub const SigHashFlag = enum(u32) {
    allOutputs = 0x01,
    noOutputs = 0x02,
    correspondingOutput = 0x03,
    utxos = 0x20,
    forkId = 0x40,
    singleInput = 0x80,
};
pub fn validSigHashType(flag: u8) bool {
    const value = @as(u32, flag);
    return switch (value) {
        @intFromEnum(SigHashType.allOutputs) => true,
        @intFromEnum(SigHashType.allOutputsAllUtxos) => true,
        @intFromEnum(SigHashType.allOutputsSingleInput) => true,
        @intFromEnum(SigHashType.correspondingOutput) => true,
        @intFromEnum(SigHashType.correspondingOutputAllUtxos) => true,
        @intFromEnum(SigHashType.correspondingOutputSingleInput) => true,
        @intFromEnum(SigHashType.noOutputs) => true,
        @intFromEnum(SigHashType.noOutputsAllUtxos) => true,
        @intFromEnum(SigHashType.noOutputsSingleInput) => true,
        else => false,
    };
}
// A.K.A. `SigningSerializationType`
const SigHashType = enum(u32) {
    allOutputs = @intFromEnum(SigHashFlag.allOutputs) | @intFromEnum(SigHashFlag.forkId),
    allOutputsAllUtxos = @intFromEnum(SigHashFlag.allOutputs) | @intFromEnum(SigHashFlag.utxos) | @intFromEnum(SigHashFlag.forkId),
    allOutputsSingleInput = @intFromEnum(SigHashFlag.allOutputs) | @intFromEnum(SigHashFlag.singleInput) | @intFromEnum(SigHashFlag.forkId),
    correspondingOutput = @intFromEnum(SigHashFlag.correspondingOutput) | @intFromEnum(SigHashFlag.forkId),
    correspondingOutputAllUtxos = @intFromEnum(SigHashFlag.correspondingOutput) | @intFromEnum(SigHashFlag.utxos) | @intFromEnum(SigHashFlag.forkId),
    correspondingOutputSingleInput = @intFromEnum(SigHashFlag.correspondingOutput) | @intFromEnum(SigHashFlag.singleInput) | @intFromEnum(SigHashFlag.forkId),
    noOutputs = @intFromEnum(SigHashFlag.noOutputs) | @intFromEnum(SigHashFlag.forkId),
    noOutputsAllUtxos = @intFromEnum(SigHashFlag.noOutputs) | @intFromEnum(SigHashFlag.utxos) | @intFromEnum(SigHashFlag.forkId),
    noOutputsSingleInput = @intFromEnum(SigHashFlag.noOutputs) | @intFromEnum(SigHashFlag.singleInput) | @intFromEnum(SigHashFlag.forkId),
};
fn match(flagtype: u32, flag: SigHashFlag) bool {
    return flagtype & @intFromEnum(flag) != 0;
}

fn equals(flagtype: u32, flag: SigHashFlag) bool {
    return flagtype & 0b11111 == @intFromEnum(flag);
}
fn shouldSerializeSingleInput(flagtype: u32) bool {
    return match(flagtype, SigHashFlag.singleInput);
}
fn shouldSerializeCorrespondingOutput(flagtype: u32) bool {
    return equals(flagtype, SigHashFlag.correspondingOutput);
}
fn shouldSerializeNoOutputs(flagtype: u32) bool {
    return equals(flagtype, SigHashFlag.noOutputs);
}
fn shouldSerializeUtxos(flagtype: u32) bool {
    return match(flagtype, SigHashFlag.utxos);
}

pub fn encodeInputs(tx: Transaction, writer: anytype) !usize {
    var len: usize = 0;
    for (tx.inputs) |*input| {
        len += try input.encode(writer);
    }
    return len;
}
pub fn encodeOutpoints(tx: *Transaction, writer: anytype) !usize {
    var len: usize = 0;
    for (tx.inputs) |*input| {
        try writer.writeInt(u256, input.txid, .big);
        len += 32;
        try writer.writeInt(u32, input.index, .little);
        len += 4;
    }
    return len;
}
pub fn encodeUtxos(utxos: []Transaction.Output, writer: anytype) !usize {
    var len: usize = 0;
    for (utxos) |*output| {
        len += try output.encode(writer);
    }
    return len;
}
pub fn encodeOutputs(tx: *Transaction, writer: anytype) !usize {
    var len: usize = 0;
    for (tx.outputs) |*output| {
        len += try output.encode(writer);
    }
    return len;
}
pub fn encodeSequence(tx: *Transaction, writer: anytype) !usize {
    var len: usize = 0;
    for (tx.inputs) |*input| {
        try writer.writeInt(u32, input.sequence, .little);
        len += 4;
    }
    return len;
}
pub const SigningCache = struct {
    hash_prevouts: u256,
    hash_sequence: u256,
    hash_outputs: u256,
    hash_utxos: u256,
    pub fn init() SigningCache {
        return SigningCache{
            .hash_prevouts = 0,
            .hash_sequence = 0,
            .hash_outputs = 0,
            .hash_utxos = 0,
        };
    }
    pub fn compute(self: *SigningCache, ctx: *ScriptExecContext, buf: []u8) !void {
        var fb = std.io.fixedBufferStream(buf);
        const w = fb.writer();
        _ = try SigningSer.encodeOutpoints(&ctx.tx, w);
        sha256(fb.getWritten(), buf[0..32], .{});
        sha256(buf[0..32], buf[0..32], .{});
        self.hash_prevouts = std.mem.readInt(u256, buf[0..32], .big);
        fb.reset();
        _ = try SigningSer.encodeSequence(&ctx.tx, w);
        sha256(fb.getWritten(), buf[32..64], .{});
        sha256(buf[32..64], buf[32..64], .{});
        self.hash_sequence = std.mem.readInt(u256, buf[32..64], .big);
        fb.reset();
        _ = try SigningSer.encodeOutputs(&ctx.tx, w);
        sha256(fb.getWritten(), buf[64..96], .{});
        sha256(buf[64..96], buf[64..96], .{});
        self.hash_outputs = std.mem.readInt(u256, buf[64..96], .big);
        fb.reset();
        _ = try SigningSer.encodeUtxos(ctx.utxo, w);
        sha256(fb.getWritten(), buf[96..128], .{});
        sha256(buf[96..128], buf[96..128], .{});
        self.hash_utxos = std.mem.readInt(u256, buf[96..128], .big);
        fb.reset();
    }
};

pub fn encodeWithPrecompute(
    ctx: *Transaction,
    src_outs: *[]Transaction.Output,
    hashflag: i32,
    script: []const u8,
    idx: usize,
    sigser_writer: *Cursor,
    alloc: Allocator,
    precompute: *SigningCache,
) !usize {
    const flag = std.mem.toBytes(hashflag);
    const emptyhash: [32]u8 = .{0x00} ** 32;
    const script_slice = try alloc.alloc(u8, script.len);
    defer alloc.free(script_slice);
    @memcpy(script_slice, script);
    var len: usize = 0;

    try sigser_writer.fbs.writer().writeInt(u32, ctx.version, .little);
    len += 4;

    // Hash PrevOuts
    if (shouldSerializeSingleInput(flag[0])) {
        len += try sigser_writer.fbs.writer().write(&emptyhash);
    } else {
        var hash_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &hash_bytes, precompute.hash_prevouts, .big);
        len += try sigser_writer.fbs.writer().write(&hash_bytes);
    }

    // SIGHASH_UTXOS
    if (shouldSerializeUtxos(flag[0])) {
        var hash_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &hash_bytes, precompute.hash_utxos, .big);
        len += try sigser_writer.fbs.writer().write(&hash_bytes);
    }

    if (!shouldSerializeSingleInput(flag[0]) and
        !shouldSerializeCorrespondingOutput(flag[0]) and
        !shouldSerializeNoOutputs(flag[0]))
    {
        var hash_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &hash_bytes, precompute.hash_sequence, .big);
        len += try sigser_writer.fbs.writer().write(&hash_bytes);
    } else {
        len += try sigser_writer.fbs.writer().write(&emptyhash);
    }

    try sigser_writer.fbs.writer().writeInt(u256, ctx.inputs[idx].txid, .big);
    len += 32;
    try sigser_writer.fbs.writer().writeInt(u32, ctx.inputs[idx].index, .little);
    len += 4;

    if (src_outs.len > idx) {
        if (src_outs.*[idx].token) |*token| {
            len += try token.encode(&sigser_writer.fbs.writer());
        }
    }

    len += try Cursor.writeVarBytes(sigser_writer.fbs.writer(), script_slice);
    try sigser_writer.fbs.writer().writeInt(u64, src_outs.*[idx].satoshis, .little);
    len += 8;
    try sigser_writer.fbs.writer().writeInt(u32, ctx.inputs[idx].sequence, .little);
    len += 4;

    if (!shouldSerializeCorrespondingOutput(flag[0]) and
        !shouldSerializeNoOutputs(flag[0]))
    {
        var hash_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &hash_bytes, precompute.hash_outputs, .big);
        len += try sigser_writer.fbs.writer().write(&hash_bytes);
    } else if (shouldSerializeCorrespondingOutput(flag[0])) {
        // SINGLE case
        if (idx < ctx.outputs.len) {
            var hash_ouputs: [32]u8 = undefined;
            var buff = std.ArrayList(u8).init(alloc);
            defer buff.deinit();
            try buff.resize(sigser_writer.fbs.buffer.len);
            @memset(buff.items, 0);
            var encoder = Cursor.init(buff.items);

            _ = try ctx.outputs[idx].encode(encoder.fbs.writer());
            _ = sha256(encoder.fbs.getWritten(), &hash_ouputs, .{});
            _ = sha256(&hash_ouputs, &hash_ouputs, .{});
            len += try sigser_writer.fbs.writer().write(&hash_ouputs);
        } else {
            len += try sigser_writer.fbs.writer().write(&emptyhash);
        }
    } else {
        len += try sigser_writer.fbs.writer().write(&emptyhash);
    }

    try sigser_writer.fbs.writer().writeInt(u32, ctx.locktime, .little);
    len += 4;
    try sigser_writer.fbs.writer().writeInt(i32, hashflag, .little);
    len += 4;
    return len;
}

test "sighash" {
    // const allocator = std.heap.page_allocator;
    // const buffer2 = try allocator.alloc(u8, 10000);
    // const source_outs_buff = try allocator.alloc(u8, 10000);
    // const sigser_expect_buff = try allocator.alloc(u8, 10000);
    // const script_buff = try allocator.alloc(u8, 10000);
    // defer allocator.free(buffer2);
    // defer allocator.free(source_outs_buff);

    // const serialized_tx = "0200000001010000000000000000000000000000000000000000000000000000000000000000000000fd68014cf002000000d5a45bffe65ef500725b4bc16e60ba39910d364324f702be75ed825c1c78a50c590708e1656805bcd8133c615530e183e762fbb09be5eed3bc6dc768ff67c8808cb9012517c817fead650287d61bdd9c68803b6bf9c64133dcab3e65b5a50cb9010000000000000000000000000000000000000000000000000000000000000000000000332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba102700000000000000000000b21e0163249698e7384609bb347d85b41c11011a4b07443763b0a39a72f3a7ef00000000610000004103536a56fe74c1e849079c6e34a7e046ceb22923fdd5a8eb499bfc69a9dad475a59f1bf609f1bf4b4cbc6a1bad7b714e80bace056ab6529538eaaeabf30e5cf661332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba000000000100000000000000000a6a08766d625f7465737400000000";
    // var out: [serialized_tx.len / 2]u8 = undefined;
    // const sigser_expect = "02000000d5a45bffe65ef500725b4bc16e60ba39910d364324f702be75ed825c1c78a50c590708e1656805bcd8133c615530e183e762fbb09be5eed3bc6dc768ff67c8808cb9012517c817fead650287d61bdd9c68803b6bf9c64133dcab3e65b5a50cb9010000000000000000000000000000000000000000000000000000000000000000000000332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba102700000000000000000000b21e0163249698e7384609bb347d85b41c11011a4b07443763b0a39a72f3a7ef0000000061000000";
    // const source_outputs = "01102700000000000017a914bd6c8a0b2ea22538d6b31ad0499a86e52f80926c87";
    // const script = "2103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba";
    // _ = try std.fmt.hexToBytes(&out, serialized_tx);
    // _ = try std.fmt.hexToBytes(source_outs_buff, source_outputs);
    // const covered_bytecode = try std.fmt.hexToBytes(script_buff, script);
    // const expect = try std.fmt.hexToBytes(sigser_expect_buff, sigser_expect);

    // var cursor = Cursor.init(&out);
    // var source_out_encoder = Cursor.init(source_outs_buff);
    // const source_outs = try Transaction.readOutputs(&source_out_encoder, allocator);
    // var data = Cursor.init(buffer2);
    // const transaction = try Transaction.decode(&cursor, allocator);
    // // const hashtype: i32 = 0x01 | 0x20;
    // const hashtype: i32 = @intFromEnum(SigHash.allOutputsAllUtxos);
    // try SigningSer.encode(transaction, source_outs, hashtype, covered_bytecode, 0, &data, allocator);
    // const actual = data.fbs.getWritten();
    // _ = &expect;
    // try std.testing.expectEqualSlices(u8, expect, actual);

}

test "precompute" {
    var buff: [1024 * 4]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buff);
    const allocator = fba.allocator();
    const tx_hex = "020000000101000000000000000000000000000000000000000000000000000000000000000000000049004730440220102b5a9fbc2b62846d3508c6a2ef74ebdcfec2a8cf4a8c364f406f06e8e8bd9802203c0bcafce15d2f5a40c768b7501b11003ad71c74e34ae70637993f09831f3e1f6100000000010000000000000000016a00000000".*;
    const tx_src_outs = "01102700000000000069512103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7852103c23083dccdc50247ebc5725c88d6d550cc49c9cb94e4bd4c485a1c6715a5dbfd210369fb8ddd38ab04cfb912a76c1bde5c7d0c1415ff4caf199461878d5fb03dc3f853ae".*;

    var buff_tx: [10000]u8 = undefined;
    var buff_src_outs: [1000]u8 = undefined;
    const raw_tx_bytes = try std.fmt.hexToBytes(&buff_tx, &tx_hex);
    const raw_src_outs_bytes = try std.fmt.hexToBytes(&buff_src_outs, &tx_src_outs);
    var src_outs_reader = Cursor.init(raw_src_outs_bytes);
    var utxos = try Transaction.readOutputs(&src_outs_reader, allocator);

    var tx_reader = Cursor.init(raw_tx_bytes);
    var tx = try Transaction.decode(&tx_reader, allocator);

    var ctx = ScriptExecContext{
        .input_index = 0,
        .utxo = utxos,
        .tx = tx,
        .signing_cache = SigningCache.init(),
    };
    _ = &ctx;
    var buf: [32 * 4]u8 = .{0} ** 128;
    // var p = SigningContextCache.init();
    // _ = try p.compute(&ctx, &buf);
    // _ = &p;
    try ctx.signing_cache.compute(&ctx, &buf);
    const hashflag: i32 = @intCast(@intFromEnum(SigHashType.allOutputs));
    const script = ctx.tx.inputs[ctx.input_index].script;
    const tx_size = tx.getTransactionSize();
    const utxo_size = Transaction.calculateOutputsSize(ctx.utxo);
    var serialized_tx_data = try std.ArrayList(u8).initCapacity(allocator, tx_size + utxo_size);
    defer serialized_tx_data.deinit();
    try serialized_tx_data.resize(tx_size + utxo_size + 128);

    var sigser_writer = Cursor.init(serialized_tx_data.items);
    var timer = try std.time.Timer.start();
    // var encode_precompute_start = try timer.read();
    _ = try encodeWithPrecompute(&tx, &utxos, hashflag, script, ctx.input_index, &sigser_writer, allocator, &ctx.signing_cache);
    const encode_precompute_end = timer.read();
    // const precompute_duration = encode_precompute_end - timer.started.since();
    std.debug.print("Sigser PRECOMPUTE TIME {}\n", .{encode_precompute_end});

    var serialized_tx_data2 = try std.ArrayList(u8).initCapacity(allocator, tx_size + utxo_size);
    defer serialized_tx_data2.deinit();
    var sigser_writer2 = Cursor.init(serialized_tx_data.items);

    timer.reset();

    _ = try encode(&tx, &utxos, hashflag, script, ctx.input_index, &sigser_writer2, allocator);
    const duration = timer.read();
    std.debug.print("Sigser encode duration {}\n", .{duration});
    try std.testing.expectEqualSlices(u8, sigser_writer.fbs.getWritten(), sigser_writer2.fbs.getWritten());
    // std.debug.print("HashSeq:{x}\nHashInputs:{x}\nHashoutputs:{x}\nHashUtxos:{x}\n", .{
    //     p.hash_sequence,
    //     p.hash_prevouts,
    //     p.hash_outputs,
    //     p.hash_utxos,
    // });
}
