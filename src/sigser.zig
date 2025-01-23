const std = @import("std");
const Transaction = @import("transaction.zig");
const Allocator = std.mem.Allocator;
const sha256 = std.crypto.hash.sha2.Sha256.hash;
const Encoder = @import("encoding.zig");
const ScriptExecContext = @import("stack.zig").ScriptExecContext;
// const VM = @import("vm.zig");
// const SCRIPT_ENABLE_MAY2025 = @import("vm.zig").SCRIPT_ENABLE_MAY2025;
// const SCRIPT_VM_LIMITS_STANDARD = @import("vm.zig").SCRIPT_VM_LIMITS_STANDARD;
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
    sigser_writer: *Encoder,
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
    var encoder = Encoder.init(buff.items);
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

    len += try Encoder.writeVarBytes(sigser_writer.fbs.writer(), script_slice);
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
// pub fn hashSequence(
//     tx: *Transaction,
//     writer: anytype,
//     out: [32]u8,
// ) !void {
//     encodeSequence(tx, writer);
//     _ = sha256(encoder.fbs.getWritten(), &hash_prev_out, .{});
//     _ = sha256(&hash_prev_out, &hash_prev_out, .{});
// }

pub fn encodeInputs(tx: Transaction, writer: anytype) !usize {
    var len: usize = 0;
    // _ = try Encoder.writeVarint(writer, len);
    for (tx.inputs) |*input| {
        len += try input.encode(writer);
    }
    return len;
}
pub fn encodeOutpoints(tx: *Transaction, writer: anytype) !usize {
    var len: usize = 0;
    // _ = try Encoder.writeVarint(writer, len);
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
    // _ = &writer;
    for (utxos) |*output| {
        len += try output.encode(writer);
        // const x = writer.context.getWritten();
        // std.debug.print("Buffer size: {}\n", .{x.len});
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
pub const SigningContextCache = struct {
    hash_prevouts: u256,
    hash_sequence: u256,
    hash_outputs: u256,
    hash_utxos: u256,
    pub fn init() SigningContextCache {
        return SigningContextCache{
            .hash_prevouts = 0,
            .hash_sequence = 0,
            .hash_outputs = 0,
            .hash_utxos = 0,
        };
    }
    pub fn compute(self: *SigningContextCache, ctx: *ScriptExec, buf: []u8) !void {
        // std.debug.print("{}\n", .{Transaction.calculateOutputsSize(ctx.utxo)});
        var fb = std.io.fixedBufferStream(buf);
        // std.debug.print("Buffer length at compute: {}\n", .{buf.len});
        const w = fb.writer();
        _ = try SigningSer.encodeOutpoints(&ctx.tx, w);
        _ = sha256(fb.getWritten(), buf[0..32], .{});
        _ = sha256(buf[0..32], buf[0..32], .{});
        self.hash_prevouts = std.mem.readInt(u256, buf[0..32], .big);
        fb.reset();
        _ = try SigningSer.encodeSequence(&ctx.tx, w);
        _ = sha256(fb.getWritten(), buf[32..64], .{});
        _ = sha256(buf[32..64], buf[32..64], .{});
        self.hash_sequence = std.mem.readInt(u256, buf[32..64], .big);
        fb.reset();
        _ = try SigningSer.encodeOutputs(&ctx.tx, w);
        _ = sha256(fb.getWritten(), buf[64..96], .{});
        _ = sha256(buf[64..96], buf[64..96], .{});
        self.hash_outputs = std.mem.readInt(u256, buf[64..96], .big);
        fb.reset();
        _ = try SigningSer.encodeUtxos(ctx.utxo, w);
        _ = sha256(fb.getWritten(), buf[96..128], .{});
        _ = sha256(buf[96..128], buf[96..128], .{});
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
    sigser_writer: *Encoder,
    alloc: Allocator,
    precompute: *SigningContextCache,
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

    // std.debug.print("pos {} end {}\n", .{ sigser_writer.fbs.pos, try sigser_writer.fbs.getEndPos() });
    len += try Encoder.writeVarBytes(sigser_writer.fbs.writer(), script_slice);
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
            var encoder = Encoder.init(buff.items);

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

    // var cursor = Encoder.init(&out);
    // var source_out_encoder = Encoder.init(source_outs_buff);
    // const source_outs = try Transaction.readOutputs(&source_out_encoder, allocator);
    // var data = Encoder.init(buffer2);
    // const transaction = try Transaction.decode(&cursor, allocator);
    // // const hashtype: i32 = 0x01 | 0x20;
    // const hashtype: i32 = @intFromEnum(SigHash.allOutputsAllUtxos);
    // try SigningSer.encode(transaction, source_outs, hashtype, covered_bytecode, 0, &data, allocator);
    // const actual = data.fbs.getWritten();
    // _ = &expect;
    // try std.testing.expectEqualSlices(u8, expect, actual);

}

const SigHashTestData = struct {
    tx: Transaction,
    script: []u8,
    index: u32,
    hashtype: i32,
    sighash_req: []const u8,
    // sighash_no_fork: []const u8,
    // sighash_protection: []const u8,
};
const ScriptExec = @import("stack.zig").ScriptExecContext;

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
    var src_outs_reader = Encoder.init(raw_src_outs_bytes);
    var utxos = try Transaction.readOutputs(&src_outs_reader, allocator);

    var tx_reader = Encoder.init(raw_tx_bytes);
    var tx = try Transaction.decode(&tx_reader, allocator);

    var ctx = ScriptExecContext{
        .input_index = 0,
        .utxo = utxos,
        .tx = tx,
        .signing_cache = SigningContextCache.init(),
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

    var sigser_writer = Encoder.init(serialized_tx_data.items);
    const encode_precompute_start = std.time.nanoTimestamp();
    _ = try encodeWithPrecompute(&tx, &utxos, hashflag, script, ctx.input_index, &sigser_writer, allocator, &ctx.signing_cache);
    const encode_precompute_end = std.time.nanoTimestamp();
    const precompute_duration = encode_precompute_end - encode_precompute_start;
    std.debug.print("PRE COMP TIME {}\n", .{precompute_duration});

    var serialized_tx_data2 = try std.ArrayList(u8).initCapacity(allocator, tx_size + utxo_size);
    defer serialized_tx_data2.deinit();
    var sigser_writer2 = Encoder.init(serialized_tx_data.items);

    const encode_start = std.time.nanoTimestamp();
    _ = try encode(&tx, &utxos, hashflag, script, ctx.input_index, &sigser_writer2, allocator);
    const encode_end = std.time.nanoTimestamp();
    const duration = encode_end - encode_start;
    std.debug.print("COMP TIME {}\n", .{duration});
    try std.testing.expectEqualSlices(u8, sigser_writer.fbs.getWritten(), sigser_writer2.fbs.getWritten());
    // std.debug.print("HashSeq:{x}\nHashInputs:{x}\nHashoutputs:{x}\nHashUtxos:{x}\n", .{
    //     p.hash_sequence,
    //     p.hash_prevouts,
    //     p.hash_outputs,
    //     p.hash_utxos,
    // });
}

test "sighash flags" {
    // var ally = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // defer ally.deinit();

    // var txlist = std.ArrayList(u8).init(ally.allocator());
    // // defer txlist.deinit();

    // const buff = try ally.allocator().alloc(
    //     u8,
    //     try get_size("testdata/sighash_bip143.json"),
    // );
    // _ = try openTestVecVMB(
    //     buff,
    //     "testdata/sighash_bip143.json",
    // );
    // var jsonally = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // defer jsonally.deinit();

    // var src_outs_ally = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // defer src_outs_ally.deinit();

    // const parsed = try std.json.parseFromSlice(std.json.Value, jsonally.allocator(), buff, .{ .duplicate_field_behavior = .use_first, .allocate = .alloc_if_needed });

    // const items = parsed.value.array.items;
    // var len: usize = 0;
    // var txbuff: [1024]u8 = undefined;
    // for (items[1..], 1..) |data, i| {
    //     const testvec = data.array;

    //     _ = &i;
    // const tx_hex = testvec.items[0].string;
    // const script_hex = testvec.items[1].string;
    // const input = testvec.items[2].integer;
    // const hash_type = testvec.items[3].integer;
    // const signature_hash_hex = testvec.items[4].string;

    // const script_buff = try ally.allocator().alloc(u8, script_hex.len);
    // const script = try std.fmt.hexToBytes(script_buff, script_hex);
    // const signature_hash_buff = try ally.allocator().alloc(u8, signature_hash_hex.len);
    // const signature = try std.fmt.hexToBytes(signature_hash_buff, signature_hash_hex);
    // try txlist.appendNTimes(0, tx_hex.len);
    // _ = try std.fmt.hexToBytes(txlist.items, tx_hex);
    // const  = try std.fmt.hexToBytes(script_buff, script_hex);

    // defer ally.free(script_buff);
    // defer ally.free(tx_buff);
    // defer ally.free(signature_hash_buff);
    // std.debug.print("{x}\n{}\n{}\n{x}\n", .{ script, input, hash_type, signature });
    // var tx_writer = Encoder.init(txlist.items);
    // const transaction = try Transaction.decode(&tx_writer, ally.allocator());

    // std.debug.print("tx {any}", .{transaction});

    // const flag = std.mem.toBytes(hash_type);
    // const is_hash_utxos = shouldSerializeUtxos(flag[0]);
    // if (!isLegacy(hash_type) and !is_hash_utxos) {
    //     var src_outs =
    //         [_]Transaction.Output{Transaction.Output{ .satoshis = 0, .script = &.{}, .token = null }} ** 5;
    //     src_outs[sighash_item.index].script = sighash_item.script;
    //     _ = try encode(tx, &src_outs, sigser_fin[0].hashtype, tx.inputs[0].script, sigser_fin[0].index, &sigser_reader, std.testing.allocator);
    //     var res_hash: [32]u8 = undefined;
    //     var expect_hash: [32]u8 = undefined;
    //     const expect_hex = try std.fmt.hexToBytes(&expect_hash, obj[4].string);
    //     _ = sha256(sigser_reader.fbs.getWritten(), &res_hash, .{});
    //     _ = sha256(&res_hash, &res_hash, .{});
    //     std.debug.print("expect {any}\nactual{any}", .{ expect_hash, res_hash });
    //     _ = try std.testing.expectEqualSlices(u8, expect_hex, &res_hash);
    // }
    // txlist.shrinkRetainingCapacity(obj[0].string.len / 2);
    // sigser_reader.fbs.reset();
    // }
}
test "multisig" {
    // var buffer: [10000]u8 = undefined;
    // var buffer2: [10000]u8 = undefined;
    // var sig_buff: [10000]u8 = undefined;
    // var pubkey_buff: [10000]u8 = undefined;

    // var fba = std.heap.FixedBufferAllocator.init(&buffer);
    // const allocator = fba.allocator();

    // const serialized_tx = "020000000201000000000000000000000000000000000000000000000000000000000000000000000064417dfb529d352908ee0a88a0074c216b09793d6aa8c94c7640bb4ced51eaefc75d0aef61f7685d0307491e2628da3d4f91e86329265a4a58ca27a41ec0b8910779c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000001000000fd4d0200473044022044d0bf359f0d0fd61263390c77050344feeb042e9995c21c1411b8aff41fc7f502206f48613e1ed0006dd5a32589e24da7cdb1b7645c7d9e0cddfc57f3cd4663fe5b414d0102512103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7852103c23083dccdc50247ebc5725c88d6d550cc49c9cb94e4bd4c485a1c6715a5dbfd210369fb8ddd38ab04cfb912a76c1bde5c7d0c1415ff4caf199461878d5fb03dc3f82102551025736a2c0f50d31a417bb3fd045c1937934617c5d3f968eeccc0326bdc2f21020d5b28cd62b3547b38c92726fb8947bff105ebf1d477e25a6935e1de3b8da58f2102405eb3e2c6f27a28cfcd352cca0531a41125595a5e36155b4a9f2cafa26733692103b1fff0524d555c3559213d44c50e76c7894709b4063d071c0b3399d61e28a8b1210240aab736dcdba6da8ec99de28b81ae3284a9b67c574cb84cfa1c8087c5b7fb892103ac7bef335fb75ef9195f9fcd1f9d6d87a23fd85b982b928a7692f737f430037c2103860c5ce8eb34de6d84e5a2dd253b9e268c77fd38f7bb91e396b4f76b6bc507042102928f7833b727f5fb7441318f32e253a6e738a6b7b40d4de77787b83372d68a052103a5090860cdd888fb697ab893380dd3d264ab1d353d47500da1ed24c2951f51892102810a88ff318d77a7f3d13063c970b5d5e34d7f3253da2c699d8202c9ca7c4ce8210277ba87309363947542c2ebdf640419b33d975390883f6fb9b455bb630aae35d221022bff9136119aa06e73f3534f5c266e194d23682c61c0f34828dfd884f31090c45fae000000000100000000000000000a6a08766d625f7465737400000000";
    // var tx_buff: [serialized_tx.len / 2]u8 = undefined;
    // const utxos = "0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac102700000000000017a9140c84609328c1d3a67338841879683e83aafed78c87";
    // const sig = "3044022044d0bf359f0d0fd61263390c77050344feeb042e9995c21c1411b8aff41fc7f502206f48613e1ed0006dd5a32589e24da7cdb1b7645c7d9e0cddfc57f3cd4663fe5b";
    // const pk = "03a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e785";
    // var utxo_buff: [utxos.len / 2]u8 = undefined;
    // _ = try std.fmt.hexToBytes(&utxo_buff, utxos);

    // _ = try std.fmt.hexToBytes(&tx_buff, serialized_tx);
    // const s = try std.fmt.hexToBytes(&sig_buff, sig);
    // const p = try std.fmt.hexToBytes(&pubkey_buff, pk);

    // var cursor = Encoder.init(&tx_buff);
    // var data = Encoder.init(&buffer2);
    // var src_outs = Encoder.init(&utxo_buff);
    // var lockscript = [_]u8{0x51};
    // var outs =
    //     [_]Transaction.Output{Transaction.Output{ .satoshis = 0, .script = &.{}, .token = null }};
    // outs[0].script = &lockscript;
    // const outs = try Transaction.readOutputs(&src_outs, allocator);
    // const transaction = try Transaction.decode(&cursor, allocator);
    // const hashtype: i32 = 0x01 | 0x40;
    // std.debug.print("HASHTYPE {any}", .{std.mem.toBytes(hashtype)});
    // try SigningSer.encode(transaction, outs, hashtype, 1, &data, std.testing.allocator);
    // std.debug.print("RES {any}\n", .{transaction.inputs[0].script});
    // var ctx = ScriptExec{ .input_index = 1, .utxo = outs, .tx = transaction };
    // var ctx_sample = ScriptContext.init();
    // std.debug.print("RES {any}\n", .{ctx_sample});
    // _ = try ScriptContext.compute(&ctx_sample, &ctx, allocator);

    // std.debug.print("RES {any}\n", .{ctx_sample});
    // var sighash: [32]u8 = undefined;
    // _ = sha256(data.fbs.getWritten(), &sighash, .{});
    // _ = sha256(&sighash, &sighash, .{});
    // std.debug.print("RES {any}\n", .{sighash});

    // const public_key = try std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256.PublicKey.fromSec1(p);
    // const signature = try std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256.Signature.fromDer(s);
    // var verifier = try signature.verifier(public_key);
    // verifier.update(data.fbs.getWritten());
    // try verifier.verify();
    // std.debug.print("RES {any}\n", .{public_key});
    // std.debug.print("RES {any}\n", .{signature});
}

test "cpg9xc" {
    // const buffer: [100000]u8 = undefined;
    // var buffer2: [10000]u8 = undefined;
    // var sig_buff: [10000]u8 = undefined;
    // var pubkey_buff: [10000]u8 = undefined;

    // const allocator = std.heap.page_allocator;

    // const buffer2 = try allocator.alloc(u8, 10000);
    // const buffer = try allocator.alloc(u8, 10000);
    // var fba = std.heap.FixedBufferAllocator.init(&buffer);
    // defer allocator.free(buffer2);
    // defer allocator.free(buffer);

    // const serialized_tx = "02000000050100000000000000000000000000000000000000000000000000000000000000000000006441bd120e87194a857ef14ad91bdf7d7b89a10a9aa3321fe4d6d68036e3db90de78ed4133a6d137b1a87992f92b6bd71c1f8f0ea0333878794fabb016025f4e720bc32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000001000000fd8e014d15010200000068225d8d7e2f476bdf91da4a471c72edca1c9a21d636b130a57027b10b9ff4b1664daebc7ef78129fe718d82bcf99f07db5e8d1ca986ef08e84a5c4112d02f1af6eab7b91a423426d06da844347472994a738cc6b105c5fa695f74832818d173010000000000000000000000000000000000000000000000000000000000000001000000ef02000000000000000000000000000000000000000000000000000000000000007101ff64332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba102700000000000000000000b9efc8d67171530419023ecc4a973d051d306ae5c42f11d9017dc0623693eabd000000006100000041a447d05f7ea5b210e424116ef44712a51d87545229e593652640592ab5c7c0277636fa3b3a8256d50684584797bf87b3b4c5e21096be114f1f29f0459d3afd9b61332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba000000000100000000000000000000000000000000000000000000000000000000000000020000006441c6b3c6d3106c98045124984f4c15ae6b956b8f34b3b56b67ca1de1c3a6eee37a4bcc50d2194479c6c2663ae24d78cb2b66aef8453fe2f6f1661c21cc98b70ea3c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000003000000025100000000000100000000000000000000000000000000000000000000000000000000000000040000000251000000000005e8030000000000003fef03000000000000000000000000000000000000000000000000000000000000006203abcdef76a9144af864646d46ee5a12f4695695ae78f993cad77588ace80300000000000041ef03000000000000000000000000000000000000000000000000000000000000006205010203040576a9144af864646d46ee5a12f4695695ae78f993cad77588ace80300000000000044ef02000000000000000000000000000000000000000000000000000000000000007003010203fea4420f0076a9144af864646d46ee5a12f4695695ae78f993cad77588ace8030000000000003fef02000000000000000000000000000000000000000000000000000000000000006103ffffff76a9144af864646d46ee5a12f4695695ae78f993cad77588ace8030000000000001976a9144af864646d46ee5a12f4695695ae78f993cad77588ac00000000";
    // var tx_buff: [serialized_tx.len]u8 = undefined;
    // const utxos = "0510270000000000003bef03000000000000000000000000000000000000000000000000000000000000002276a91460011c6bf3f1dd98cff576437b9d85de780f497488ac10270000000000003cef02000000000000000000000000000000000000000000000000000000000000007101ff64a914bd6c8a0b2ea22538d6b31ad0499a86e52f80926c8710270000000000003fef0200000000000000000000000000000000000000000000000000000000000000600301020376a91460011c6bf3f1dd98cff576437b9d85de780f497488ac10270000000000003eef020000000000000000000000000000000000000000000000000000000000000010fe40420f00a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87102700000000000017a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87";
    // // const sig = "3044022044d0bf359f0d0fd61263390c77050344feeb042e9995c21c1411b8aff41fc7f502206f48613e1ed0006dd5a32589e24da7cdb1b7645c7d9e0cddfc57f3cd4663fe5b";
    // // const pk = "03a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e785";
    // const expect_sigser = "0200000068225d8d7e2f476bdf91da4a471c72edca1c9a21d636b130a57027b10b9ff4b1664daebc7ef78129fe718d82bcf99f07db5e8d1ca986ef08e84a5c4112d02f1af6eab7b91a423426d06da844347472994a738cc6b105c5fa695f74832818d173010000000000000000000000000000000000000000000000000000000000000001000000ef02000000000000000000000000000000000000000000000000000000000000007101ff64332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba102700000000000000000000b9efc8d67171530419023ecc4a973d051d306ae5c42f11d9017dc0623693eabd0000000061000000";
    // var utxo_buff: [utxos.len]u8 = undefined;
    // _ = try std.fmt.hexToBytes(&utxo_buff, utxos);

    // _ = try std.fmt.hexToBytes(&tx_buff, serialized_tx);
    // const ser_expect = try std.fmt.hexToBytes(&sig_buff, expect_sigser);
    // // const p = try std.fmt.hexToBytes(&pubkey_buff, pk);

    // var cursor = Encoder.init(&tx_buff);
    // var data = Encoder.init(buffer2);
    // var src_outs = Encoder.init(&utxo_buff);
    // var lockscript = [_]u8{0x51};
    // var outs =
    //     [_]Transaction.Output{Transaction.Output{ .satoshis = 0, .script = &.{}, .token = null }};
    // outs[0].script = &lockscript;
    // var outs = try Transaction.readOutputs(&src_outs, allocator);
    // var transaction = try Transaction.decode(&cursor, allocator);
    // std.debug.print("SRC OUTS  {any}\n", .{outs});
    // const hashtype: i32 = 0x01 | 0x40;
    // std.debug.print("HASHTYPE {any}", .{std.mem.toBytes(hashtype)});
    // try SigningSer.encode(transaction, outs, hashtype, 1, &data, std.testing.allocator);
    // std.debug.print("RES {any}\n", .{transaction.inputs[0].script});
    // var ctx = ScriptExec{ .input_index = 1, .utxo = outs, .tx = transaction };
    // var ctx_sample = ScriptContext.init();
    // std.debug.print("RES {any}\n", .{ctx_sample});
    // _ = try ScriptContext.compute(&ctx_sample, &ctx, allocator);
    // const unlock_script = &.{ 77, 21, 1, 2, 0, 0, 0, 104, 34, 93, 141, 126, 47, 71, 107, 223, 145, 218, 74, 71, 28, 114, 237, 202, 28, 154, 33, 214, 54, 177, 48, 165, 112, 39, 177, 11, 159, 244, 177, 102, 77, 174, 188, 126, 247, 129, 41, 254, 113, 141, 130, 188, 249, 159, 7, 219, 94, 141, 28, 169, 134, 239, 8, 232, 74, 92, 65, 18, 208, 47, 26, 246, 234, 183, 185, 26, 66, 52, 38, 208, 109, 168, 68, 52, 116, 114, 153, 74, 115, 140, 198, 177, 5, 197, 250, 105, 95, 116, 131, 40, 24, 209, 115, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 239, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 113, 1, 255, 100, 51, 33, 3, 165, 36, 244, 61, 97, 102, 173, 53, 103, 241, 139, 10, 92, 118, 156, 106, 180, 220, 2, 20, 159, 77, 80, 149, 204, 244, 232, 255, 162, 147, 231, 133, 110, 172, 105, 110, 173, 124, 130, 81, 148, 127, 117, 123, 168, 123, 111, 187, 186, 16, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 185, 239, 200, 214, 113, 113, 83, 4, 25, 2, 62, 204, 74, 151, 61, 5, 29, 48, 106, 229, 196, 47, 17, 217, 1, 125, 192, 98, 54, 147, 234, 189, 0, 0, 0, 0, 97, 0, 0, 0, 65, 164, 71, 208, 95, 126, 165, 178, 16, 228, 36, 17, 110, 244, 71, 18, 165, 29, 135, 84, 82, 41, 229, 147, 101, 38, 64, 89, 42, 181, 199, 192, 39, 118, 54, 250, 59, 58, 130, 86, 213, 6, 132, 88, 71, 151, 191, 135, 179, 180, 197, 226, 16, 150, 190, 17, 79, 31, 41, 240, 69, 157, 58, 253, 155, 97, 51, 33, 3, 165, 36, 244, 61, 97, 102, 173, 53, 103, 241, 139, 10, 92, 118, 156, 106, 180, 220, 2, 20, 159, 77, 80, 149, 204, 244, 232, 255, 162, 147, 231, 133, 110, 172, 105, 110, 173, 124, 130, 81, 148, 127, 117, 123, 168, 123, 111, 187, 186 };

    // _ = try SigningSer.encode(&transaction, &outs, 97, unlock_script, 1, &data, allocator);
    // std.debug.print("RES {any}\n", .{data.fbs.getWritten()});
    // _ = try std.testing.expectEqualSlices(u8, ser_expect, data.fbs.getWritten());
    // var sighash: [32]u8 = undefined;
    // _ = sha256(data.fbs.getWritten(), &sighash, .{});
    // _ = sha256(&sighash, &sighash, .{});
    // std.debug.print("RES {any}\n", .{sighash});

    // const public_key = try std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256.PublicKey.fromSec1(p);
    // const signature = try std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256oSha256.Signature.fromDer(s);
    // var verifier = try signature.verifier(public_key);
    // verifier.update(data.fbs.getWritten());
    // try verifier.verify();
    // std.debug.print("RES {any}\n", .{public_key});
    // std.debug.print("RES {any}\n", .{signature});
}
fn get_size(
    // buff: []u8,
    file_name: []const u8,
) !usize {
    const file = try std.fs.cwd().openFile(file_name, .{});
    return try file.getEndPos();
}

pub fn openTestVecVMB(
    buff: []u8,
    file_name: []const u8,
) !void {
    var ally = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer ally.deinit();
    // const file = try std.fs.cwd().openFile("testdata/bch_vmb_tests_chip_cashtokens_standard.json", .{});
    const file = try std.fs.cwd().openFile(file_name, .{});

    // const file = try std.fs.cwd().openFile("testdata/core.push.vmb_tests.json", .{});
    // const file = try std.fs.cwd().openFile("testdata/core.benchmarks.arithmetic.add-sub.vmb_tests.json", .{});
    const bytes_read = try file.read(buff[0..]);
    _ = &bytes_read;
    // const bytes_read = try file.read(buff[0..19367]);
    // std.debug.print("BYTES {any}\n", .{file.getEndPos()});
    // _ = &bytes_read;
}
