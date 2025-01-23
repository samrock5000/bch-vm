const std = @import("std");
const Encoder = @import("encoding.zig");
const CashToken = @import("token.zig");
pub const Transaction = @This();
const Allocator = std.mem.Allocator;
version: u32,
inputs: []Input,
outputs: []Output,
locktime: u32,

pub fn init() Transaction {
    return Transaction{
        .version = 0,
        .inputs = &.{},
        .outputs = &.{},
        .locktime = 0,
    };
}
pub const Input = struct {
    txid: u256,
    index: u32,
    sequence: u32,
    script: []u8,
    pub fn decode(encoder: anytype, allocator: Allocator) !Input {
        return Input{
            .txid = try encoder.readInt(u256, .big),
            .index = try encoder.readInt(u32, .little),
            .script = try Encoder.readVarBytes(encoder, allocator),
            .sequence = try encoder.readInt(u32, .little),
        };
    }
    pub fn encode(self: Input, writer: anytype) !usize {
        var len: usize = 0;
        try writer.writeInt(u256, self.txid, .big);
        len += 32;
        try writer.writeInt(u32, self.index, .little);
        len += 4;
        len += try Encoder.writeVarBytes(writer, self.script);
        try writer.writeInt(u32, self.sequence, .little);
        len += 4;
        return len;
    }
};

pub const Output = struct {
    script: []u8,
    satoshis: u64,
    token: ?CashToken,
    pub fn decode(encoder: *Encoder, allocator: Allocator) !Output {
        // _ = &allocator;
        const reader = encoder.fbs.reader();
        const sats = try reader.readInt(u64, .little);
        const seek_pos = encoder.fbs.pos;
        var has_token = false;
        _ = try Encoder.readVarint(reader);
        // std.debug.print("WE HERE {}", .{seek_pos});
        if (try encoder.fbs.getPos() < try encoder.fbs.getEndPos()) {
            const prefix_byte = try reader.readByte();
            has_token = prefix_byte == CashToken.PREFIX_TOKEN;
        }
        try encoder.fbs.seekTo(seek_pos);
        if (has_token) {
            const output_data =
                try CashToken.decodeTokenScript(encoder, allocator);
            return Output{
                .satoshis = sats,
                .script = output_data.script,
                .token = output_data.token,
            };
        } else {
            return Output{
                .satoshis = sats,
                .script = try Encoder.readVarBytes(reader, allocator),
                .token = null,
            };
        }
    }
    pub fn encode(self: Output, writer: anytype) !usize {
        var len: usize = 0;
        // std.debug.print("Buffer length at encode: {}\n", .{writer.context.buffer.len});
        // Write satoshis
        try writer.writeInt(u64, self.satoshis, .little);
        len += @sizeOf(u64);

        if (self.token) |token| {
            // // First, calculate the total script length
            // var counting_writer = std.io.countingWriter(std.io.null_writer);
            // _ = try token.encodeTokenScript(counting_writer.writer());
            // const token_script_len = counting_writer.bytes_written;
            // const total_script_len = token_script_len + self.script.len;

            // // Write the total script length as varint
            // len += try Encoder.writeVarint(writer, total_script_len);

            // // Now write the actual data
            // len += try token.encodeTokenScript(writer);
            // len += try writer.write(self.script);
            //----------------------
            // Get length directly from encode function
            const token_script_len = try token.encodeTokenScript(std.io.null_writer);
            const total_script_len = token_script_len + self.script.len;

            // Write the total script length as varint
            len += try Encoder.writeVarint(writer, total_script_len);

            // Now write the actual data
            len += try token.encodeTokenScript(writer);
            len += try writer.write(self.script);
        } else {
            // Write script length as varint
            len += try Encoder.writeVarint(writer, self.script.len);

            // Write the script
            // self.script.len;
            // std.debug.print("Script length: {}, Current pos: {}, Available space: {}\n", .{
            //     self.script.len,
            //     try writer.context.getPos(),
            //     try writer.context.getEndPos() - try writer.context.getPos(),
            // });
            len += try writer.write(self.script);
            // std.debug.print("POS {any}\n", .{try writer.context.getPos()});
            // std.debug.print("POS END {any}\n", .{try writer.context.getEndPos()});
        }

        return len;
    }
};

pub fn readInputs(
    encoder: anytype,
    allocator: Allocator,
) ![]Input {
    const reader = encoder.fbs.reader();
    const inputs_len = try Encoder.readVarint(reader);
    const inputs = try allocator.alloc(Input, inputs_len);
    for (0..inputs_len) |i| {
        inputs[i] = try Input.decode(reader, allocator);
    }
    return inputs;
}
pub fn readOutputs(encoder: *Encoder, allocator: Allocator) ![]Output {
    const reader = encoder.fbs.reader();
    const outputs_len = try Encoder.readVarint(reader);
    const outputs = try allocator.alloc(Output, outputs_len);
    // var fbs = std.io.fixedBufferStream(outputs);
    for (0..outputs_len) |i| {
        const output = try Output.decode(encoder, allocator);
        outputs[i] = output;
    }
    return outputs;
}
pub fn decode(
    encoder: *Encoder,
    allocator: Allocator,
) !Transaction {
    const reader = encoder.fbs.reader();
    return Transaction{
        .version = try reader.readInt(u32, .little),
        .inputs = try readInputs(encoder, allocator),
        .outputs = try readOutputs(encoder, allocator),
        .locktime = try reader.readInt(u32, .little),
    };
}
pub fn encodeOutputs(tx: *Transaction, writer: anytype) !usize {
    var len: usize = 0;
    len += try Encoder.writeVarint(writer, tx.outputs.len);
    for (tx.outputs) |*output| {
        len += try output.encode(writer);
    }
    return len;
}
pub fn encode(tx: *Transaction, writer: anytype) !usize {
    var len: usize = 0;
    try writer.writeInt(u32, tx.version, .little);
    len += 4;

    len += try Encoder.writeVarint(writer, tx.inputs.len);
    for (tx.inputs) |*input| {
        len += try input.encode(writer);
    }
    len += try Encoder.writeVarint(writer, tx.outputs.len);
    for (tx.outputs) |*output| {
        len += try output.encode(writer);
    }
    // len += try tx.encodeOutputs(writer);
    try writer.writeInt(u32, tx.locktime, .little);
    len += 4;
    return len;
}
pub fn totalOutputValue(outputs: []Output) u64 {
    var total: u64 = 0;
    for (outputs) |output| {
        total += output.satoshis;
    }
    return total;
}

test "txid to bytes" {
    // var out: [32]u8 = undefined;
    // _ = try std.fmt.hexToBytes(&out, "f8678701920862879b874a37bd9ed3e15d1623b00ead71ffe4c302d4af923bcd");

    // const txid = std.mem.readInt(u256, out[0..], .big);
    // _ = &txid;
    // std.debug.print("{x}\n", .{out});
    // std.debug.print("{any}\n", .{txid});

    // const txid = u8[32](f8678701920862879b874a37bd9ed3e15d1623b00ead71ffe4c302d4af923bcd)
}

test "encode(de)code input" {
    // var list = std.ArrayList(u8).init(std.testing.allocator);
    // defer list.deinit();

    // const serialized_input = "4958e186f13cd295e717a70a56e878eab92ef2e257800bd8ccc39f1e34c429b20100000064410c23257856dbc87cca9c1bfe99e4a1dc5412688e04c44b1bcfb01d0912740064e8b87b2efc8d66b8bc39144a9868fd05b38a729a6bd57dcb50575173f995c68c4121024748d057afc38a7814e46f9d36addffb04524b061abd168a8c798c138eafe8ec00000000";

    // var out: [serialized_input.len / 2]u8 = undefined;

    // _ = try std.fmt.hexToBytes(&out, serialized_input);

    // var cursor = Encoder.init(&out);
    // var vin = try Input.decode(&cursor);

    // _ = try vin.encode(list.writer());

    // std.debug.assert(std.mem.eql(u8, out[0..], list.items[0..]));
}
pub fn getTransactionSize(tx: Transaction) usize {
    var size: usize = 0;

    // Base transaction fields
    size += @sizeOf(u32); // version
    size += @sizeOf(u32); // locktime

    // Add inputs and outputs sizes
    size += calculateInputsSize(tx.inputs);
    size += calculateOutputsSize(tx.outputs);

    return size;
}

pub fn calculateInputsSize(inputs: []Input) usize {
    var size: usize = 0;

    // VarInt for number of inputs
    size += getVarIntSize(inputs.len);

    // Calculate size of each input
    for (inputs) |input| {
        size += @sizeOf(u256); // txid
        size += @sizeOf(u32); // index
        size += @sizeOf(u32); // sequence
        size += getVarIntSize(input.script.len); // script length
        size += input.script.len; // script data
    }

    return size;
}

pub fn calculateOutputsSize(outputs: []Output) usize {
    var size: usize = 0;

    // VarInt for number of outputs
    size += getVarIntSize(outputs.len);

    // Calculate size of each output
    for (outputs) |output| {
        size += @sizeOf(u64); // satoshis

        // Token field
        if (output.token) |token| {
            size += @sizeOf(u8); // prefix
            size += getVarIntSize(output.token.?.amount); // amount
            size += @sizeOf(u256); // id
            size += @sizeOf(u8); // capability

            // size += @sizeOf(u8); // capability
            // NFT field
            if (token.nft) |nft| {
                size += getVarIntSize(nft.commitment.len); // commitment length
                size += nft.commitment.len; // commitment data
            }
            size += output.script.len; // script data
        } else {
            size += getVarIntSize(output.script.len); // script length
            size += output.script.len; // script data
        }
    }

    return size;
}
// Helper function to calculate VarInt size
fn getVarIntSize(value: usize) usize {
    if (value < 0xfd) {
        return 1;
    } else if (value <= 0xffff) {
        return 3;
    } else if (value <= 0xffffffff) {
        return 5;
    } else {
        return 9;
    }
}
test "encode(de)code output" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const serialized_ouput = "e80300000000000045efe5d95b718f462608d31bdf006ed488c5f074c3d4d2df4624b96bbbec86e14de922aa2059d57d9c082afcf016f8311067cf825163d1c6ecca887c2af63b98ceb5bf071d87";

    var out: [serialized_ouput.len / 2]u8 = undefined;

    _ = try std.fmt.hexToBytes(&out, serialized_ouput);

    var cursor = Encoder.init(&out);
    const output = try Output.decode(&cursor, std.testing.allocator);
    _ = output;
    // std.debug.print("OUTPUT: {any}\n", .{output.script});
    // std.debug.print("OUTPUT {any}\n", .{cursor.fbs.buffer.len});
    // _ = &vout;
    // _ = try vout.encode(list.writer());

    // std.debug.assert(std.mem.eql(u8, out[0..], list.items[0..]));
}
test "encode(de)code transaction" {
    const allocator = std.heap.page_allocator;
    // var fba = std.heap.FixedBufferAllocator.init(&buffer);

    // defer allocator.free(memory);
    const serialized_tx = "02000000050100000000000000000000000000000000000000000000000000000000000000000000006441bd120e87194a857ef14ad91bdf7d7b89a10a9aa3321fe4d6d68036e3db90de78ed4133a6d137b1a87992f92b6bd71c1f8f0ea0333878794fabb016025f4e720bc32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000001000000fd8e014d15010200000068225d8d7e2f476bdf91da4a471c72edca1c9a21d636b130a57027b10b9ff4b1664daebc7ef78129fe718d82bcf99f07db5e8d1ca986ef08e84a5c4112d02f1af6eab7b91a423426d06da844347472994a738cc6b105c5fa695f74832818d173010000000000000000000000000000000000000000000000000000000000000001000000ef02000000000000000000000000000000000000000000000000000000000000007101ff64332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba102700000000000000000000b9efc8d67171530419023ecc4a973d051d306ae5c42f11d9017dc0623693eabd000000006100000041a447d05f7ea5b210e424116ef44712a51d87545229e593652640592ab5c7c0277636fa3b3a8256d50684584797bf87b3b4c5e21096be114f1f29f0459d3afd9b61332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba000000000100000000000000000000000000000000000000000000000000000000000000020000006441c6b3c6d3106c98045124984f4c15ae6b956b8f34b3b56b67ca1de1c3a6eee37a4bcc50d2194479c6c2663ae24d78cb2b66aef8453fe2f6f1661c21cc98b70ea3c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000003000000025100000000000100000000000000000000000000000000000000000000000000000000000000040000000251000000000005e8030000000000003fef03000000000000000000000000000000000000000000000000000000000000006203abcdef76a9144af864646d46ee5a12f4695695ae78f993cad77588ace80300000000000041ef03000000000000000000000000000000000000000000000000000000000000006205010203040576a9144af864646d46ee5a12f4695695ae78f993cad77588ace80300000000000044ef02000000000000000000000000000000000000000000000000000000000000007003010203fea4420f0076a9144af864646d46ee5a12f4695695ae78f993cad77588ace8030000000000003fef02000000000000000000000000000000000000000000000000000000000000006103ffffff76a9144af864646d46ee5a12f4695695ae78f993cad77588ace8030000000000001976a9144af864646d46ee5a12f4695695ae78f993cad77588ac00000000";

    var out: [serialized_tx.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, serialized_tx);

    const memory = try allocator.alloc(u8, 10000);
    defer allocator.free(memory);
    // var fbs = std.io.fixedBufferStream(&memory);
    // var buff: [20000]u8 = undefined;
    var decoder = Encoder.init(&out);
    var transaction = try Transaction.decode(&decoder, allocator);
    // for (transaction.outputs) |t| {
    //     std.debug.print("decoded {any}\n\n", .{t.token});
    // }
    // cursor.fbs.reset();
    var coder = Encoder.init(memory);
    // _ = try transaction.encode(coder.fbs.writer());
    _ = try transaction.outputs[3].encode(coder.fbs.writer());
    // std.debug.print("encoded {any}\n\n", .{coder.fbs.getWritten()});

    // _ = try tx.outputs[0].encode(fbs.writer());
    // _ = try tx.encodeOutputs(fbs.writer());
    // std.debug.print("{any}\n", .{transaction.outputs[1].token});
    // _ = try std.testing.expectEqualSlices(u8, &out, coder.fbs.getWritten());
}
test "scratch" {
    const allocator = std.heap.page_allocator;
    const serialized_tx = "02000000050100000000000000000000000000000000000000000000000000000000000000000000006441bd120e87194a857ef14ad91bdf7d7b89a10a9aa3321fe4d6d68036e3db90de78ed4133a6d137b1a87992f92b6bd71c1f8f0ea0333878794fabb016025f4e720bc32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000001000000fd8e014d15010200000068225d8d7e2f476bdf91da4a471c72edca1c9a21d636b130a57027b10b9ff4b1664daebc7ef78129fe718d82bcf99f07db5e8d1ca986ef08e84a5c4112d02f1af6eab7b91a423426d06da844347472994a738cc6b105c5fa695f74832818d173010000000000000000000000000000000000000000000000000000000000000001000000ef02000000000000000000000000000000000000000000000000000000000000007101ff64332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba102700000000000000000000b9efc8d67171530419023ecc4a973d051d306ae5c42f11d9017dc0623693eabd000000006100000041a447d05f7ea5b210e424116ef44712a51d87545229e593652640592ab5c7c0277636fa3b3a8256d50684584797bf87b3b4c5e21096be114f1f29f0459d3afd9b61332103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7856eac696ead7c8251947f757ba87b6fbbba000000000100000000000000000000000000000000000000000000000000000000000000020000006441c6b3c6d3106c98045124984f4c15ae6b956b8f34b3b56b67ca1de1c3a6eee37a4bcc50d2194479c6c2663ae24d78cb2b66aef8453fe2f6f1661c21cc98b70ea3c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e78500000000010000000000000000000000000000000000000000000000000000000000000003000000025100000000000100000000000000000000000000000000000000000000000000000000000000040000000251000000000005e8030000000000003fef03000000000000000000000000000000000000000000000000000000000000006203abcdef76a9144af864646d46ee5a12f4695695ae78f993cad77588ace80300000000000041ef03000000000000000000000000000000000000000000000000000000000000006205010203040576a9144af864646d46ee5a12f4695695ae78f993cad77588ace80300000000000044ef02000000000000000000000000000000000000000000000000000000000000007003010203fea4420f0076a9144af864646d46ee5a12f4695695ae78f993cad77588ace8030000000000003fef02000000000000000000000000000000000000000000000000000000000000006103ffffff76a9144af864646d46ee5a12f4695695ae78f993cad77588ace8030000000000001976a9144af864646d46ee5a12f4695695ae78f993cad77588ac00000000";

    var out: [serialized_tx.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, serialized_tx);

    const memory = try allocator.alloc(u8, 10000);
    defer allocator.free(memory);
    // var fbs = std.io.fixedBufferStream(&memory);
    // var buff: [20000]u8 = undefined;
    var decoder = Encoder.init(&out);
    var transaction = try Transaction.decode(&decoder, allocator);
    // for (transaction.outputs) |t| {
    //     std.debug.print("decoded {any}\n\n", .{t.token});
    // }
    var counting_writer = std.io.countingWriter(std.io.null_writer);
    // _ = context.tx.encode(counting_writer.writer());
    // counting_writer.bytes_written;
    // if (counting_writer)
    // var list = std.ArrayList(u8).init(allocator);
    _ = try transaction.encode(counting_writer.writer());
    // std.debug.print("decoded {any}\n\n", .{counting_writer.bytes_written});
    // cursor.fbs.reset();
    // var coder = Encoder.init(memory);
    // _ = try transaction.encode(coder.fbs.writer());
    // _ = try transaction.outputs[3].encode(coder.fbs.writer());
}
