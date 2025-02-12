pub const CashToken = @This();
const Encoder = @import("encoding.zig");
const Output = @import("transaction.zig").Transaction.Output;
const Transaction = @import("transaction.zig").Transaction;
const std = @import("std");
pub const PREFIX_TOKEN: u8 = 0xef;
const tokenFormatMask = 0xf0;
const tokenCapabilityMask = 0x0f;
const HashSet = @import("hashset.zig").HashSet;
const Allocator = std.mem.Allocator;
const testing = std.testing;

amount: u64,
id: u256,
capability: u8,
nft: ?NonFungibleToken,

pub const TokenValidationError = error{
    invalid_category,
    duplicate_genesis,
    invalid_minting_category,
    genesis_sum_exceeded,
    insufficient_mutable_tokens,
    invalid_capability,
    excessive_commitment,
    value_in_less_than_value_out,
    cannot_find_nft,
    invalid_token_amount,
    invalid_mutable_token_count,
    bad_bitfield,
    negative_amount,
    zero_fungible_amount,
    amount_bitfield_mismatch,
    commitment_bitfield_mismatch,
    fungible_with_commitment,
    maximum_fungible_token_amount,
    duplicate_immutable_commitment,
    attempt_to_modify_immutable_token,
    commitment_swap_attempt,
};

pub const TokenId = u256;

pub const MAXIMUM_COMMITMENT_LENGTH: u8 = 80;
pub const MAX_FUNGIBLE_TOKEN_AMOUNT = std.math.maxInt(i64);

fn hasNFT(bitfield: u8) bool {
    return bitfield & @intFromEnum(Structure.HasNFT) != 0;
}
fn hasAmount(bitfield: u8) bool {
    return bitfield & @intFromEnum(Structure.HasAmount) != 0;
}
fn hasCommitmentLen(bitfield: u8) bool {
    return bitfield & @intFromEnum(Structure.HasCommitmentLength) != 0;
}
pub fn isMutable(bitfield: u8) bool {
    return bitfield & @intFromEnum(Capability.Mutable) != 0;
}
pub fn isMinting(bitfield: u8) bool {
    return bitfield & @intFromEnum(Capability.Minting) != 0;
}
pub fn getCapability(bitfield: u8) !Capability {
    return switch (bitfield & tokenCapabilityMask) {
        0 => Capability.None,
        0x01 => Capability.Mutable,
        0x02 => Capability.Minting,
        else => TokenValidationError.invalid_capability,
    };
}
pub fn getCapabilityByte(bitfield: u8) u8 {
    return bitfield & tokenCapabilityMask;
}

pub const NonFungibleToken = struct {
    capability: u8,
    commitment: []u8,
    pub fn decode(reader: anytype, bitfield: u8, alloc: std.mem.Allocator) !NonFungibleToken {
        return NonFungibleToken{
            .capability = bitfield,
            .commitment = if (hasCommitmentLen(bitfield))
                try Encoder.readVarBytes(reader, alloc)
            else
                &[_]u8{},
        };
    }
};

pub fn decode(encoder: *Encoder, allocator: std.mem.Allocator) !?CashToken {
    var reader = encoder.fbs.reader();
    // READ TOKEN PREFIX
    _ = try reader.readInt(u8, .little);

    const id = try reader.readInt(u256, .big);
    const bitfield = try reader.readInt(u8, .little);
    return CashToken{
        .id = id,
        .capability = bitfield,
        .nft = try NonFungibleToken.decode(reader, bitfield, allocator),
        .amount = if (hasAmount(bitfield)) try Encoder.readVarint(reader) else 0, // readVarint()
    };
}
pub fn encode(token: CashToken, writer: anytype) !usize {
    try writer.writeInt(u8, PREFIX_TOKEN, .little);
    var len: usize = 1;
    try writer.writeInt(u256, token.id, .big);
    try writer.writeInt(u8, token.capability, .little);
    len += 1;
    len += 32;
    if (token.nft) |nft| {
        if (hasCommitmentLen(token.capability)) {
            len += try Encoder.writeVarBytes(writer, nft.commitment);
        }
        if (hasAmount(nft.capability)) {
            len += try Encoder.writeVarint(writer, token.amount);
        }
    } else {
        len += try Encoder.writeVarint(writer, token.amount);
    }
    return len;
}
pub const WrappedScript = struct {
    token: ?CashToken,
    script: []u8,
};
pub fn decodeTokenScript(
    encoder: *Encoder,
    alloc: std.mem.Allocator,
) !WrappedScript {
    const reader = encoder.fbs.reader();
    const script_len = try Encoder.readVarint(reader);
    const pos: usize = @intCast(try encoder.fbs.getPos());
    const token = try CashToken.decode(encoder, alloc);
    const post_pos: usize = @intCast(try encoder.fbs.getPos());
    const token_bytes_read = post_pos - pos;
    const lockscript = encoder.fbs.buffer[post_pos .. post_pos + (script_len - token_bytes_read)][0..];
    encoder.fbs.pos += lockscript.len;
    return WrappedScript{
        .token = token,
        .script = lockscript,
    };
}
pub fn encodeTokenScript(
    self: CashToken,
    writer: anytype,
) !usize {
    var len: usize = 0;
    len += try self.encode(writer);
    return len;
}

const Structure = enum(u8) {
    /// The payload encodes an amount of fungible tokens.
    HasAmount = 0x10,
    /// The payload encodes a non-fungible token.
    HasNFT = 0x20,
    /// The payload encodes a commitment-length and a commitment (HasNFT must also be set).
    HasCommitmentLength = 0x40,
    /// Must be unset.
    Reserved = 0x80,
};
const Capability = enum(u8) {
    /// No capability – either a pure-fungible or a non-fungible token which is an immutable token.
    None = 0x0,
    /// The `mutable` capability – the encoded non-fungible token is a mutable token.
    Mutable = 0x01,
    /// The `minting` capability – the encoded non-fungible token is a minting token.
    Minting = 0x02,
};

pub fn checkTokenData(token_data: ?@This()) TokenValidationError!void {
    // Early return if no token data
    const token = token_data orelse return;

    // Validate bitfield
    if (!validTokenField(token.capability)) {
        return error.bad_bitfield;
    }

    // Check token amount validations
    if (token.amount < 0) {
        return error.negative_amount;
    }
    if (token.amount > MAX_FUNGIBLE_TOKEN_AMOUNT) {
        return error.maximum_fungible_token_amount;
    }

    if (token.amount == 0 and !hasNFT(token.capability)) {
        return error.zero_fungible_amount;
    }

    // Validate amount and bitfield consistency
    if ((token.amount != 0) != hasAmount(token.capability)) {
        return error.amount_bitfield_mismatch;
    }

    // Validate commitment
    if (hasCommitmentLen(token.capability) != (token.nft.?.commitment.len > 0)) {
        return error.commitment_bitfield_mismatch;
    }

    // Additional checks for fungible-only tokens
    if (!hasNFT(token.capability)) {
        if (token.nft.?.commitment.len > 0) {
            return error.fungible_with_commitment;
        }
        return; // Early return for pure fungible tokens
    }
    // std.debug.print("COMMIT SIZE {}", .{token.nft.?.commitment.len});
    // NFT-specific commitment length check
    if (token.nft.?.commitment.len > MAXIMUM_COMMITMENT_LENGTH) {
        return error.excessive_commitment;
    }
}

pub fn validTokenField(bitfield: u8) bool {
    // Check structure nibble: must have at least 1 bit set, but not Reserved bit
    const structure_nibble = bitfield & 0xF0;
    if (structure_nibble >= 0x80 or structure_nibble == 0x00) return false;

    // Capability nibble must be 0, 1, or 2
    const capability_nibble = bitfield & 0x0F;
    if (capability_nibble > 2) return false;

    // A token prefix must encode at least one token type (NFT or Amount)
    if (!hasNFT(bitfield) and !hasAmount(bitfield)) return false;

    // If no NFT, capability must be 0
    if (!hasNFT(bitfield) and capability_nibble != 0) return false;

    // Cannot have commitment length without NFT
    if (!hasNFT(bitfield) and hasCommitmentLen(bitfield)) return false;

    return true;
}
pub fn verifyTransactionTokens(
    transaction: Transaction,
    source_outputs: []Output,
    alloc: std.mem.Allocator,
) (TokenValidationError || anyerror)!bool {
    // Step 1: Gather input token information
    var genesis_categories = HashSet(u256).init(alloc);
    defer genesis_categories.deinit();

    var available_sums = std.AutoArrayHashMap(u256, u64).init(alloc);
    defer available_sums.deinit();

    var available_mutable_tokens = std.AutoArrayHashMap(u256, usize).init(alloc);
    defer available_mutable_tokens.deinit();

    var minting_categories = HashSet(u256).init(alloc);
    defer minting_categories.deinit();

    var immutable_tokens = std.ArrayList(ImmutableToken).init(alloc);
    defer immutable_tokens.deinit();

    // Process inputs
    for (transaction.inputs, 0..) |input, index| {
        const source_output = source_outputs[index];

        if (input.index == 0) {
            try genesis_categories.insert(input.txid);
        }

        if (source_output.token) |token| {
            _ = try checkTokenData(token);

            // Update available sums
            const current_sum = available_sums.get(token.id) orelse 0;

            try available_sums.put(token.id, current_sum + token.amount);
            if (token.nft) |nft| {
                const capability = try getCapability(token.capability);
                switch (capability) {
                    .Minting => try minting_categories.insert(token.id),
                    .Mutable => {
                        const current_count = available_mutable_tokens.get(token.id) orelse 0;
                        try available_mutable_tokens.put(token.id, current_count + 1);
                    },
                    .None => {
                        try immutable_tokens.append(.{
                            .category_id = token.id,
                            .commitment = nft.commitment,
                        });
                    },
                }
            }
        }
    }
    // var genesis_categories_iter_tmp = genesis_categories.iterator();
    // while (genesis_categories_iter_tmp.next()) |item| {
    //     std.debug.print("Inputs Genesis {x}\n", .{item.*});
    // }
    // var available_sums_tmp = available_sums.iterator();
    // while (available_sums_tmp.next()) |entry| {
    //     std.debug.print("Input Sums Key {x} Val {x}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    // }
    // var available_mutable_tokens_iter = available_mutable_tokens.iterator();
    // while (available_mutable_tokens_iter.next()) |entry| {
    //     std.debug.print("Input Mutables Key {x} Val {x}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    // }
    // var minting_categories_iter_tmp = minting_categories.iterator();
    // while (minting_categories_iter_tmp.next()) |entry| {
    //     std.debug.print("Inputs Minting {x}\n", .{entry.*});
    // }
    // for (immutable_tokens.items) |item| {
    //     std.debug.print("Input Immutable ID {x} Commit{x} \n\n\n", .{ item.category_id, item.commitment });
    // }

    // Step 2: Process and validate outputs
    var output_sums = std.AutoArrayHashMap(u256, u64).init(alloc);
    defer output_sums.deinit();

    var output_mutable_tokens = std.AutoArrayHashMap(u256, usize).init(alloc);
    defer output_mutable_tokens.deinit();

    var output_immutable_tokens = std.ArrayList(ImmutableToken).init(alloc);
    defer output_immutable_tokens.deinit();

    var output_minting_categories = HashSet(u256).init(alloc);
    defer output_minting_categories.deinit();

    // Process outputs
    for (transaction.outputs) |output| {
        if (output.token) |token| {
            _ = try checkTokenData(token);
            // Update output sums
            const current_sum = output_sums.get(token.id) orelse 0;
            try output_sums.put(token.id, current_sum + token.amount);
            if (hasNFT(token.capability)) {
                const capability = try getCapability(token.capability);
                switch (capability) {
                    .Minting => try output_minting_categories.insert(token.id),
                    .Mutable => {
                        const current_count = output_mutable_tokens.get(token.id) orelse 0;
                        try output_mutable_tokens.put(token.id, current_count + 1);
                    },
                    .None => {
                        // std.debug.print("NFT {any}\n", .{nft});
                        try output_immutable_tokens.append(.{
                            .category_id = token.id,
                            .commitment = token.nft.?.commitment,
                        });
                    },
                }
            }
            // const available_mutable = available_mutable_tokens.get(token.id) orelse 0;
            // std.debug.print("AVAL MUTS {any}\n", .{available_mutable});
        }
    }
    // Validation Step : Minting Categories
    var minting_iter = output_minting_categories.iterator();
    while (minting_iter.next()) |category| {
        // std.debug.print("minting {any}\n\n", .{category.*});
        if (!minting_categories.contains(category.*) and !genesis_categories.contains(category.*)) {
            return TokenValidationError.invalid_minting_category;
        }
    }
    // Validation Step : Category Sums
    var sum_iter = output_sums.iterator();
    while (sum_iter.next()) |entry| {
        const category = entry.key_ptr.*;
        const output_sum = entry.value_ptr.*;

        const available_sum = available_sums.get(category) orelse 0;
        // std.debug.print("AVAILABLE SUMS {any}\nOUTPUT SUMS {}\n", .{ available_sum, output_sum });

        const is_genesis = genesis_categories.contains(category);

        // For non-genesis categories, ensure output sum does not exceed available sum
        // if (!is_genesis and !is_minting) {
        if (!is_genesis) {
            if (output_sum > available_sum) {
                return TokenValidationError.value_in_less_than_value_out;
            }
        }

        // For genesis categories, ensure output sum does not exceed max amount
        if (is_genesis and output_sum > MAX_FUNGIBLE_TOKEN_AMOUNT) {
            return TokenValidationError.genesis_sum_exceeded;
        }
    }
    // Validation Step : Immutable Tokens
    for (output_immutable_tokens.items) |output_token| {
        if (!minting_categories.contains(output_token.category_id) and
            !genesis_categories.contains(output_token.category_id))
        {
            var found_match = false;
            const tokens_to_downgrade: usize = 1;

            // First pass: find exact match or determine downgrade strategy
            for (immutable_tokens.items, 0..) |*input_token, i| {
                if (input_token.category_id == output_token.category_id) {
                    // std.debug.print("IMMUTABLE VALIDATION COMMIT MATCH {} \n", .{std.mem.eql(u8, input_token.commitment, output_token.commitment)});
                    // Exact match found
                    if (std.mem.eql(u8, input_token.commitment, output_token.commitment)) {
                        found_match = true;
                        _ = immutable_tokens.orderedRemove(i);

                        break;
                    }
                }
            }

            // const is_minting = minting_categories.contains(output_token.category_id);
            // If no match found in immutable tokens and not a Genesis category
            if (!found_match) {
                const category = output_token.category_id;
                var available_mutable = available_mutable_tokens.get(category) orelse 0;

                // Allow downgrading to mutable token
                if (available_mutable == 0) {
                    return TokenValidationError.cannot_find_nft;
                }

                // std.debug.print("AVAILABLE MUTS {any}\n ", .{available_mutable});
                // Deduct the tokens from available mutable tokens
                available_mutable = available_mutable - (tokens_to_downgrade);
                try available_mutable_tokens.put(category, available_mutable);
                found_match = true;
            }
            if (!found_match) {
                return TokenValidationError.cannot_find_nft;
            }
        }
    }

    // if (hasNFT(token.capability) and !genesis_categories.contains(token.id)) {
    // Validation Step : Mutable Tokens
    var mutable_iter = output_mutable_tokens.iterator();
    while (mutable_iter.next()) |entry| {
        const category = entry.key_ptr.*;
        var output_mutable_count: isize = @intCast(entry.value_ptr.*);

        // const is_genesis = genesis_categories.contains(category);
        if (!minting_categories.contains(category) and
            !genesis_categories.contains(category))
        {
            const available_mutable = available_mutable_tokens.get(category) orelse 0;
            // std.debug.print("AVAL MUTS {any} OUTPUTS MUTS {any}\n", .{ available_mutable, output_mutable_count });
            if (output_mutable_count < 0 or output_mutable_count > available_mutable) {
                return TokenValidationError.invalid_mutable_token_count;
            }
            output_mutable_count -= @intCast(available_mutable);
            // entry.value_ptr.* -= @intCast(available_mutable);
            // If output mutable count is less than or equal to available mutable tokens, it's valid
        }
    }
    // for (output_immutable_tokens.items) |item| {
    //     std.debug.print("outputImmutableTokens id {x} Commit {x} \n", .{ item.category_id, item.commitment });
    // }
    // var minting_iter_tmp = output_minting_categories.iterator();
    // while (minting_iter_tmp.next()) |entry| {
    //     std.debug.print("outputMintingCategories {x}\n", .{entry.*});
    // }
    // var mutable_iter_tmp = output_mutable_tokens.iterator();
    // while (mutable_iter_tmp.next()) |entry| {
    //     std.debug.print("outputMutables Key {x} Val {x}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    // }
    // var output_sums_iter_tmp = output_sums.iterator();
    // while (output_sums_iter_tmp.next()) |entry| {
    //     std.debug.print("outputSums Key {x} Val {x}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    // }
    return true;
}
const ImmutableToken = struct {
    category_id: u256,
    commitment: []const u8,
};
test "token" {
    // var list = std.ArrayList(u8).init(std.testing.allocator);
    // defer list.deinit();
    // const pref = "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb710acccccccccccccccccccc01";

    // var out: [pref.len / 2]u8 = undefined;
    // _ = try std.fmt.hexToBytes(&out, pref);
    // var cursor = Cursor.init(&out);
    // _ = &cursor;
    // _ = try CashToken.decode(&cursor);
    // const x: u8 = 0x0f;
    // std.debug.print("{any}", .{x});
    // std.debug.print("{any}", .{@intFromEnum(Structure.HasAmount)});
}
// Example usage and tests
