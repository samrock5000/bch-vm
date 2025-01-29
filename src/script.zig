const std = @import("std");
const isPushOnly = @import("push.zig").isPushOnly;
const BigInt = std.math.big.int.Managed;
// Constants for script operations
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xA9;
const OP_HASH256: u8 = 0xAA;
const OP_CHECKSIG: u8 = 0xAC;
const OP_EQUAL: u8 = 0x87;
const OP_CHECKMULTISIG: u8 = 0xAE;
const OP_RETURN: u8 = 0x6A;
const OP_EQUALVERIFY: u8 = 0x88;
const MAXIMUM_STANDARD_N = 20;

pub const P2SHType = enum {
    // not_p2sh,
    p2sh_160,
    p2sh_256,
};

/// Checks if a script matches either P2SH pattern and returns the type
pub fn isP2SH(script: []const u8) bool {
    // Check for legacy P2SH (160-bit)
    // Pattern: OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (script.len == 23 and
        script[0] == OP_HASH160 and
        script[1] == 0x14 and
        script[22] == OP_EQUAL)
    {
        return true;
    }

    // Check for P2SH_32 (256-bit)
    // Pattern: OP_HASH256 32 [32 byte hash] OP_EQUAL
    if (script.len == 35 and
        script[0] == OP_HASH256 and
        script[1] == 0x20 and
        script[34] == OP_EQUAL)
    {
        return true;
    }

    return false;
}
pub fn readScriptInt(data: []u8, gpa: std.mem.Allocator) !BigInt {
    // std.debug.print("READ SCRIPT INT {any}\n", .{data.len});
    var zero = try BigInt.initSet(gpa, 0);
    defer zero.deinit();

    if (data.len == 0) return zero.clone();

    const last = data[data.len - 1];
    if (last & 0x7f == 0) {
        if (data.len <= 1 or data[data.len - 2] & 0x80 == 0) {
            return error.non_minimal;
        }
    }
    return scriptIntParse(data, gpa);
}
/// reads script int unchecked
pub fn scriptIntParse(data: []u8, gpa: std.mem.Allocator) !BigInt {
    // Fast path for empty input
    if (data.len == 0) {
        return try BigInt.initSet(gpa, 0);
    }

    // Fast path for small numbers (8 bytes or less) - can fit in i64
    if (data.len <= 8) {
        const num = scriptIntParseI64(data);
        return try BigInt.initSet(gpa, num);
    }

    // Regular path for larger numbers
    var ret = try BigInt.init(gpa);
    errdefer ret.deinit();

    var val = try BigInt.init(gpa);
    defer val.deinit();

    var batch = try BigInt.init(gpa);
    defer batch.deinit();

    var one = try BigInt.initSet(gpa, 1);
    defer one.deinit();

    var shift_val = try BigInt.init(gpa);
    defer shift_val.deinit();

    // Process bytes in batches of 8
    var i: usize = 0;
    while (i + 8 <= data.len) : (i += 8) {
        // Combine 8 bytes into a u64
        var batch_val: u64 = 0;
        for (data[i .. i + 8], 0..) |byte, j| {
            batch_val |= @as(u64, byte) << @intCast(j * 8);
        }

        // Add batch to result
        try batch.set(batch_val);
        if (i > 0) {
            try batch.shiftLeft(&batch, @intCast(i * 8));
        }
        try ret.add(&ret, &batch);
    }

    // Handle remaining bytes
    if (i < data.len) {
        var sh: u64 = i * 8;
        for (data[i..]) |n| {
            try val.set(n);
            try val.shiftLeft(&val, @intCast(sh));
            try ret.add(&ret, &val);
            sh += 8;
        }
    }
    // Handle negative numbers
    if (data[data.len - 1] & 0x80 != 0) {
        const total_bits = data.len * 8;
        try shift_val.set(1);
        try shift_val.shiftLeft(&shift_val, @intCast(total_bits - 1));
        _ = try shift_val.sub(&shift_val, &one);
        _ = try ret.bitAnd(&ret, &shift_val);
        ret.negate();
    }
    return ret;
}
/// parse script num unchecked.
pub fn scriptIntParseI64(v: []const u8) i64 {
    if (v.len == 0) return 0;
    var ret: i64 = 0;
    var shift: u6 = 0;

    // Accumulate bytes with shifting
    for (v) |byte| {
        ret += @as(i64, byte) << shift;
        shift +%= 8;
    }

    // Check sign bit in last byte and adjust if negative
    if (v[v.len - 1] & 0x80 != 0) {
        const mask = (@as(i64, 1) << (shift -% 1)) -% 1;
        ret &= mask;
        ret = -ret;
    }
    return ret;
}
pub fn encodeScriptIntMininal(num: *BigInt, allocator: std.mem.Allocator) ![]u8 {
    if (num.eqlZero()) {
        // var result = try allocator.alloc(u8, 1);
        // result[0] = 0x00; // -1 in VM number format
        return &.{};
    }

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    const neg = !num.isPositive();
    num.abs();
    // defer absValue.deinit();

    while (!num.eqlZero()) {
        const byte: u8 = @truncate(num.limbs[0] & 0xFF);
        try result.append(byte);
        try num.shiftRight(num, 8);
    }

    // std.mem.reverse(u8, result.items);

    // Handle sign and high bit logic similar to C++
    if (result.getLast() & 0x80 != 0) {
        try result.append(if (neg) 0x80 else 0);
    } else if (neg) {
        result.items[result.items.len - 1] |= 0x80;
    }

    return result.toOwnedSlice();
}
pub fn readScriptBool(v: []const u8) bool {
    if (v.len == 0) return false;

    for (v, 0..) |b, i| {
        if (b != 0) {
            // Single byte negative zero case
            if (v.len == 1 and b == 0x80) {
                return false;
            }

            // Check for negative zero condition
            // If last byte is 0x80 and all previous bytes are zero
            if (i == v.len - 1 and b == 0x80 and v[0..i].len > 0) {
                for (v[0..i]) |prev_byte| {
                    if (prev_byte != 0) {
                        return true;
                    }
                }
                return false;
            }
            return true;
        }
    }
    return false;
}
pub fn readScriptIntI64(data: []const u8) !i64 {
    if (data.len == 0) return 0;
    if (data.len > 8) return error.invalid_script_int;

    const last = data[data.len - 1];
    if (last & 0x7f == 0) {
        if (data.len <= 1 or data[data.len - 2] & 0x80 == 0) {
            return error.non_minimal;
        }
    }
    return scriptIntParseI64(data);
}
pub fn isStandardMultisig(locking_bytecode: []u8) bool {
    // Use optional unwrapping to handle potential null return
    // std.debug.print("isStandardMultisigPROPS {any}\n", .{isSimpleMultisigProperties(locking_bytecode)});
    const multisigProperties = isSimpleMultisigProperties(locking_bytecode) catch return false;

    const m = multisigProperties.m;
    const n = multisigProperties.n;
    // std.debug.print("M {} N {}\n", .{ m, n });

    // Validate m and n are within acceptable ranges
    if (n < 1 or n > MAXIMUM_STANDARD_N or m < 1 or m > n) {
        return false;
    }

    return true;
}
pub const MultisigProperties = struct {
    m: u8, // Number of required signatures (first index)
    n: u8, // Total number of public keys (second to last index)
};

pub fn isSimpleMultisigProperties(script: []u8) !MultisigProperties {
    // Basic validation for minimum length and ending with OP_CHECKMULTISIG
    if (script.len < 3 or script[script.len - 1] != OP_CHECKMULTISIG) {
        return error.InvalidMultiSigProperties;
    }
    const m = pushOpcodeToNum(script[0]);
    const n = pushOpcodeToNum(script[script.len - 2]);
    // Extract m from the first index and n from the second to last index
    return MultisigProperties{ .m = @intCast(m), .n = @intCast(n) };
}
pub fn pushOpcodeToNum(opcode: u8) i32 {
    if (opcode == 0) return 0;
    if (opcode == 0x4f) return -1;
    if (std.math.isNan(opcode) or opcode < 0x51 or opcode > 0x60) return @intCast(opcode);
    return opcode - 0x50;
}
/// Checks if a script is a standard address type (P2PKH, P2PK, P2SH, P2MS)
pub fn isStandard(script: []u8, gpa: std.mem.Allocator) bool {
    // P2PKH (Pay to Public Key Hash)
    // Pattern: OP_DUP OP_HASH160 20 [20 byte pubkey hash] OP_EQUALVERIFY OP_CHECKSIG
    if (script.len == 25 and
        script[0] == OP_DUP and
        script[1] == OP_HASH160 and
        script[2] == 0x14 and
        script[23] == OP_EQUALVERIFY and
        script[24] == OP_CHECKSIG)
    {
        return true;
    }

    // P2PK (Pay to Public Key)
    // Pattern: [compressed/uncompressed pubkey] OP_CHECKSIG
    if ((script.len == 35 or script.len == 67) and
        script[script.len - 1] == OP_CHECKSIG)
    {
        return true;
    }

    // P2SH (Pay to Script Hash)
    // Legacy P2SH (160-bit)
    // Pattern: OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (script.len == 23 and
        script[0] == OP_HASH160 and
        script[1] == 0x14 and
        script[22] == OP_EQUAL)
    {
        return true;
    }
    // P2SH (Pay to Script Hash)
    // Legacy P2SH (256-bit)
    // Pattern: OP_HASH256 32 [32 byte hash] OP_EQUAL
    if (script.len == 35 and
        script[0] == OP_HASH256 and
        script[1] == 0x20 and
        script[34] == OP_EQUAL)
    {
        return true;
    }

    // P2MS (Pay to Multisig)
    // Pattern varies, but typically starts with a number (m) of required signatures
    // Then lists public keys
    // Ends with total number of keys (n) OP_CHECKMULTISIG
    // std.debug.print("isStandardMultisig {}\n", .{isStandardMultisig(script)});
    if (isStandardMultisig(script)) return true;
    // OP_RETURN (Arbitrary Data Output)
    // Must start with OP_RETURN and be push-only after that
    if (script.len >= 1 and
        script[0] == OP_RETURN and
        isPushOnly(script[1..], gpa))
    {
        return true;
    }

    return false;
}
