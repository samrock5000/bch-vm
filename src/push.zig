const std = @import("std");
const Allocator = std.mem.Allocator;
const OpCodes = @import("opcodes.zig").Opcodes;
pub const PushOperationConstants = struct {
    pub const maximumPushByteOperationSize: u32 = 75;
    pub const maximumPushData1Size: u32 = 255;
    pub const maximumPushData2Size: u32 = 65535;
    pub const pushNumberOpcodes: u8 = 16;
    pub const pushNumberOpcodesOffset: u8 = 0x50;
    pub const negativeOne: u8 = 0x81;
    pub const maximumPushData4Size = 4294967295;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const OP_PUSHDATA_1: u8 = 0x4c;
    pub const OP_PUSHDATA_2: u8 = 0x4d;
    pub const OP_PUSHDATA_4: u8 = 0x4e;
    pub const OP_0 = 0;
};
pub fn isPushOnly(code: []u8, allocator: std.mem.Allocator) bool {
    var i: usize = 0;
    while (i < code.len) {
        const res = readPushData(code[i..], allocator) catch return false;
        i += res.bytes_read;

        // If we encounter anything that isn't a push operation, return false
        if (res.bytes_read == 0) return false;
    }

    // If we've processed the entire script without finding non-push operations, return true
    return true;
}

/// Converts a number to a little-endian 16-bit unsigned integer byte sequence
fn numberToBinUint16LE(number: u16) [2]u8 {
    return .{
        @truncate(number & 0xFF),
        @truncate((number >> 8) & 0xFF),
    };
}

/// Converts a number to a little-endian 32-bit unsigned integer byte sequence
fn numberToBinUint32LE(number: u32) [4]u8 {
    return .{
        @truncate(number & 0xFF),
        @truncate((number >> 8) & 0xFF),
        @truncate((number >> 16) & 0xFF),
        @truncate((number >> 24) & 0xFF),
    };
}

/// Returns the minimal bytecode required to push the provided data to the stack.
///
/// This function conservatively encodes a slice of bytes as a data push. For VM
/// Numbers that can be pushed using a single opcode (-1 through 16), the
/// equivalent bytecode value is returned. Other data values will be prefixed
/// with the proper opcode and push length bytes (if necessary) to create the
/// minimal push instruction.
pub fn encodeDataPush(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const len = data.len;

    // Handle cases based on data length
    if (len <= PushOperationConstants.maximumPushByteOperationSize) {
        if (len == 0) {
            // Empty data case
            var result = try allocator.alloc(u8, 1);
            result[0] = 0;
            return result;
        } else if (len == 1) {
            // Single byte cases
            const value = data[0];
            if (value != 0 and value <= PushOperationConstants.pushNumberOpcodes) {
                var result = try allocator.alloc(u8, 1);
                result[0] = value + PushOperationConstants.pushNumberOpcodesOffset;
                return result;
            } else if (value == PushOperationConstants.negativeOne) {
                var result = try allocator.alloc(u8, 1);
                result[0] = PushOperationConstants.OP_1NEGATE;
                return result;
            } else {
                // Regular single byte push
                var result = try allocator.alloc(u8, 2);
                result[0] = 1;
                result[1] = value;
                return result;
            }
        } else {
            // Small data push
            var result = try allocator.alloc(u8, len + 1);
            result[0] = @truncate(len);
            @memcpy(result[1..], data);
            return result;
        }
    } else if (len <= PushOperationConstants.maximumPushData1Size) {
        // PUSHDATA1 case
        var result = try allocator.alloc(u8, len + 2);
        result[0] = PushOperationConstants.OP_PUSHDATA_1;
        result[1] = @truncate(len);
        @memcpy(result[2..], data);
        return result;
    } else if (len <= PushOperationConstants.maximumPushData2Size) {
        // PUSHDATA2 case
        var result = try allocator.alloc(u8, len + 3);
        result[0] = PushOperationConstants.OP_PUSHDATA_2;
        const lenBytes = numberToBinUint16LE(@truncate(len));
        @memcpy(result[1..3], &lenBytes);
        @memcpy(result[3..], data);
        return result;
    } else {
        // PUSHDATA4 case
        var result = try allocator.alloc(u8, len + 5);
        result[0] = PushOperationConstants.OP_PUSHDATA_4;
        const lenBytes = numberToBinUint32LE(@truncate(len));
        @memcpy(result[1..5], &lenBytes);
        @memcpy(result[5..], data);
        return result;
    }
}

// Test function to demonstrate usage
test "encodeDataPush" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test empty push
    {
        const result = try encodeDataPush(allocator, &[_]u8{});
        defer allocator.free(result);
        try testing.expectEqualSlices(u8, &[_]u8{0}, result);
    }

    // Test single byte number push
    {
        const result = try encodeDataPush(allocator, &[_]u8{1});
        defer allocator.free(result);
        try testing.expectEqualSlices(u8, &[_]u8{0x51}, result);
    }

    // Test negative one push
    {
        const result = try encodeDataPush(allocator, &[_]u8{0x81});
        defer allocator.free(result);
        try testing.expectEqualSlices(u8, &[_]u8{0x4f}, result);
    }

    // Test regular small push
    {
        const data = &[_]u8{ 0x11, 0x22, 0x33 };
        const result = try encodeDataPush(allocator, data);
        defer allocator.free(result);
        const expected = &[_]u8{ 3, 0x11, 0x22, 0x33 };
        try testing.expectEqualSlices(u8, expected, result);
    }
}

pub const PushError = error{
    InvalidPushOperation,
    InvalidLength,
    InsufficientData,
    InvalidPushOpcode,
};

pub const PushResult = struct {
    data: []u8,
    bytes_read: u32,
};

/// Reads a push operation from the input data and returns the pushed data along with
/// the number of bytes read. Handles all standard Bitcoin push operations including
/// OP_0 through OP_16, OP_1NEGATE, and PUSHDATA operations.
///
/// The caller owns the returned data and must free it.
pub fn readPushData(data: []const u8, alloc: Allocator) !PushResult {
    if (data.len == 0) return PushError.InsufficientData;
    const opcode = data[0];
    // Handle OP_0
    if (opcode == 0x00) {
        const result = &.{};
        return PushResult{ .data = result, .bytes_read = 1 };
    }

    // Handle OP_1NEGATE
    if (opcode == 0x4f) {
        var result = try alloc.alloc(u8, 1);
        result[0] = 0x81; // -1 in VM number format
        return PushResult{ .data = result, .bytes_read = 1 };
    }

    // Handle OP_1 through OP_16
    if (opcode >= 0x51 and opcode <= 0x60) {
        var result = try alloc.alloc(u8, 1);
        result[0] = opcode - 0x50;
        return PushResult{ .data = result, .bytes_read = 1 };
    }

    // Handle direct small pushes (0x01-0x4b)
    if (opcode <= 0x4b) {
        const length = opcode;
        if (data.len < length + 1) return PushError.InsufficientData;
        const result = try alloc.alloc(u8, length);
        @memcpy(result, data[1 .. length + 1]);
        // if (result.len == 1 and result[0] == 0) {
        //     return PushResult{ .data = &.{}, .bytes_read = length + 1 };
        // }
        return PushResult{ .data = result, .bytes_read = length + 1 };
    }
    // Handle PUSHDATA1
    if (opcode == 0x4c) {
        if (data.len < 2) return PushError.InsufficientData;
        const length: u16 = data[1];

        // Check for potential overflow and ensure sufficient data
        if (length > data.len - 2) return PushError.InsufficientData;

        const result = try alloc.alloc(u8, length);

        // Safely copy the data using a range that won't overflow
        @memcpy(result, data[2..][0..length]);

        return PushResult{ .data = result, .bytes_read = length + 2 };
    }
    // Handle PUSHDATA2
    if (opcode == 0x4d) {
        if (data.len < 3) return PushError.InsufficientData;
        const length = @as(usize, data[1]) | (@as(usize, data[2]) << 8);
        if (data.len < length + 3) return PushError.InsufficientData;

        const result = try alloc.alloc(u8, length);
        @memcpy(result, data[3 .. length + 3]);
        return PushResult{ .data = result, .bytes_read = @intCast(length + 3) };
    }

    // Handle PUSHDATA4
    if (opcode == 0x4e) {
        if (data.len < 5) return PushError.InsufficientData;
        const length = @as(usize, data[1]) |
            (@as(u32, data[2]) << 8) |
            (@as(u32, data[3]) << 16) |
            (@as(u32, data[4]) << 24);
        if (data.len < length + 5) return PushError.InsufficientData;

        const result = try alloc.alloc(u8, length);
        @memcpy(result, data[5 .. length + 5]);
        return PushResult{ .data = result, .bytes_read = @as(u32, @intCast(length + 5)) };
    }

    return PushError.InvalidPushOpcode;
}

test "readPushData" {
    const testing = std.testing;
    const alloc = testing.allocator;

    // Test OP_0
    {
        const input = &[_]u8{0x00};
        const result = try readPushData(input, alloc);
        defer alloc.free(result.data);
        try testing.expectEqual(@as(usize, 0), result.data.len);
        try testing.expectEqual(@as(usize, 1), result.bytes_read);
    }

    // Test OP_1NEGATE
    {
        const input = &[_]u8{0x4f};
        const result = try readPushData(input, alloc);
        defer alloc.free(result.data);
        try testing.expectEqualSlices(u8, &[_]u8{0x81}, result.data);
        try testing.expectEqual(@as(usize, 1), result.bytes_read);
    }

    // Test OP_1 through OP_16
    {
        const input = &[_]u8{0x51}; // OP_1
        const result = try readPushData(input, alloc);
        defer alloc.free(result.data);
        try testing.expectEqualSlices(u8, &[_]u8{1}, result.data);
        try testing.expectEqual(@as(usize, 1), result.bytes_read);
    }

    // Test direct small push
    {
        const input = &[_]u8{ 0x03, 0x11, 0x22, 0x33 };
        const result = try readPushData(input, alloc);
        defer alloc.free(result.data);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33 }, result.data);
        try testing.expectEqual(@as(usize, 4), result.bytes_read);
    }

    // Test PUSHDATA1
    {
        const input = &[_]u8{ 0x4c, 0x03, 0x11, 0x22, 0x33 };
        const result = try readPushData(input, alloc);
        defer alloc.free(result.data);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33 }, result.data);
        try testing.expectEqual(@as(usize, 5), result.bytes_read);
    }

    // Test PUSHDATA2
    {
        const input = &[_]u8{ 0x4d, 0x03, 0x00, 0x11, 0x22, 0x33 };
        const result = try readPushData(input, alloc);
        defer alloc.free(result.data);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33 }, result.data);
        try testing.expectEqual(@as(usize, 6), result.bytes_read);
    }

    // Test error cases
    {
        // Test insufficient data
        try testing.expectError(PushError.InsufficientData, readPushData(&[_]u8{0x01}, alloc));

        // Test invalid opcode
        try testing.expectError(PushError.InvalidPushOpcode, readPushData(&[_]u8{0xff}, alloc));
    }
}

/// Determines if the data push is minimal according to Bitcoin script rules
pub fn isMinimalDataPush(opcode: u8, data: []const u8) bool {
    if (data.len == 0) {
        return opcode == PushOperationConstants.OP_0;
    }

    if (data.len == 1) {
        const byte = data[0];
        if (byte >= 1 and byte <= PushOperationConstants.pushNumberOpcodes) {
            return opcode == byte + PushOperationConstants.pushNumberOpcodesOffset;
        }
        if (byte == PushOperationConstants.negativeOne) {
            return opcode == PushOperationConstants.OP_1NEGATE;
        }
    }

    if (data.len <= PushOperationConstants.maximumPushByteOperationSize) {
        return opcode == data.len;
    }

    if (data.len <= PushOperationConstants.maximumPushData1Size) {
        return opcode == PushOperationConstants.OP_PUSHDATA_1;
    }

    if (data.len <= PushOperationConstants.maximumPushData2Size) {
        return opcode == PushOperationConstants.OP_PUSHDATA_2;
    }

    if (data.len <= PushOperationConstants.maximumPushData4Size) {
        return opcode == PushOperationConstants.OP_PUSHDATA_4;
    }

    return false;
}

test "checkminimal" {
    // Example test cases
    try std.testing.expect(isMinimalDataPush(0x00, &[_]u8{}) == true);
    try std.testing.expect(isMinimalDataPush(0x51, &[_]u8{0x01}) == true);
    try std.testing.expect(isMinimalDataPush(0x4c, &[_]u8{ 0x01, 0x02 }) == false);
    try std.testing.expect(isMinimalDataPush(0x4c, &[_]u8{0} ** 255) == true);
}
