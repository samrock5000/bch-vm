const std = @import("std");

pub const Cursor = @This();
fbs: std.io.FixedBufferStream([]u8),

pub fn init(data: []u8) Cursor {
    return .{
        .fbs = std.io.fixedBufferStream(data),
    };
}

/// Reads a variable-length integer from a Reader
pub fn readCompactUint(r: *Cursor) !usize {
    var reader = r.fbs.reader();
    const first_byte = try reader.readInt(u8, .little);
    return switch (first_byte) {
        else => @intCast(first_byte),
        0xfd => @intCast(try reader.readInt(u16, .little)),
        0xfe => @intCast(try reader.readInt(u32, .little)),
        0xff => @intCast(try reader.readInt(u64, .little)),
    };
}

/// Reads variable-length bytes from a Reader
pub fn readCompactBytes(reader: *Cursor) ![]u8 {
    const len = try readCompactUint(reader);
    const buffer = reader.fbs.buffer[reader.fbs.pos..];
    if (len > buffer.len) {
        return error.EndOfStream;
    }
    _ = try reader.fbs.seekBy(@intCast(len));

    return buffer[0..len];
}

/// Writes a variable-length integer to a Writer
pub fn writeVarint(encoder: anytype, value: u64) !usize {
    if (value < 0xfd) {
        try encoder.writeInt(u8, @intCast(value), .little);
        return 1;
    } else if (value <= 0xffff) {
        try encoder.writeByte(0xfd);
        try encoder.writeInt(u16, @intCast(value), .little);
        return 3;
    } else if (value < 0xffffff) {
        try encoder.writeByte(0xfe);
        try encoder.writeInt(u32, @intCast(value), .little);
        return 5;
    } else {
        try encoder.writeByte(0xff);
        try encoder.writeInt(u64, value, .little);
        return 9;
    }
}
/// Writes variable-length bytes to a Writer
pub fn writeVarBytes(writer: anytype, bytes: []const u8) !usize {
    var len: usize = 0;
    len += try writeVarint(writer, bytes.len);
    len += try writer.write(bytes);
    return len;
}
