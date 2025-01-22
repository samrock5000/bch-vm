const std = @import("std");
const hash_map = std.hash_map;
const auto_hash = std.hash.autoHashStrat;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Utxo = @import("utxo.zig").Utxo;

pub fn HashSet(comptime T: type) type {
    return struct {
        const Self = @This();
        const Context = switch (T) {
            Utxo => UtxoContext,
            else => hash_map.AutoContext(T),
        };
        // Use std.HashMap as the underlying storage
        map: hash_map.HashMap(T, void, Context, hash_map.default_max_load_percentage),
        // Initialize the HashSet with a given allocator
        pub fn init(allocator: Allocator) Self {
            return Self{
                .map = hash_map.HashMap(T, void, Context, hash_map.default_max_load_percentage).init(allocator),
            };
        }

        // Deinitialize and free resources
        pub fn deinit(self: *Self) void {
            self.map.deinit();
        }

        // Insert an element into the set
        pub fn insert(self: *Self, item: T) !void {
            try self.map.put(item, {});
        }

        // Remove an element from the set
        pub fn remove(self: *Self, item: T) bool {
            return self.map.remove(item);
        }

        // Check if an element exists in the set
        pub fn contains(self: *const Self, item: T) bool {
            return self.map.contains(item);
        }

        // Get the number of elements in the set
        pub fn count(self: *const Self) usize {
            return self.map.count();
        }

        // Clear all elements from the set
        pub fn clear(self: *Self) void {
            self.map.clearRetainingCapacity();
        }

        // Iterator for the set
        pub fn iterator(self: *const Self) hash_map.HashMap(T, void, hash_map.AutoContext(T), hash_map.default_max_load_percentage).KeyIterator {
            return self.map.keyIterator();
        }
    };
}
pub const UtxoContext = struct {
    pub fn hash(self: @This(), utxo: Utxo) u64 {
        _ = self;
        var hasher = std.hash.Wyhash.init(0);
        // Hash the txid
        std.hash.autoHash(&hasher, utxo.outpoint.txid);
        // Hash the index
        std.hash.autoHash(&hasher, utxo.outpoint.index);
        // Hash the output fields if needed
        // Add any Output fields that should contribute to uniqueness
        return hasher.final();
    }

    pub fn eql(self: @This(), a: Utxo, b: Utxo) bool {
        _ = self;
        // Compare outpoint fields
        if (a.outpoint.txid != b.outpoint.txid) return false;
        if (a.outpoint.index != b.outpoint.index) return false;
        // Add additional Output field comparisons if they should contribute to equality
        return true;
    }
};

test "hashset_basic" {
    const testing_allocator = testing.allocator;

    // Create a HashSet of integers
    var set = HashSet(i32).init(testing_allocator);
    defer set.deinit();

    // Insert elements
    try set.insert(5);
    try set.insert(10);
    try set.insert(15);

    // Check count and contains
    try testing.expectEqual(@as(usize, 3), set.count());
    try testing.expect(set.contains(5));
    try testing.expect(set.contains(10));
    try testing.expect(set.contains(15));
    try testing.expect(!set.contains(20));

    // Remove an element
    try testing.expect(set.remove(10));
    try testing.expectEqual(@as(usize, 2), set.count());
    try testing.expect(!set.contains(10));

    // Clear the set
    set.clear();
    try testing.expectEqual(@as(usize, 0), set.count());
}

// Demonstrate usage with different types
test "hashset_diff" {
    // const testing_allocator = testing.allocator;

    // // HashSet of strings
    // var str_set = HashSet([]const u8).init(testing_allocator);
    // defer str_set.deinit();

    // try str_set.insert("hello");
    // try str_set.insert("world");

    // try testing.expectEqual(@as(usize, 2), str_set.count());
    // try testing.expect(str_set.contains("hello"));
}
