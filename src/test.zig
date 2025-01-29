const ControlStack = @import("stack.zig").ControlStack;
const std = @import("std");

test "constrolstack  basic" {
    var stack = ControlStack.init();

    // Test initial state
    try std.testing.expect(stack.empty());
    try std.testing.expect(stack.allTrue());

    // Push true values
    stack.push(true);
    stack.push(true);
    stack.push(true);

    // Test after pushing true values
    try std.testing.expect(!stack.empty());
    try std.testing.expect(stack.allTrue());

    // Push a false value
    stack.push(false);

    // Test after pushing a false value
    try std.testing.expect(!stack.empty());
    try std.testing.expect(!stack.allTrue());

    // Toggle the top (false -> true)
    stack.toggleTop();

    // Test after toggling the top
    try std.testing.expect(!stack.empty());
    try std.testing.expect(stack.allTrue());

    // Toggle the top again (true -> false)
    stack.toggleTop();

    // Test after toggling the top again
    try std.testing.expect(!stack.empty());
    try std.testing.expect(!stack.allTrue());

    // Pop the top (false)
    stack.pop();

    // Test after popping the top
    try std.testing.expect(!stack.empty());
    try std.testing.expect(stack.allTrue());

    // Pop remaining true values
    stack.pop();
    stack.pop();
    stack.pop();

    // Test after popping all values
    try std.testing.expect(stack.empty());
    try std.testing.expect(stack.allTrue());
}

test "constrolstack edge" {
    var stack = ControlStack.init();

    // Test toggling an empty stack (should do nothing)
    stack.toggleTop();
    try std.testing.expect(stack.empty());
    try std.testing.expect(stack.allTrue());

    // Test popping an empty stack (should not crash)
    stack.pop();
    try std.testing.expect(stack.empty());
    try std.testing.expect(stack.allTrue());

    // Push and toggle a single value
    stack.push(false);
    stack.toggleTop();
    try std.testing.expect(!stack.empty());
    try std.testing.expect(stack.allTrue());

    // Toggle again and pop
    stack.toggleTop();
    stack.pop();
    try std.testing.expect(stack.empty());
    try std.testing.expect(stack.allTrue());
}
test {
    var stack = ControlStack.init();
    for (0..1000) |i| {
        if (i == 999) {
            stack.push(false);
        }
    }
    // stack.toggleTop();
    // std.debug.print("STACK {}\n", .{stack.allTrue()});
    // stack.toggleTop();
    // std.debug.print("STACK {}\n", .{stack.allTrue()});
}
