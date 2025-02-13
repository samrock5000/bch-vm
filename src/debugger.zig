pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    // Parse command-line arguments
    const args = try std.process.argsAlloc(ally);
    defer std.process.argsFree(ally, args);

    if (args.len < 3) {
        std.debug.print("Usage: {s} <identifier> <path>\n", .{args[0]});
        return;
    }

    const specific_test = args[1];
    const path = args[2];

    const base_url = try std.fmt.allocPrint(ally, "./{s}", .{path});
    defer ally.free(base_url);

    var current_dir = try std.fs.cwd().openDir(base_url, .{ .iterate = true });
    defer current_dir.close();
    var test_files = std.ArrayList(struct {
        filename: []const u8,
        contents: []const u8,
        parsed_data: std.json.Parsed(std.json.Value),
    }).init(ally);

    // Collect all test files first
    var dir_iterator = current_dir.iterate();
    while (try dir_iterator.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".vmb_tests.json")) {
            const filename = try ally.dupe(u8, entry.name);
            const file = try current_dir.openFile(entry.name, .{});
            const bytes_read = try file.getEndPos();
            const file_contents = try current_dir.readFileAlloc(ally, entry.name, bytes_read);
            const parsed = try std.json.parseFromSlice(std.json.Value, ally, file_contents, .{ .allocate = .alloc_if_needed });
            try test_files.append(.{ .filename = filename, .contents = file_contents, .parsed_data = parsed });
        }
    }
    for (test_files.items) |*test_file| {
        const json_data = test_file.parsed_data.value.array.items;

        //     std.debug.print("Warm-up phase complete.\n\n", .{});
        for (json_data) |item| {
            const identifier = item.array.items[0].string;
            const description = item.array.items[1].string;
            const skip = blk: {
                const phrases = [_][]const u8{ "authorization", "before upgrade" };
                for (phrases) |phrase| {
                    var it = std.mem.window(u8, description, phrase.len, 1);
                    while (it.next()) |slice| {
                        if (std.mem.eql(u8, slice, phrase)) {
                            break :blk true;
                        }
                    }
                }
                break :blk false;
            };

            if (std.mem.eql(u8, identifier, specific_test) and !skip) {
                // Warm-up phase
                var tx_buff = std.ArrayList(u8).init(ally);
                defer tx_buff.deinit();

                var utxo_buff = std.ArrayList(u8).init(ally);
                defer utxo_buff.deinit();

                const tx = item.array.items[4].string;
                const input_index = if (item.array.items.len == 7) item.array.items[6].integer else 0;
                const src_outs = item.array.items[5].string;

                try utxo_buff.resize(src_outs.len);
                const utxos_slice = try std.fmt.hexToBytes(utxo_buff.items, src_outs);

                var utxo_writer = Cursor.init(utxos_slice);

                const utxos = Transaction.readOutputs(&utxo_writer, ally) catch |err| {
                    std.debug.print("ID {s}\n", .{identifier});
                    std.debug.print("UTXO decoding error {any}\n", .{err});
                    continue;
                };

                try tx_buff.resize(tx.len);
                const tx_slice = try std.fmt.hexToBytes(tx_buff.items, tx);

                var tx_reader = Cursor.init(tx_slice);
                const tx_decoded = Transaction.decode(&tx_reader, ally) catch |err| {
                    std.debug.print("Transaction decoding error {any}\n", .{err});
                    continue;
                };

                var script_exec = ScriptExecutionContext{
                    .input_index = @intCast(input_index),
                    .utxo = utxos,
                    .tx = tx_decoded,
                    .signing_cache = SigningCache.init(),
                };
                var sigser_buff = [_]u8{0} ** (ConsensusBch2026.maximum_standard_transaction_size * 2);
                try script_exec.computeSigningCache(&sigser_buff);

                var program = try Program.init(ally, &script_exec);
                const unlock_code = program.context.tx.inputs[program.context.input_index].script;
                program.metrics.setScriptLimits(true, unlock_code.len);
                const res = try VirtualMachine.verify(&program);
                std.debug.print("Verification: {}\n", .{res});
            }
        }
    }
}
const std = @import("std");
const Cursor = @import("encoding.zig").Cursor;
const Transaction = @import("transaction.zig").Transaction;
const ScriptExecutionContext = @import("stack.zig").ScriptExecutionContext;
const Program = @import("stack.zig").Program;
const VirtualMachine = @import("stack.zig").VirtualMachine;
const SigningCache = @import("sigser.zig").SigningCache;
const ConsensusBch2026 = @import("consensus2026.zig").ConsensusBch2026.init();
