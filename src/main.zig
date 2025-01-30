const std = @import("std");
const Cursor = @import("encoding.zig").Cursor;
const Transaction = @import("transaction.zig").Transaction;
const ScriptExecutionContext = @import("stack.zig").ScriptExecutionContext;
const Program = @import("stack.zig").Program;
const VirtualMachine = @import("stack.zig").VirtualMachine;
const SigningCache = @import("sigser.zig").SigningCache;
const ConsensusBch2025 = @import("consensus2025.zig").ConsensusBch2025.init();

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

    // Pre-allocate and read all test files
    var test_files = std.ArrayList(struct { filename: []const u8, contents: []const u8, parsed_data: std.json.Parsed(std.json.Value) }).init(ally);
    defer {
        for (test_files.items) |*file| {
            ally.free(file.filename);
            ally.free(file.contents);
            file.parsed_data.deinit();
        }
        test_files.deinit();
    }

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

    const start_time = std.time.nanoTimestamp();
    var verify_start: i128 = 0;
    var verify_end: i128 = 0;
    var verification_count: usize = 0;
    var failed_verifications: usize = 0;
    var total_verification_time: i128 = 0;
    var end_time: i128 = 0;

    // Process all collected test files
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
                    failed_verifications += 1;
                    continue;
                };

                try tx_buff.resize(tx.len);
                const tx_slice = try std.fmt.hexToBytes(tx_buff.items, tx);

                var tx_reader = Cursor.init(tx_slice);
                const tx_decoded = Transaction.decode(&tx_reader, ally) catch |err| {
                    std.debug.print("Transaction decoding error {any}\n", .{err});
                    failed_verifications += 1;
                    continue;
                };

                var script_exec = ScriptExecutionContext{
                    .input_index = @intCast(input_index),
                    .utxo = utxos,
                    .tx = tx_decoded,
                    .signing_cache = SigningCache.init(),
                };
                var sigser_buff = [_]u8{0} ** (ConsensusBch2025.maximum_standard_transaction_size * 2);
                try script_exec.computeSigningCache(&sigser_buff);

                var program = try Program.init(ally, &script_exec);
                const unlock_code = program.context.tx.inputs[program.context.input_index].script;
                program.metrics.setScriptLimits(true, unlock_code.len);

                verify_start = std.time.microTimestamp();
                const res = VirtualMachine.verify(&program) catch |err| {
                    std.debug.print("verification err {any}", .{err});
                    failed_verifications += 1;
                    verification_count += 1;
                    std.debug.print("Metrics:\n" ++
                        "sig checks: {}\n" ++
                        "op cost: {}\n" ++
                        "hash iterations: {}\n" ++
                        "Over operation limit: {}\n" ++
                        "Over hash limit: {}\n" ++
                        "Composite op cost: {}\n", .{
                        program.metrics.sig_checks,
                        program.metrics.op_cost,
                        program.metrics.hash_digest_iterations,
                        program.metrics.isOverOpCostLimit(true),
                        program.metrics.isOverHashItersLimit(),
                        program.metrics.getCompositeOpCost(true),
                    });
                    continue;
                };
                if (!res) {
                    verification_count += 1;
                    failed_verifications += 1;
                    std.debug.print("Metrics:\n" ++
                        "sig checks: {}\n" ++
                        "op cost: {}\n" ++
                        "hash iterations: {}\n" ++
                        "Over operation limit: {}\n" ++
                        "Over hash limit: {}\n" ++
                        "Composite op cost: {}\n", .{
                        program.metrics.sig_checks,
                        program.metrics.op_cost,
                        program.metrics.hash_digest_iterations,
                        program.metrics.isOverOpCostLimit(true),
                        program.metrics.isOverHashItersLimit(),
                        program.metrics.getCompositeOpCost(true),
                    });
                    continue;
                }

                verify_end = std.time.microTimestamp();
                if (res) {
                    verification_count += 1;
                }
                end_time = std.time.nanoTimestamp();
                const verification_duration = verify_end - verify_start;
                total_verification_time += verification_duration;

                std.debug.print("Metrics:\n" ++
                    "sig checks: {}\n" ++
                    "op cost: {}\n" ++
                    "hash iterations: {}\n" ++
                    "Over operation limit: {}\n" ++
                    "Over hash limit: {}\n" ++
                    "Composite op cost: {}\n", .{
                    program.metrics.sig_checks,
                    program.metrics.op_cost,
                    program.metrics.hash_digest_iterations,
                    program.metrics.isOverOpCostLimit(true),
                    program.metrics.isOverHashItersLimit(),
                    program.metrics.getCompositeOpCost(true),
                });
            }
        }
    }
    const total_execution_time = end_time - start_time; // in nanoseconds
    const average_verification_time = if (verification_count > 0)
        @divTrunc(total_verification_time, @as(i128, @intCast(verification_count)))
    else
        0; // in microseconds

    const verification_rate = if (average_verification_time > 0)
        @divTrunc(@as(i128, 1_000_000), average_verification_time) // convert microseconds to seconds
    else
        0;

    std.debug.print("\nPerformance Statistics:\n" ++
        "Total Execution Time: {d} ns\n" ++
        "Total Verification Time: {d} us\n" ++
        "Average Verification Time: {d} us\n" ++
        "Number of Verifications: {d}\n" ++
        "Failed Verifications: {d}\n" ++
        "Verification Rate: {d} ops/sec\n", .{
        total_execution_time,
        total_verification_time,
        average_verification_time,
        verification_count,
        failed_verifications,
        verification_rate,
    });
}

// test "tracy" {
//     std.debug.print("{any}", .{tracy});
// }
