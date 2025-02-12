const ControlStack = @import("stack.zig").ControlStack;
const ConsensusBch2025 = @import("consensus2025.zig").ConsensusBch2025.init();
const std = @import("std");
const Encoder = @import("encoding.zig").Cursor;
const Transaction = @import("transaction.zig").Transaction;
const ScriptExecutionContext = @import("stack.zig").ScriptExecutionContext;
const SigningCache = @import("sigser.zig").SigningCache;
const Program = @import("stack.zig").Program;
const VirtualMachine = @import("stack.zig").VirtualMachine;

test "vmbstandard2025" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    const path = "bch_2025_standard";
    const base_url = try std.fmt.allocPrint(std.heap.page_allocator, "../vmb_tests/{s}", .{path});

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
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".vmb_tests.json")
        // and !std.mem.startsWith(u8, entry.name, "core.bigint-limits.unary")
        ) {
            // Allocate and copy the filename
            const filename = try ally.dupe(u8, entry.name);
            const all = filename;
            _ = &all;

            const test_match_file = std.mem.eql(u8, all, filename);
            // const test_match = std.mem.eql(u8, all, "core.push.data.vmb_tests.json");
            // Add to our list of test files
            if (test_match_file) {
                const file = try current_dir.openFile(entry.name, .{});
                const bytes_read = try file.getEndPos();

                // Read file contents
                const file_contents = try current_dir.readFileAlloc(ally, entry.name, bytes_read);

                // Parse JSON
                const parsed = try std.json.parseFromSlice(std.json.Value, ally, file_contents, .{ .allocate = .alloc_if_needed });
                try test_files.append(.{ .filename = filename, .contents = file_contents, .parsed_data = parsed });
            }
        }
    }

    const start_time = std.time.nanoTimestamp();
    var verify_start: i128 = 0;
    var verify_end: i128 = 0;
    var verification_count: usize = 0;
    var failed_verifications: usize = 0;
    var total_verification_time: i128 = 0;
    var end_time: i128 = 0;
    var max_duration: i128 = 0; // Variable to store the longest duration
    var max_duration_id = [_]u8{ 0, 0, 0, 0, 0, 0 };
    // Process all collected test files
    for (test_files.items, 0..) |*test_file, i| {
        const json_data = test_file.parsed_data.value.array.items;
        _ = i;
        var passed_count: usize = 0;
        for (json_data[0..]) |item| {
            // _ = i;
            const identifier = item.array.items[0].string;
            const description = item.array.items[1].string;
            const skip = blk: {
                // const phrases = [_][]const u8{ "authorization", "before upgrade", "benchmark" };
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
            const specific_test = "6ffhwj";
            const all = identifier;
            _ = &all;
            _ = &specific_test;
            const test_match = std.mem.eql(u8, identifier, all);
            _ = &test_match;
            // const test_match_file = std.mem.eql(u8, "core.signing-serialization.vmb_tests.json", test_file.filename);
            // _ = &test_match_file;

            if (test_match and !skip) {
                // Allocate buffers for each iteration to avoid reusing potentially modified buffers
                var tx_buff = std.ArrayList(u8).init(ally);
                defer tx_buff.deinit();

                var utxo_buff = std.ArrayList(u8).init(ally);
                defer utxo_buff.deinit();

                const tx = item.array.items[4].string;

                const input_index = if (item.array.items.len == 7) item.array.items[6].integer else 0;
                _ = &tx;
                const src_outs = item.array.items[5].string;

                try utxo_buff.resize(src_outs.len);
                const utxos_slice = try std.fmt.hexToBytes(utxo_buff.items, src_outs);

                var utxo_writer = Encoder.init(utxos_slice);

                // std.debug.print("Testing {s}nID {s}n", .{ test_file.filename, identifier });
                const utxos = Transaction.readOutputs(&utxo_writer, ally) catch |err| {
                    std.debug.print("ID {s}\n", .{identifier});
                    std.debug.print("UTXO decoding error {any}\n", .{err});
                    failed_verifications += 1;
                    continue;
                };

                try tx_buff.resize(tx.len);
                const tx_slice = try std.fmt.hexToBytes(tx_buff.items, tx);

                var tx_reader = Encoder.init(tx_slice);
                const tx_decoded = Transaction.decode(&tx_reader, ally) catch |err| {
                    std.debug.print("Transaction decoding error {any}\n", .{err});

                    failed_verifications += 1;
                    continue;
                };
                // std.debug.print("ID {s}\n", .{identifier});
                // const sig_cache = SigningContextCache.init();
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
                    _ = &err;
                    // std.debug.print("ID {s}\n", .{identifier});
                    // std.debug.print("Failed verification  {any}\n", .{err});
                    failed_verifications += 1;
                    verification_count += 1;
                    continue;
                };
                if (!res) {
                    // std.debug.print("ID {s}\n", .{identifier});
                    //     std.debug.print("Failed non truthy stack top item {any}\n", .{res});
                    verification_count += 1;
                    failed_verifications += 1;
                    continue;
                }

                verify_end = std.time.microTimestamp();
                const current_duration = verify_end - verify_start;

                // Update max_duration if the current duration is longer
                if (current_duration > max_duration) {
                    max_duration = current_duration;
                    max_duration_id = identifier[0..max_duration_id.len].*;
                }
                // std.debug.print("ID {s} Duration {} ms\n", .{ identifier, verify_end - verify_start });
                if (res) {
                    // std.debug.print("ID {s}\n", .{identifier});
                    // std.debug.print("Testing {s}\nID {s}\n", .{ test_file.filename, identifier });
                    passed_count += 1;
                    verification_count += 1;
                }
                end_time = std.time.nanoTimestamp();
                const verification_duration = verify_end - verify_start;
                total_verification_time += verification_duration;
                const test_match_single = std.mem.eql(u8, identifier, specific_test);
                if (test_match_single) {
                    std.debug.print("metrics\n" ++
                        "sig checks: {}\n" ++
                        "op cost: {}\n" ++
                        "hash iterations: {}\n" ++
                        "is over cost limit: {}\n" ++
                        "is over hash {}\n" ++
                        // "has limits {}\n" ++
                        "composite op cost: {}\n", .{
                        program.metrics.sig_checks,
                        program.metrics.op_cost,
                        program.metrics.hash_digest_iterations,
                        program.metrics.isOverOpCostLimit(true),
                        program.metrics.isOverHashItersLimit(),
                        // program.metrics.hasvalidscriptlimits(),
                        program.metrics.getCompositeOpCost(true),
                    });
                }
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

    std.debug.print("ID {s} Longest Duration {} ms\n", .{ max_duration_id, max_duration });
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

test "vmbinvalid2025" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    const path = "bch_2025_invalid";
    const base_url = try std.fmt.allocPrint(std.heap.page_allocator, "../vmb_tests/{s}", .{path});

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
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".vmb_tests.json")
        // and !std.mem.startsWith(u8, entry.name, "core.bigint-limits.unary")
        ) {
            // Allocate and copy the filename
            const filename = try ally.dupe(u8, entry.name);
            const all = filename;
            _ = &all;

            const test_match_file = std.mem.eql(u8, all, filename);
            // const test_match = std.mem.eql(u8, all, "core.push.data.vmb_tests.json");
            // Add to our list of test files
            if (test_match_file) {
                const file = try current_dir.openFile(entry.name, .{});
                const bytes_read = try file.getEndPos();

                // Read file contents
                const file_contents = try current_dir.readFileAlloc(ally, entry.name, bytes_read);

                // Parse JSON
                const parsed = try std.json.parseFromSlice(std.json.Value, ally, file_contents, .{ .allocate = .alloc_if_needed });
                try test_files.append(.{ .filename = filename, .contents = file_contents, .parsed_data = parsed });
            }
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
    for (test_files.items, 0..) |*test_file, i| {
        const json_data = test_file.parsed_data.value.array.items;
        _ = i;
        var passed_count: usize = 0;
        for (json_data[0..]) |item| {
            // _ = i;
            const identifier = item.array.items[0].string;
            const description = item.array.items[1].string;
            const skip = blk: {
                // const phrases = [_][]const u8{ "authorization", "before upgrade", "benchmark" };
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
            const specific_test = "6ffhwj";
            const all = identifier;
            _ = &all;
            _ = &specific_test;
            const test_match = std.mem.eql(u8, identifier, all);
            _ = &test_match;
            // const test_match_file = std.mem.eql(u8, "core.cashtokens.vmb_tests.json", test_file.filename);
            const test_match_file = std.mem.eql(u8, "core.signing-serialization.vmb_tests.json", test_file.filename);
            _ = &test_match_file;

            if (test_match and !skip) {
                // Allocate buffers for each iteration to avoid reusing potentially modified buffers
                var tx_buff = std.ArrayList(u8).init(ally);
                defer tx_buff.deinit();

                var utxo_buff = std.ArrayList(u8).init(ally);
                defer utxo_buff.deinit();

                const tx = item.array.items[4].string;

                const input_index = if (item.array.items.len == 7) item.array.items[6].integer else 0;
                _ = &tx;
                const src_outs = item.array.items[5].string;

                try utxo_buff.resize(src_outs.len);
                const utxos_slice = try std.fmt.hexToBytes(utxo_buff.items, src_outs);

                var utxo_writer = Encoder.init(utxos_slice);

                // std.debug.print("Testing {s}nID {s}n", .{ test_file.filename, identifier });
                const utxos = Transaction.readOutputs(&utxo_writer, ally) catch |err| {
                    std.debug.print("ID {s}\n", .{identifier});
                    std.debug.print("UTXO decoding error {any}\n", .{err});
                    failed_verifications += 1;
                    continue;
                };

                try tx_buff.resize(tx.len);
                const tx_slice = try std.fmt.hexToBytes(tx_buff.items, tx);

                var tx_reader = Encoder.init(tx_slice);
                const tx_decoded = Transaction.decode(&tx_reader, ally) catch |err| {
                    std.debug.print("Transaction decoding error {any}\n", .{err});

                    failed_verifications += 1;
                    continue;
                };
                // std.debug.print("ID {s}\n", .{identifier});
                // const sig_cache = SigningContextCache.init();
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
                    _ = &err;
                    // std.debug.print("ID {s}\n", .{identifier});
                    // std.debug.print("Failed verification  {any}\n", .{err});
                    failed_verifications += 1;
                    verification_count += 1;
                    continue;
                };
                if (!res) {
                    // std.debug.print("ID {s}\n", .{identifier});
                    //     std.debug.print("Failed non truthy stack top item {any}\n", .{res});
                    verification_count += 1;
                    failed_verifications += 1;
                    continue;
                }

                verify_end = std.time.microTimestamp();
                if (res) {
                    // std.debug.print("ID {s}\n", .{identifier});
                    // std.debug.print("Testing {s}\nID {s}\n", .{ test_file.filename, identifier });
                    passed_count += 1;
                    verification_count += 1;
                }
                end_time = std.time.nanoTimestamp();
                const verification_duration = verify_end - verify_start;
                total_verification_time += verification_duration;
                const test_match_single = std.mem.eql(u8, identifier, specific_test);
                if (test_match_single) {
                    std.debug.print("metrics\n" ++
                        "sig checks: {}\n" ++
                        "op cost: {}\n" ++
                        "hash iterations: {}\n" ++
                        "is over cost limit: {}\n" ++
                        "is over hash {}\n" ++
                        // "has limits {}\n" ++
                        "composite op cost: {}\n", .{
                        program.metrics.sig_checks,
                        program.metrics.op_cost,
                        program.metrics.hash_digest_iterations,
                        program.metrics.isOverOpCostLimit(true),
                        program.metrics.isOverHashItersLimit(),
                        // program.metrics.hasvalidscriptlimits(),
                        program.metrics.getCompositeOpCost(true),
                    });
                }
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
test "soa" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const ally = arena.allocator();
    const DefaultPrng = std.Random.DefaultPrng;
    var seed: u64 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&seed));
    var prng = DefaultPrng.init(seed);
    const randUtxo = @import("utxo.zig").generateRandomUtxos;
    const randUtxoMulti = @import("utxo.zig").generateRandUtxosMulti;

    var timer2 = try std.time.Timer.start();
    _ = try randUtxoMulti(ally, 100_000 * 2, prng.random());
    const time2 = timer2.read();
    std.debug.print("Time 2 {any}\n", .{time2});

    var timer = try std.time.Timer.start();
    _ = try randUtxo(ally, 100_000 * 2, prng.random());
    const time1 = timer.read();
    std.debug.print("Time 1 {any}\n", .{time1});
    timer.reset();

    // var multi_all = std.MultiArrayList(@import("utxo.zig").Utxo){};

    // for (utxos.items) |t| {
    //     try multi_all.append(ally, t);
    // }
    // const sliced = multi_all.slice();
    // const outpoints = sliced.items(.outpoint);
    // for (outpoints) |o| {
    //     std.debug.print("out {any}\n", .{o});
    // }
}
