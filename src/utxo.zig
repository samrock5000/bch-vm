const std = @import("std");
const Output = @import("transaction.zig").Output;
const Input = @import("transaction.zig").Input;
const writeVarBytes = @import("encoding.zig").writeVarBytes;
const crypto = std.crypto;
const ArrayList = std.ArrayList;
const HashSet = @import("hashset.zig").HashSet;
const MaxMoney = @import("consensus2025.zig").MAX_MONEY;

pub const Outpoint = struct {
    txid: u256,
    index: u32,
};
pub const Utxo = struct {
    outpoint: Outpoint,
    output: Output,
};
pub const CandidateUtxo = struct {
    unlocking_bytecode_length: u64,
    utxo: Utxo,
};

pub const CoinSelectionResult = struct {
    selected: []Utxo,
    fee_amount: u64,
    excess: Excess,
    pub fn init() CoinSelectionResult {
        return .{
            .selected = undefined,
            .fee_amount = 0,
            .excess = undefined,
        };
    }
};
const Excess = union(enum) {
    /// It's not possible to create spendable output from excess using the current drain output
    NoChange: struct {
        /// Threshold to consider amount as dust for this particular change script_pubkey
        dust_threshold: u64,
        /// Exceeding amount of current selection over outgoing value and fee costs
        remaining_amount: u64,
        /// The calculated fee for the drain TxOut with the selected script_pubkey
        change_fee: u64,
    },
    /// It's possible to create spendable output from excess using the current drain output
    Change: struct {
        /// Effective amount available to create change after deducting the change output fee
        amount: u64,
        /// The deducted change output fee
        fee: u64,
    },
};
pub const OutputGroup = struct {
    weighted_utxo: []CandidateUtxo,
    // fee: u64,
    effective_value: i64,
    pub fn init(
        utxos: []CandidateUtxo,
        fee_rate: i64,
    ) OutputGroup {
        var effective_value: i64 = 0;
        const base_input_weight = 40; //txid :u256 + index:u32 + sequence:u32
        for (utxos) |x| {
            const input_weight = @as(i64, @intCast(x.unlocking_bytecode_length)) - base_input_weight;
            const fee = fee_rate * input_weight;
            effective_value =
                @as(i64, @intCast(x.utxo.output.satoshis)) -
                @as(i64, @intCast(fee));
        }

        return OutputGroup{
            .weighted_utxo = utxos,
            // .fee = fee,
            .effective_value = effective_value,
        };
    }
};
pub fn coinSelect(
    allocator: std.mem.Allocator,
    required_utxos: []CandidateUtxo,
    optional_utxos: []CandidateUtxo,
    fee_rate: u64,
    target_amount: u64,
    drain_script: []const u8,
) !CoinSelectionResult {
    var required_output_group = ArrayList(OutputGroup).init(allocator);
    var optional_output_group = ArrayList(OutputGroup).init(allocator);
    defer {
        required_output_group.deinit();
        optional_output_group.deinit();
    }
    for (required_utxos) |weighted_utxo| {
        const og = OutputGroup.init(weighted_utxo, 1);
        try required_output_group.append(og);
    }
    for (optional_utxos) |weighted_utxo| {
        const og = OutputGroup.init(weighted_utxo, 1);
        if (og.effective_value > 0) {
            try optional_output_group.append(og);
        }
    }
    const curr_value = blk: {
        var sum: i64 = 0;
        for (required_output_group.items) |utxos| {
            sum += utxos.effective_value;
        }
        break :blk sum;
    };
    const curr_available_value = blk: {
        var sum: i64 = 0;
        for (optional_output_group.items) |utxos| {
            sum += utxos.effective_value;
        }
        break :blk sum;
    };
    //ASSUME OUTPUT SIZE OF P2PKH FOR NOW
    // const cost_of_change: u64 = 25 * fee_rate;

    //TODO check valid total_value
    const total_value = curr_value; //+ curr_available_value;
    if (total_value >= target_amount) {} else {
        var total_fees: u64 = 0;
        var total_value_err: u64 = 0;

        // Process required output groups
        for (required_output_group.items) |og| {
            total_fees += og.fee;
            total_value_err += og.weighted_utxo.utxo.output.satoshis;
        }

        // Process optional output groups
        for (optional_output_group.items) |og| {
            total_fees += og.fee;
            total_value_err += og.weighted_utxo.utxo.output.satoshis;
        }

        //TODO Handle
        // return InsufficientFunds{
        //     .needed = target_amount + total_fees,
        //     .available = total_value_err,
        // };
    }
    const signed_target_amount = target_amount;
    if (curr_value > signed_target_amount) {
        const remaining_amount: u64 = @intCast(@abs(curr_value) - signed_target_amount);

        const excess = decideChange(remaining_amount, fee_rate, drain_script);
        var empty_selection: [0]OutputGroup = undefined;
        return calculateCoinSelectionResult(
            allocator,
            &empty_selection,
            required_output_group.items,
            excess,
        );
    }
    const res = bnb(
        allocator,
        required_output_group.items,
        optional_output_group.items,
        curr_value,
        curr_available_value,
        @as(i64, @intCast(target_amount)),
        40,
        drain_script,
        fee_rate,
    );
    std.debug.print("BNB {any}", .{res});
    return error.SelectFail;
}
const TOTAL_TRIES = 100000;

// pub fn coinSelectBnB(
//     allocator: std.mem.Allocator,
//         target: u64,
//     cost_of_change:u64,
//     fee_rate: u64,
//     long_term_fee_rate: u64,
//     weighted_utxos: []Utxo,
// ) void {
//     out_set.clear();
//     var curr_value = 0;
//     var curr_selection = ArrayList(bool).init(allocator);
//     var best_selection = ArrayList(bool).init(allocator);
//     try curr_selection.resize(utxo_pool.len);
//     const actual_target = non_input_fees + target_value;

//     var curr_available_value = 0;
//     for (utxo_pool) |utxo| {
//         std.debug.assert(utxo.effective_value > 0);
//         curr_available_value += utxo.effective_value;
//     }
//     if (curr_available_value < actual_target) {
//         return false;
//     }
//     std.sort.heap(OutputGroup, utxo_pool, {}, struct {
//         fn lessThan(_: void, a: OutputGroup, b: OutputGroup) bool {
//             return b.effective_value < a.effective_value;
//         }
//     }.lessThan);
//     var curr_waste = 0;
//     const best_waste = MaxMoney;
//     for (0..TOTAL_TRIES) |i| {
//         var backtrack = false;
//         if (curr_value + curr_available_value <
//         actual_target or
//         curr_value > actual_target + cost_of_change or
//         (curr_waste > best_waste and (utxo_pool[0].fee - utxo[0]))

//     )
//     }
// }
pub fn bnb(
    allocator: std.mem.Allocator,
    required_utxos: []OutputGroup,
    optional_utxos: []OutputGroup,
    curr_value: i64,
    curr_available_value: i64,
    target_amount: i64,
    cost_of_change: i64,
    drain_script: []const u8,
    fee_rate: u64,
) !CoinSelectionResult {
    const BNB_TOTAL_TRIES = 100000;
    var current_selection = std.ArrayList(bool).init(allocator);
    defer current_selection.deinit();

    // Sort optional_utxos by effective_value in descending order
    // std.sort.
    std.sort.heap(OutputGroup, optional_utxos, {}, struct {
        fn lessThan(_: void, a: OutputGroup, b: OutputGroup) bool {
            return b.effective_value < a.effective_value;
        }
    }.lessThan);

    var best_selection = std.ArrayList(bool).init(allocator);
    defer best_selection.deinit();

    var best_selection_value: ?i64 = null;
    var curr_value_mut = curr_value;
    var curr_available_value_mut = curr_available_value;

    // Depth First search loop
    var tries: usize = 0;
    while (tries < BNB_TOTAL_TRIES) : (tries += 1) {
        var backtrack = false;

        if (curr_value_mut + curr_available_value_mut < target_amount or
            curr_value_mut > target_amount + cost_of_change)
        {
            backtrack = true;
        } else if (curr_value_mut >= target_amount) {
            backtrack = true;

            if (best_selection_value == null or curr_value_mut < best_selection_value.?) {
                best_selection.clearRetainingCapacity();
                try best_selection.appendSlice(current_selection.items);
                best_selection_value = curr_value_mut;
            }

            if (curr_value_mut == target_amount) {
                break;
            }
        }

        if (backtrack) {
            // Walk backwards
            while (current_selection.items.len > 0 and
                !current_selection.items[current_selection.items.len - 1])
            {
                current_selection.shrinkRetainingCapacity(current_selection.items.len - 1);
                curr_available_value_mut += optional_utxos[current_selection.items.len].effective_value;
            }

            if (current_selection.items.len == 0) {
                if (best_selection.items.len == 0) {
                    return error.NoExactMatch;
                }
                break;
            }

            // Change last selection from true to false
            current_selection.items[current_selection.items.len - 1] = false;
            curr_value_mut -= optional_utxos[current_selection.items.len - 1].effective_value;
        } else {
            // Moving forwards
            const utxo = optional_utxos[current_selection.items.len];
            curr_available_value_mut -= utxo.effective_value;

            try current_selection.append(true);
            curr_value_mut += utxo.effective_value;
        }
    }
    if (best_selection.items.len == 0) {
        return error.TotalTriesExceeded;
    }

    // Build selected UTXOs
    var selected = std.ArrayList(OutputGroup).init(allocator);
    defer selected.deinit();

    for (optional_utxos, 0..) |utxo, i| {
        if (i >= best_selection.items.len) break;
        if (best_selection.items[i]) {
            try selected.append(utxo);
        }
    }

    const selected_amount = best_selection_value.?;
    const remaining_amount: u64 = @intCast(selected_amount - target_amount);

    const excess = decideChange(remaining_amount, fee_rate, drain_script);
    return calculateCoinSelectionResult(allocator, selected.items, required_utxos, excess);
}

pub fn calculateCoinSelectionResult(
    allocator: std.mem.Allocator,
    selected_utxos: []OutputGroup,
    required_utxos: []OutputGroup,
    excess: Excess,
) !CoinSelectionResult {
    var coin_selection_res = CoinSelectionResult.init();
    var selected = ArrayList(Utxo).init(allocator);
    // var res = try allocator.alloc(CoinSelectionResult, 1);
    defer {
        selected.deinit();
    }
    var fee_amount: u64 = 0;
    for (selected_utxos) |w_utxo| {
        try selected.append(w_utxo.weighted_utxo.utxo);
        fee_amount += w_utxo.fee;
    }
    for (required_utxos) |w_utxo| {
        try selected.append(w_utxo.weighted_utxo.utxo);
        fee_amount += w_utxo.fee;
    }

    coin_selection_res.selected = selected.items;
    coin_selection_res.fee_amount = fee_amount;
    coin_selection_res.excess = excess;
    // res[0] = coin_selection_res;
    return coin_selection_res;
}

pub fn minimalDust(
    script: []const u8,
    relay_fee: u64,
) u64 {
    var counting_stream = std.io.countingWriter(std.io.null_writer);
    const stream = counting_stream.writer();
    const script_encoded_len = try writeVarBytes(stream, script);
    const spend_cost = 32 + 4 + 1 + 107 + 4 + // The spend cost copied from Core
        8 + // The serialized size of the TxOut's amount field
        script_encoded_len;
    const sats = relay_fee * spend_cost;
    return sats;
}

pub fn decideChange(
    remaining_amount: u64,
    fee_rate: u64,
    drain_script: []const u8,
) Excess {
    var counting_stream = std.io.countingWriter(std.io.null_writer);
    const stream = counting_stream.writer();
    var drain_output_len = try writeVarBytes(stream, drain_script);
    drain_output_len += 8; //output drain_script satoshi size;
    const change_fee = fee_rate * drain_output_len;
    const drain_val, const overflow = @subWithOverflow(remaining_amount, change_fee);

    if (drain_val < @as(u64, 546) or overflow == 1) {
        return .{
            .NoChange = .{
                .dust_threshold = minimalDust(drain_script, fee_rate),
                .change_fee = change_fee,
                .remaining_amount = remaining_amount,
            },
        };
    } else {
        return .{
            .Change = .{
                .amount = drain_val,
                .fee = change_fee,
            },
        };
    }
}

pub fn generateRandomUtxos(
    allocator: std.mem.Allocator,
    n: usize,
    random: std.Random,
) !ArrayList(Utxo) {
    var utxos = ArrayList(Utxo).init(allocator);
    errdefer {
        for (utxos.items) |utxo| {
            allocator.free(utxo.output.script);
        }
        utxos.deinit();
    }

    var i: usize = 0;
    while (i < n) : (i += 1) {
        // Generate random txid
        const txid: u256 = random.int(u256);
        // random.bytes(&txid);

        // Generate random script
        const script_len = random.intRangeAtMost(u32, 0, 1000);
        const script_buffer = try allocator.alloc(u8, script_len);
        defer allocator.free(script_buffer);
        random.bytes(script_buffer);

        // Make a separate allocation for this UTXO's script
        const script_copy = try allocator.dupe(u8, script_buffer);
        errdefer allocator.free(script_copy);

        // Generate random index and amount
        const index = random.intRangeAtMost(u32, 0, 10);
        const amount = random.intRangeAtMost(u64, 546, 1000);
        // std.debug.print("AMOUNT {}\n", .{amount});

        // Create random output with its own script copy
        const output = Output{
            .satoshis = amount,
            .script = script_copy,
            .token = null,
        };

        // Create outpoint
        const outpoint = Outpoint{
            .txid = txid,
            .index = index,
        };

        // Create Utxo
        const utxo = Utxo{
            .outpoint = outpoint,
            .output = output,
        };

        try utxos.append(utxo);
    }

    return utxos;
}

const InsufficientFunds = struct {
    needed: u64,
    available: u64,
};

test "genutxos" {
    const DefaultPrng = std.Random.DefaultPrng;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var seed: u64 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&seed));
    var prng = DefaultPrng.init(seed);

    // Generate 5 random UTXOs
    const utxos = try generateRandomUtxos(allocator, 25, prng.random());
    defer {
        // First free all the individual script buffers
        for (utxos.items) |utxo| {
            allocator.free(utxo.output.script);
        }
        // Then free the ArrayList itself
        utxos.deinit();
    }

    // // Print or use the UTXOs as needed
    // for (utxos.items) |utxo| {
    //     std.debug.print("output script len {any}\namount = {}\nTxID:{x}\nIndex:{}\n\n", .{
    //         utxo.output.script.len,
    //         utxo.output.satoshis,
    //         utxo.outpoint.txid,
    //         utxo.outpoint.index,
    //     });
    // }
    var required_output_weighted = ArrayList(CandidateUtxo).init(allocator);
    var optional_output_weighted = ArrayList(CandidateUtxo).init(allocator);
    defer {
        required_output_weighted.deinit();
        optional_output_weighted.deinit();
    }
    _ = &optional_output_weighted;
    var total_available: u64 = 0;
    for (utxos.items) |utxo| {
        const req_utxo = CandidateUtxo{ .unlocking_bytecode_length = utxo.output.script.len, .utxo = utxo };
        // const optional_utxo = WeightedUtxo{ .satisfaction_weight = 40, .utxo = utxo };
        try required_output_weighted.append(req_utxo);
        try optional_output_weighted.append(req_utxo);
        total_available += req_utxo.utxo.output.satoshis;
    }

    // for (required_output_weighted.items) |x| {
    //     std.debug.print("Script len{any}\n", .{x.unlocking_bytecode_length});
    //     std.debug.print("Script len{any}\n", .{x.unlocking_bytecode_length});
    // }
    const o_group = OutputGroup.init(
        required_output_weighted.items,
        1,
    );
    const average_script_len = blk: {
        var total_script_amt_len: usize = 0;
        for (required_output_weighted.items) |x| {
            total_script_amt_len = x.utxo.output.script.len;
        }
        const average = total_script_amt_len / required_output_weighted.items.len;
        break :blk average;
    };
    std.debug.print("OutputGroup  Effective Val {any}\n", .{o_group.effective_value});
    std.debug.print("Average len {any}\n", .{average_script_len});
    std.debug.print("Total sats {any}\n", .{total_available});
    // const res = try coinSelect(
    //     allocator,
    //     required_output_weighted.items,
    //     optional_output_weighted.items,
    //     1,
    //     110000000,
    //     &[_]u8{1} ** 25,
    // );
    // std.debug.print("Available:{}\nselected len:{any}\nfee:{}\nExcess {any}", .{
    //     total_available,
    //     res.selected.len,
    //     res.fee_amount,
    //     res.excess,
    // });
}

test "outputgroup" {
    const outpoint = Outpoint{ .txid = 0, .index = 0 };
    const output = Output{ .script = &.{}, .satoshis = 1000, .token = null };
    var weighted_utxo = [_]CandidateUtxo{CandidateUtxo{ .unlocking_bytecode_length = 100, .utxo = Utxo{
        .outpoint = outpoint,
        .output = output,
    } }};

    const res = OutputGroup.init(&weighted_utxo, 1);
    _ = &res;

    // std.debug.print("Oupoint: {}\nOutput{}", .{ outpoint, output });
    std.debug.print("Oupoint Group: {any}\n", .{res});
}

test "hashset" {
    const outpoint = Outpoint{ .txid = 0, .index = 0 };
    const output = Output{ .script = &.{}, .satoshis = 1000, .token = null };
    const utxo =
        Utxo{
        .outpoint = outpoint,
        .output = output,
    };
    const outpoint2 = Outpoint{ .txid = 1, .index = 20 };
    const output2 = Output{ .script = &.{}, .satoshis = 1000, .token = null };
    const utxo2 =
        Utxo{
        .outpoint = outpoint2,
        .output = output2,
    };
    var utxo_set = HashSet(Utxo).init(std.testing.allocator);
    defer {
        utxo_set.deinit();
    }
    try utxo_set.insert(utxo);
    var res = utxo_set.contains(utxo);
    try std.testing.expect(res);
    res = utxo_set.contains(utxo2);
    try std.testing.expect(!res);
    try utxo_set.insert(utxo2);
    res = utxo_set.contains(utxo2);
    try std.testing.expect(res);
    _ = utxo_set.remove(utxo2);
    res = utxo_set.contains(utxo2);
    try std.testing.expect(!res);
}
