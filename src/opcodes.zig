const std = @import("std");
pub const Opcodes = enum(u8) {
    op_0 = 0x00,
    op_pushbytes_1 = 0x01,
    op_pushbytes_2 = 0x02,
    op_pushbytes_3 = 0x03,
    op_pushbytes_4 = 0x04,
    op_pushbytes_5 = 0x05,
    op_pushbytes_6 = 0x06,
    op_pushbytes_7 = 0x07,
    op_pushbytes_8 = 0x08,
    op_pushbytes_9 = 0x09,
    op_pushbytes_10 = 0x0a,
    op_pushbytes_11 = 0x0b,
    op_pushbytes_12 = 0x0c,
    op_pushbytes_13 = 0x0d,
    op_pushbytes_14 = 0x0e,
    op_pushbytes_15 = 0x0f,
    op_pushbytes_16 = 0x10,
    op_pushbytes_17 = 0x11,
    op_pushbytes_18 = 0x12,
    op_pushbytes_19 = 0x13,
    op_pushbytes_20 = 0x14,
    op_pushbytes_21 = 0x15,
    op_pushbytes_22 = 0x16,
    op_pushbytes_23 = 0x17,
    op_pushbytes_24 = 0x18,
    op_pushbytes_25 = 0x19,
    op_pushbytes_26 = 0x1a,
    op_pushbytes_27 = 0x1b,
    op_pushbytes_28 = 0x1c,
    op_pushbytes_29 = 0x1d,
    op_pushbytes_30 = 0x1e,
    op_pushbytes_31 = 0x1f,
    op_pushbytes_32 = 0x20,
    op_pushbytes_33 = 0x21,
    op_pushbytes_34 = 0x22,
    op_pushbytes_35 = 0x23,
    op_pushbytes_36 = 0x24,
    op_pushbytes_37 = 0x25,
    op_pushbytes_38 = 0x26,
    op_pushbytes_39 = 0x27,
    op_pushbytes_40 = 0x28,
    op_pushbytes_41 = 0x29,
    op_pushbytes_42 = 0x2a,
    op_pushbytes_43 = 0x2b,
    op_pushbytes_44 = 0x2c,
    op_pushbytes_45 = 0x2d,
    op_pushbytes_46 = 0x2e,
    op_pushbytes_47 = 0x2f,
    op_pushbytes_48 = 0x30,
    op_pushbytes_49 = 0x31,
    op_pushbytes_50 = 0x32,
    op_pushbytes_51 = 0x33,
    op_pushbytes_52 = 0x34,
    op_pushbytes_53 = 0x35,
    op_pushbytes_54 = 0x36,
    op_pushbytes_55 = 0x37,
    op_pushbytes_56 = 0x38,
    op_pushbytes_57 = 0x39,
    op_pushbytes_58 = 0x3a,
    op_pushbytes_59 = 0x3b,
    op_pushbytes_60 = 0x3c,
    op_pushbytes_61 = 0x3d,
    op_pushbytes_62 = 0x3e,
    op_pushbytes_63 = 0x3f,
    op_pushbytes_64 = 0x40,
    op_pushbytes_65 = 0x41,
    op_pushbytes_66 = 0x42,
    op_pushbytes_67 = 0x43,
    op_pushbytes_68 = 0x44,
    op_pushbytes_69 = 0x45,
    op_pushbytes_70 = 0x46,
    op_pushbytes_71 = 0x47,
    op_pushbytes_72 = 0x48,
    op_pushbytes_73 = 0x49,
    op_pushbytes_74 = 0x4a,
    op_pushbytes_75 = 0x4b,
    op_pushdata_1 = 0x4c,
    op_pushdata_2 = 0x4d,
    op_pushdata_4 = 0x4e,
    op_1negate = 0x4f,
    op_reserved = 0x50,
    // * A.K.A. `OP_TRUE`
    op_1 = 0x51,
    op_2 = 0x52,
    op_3 = 0x53,
    op_4 = 0x54,
    op_5 = 0x55,
    op_6 = 0x56,
    op_7 = 0x57,
    op_8 = 0x58,
    op_9 = 0x59,
    op_10 = 0x5a,
    op_11 = 0x5b,
    op_12 = 0x5c,
    op_13 = 0x5d,
    op_14 = 0x5e,
    op_15 = 0x5f,
    op_16 = 0x60,
    op_nop = 0x61,
    op_ver = 0x62,
    op_if = 0x63,
    op_notif = 0x64,
    op_verif = 0x65,
    op_vernotif = 0x66,
    op_else = 0x67,
    op_endif = 0x68,
    op_verify = 0x69,
    op_return = 0x6a,
    op_toaltstack = 0x6b,
    op_fromaltstack = 0x6c,
    op_2drop = 0x6d,
    op_2dup = 0x6e,
    op_3dup = 0x6f,
    op_2over = 0x70,
    op_2rot = 0x71,
    op_2swap = 0x72,
    op_ifdup = 0x73,
    op_depth = 0x74,
    op_drop = 0x75,
    op_dup = 0x76,
    op_nip = 0x77,
    op_over = 0x78,
    op_pick = 0x79,
    op_roll = 0x7a,
    op_rot = 0x7b,
    op_swap = 0x7c,
    op_tuck = 0x7d,
    op_cat = 0x7e,
    op_split = 0x7f,
    op_num2bin = 0x80,
    op_bin2num = 0x81,
    op_size = 0x82,
    op_invert = 0x83,
    op_and = 0x84,
    op_or = 0x85,
    op_xor = 0x86,
    op_equal = 0x87,
    op_equalverify = 0x88,
    op_reserved1 = 0x89,
    op_reserved2 = 0x8a,
    op_1add = 0x8b,
    op_1sub = 0x8c,
    op_2mul = 0x8d,
    op_2div = 0x8e,
    op_negate = 0x8f,
    op_abs = 0x90,
    op_not = 0x91,
    op_0notequal = 0x92,
    op_add = 0x93,
    op_sub = 0x94,
    op_mul = 0x95,
    op_div = 0x96,
    op_mod = 0x97,
    op_lshift = 0x98,
    op_rshift = 0x99,
    op_booland = 0x9a,
    op_boolor = 0x9b,
    op_numequal = 0x9c,
    op_numequalverify = 0x9d,
    op_numnotequal = 0x9e,
    op_lessthan = 0x9f,
    op_greaterthan = 0xa0,
    op_lessthanorequal = 0xa1,
    op_greaterthanorequal = 0xa2,
    op_min = 0xa3,
    op_max = 0xa4,
    op_within = 0xa5,
    op_ripemd160 = 0xa6,
    op_sha1 = 0xa7,
    op_sha256 = 0xa8,
    op_hash160 = 0xa9,
    op_hash256 = 0xaa,
    op_codeseparator = 0xab,
    op_checksig = 0xac,
    op_checksigverify = 0xad,
    op_checkmultisig = 0xae,
    op_checkmultisigverify = 0xaf,
    op_nop1 = 0xb0,
    op_checklocktimeverify = 0xb1,
    op_checksequenceverify = 0xb2,
    op_nop4 = 0xb3,
    op_nop5 = 0xb4,
    op_nop6 = 0xb5,
    op_nop7 = 0xb6,
    op_nop8 = 0xb7,
    op_nop9 = 0xb8,
    op_nop10 = 0xb9,
    op_checkdatasig = 0xba,
    op_checkdatasigverify = 0xbb,
    op_reversebytes = 0xbc,
    // * First CODEPOINT left undefined before nullary introspection operations.
    op_unknown189 = 0xbd,
    op_unknown190 = 0xbe,
    // * Last CODEPOINT left undefined before nullary introspection operations.
    op_unknown191 = 0xbf,
    op_inputindex = 0xC0,
    op_activebytecode = 0xc1,
    op_txversion = 0xC2,
    op_txinputcount = 0xc3,
    op_txoutputcount = 0xc4,
    op_txlocktime = 0xc5,
    op_utxovalue = 0xC6,
    op_utxobytecode = 0xc7,
    op_outpointtxhash = 0xc8,
    op_outpointindex = 0xc9,
    op_inputbytecode = 0xca,
    op_inputsequencenumber = 0xcb,
    op_outputvalue = 0xcc,
    op_outputbytecode = 0xcd,
    op_utxotokencategory = 0xce,
    op_utxotokencommitment = 0xcf,
    op_utxotokenamount = 0xd0,
    op_outputtokencategory = 0xd1,
    op_outputtokencommitment = 0xd2,
    op_outputtokenamount = 0xd3,
    op_unknown212 = 0xd4,
    op_unknown213 = 0xd5,
    op_unknown214 = 0xd6,
    op_unknown215 = 0xd7,
    op_unknown216 = 0xd8,
    op_unknown217 = 0xd9,
    op_unknown218 = 0xda,
    op_unknown219 = 0xdb,
    op_unknown220 = 0xdc,
    op_unknown221 = 0xdd,
    op_unknown222 = 0xde,
    op_unknown223 = 0xdf,
    op_unknown224 = 0xe0,
    op_unknown225 = 0xe1,
    op_unknown226 = 0xe2,
    op_unknown227 = 0xe3,
    op_unknown228 = 0xe4,
    op_unknown229 = 0xe5,
    op_unknown230 = 0xe6,
    op_unknown231 = 0xe7,
    op_unknown232 = 0xe8,
    op_unknown233 = 0xe9,
    op_unknown234 = 0xea,
    op_unknown235 = 0xeb,
    op_unknown236 = 0xec,
    op_unknown237 = 0xed,
    op_unknown238 = 0xee,
    op_unknown239 = 0xef,
    // * A.K.A. `OP_PREFIX_BEGIN`
    op_unknown240 = 0xf0,
    op_unknown241 = 0xf1,
    op_unknown242 = 0xf2,
    op_unknown243 = 0xf3,
    op_unknown244 = 0xf4,
    op_unknown245 = 0xf5,
    op_unknown246 = 0xf6,
    // * A.K.A. `OP_PREFIX_END`
    op_unknown247 = 0xf7,
    op_unknown248 = 0xf8,
    op_unknown249 = 0xf9,
    op_unknown250 = 0xfa,
    op_unknown251 = 0xfb,
    op_unknown252 = 0xfc,
    op_unknown253 = 0xfd,
    op_unknown254 = 0xfe,
    op_unknown255 = 0xff,

    pub fn disabled(op: u8) bool {
        return switch (@as(@This(), @enumFromInt(op))) {
            .op_invert => true,
            .op_2mul => true,
            .op_2div => true,
            .op_lshift => true,
            .op_rshift => true,
            .op_ver => true,
            else => false,
        };
    }

    pub fn fromString(str: []const u8) ?Opcodes {
        inline for (std.meta.fields(Opcodes)) |field| {
            if (std.mem.eql(u8, str, field.name)) {
                return @enumFromInt(field.value);
            }
        }
        return null;
    }
};
/// Converts a space-separated string of opcodes into a byte array
pub fn opcodeStringToBytes(allocator: std.mem.Allocator, opcode_str: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    var iter = std.mem.splitScalar(u8, opcode_str, ' ');
    while (iter.next()) |opcode| {
        if (Opcodes.fromString(opcode)) |op| {
            try result.append(@intFromEnum(op));
        } else {
            return error.InvalidOpcode;
        }
    }

    return try result.toOwnedSlice();
}
