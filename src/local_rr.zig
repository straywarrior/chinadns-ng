const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const opt = @import("opt.zig");
const dns = @import("dns.zig");
const assert = std.debug.assert;

/// [name] => records
/// - name and records are in wire format
/// - name does not include the null label
var _name_to_records: std.StringHashMapUnmanaged(Records) = .{};

/// ["*.internal.xx.com"] => 记录，key = 去掉 `*.` 前缀后的后缀域 wire 格式（不含末尾 null）
var _wild_name_to_records: std.StringHashMapUnmanaged(Records) = .{};

/// dns.qname_domains 的 interest_levels：查 level 1..8。
/// apex（完整 qname）由精确表处理，通配永不匹配 apex —— 在 find_wild_records 中按指针跳过。
const WILD_INTEREST_LEVELS: u8 = 0b1111_1111;

const Records = struct {
    ipv4: []RR_A = &.{},
    ipv6: []RR_AAAA = &.{},

    fn do_add_ip(self: *Records, net_ip: []const u8, comptime is_ipv4: bool) void {
        const field = if (is_ipv4) "ipv4" else "ipv6";
        var rrset = @field(self, field);

        // avoid duplicate
        for (rrset) |*rr| {
            if (std.mem.eql(u8, &rr.data, net_ip))
                return;
        }

        const new_n = rrset.len + 1;
        rrset = (g.allocator.realloc(rrset, new_n) catch unreachable)[0..new_n];
        @field(self, field) = rrset;

        const rr = &rrset[new_n - 1];
        rr.* = .{
            .name = cc.htons((0b11 << 14) + dns.header_len()),
            .type = cc.htons(if (is_ipv4) c.DNS_TYPE_A else c.DNS_TYPE_AAAA),
            .class = cc.htons(c.DNS_CLASS_IN),
            .ttl = 0,
            .datalen = cc.htons(if (is_ipv4) c.IPV4_LEN else c.IPV6_LEN),
            .data = undefined,
        };
        @memcpy(&rr.data, net_ip.ptr, net_ip.len);
    }

    pub noinline fn add_ip(self: *Records, net_ip: []const u8) void {
        if (net_ip.len == c.IPV4_LEN)
            self.do_add_ip(net_ip, true)
        else
            self.do_add_ip(net_ip, false);
    }
};

// TODO: change to extern struct
const RR_A = packed struct {
    name: u16, // ptr
    type: u16,
    class: u16,
    ttl: u32,
    datalen: u16,
    data: [c.IPV4_LEN]u8,
};

// TODO: change to extern struct
const RR_AAAA = packed struct {
    name: u16, // ptr
    type: u16,
    class: u16,
    ttl: u32,
    datalen: u16,
    data: [c.IPV6_LEN]u8,
};

comptime {
    assert(@sizeOf(RR_A) == 2 * 3 + 4 + 2 + c.IPV4_LEN);
    assert(@sizeOf(RR_AAAA) == 2 * 3 + 4 + 2 + c.IPV6_LEN);
}

/// for opt.zig
pub fn read_hosts(path: []const u8) ?void {
    const src = @src();

    const mem = cc.mmap_file(cc.to_cstr(path)) orelse {
        opt.printf(src, "open file: %m", .{});
        return null;
    };
    defer _ = cc.munmap(mem);

    var line_it = std.mem.split(u8, mem, "\n");
    while (line_it.next()) |raw_line| {
        // ignore comments
        const pos = std.mem.indexOfScalar(u8, raw_line, '#');
        const line = if (pos) |p| raw_line[0..p] else raw_line;

        // ip name name ...
        var it = std.mem.tokenize(u8, line, " \t\r");

        const ip = it.next() orelse continue;

        if (it.peek() == null) {
            opt.print(src, "missing domain", line);
            return null;
        }

        while (it.next()) |name|
            add_ip(name, ip) orelse return null;
    }
}

fn add_ip_to(map: *std.StringHashMapUnmanaged(Records), name: []const u8, str_ip: []const u8) ?void {
    const src = @src();

    var name_buf: [c.DNS_NAME_WIRE_MAXLEN]u8 = undefined;
    const name_z = dns.ascii_to_wire(name, &name_buf, null) orelse {
        opt.print(src, "invalid domain", name);
        return null;
    };
    const name_wire = name_z[0 .. name_z.len - 1];

    const res = map.getOrPut(g.allocator, name_wire) catch unreachable;
    if (!res.found_existing) {
        res.key_ptr.* = g.allocator.dupe(u8, name_wire) catch unreachable;
        res.value_ptr.* = .{};
    }

    var ip_buf: cc.IpNetBuf = undefined;
    const net_ip = cc.ip_to_net(cc.to_cstr(str_ip), &ip_buf) orelse {
        opt.print(src, "invalid ip", str_ip);
        return null;
    };
    res.value_ptr.add_ip(net_ip);
}

/// for opt.zig; "*.internal.xx.com" 入通配表，其余入精确表
pub noinline fn add_ip(ascii_name: []const u8, str_ip: []const u8) ?void {
    if (ascii_name.len >= 2 and ascii_name[0] == '*' and ascii_name[1] == '.')
        return add_ip_to(&_wild_name_to_records, ascii_name[2..], str_ip);
    return add_ip_to(&_name_to_records, ascii_name, str_ip);
}

/// 查 qname 各级真后缀（最深→最浅）中的通配记录；永不匹配 apex（完整 qname）
fn find_wild_records(msg: []const u8, qnamelen: c_int) ?*Records {
    if (_wild_name_to_records.count() == 0)
        return null;

    // apex 自身由精确表处理，通配只匹配其真后缀
    const apex = dns.get_qname(msg, qnamelen);

    var domains: [8][*]const u8 = undefined;
    var domain_end: [*]const u8 = undefined;
    const n = dns.qname_domains(msg, qnamelen, WILD_INTEREST_LEVELS, &domains, &domain_end) orelse return null;

    // qname_domains 按 level 从 N（完整 qname）递减填充，故 domains[0..] 即最深→最浅。
    // 跳过 apex（仅当其 level ≤ 8 时才在数组中），其余顺序即最深通配优先。
    for (domains[0..n]) |domain| {
        if (domain == apex.ptr)
            continue;
        const suffix_len = cc.ptrdiff_u(u8, domain_end, domain); // 与 cache_ignore.zig:57 一致
        if (_wild_name_to_records.getPtr(domain[0..suffix_len])) |records|
            return records;
    }
    return null;
}

pub fn find_answer(msg: []const u8, qnamelen: c_int, p_answer_n: *u16) ?[]const u8 {
    if (_name_to_records.count() == 0 and _wild_name_to_records.count() == 0)
        return null;

    const qtype = dns.get_qtype(msg, qnamelen);
    if (qtype != c.DNS_TYPE_A and qtype != c.DNS_TYPE_AAAA)
        return null;

    const qname = dns.get_qname(msg, qnamelen);
    const records = _name_to_records.getPtr(qname) orelse
        find_wild_records(msg, qnamelen) orelse return null;

    switch (qtype) {
        c.DNS_TYPE_A => {
            p_answer_n.* = cc.to_u16(records.ipv4.len);
            return std.mem.sliceAsBytes(records.ipv4);
        },
        c.DNS_TYPE_AAAA => {
            p_answer_n.* = cc.to_u16(records.ipv6.len);
            return std.mem.sliceAsBytes(records.ipv6);
        },
        else => unreachable,
    }
}

fn deinit_map(map: *std.StringHashMapUnmanaged(Records)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        g.allocator.free(entry.key_ptr.*);
        g.allocator.free(entry.value_ptr.ipv4);
        g.allocator.free(entry.value_ptr.ipv6);
    }
    map.deinit(g.allocator);
    // std 0.10.1 HashMapUnmanaged.deinit 将 self 置为 undefined；
    // 测试函数间复用全局 map，须重新初始化，否则下一次 getOrPut 读到非法 metadata
    map.* = .{};
}

/// 释放所有记录；仅测试调用（守护进程经 cc.exit 退出，不调用）
pub fn deinit() void {
    deinit_map(&_name_to_records);
    deinit_map(&_wild_name_to_records);
}

const testing = std.testing;

fn put_u16(buf: []u8, off: usize, v: u16) void {
    buf[off] = @intCast(u8, v >> 8);
    buf[off + 1] = @intCast(u8, v & 0xff);
}

const TestQuery = struct { msg: []const u8, qnamelen: c_int };

/// header(12) + qname(wire, 含末尾 null) + qtype(2) + qclass(2)
fn make_query(buf: *[512]u8, ascii_name: []const u8, qtype: u16) TestQuery {
    put_u16(buf, 0, 0);      // id
    put_u16(buf, 2, 0x0100); // flags: RD
    put_u16(buf, 4, 1);      // qdcount
    put_u16(buf, 6, 0);      // ancount
    put_u16(buf, 8, 0);      // nscount
    put_u16(buf, 10, 0);     // arcount

    var i: usize = 12;
    var name_buf: [c.DNS_NAME_WIRE_MAXLEN]u8 = undefined;
    const wire = dns.ascii_to_wire(ascii_name, &name_buf, null).?;
    @memcpy(buf[i..].ptr, wire.ptr, wire.len);
    const qnamelen = wire.len;
    i += wire.len;

    put_u16(buf, i, qtype);
    i += 2;
    put_u16(buf, i, c.DNS_CLASS_IN);
    i += 2;

    return .{ .msg = buf[0..i], .qnamelen = @intCast(c_int, qnamelen) };
}

/// add_ip 失败（返回 null）时让测试以 error 退出
fn must_add_ip(name: []const u8, ip: []const u8) !void {
    if (add_ip(name, ip) == null)
        return error.InvalidArg;
}

/// RR_A/RR_AAAA 为 packed 布局：name(2) type(2) class(2) ttl(4) datalen(2) data(..)，data 偏移 12
const ANSWER_DATA_OFFSET = 2 * 3 + 4 + 2;

pub fn @"test: wildcard subdomain"() !void {
    defer deinit();
    try must_add_ip("*.internal.xx.com", "192.168.31.204");

    var buf: [512]u8 = undefined;
    const q = make_query(&buf, "a.internal.xx.com", c.DNS_TYPE_A);
    var n: u16 = undefined;
    const answer = find_answer(q.msg, q.qnamelen, &n) orelse return error.NoMatch;
    try testing.expectEqual(@as(u16, 1), n);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 31, 204 }, answer[ANSWER_DATA_OFFSET..][0..4]);

    // AAAA 查询命中同一通配项，但未配 v6 IP -> NODATA（answer_n = 0）
    const q6 = make_query(&buf, "a.internal.xx.com", c.DNS_TYPE_AAAA);
    var n6: u16 = undefined;
    const a6 = find_answer(q6.msg, q6.qnamelen, &n6) orelse return error.NoMatch;
    try testing.expectEqual(@as(u16, 0), n6);
    try testing.expect(a6.len == 0);
}

pub fn @"test: wildcard apex miss"() !void {
    defer deinit();
    try must_add_ip("*.internal.xx.com", "192.168.31.204");

    var buf: [512]u8 = undefined;
    const q = make_query(&buf, "internal.xx.com", c.DNS_TYPE_A);
    var n: u16 = undefined;
    try testing.expect(find_answer(q.msg, q.qnamelen, &n) == null);
}

pub fn @"test: wildcard deepest wins"() !void {
    defer deinit();
    try must_add_ip("*.b.xx.com", "1.1.1.1");
    try must_add_ip("*.xx.com", "2.2.2.2");

    var buf: [512]u8 = undefined;
    const q = make_query(&buf, "x.y.b.xx.com", c.DNS_TYPE_A);
    var n: u16 = undefined;
    const answer = find_answer(q.msg, q.qnamelen, &n) orelse return error.NoMatch;
    try testing.expectEqual(@as(u16, 1), n);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 1, 1 }, answer[ANSWER_DATA_OFFSET..][0..4]);
}

pub fn @"test: exact over wildcard"() !void {
    defer deinit();
    try must_add_ip("a.internal.xx.com", "3.3.3.3");
    try must_add_ip("*.internal.xx.com", "2.2.2.2");

    var buf: [512]u8 = undefined;
    const q = make_query(&buf, "a.internal.xx.com", c.DNS_TYPE_A);
    var n: u16 = undefined;
    const answer = find_answer(q.msg, q.qnamelen, &n) orelse return error.NoMatch;
    try testing.expectEqual(@as(u16, 1), n);
    try testing.expectEqualSlices(u8, &.{ 3, 3, 3, 3 }, answer[ANSWER_DATA_OFFSET..][0..4]);
}

pub fn @"test: wildcard multi names and ips"() !void {
    defer deinit();
    try must_add_ip("*.a", "1.2.3.4");
    try must_add_ip("*.a", "5.6.7.8");
    try must_add_ip("*.b", "5.6.7.8");

    var buf: [512]u8 = undefined;
    const q = make_query(&buf, "x.a", c.DNS_TYPE_A);
    var n: u16 = undefined;
    const answer = find_answer(q.msg, q.qnamelen, &n) orelse return error.NoMatch;
    try testing.expectEqual(@as(u16, 2), n); // 两条 A 记录
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, answer[ANSWER_DATA_OFFSET..][0..4]);
    try testing.expectEqualSlices(u8, &.{ 5, 6, 7, 8 }, answer[ANSWER_DATA_OFFSET + 16 ..][0..4]);
}

pub fn @"test: wildcard non A AAAA"() !void {
    defer deinit();
    try must_add_ip("*.internal.xx.com", "192.168.31.204");

    var buf: [512]u8 = undefined;
    const q = make_query(&buf, "a.internal.xx.com", c.DNS_TYPE_OPT); // 非 A/AAAA 不查本地表
    var n: u16 = undefined;
    try testing.expect(find_answer(q.msg, q.qnamelen, &n) == null);
}
