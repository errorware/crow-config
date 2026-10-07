//! Well-known kernel parameters: what each does, in words, and for those
//! that take a few fixed values, the values and how safe each is. A `*`
//! segment matches any interface (`all`, `default`, `eth0`).

use crow_config_core::schema::{EnumOption, RiskLevel};

use RiskLevel::{Recommended as Ok, NeverOnProd as Never, Weak};

/// A known parameter.
pub struct Known {
    pub pattern: &'static str,
    pub help: &'static str,
    /// Its values, when it takes a few fixed ones: (value, meaning, risk).
    pub values: &'static [(&'static str, &'static str, Option<RiskLevel>)],
}

impl Known {
    pub fn options(&self) -> Option<Vec<EnumOption>> {
        (!self.values.is_empty()).then(|| self.values.iter().map(|(v, l, r)| EnumOption { value: v.to_string(), label: l.to_string(), risk: r.clone() }).collect())
    }
}

const OFF_ON: &[(&str, &str, Option<RiskLevel>)] = &[("0", "off", None), ("1", "on", None)];

const KNOWN: &[Known] = &[
    // Routing and forwarding
    Known { pattern: "net.ipv4.ip_forward", help: "Routes packets between interfaces. Needed on routers, VPN gateways and container hosts (Docker, Kubernetes); off elsewhere.", values: OFF_ON },
    Known { pattern: "net.ipv6.conf.*.forwarding", help: "Routes IPv6 packets between interfaces. Needed on routers and container hosts.", values: OFF_ON },
    Known {
        pattern: "net.ipv4.conf.*.rp_filter",
        help: "Reverse-path filtering: drops packets whose source address couldn't be routed back, which stops simple spoofing.",
        values: &[("0", "off", Some(Weak)), ("1", "strict", Some(Ok)), ("2", "loose (for asymmetric routing)", None)],
    },
    Known { pattern: "net.ipv4.conf.*.accept_redirects", help: "Lets ICMP redirects change this server's routes. Off unless you know you need it.", values: &[("0", "off", Some(Ok)), ("1", "on", Some(Weak))] },
    Known { pattern: "net.ipv6.conf.*.accept_redirects", help: "Lets ICMPv6 redirects change this server's routes. Off unless you know you need it.", values: &[("0", "off", Some(Ok)), ("1", "on", Some(Weak))] },
    Known { pattern: "net.ipv4.conf.*.secure_redirects", help: "Accepts redirects only from gateways already in the routing table.", values: OFF_ON },
    Known { pattern: "net.ipv4.conf.*.send_redirects", help: "Sends ICMP redirects to other hosts. Only routers should.", values: &[("0", "off", Some(Ok)), ("1", "on", None)] },
    Known { pattern: "net.ipv4.conf.*.accept_source_route", help: "Accepts packets that dictate their own route. A spoofing aid; off everywhere.", values: &[("0", "off", Some(Ok)), ("1", "on", Some(Never))] },
    Known { pattern: "net.ipv6.conf.*.accept_source_route", help: "Accepts IPv6 packets that dictate their own route. Off everywhere.", values: &[("0", "off", Some(Ok)), ("1", "on", Some(Never))] },
    Known { pattern: "net.ipv4.conf.*.log_martians", help: "Logs packets with impossible source addresses.", values: &[("0", "off", None), ("1", "on", Some(Ok))] },
    Known {
        pattern: "net.ipv6.conf.*.accept_ra",
        help: "Accepts IPv6 router advertisements (address and route autoconfiguration).",
        values: &[("0", "off", None), ("1", "on, unless forwarding", None), ("2", "on, even when forwarding", None)],
    },
    Known { pattern: "net.ipv6.conf.*.disable_ipv6", help: "Turns IPv6 off on the interface.", values: &[("0", "IPv6 on", None), ("1", "IPv6 off", None)] },
    Known { pattern: "net.ipv6.conf.*.use_tempaddr", help: "IPv6 privacy addresses.", values: &[("0", "off", None), ("1", "made, not preferred", None), ("2", "made and preferred", None)] },
    // TCP and ICMP
    Known { pattern: "net.ipv4.tcp_syncookies", help: "SYN cookies: keeps accepting connections during a SYN flood.", values: &[("0", "off", Some(Weak)), ("1", "on", Some(Ok))] },
    Known { pattern: "net.ipv4.icmp_echo_ignore_broadcasts", help: "Ignores pings sent to broadcast addresses (smurf attacks).", values: &[("0", "answers them", Some(Weak)), ("1", "ignores them", Some(Ok))] },
    Known { pattern: "net.ipv4.icmp_ignore_bogus_error_responses", help: "Ignores malformed ICMP error responses instead of logging them.", values: &[("0", "logs them", None), ("1", "ignores them", Some(Ok))] },
    Known { pattern: "net.ipv4.icmp_echo_ignore_all", help: "Ignores every ping.", values: &[("0", "answers pings", None), ("1", "ignores pings", None)] },
    Known { pattern: "net.ipv4.tcp_timestamps", help: "TCP timestamps (better throughput estimates; reveal uptime).", values: OFF_ON },
    Known { pattern: "net.ipv4.tcp_mtu_probing", help: "Probes the path MTU when ICMP is blocked along the way.", values: &[("0", "off", None), ("1", "when a black hole is detected", None), ("2", "always", None)] },
    Known { pattern: "net.ipv4.tcp_congestion_control", help: "TCP congestion algorithm (cubic, bbr…); must be one the kernel has loaded.", values: &[] },
    Known { pattern: "net.ipv4.ip_local_port_range", help: "The range of ports for outgoing connections: low and high, separated by a space.", values: &[] },
    Known { pattern: "net.core.somaxconn", help: "Longest queue of connections waiting to be accepted, per listening socket.", values: &[] },
    Known { pattern: "net.core.default_qdisc", help: "Default queueing discipline for network interfaces (fq_codel, fq…).", values: &[] },
    // Kernel hardening
    Known {
        pattern: "kernel.randomize_va_space",
        help: "Address-space layout randomization (ASLR): makes memory-corruption exploits much harder.",
        values: &[("0", "off", Some(Never)), ("1", "partial", Some(Weak)), ("2", "full", Some(Ok))],
    },
    Known {
        pattern: "kernel.kptr_restrict",
        help: "Hides kernel addresses (in /proc and logs) that help exploits.",
        values: &[("0", "shown to everyone", Some(Weak)), ("1", "hidden from unprivileged users", Some(Ok)), ("2", "hidden from everyone", None)],
    },
    Known { pattern: "kernel.dmesg_restrict", help: "Who can read the kernel log.", values: &[("0", "every user", Some(Weak)), ("1", "only root", Some(Ok))] },
    Known {
        pattern: "kernel.yama.ptrace_scope",
        help: "Who may attach a debugger to a running process.",
        values: &[("0", "any process of the same user", Some(Weak)), ("1", "only a process's parents", Some(Ok)), ("2", "only admins", None), ("3", "nobody, until reboot", None)],
    },
    Known {
        pattern: "kernel.unprivileged_bpf_disabled",
        help: "Whether users without privileges can load BPF programs.",
        values: &[("0", "allowed", Some(Weak)), ("1", "disabled until reboot", Some(Ok)), ("2", "disabled (an admin can re-enable)", Some(Ok))],
    },
    Known { pattern: "kernel.sysrq", help: "Magic SysRq keys: 0 off, 1 all on, other values a bitmask of allowed functions.", values: &[] },
    Known { pattern: "kernel.core_uses_pid", help: "Adds the process id to core dump file names.", values: OFF_ON },
    Known { pattern: "kernel.core_pattern", help: "Where core dumps go: a file name pattern, or |program to pipe them to (e.g. systemd-coredump).", values: &[] },
    Known { pattern: "kernel.pid_max", help: "Highest process id before ids wrap around.", values: &[] },
    // Filesystem protections
    Known { pattern: "fs.protected_hardlinks", help: "Stops users hard-linking files they don't own (a classic privilege-escalation trick).", values: &[("0", "off", Some(Weak)), ("1", "on", Some(Ok))] },
    Known { pattern: "fs.protected_symlinks", help: "Stops following other users' symlinks in world-writable sticky folders like /tmp.", values: &[("0", "off", Some(Weak)), ("1", "on", Some(Ok))] },
    Known {
        pattern: "fs.protected_regular",
        help: "Limits opening other users' files in world-writable sticky folders like /tmp.",
        values: &[("0", "off", Some(Weak)), ("1", "on", Some(Ok)), ("2", "strict", None)],
    },
    Known { pattern: "fs.protected_fifos", help: "Limits opening other users' FIFOs in world-writable sticky folders.", values: &[("0", "off", Some(Weak)), ("1", "on", Some(Ok)), ("2", "strict", None)] },
    Known {
        pattern: "fs.suid_dumpable",
        help: "Whether setuid programs leave core dumps (which can hold secrets).",
        values: &[("0", "no dumps", Some(Ok)), ("1", "dumps, readable by the user", Some(Never)), ("2", "dumps, readable by root only", None)],
    },
    Known { pattern: "fs.file-max", help: "Most open files across the whole system.", values: &[] },
    Known { pattern: "fs.inotify.max_user_watches", help: "Most files one user can watch for changes (editors, sync tools and build watchers use many).", values: &[] },
    Known { pattern: "fs.inotify.max_user_instances", help: "Most inotify instances one user can open.", values: &[] },
    // Memory
    Known { pattern: "vm.swappiness", help: "How eagerly the kernel swaps, 0–200 (default 60). Lower keeps more in RAM.", values: &[] },
    Known {
        pattern: "vm.overcommit_memory",
        help: "How the kernel promises memory to programs.",
        values: &[("0", "heuristic (default)", None), ("1", "always say yes", None), ("2", "never overcommit", None)],
    },
    Known { pattern: "vm.max_map_count", help: "Most memory map areas per process; Elasticsearch and some games need far more than the default.", values: &[] },
    Known { pattern: "vm.dirty_ratio", help: "Percent of memory that can hold unwritten data before writers have to wait.", values: &[] },
    Known { pattern: "vm.dirty_background_ratio", help: "Percent of memory with unwritten data at which the kernel starts writing it out.", values: &[] },
];

/// A key in dot form. When a key's first separator is `/`, it's written as
/// a path, and a `.` in it is a literal dot (in an interface name, say).
fn dotted(key: &str) -> String {
    let key = key.trim_start_matches('-');
    if key.find(['.', '/']).is_some_and(|i| key[i..].starts_with('/')) {
        key.chars().map(|c| match c {
            '/' => '.',
            '.' => '/',
            c => c,
        }).collect()
    } else {
        key.to_string()
    }
}

/// What's known about `key`, if anything.
pub fn known(key: &str) -> Option<&'static Known> {
    let key = dotted(key);
    let parts: Vec<&str> = key.split('.').collect();
    KNOWN.iter().find(|k| {
        let pat: Vec<&str> = k.pattern.split('.').collect();
        pat.len() == parts.len() && pat.iter().zip(&parts).all(|(p, s)| *p == "*" || p == s)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_by_pattern_and_either_separator() {
        assert!(known("net.ipv4.ip_forward").is_some());
        assert_eq!(known("net/ipv4/conf/eth0/rp_filter").map(|k| k.pattern), Some("net.ipv4.conf.*.rp_filter"));
        assert_eq!(known("net.ipv4.conf.all.rp_filter").map(|k| k.pattern), Some("net.ipv4.conf.*.rp_filter"));
        assert!(known("net.ipv4.conf.rp_filter").is_none(), "segments must line up");
        assert!(known("-kernel.kptr_restrict").is_some(), "the ignore marker isn't part of the key");
        assert!(known("made.up.key").is_none());
        assert_eq!(known("net.ipv4.conf.eth0/100.rp_filter").map(|k| k.pattern), Some("net.ipv4.conf.*.rp_filter"), "dot form with a VLAN interface");
        assert_eq!(known("net/ipv4/conf/eth0.100/rp_filter").map(|k| k.pattern), Some("net.ipv4.conf.*.rp_filter"), "path form with a VLAN interface");
    }

    #[test]
    fn every_known_key_says_what_it_does() {
        for k in KNOWN {
            assert!(!k.help.is_empty() && k.help.ends_with(['.', ')']), "{}", k.pattern);
            let values: Vec<&str> = k.values.iter().map(|v| v.0).collect();
            let mut dedup = values.clone();
            dedup.dedup();
            assert_eq!(values, dedup, "{}", k.pattern);
        }
    }
}
