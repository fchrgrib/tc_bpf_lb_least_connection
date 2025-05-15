struct conn_info_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 pid;
    __u64 ts;
    __u8 type;
    __u8 old_state;
    __u8 new_state;
    char comm[16];
};