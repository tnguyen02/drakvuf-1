void print_xow(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t instr);
static void recurse_create_page_table_traps(drakvuf_t drakvuf, vmi_instance_t vmi, xowmon* plugin, addr_t gfn, uint8_t level);
static event_response_t write_trap_cb(drakvuf_t drakvuf, drakvuf_trap_info* info);
