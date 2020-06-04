#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <assert.h>
#include <libdrakvuf/json-util.h>
#include <librepl/librepl.h>

#include "xowmon.h"
#include "private.h"

void print_xow(output_format_t format, drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t instr)
{
    // print out:
    // plugin, timestamp, pid, ppid, processname, cr3, rip
    char* escaped_pname;
    switch (format)
    {
        case OUTPUT_CSV:
            printf("xowmon," FORMAT_TIMEVAL ",%" PRIu32 ",%" PRIu32 ",\"%s\",%" PRIx64 ",%" PRIx64 ",%" PRIx64 "\n",
                    UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid,
                    info->proc_data.ppid, info->proc_data.name, info->regs->cr3, info->regs->rip, instr);
            break;
        case OUTPUT_KV:
            printf("xowmon Time=" FORMAT_TIMEVAL ",PID=%" PRIu32 ",PPID=%" PRIu32
                    "ProcessName=\"%s\",CR3=%" PRIx64 ",RIP=%" PRIx64 ", INSTR=%" PRIx64 "\n",
                    UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid,
                    info->proc_data.ppid, info->proc_data.name, info->regs->cr3, info->regs->rip, instr);
            break;
        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            printf("{"
                "\"Plugin\":\"xowmon\","
                "\"Timestamp\":\"" FORMAT_TIMEVAL "\","
                "\"PID\":%" PRIu32 ","
                "\"PPID\":%" PRIu32 ","
                "\"ProcessName\":%s,"
                "\"CR3\":\"%" PRIx64 "\","
                "\"RIP\":\"%" PRIx64 "\","
                "\"Instructions\":%" PRIx64 "\""
                "}\n",
                UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid,
                info->proc_data.ppid, escaped_pname, info->regs->cr3, info->regs->rip, instr);
            break;
        default:
        case OUTPUT_DEFAULT:
            printf("[XOWMON] TIME:" FORMAT_TIMEVAL " PID:%" PRIu32 " PPID:%" PRIu32
                    "ProcessName:%s CR3:%" PRIx64 " RIP:%" PRIx64 " Instructions:%" PRIx64 "\n",
                    UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid,
                    info->proc_data.ppid, info->proc_data.name, info->regs->cr3, info->regs->rip, instr);
            break;
    }
}

static event_response_t execute_trap_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    xowmon* plugin = (xowmon*) info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rip
    };

    uint64_t instr = 0;
    uint8_t instr_temp = 0;

    for (int i = 0; i < 8; i++)
    {
        ctx.addr = info->regs->rip + i;
        if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &instr_temp))
        {
            PRINT_DEBUG("Fail to fetch instructions at RIP\n");
        }
        instr = (instr << 8) | instr_temp;
    }

    print_xow(plugin->m_output_format, drakvuf, info, instr);
    drakvuf_remove_trap(drakvuf, &plugin->rescan_trap, nullptr);

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, plugin->write_traps);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        drakvuf_remove_trap(drakvuf, (drakvuf_trap_t*) value, nullptr);
    }
    g_hash_table_iter_init(&iter, plugin->execute_traps);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        drakvuf_remove_trap(drakvuf, (drakvuf_trap_t*) value, nullptr);
    }
    g_hash_table_destroy(plugin->write_traps);
    g_hash_table_destroy(plugin->execute_traps);
    g_hash_table_destroy(plugin->gfn_pagetable_tracker);
    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t rescan_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    // get the rescan list
    // call recurse rescan
    xowmon* plugin = (xowmon*) info->trap->data;
    addr_t* trap_pa;
    addr_t gfn;
    uint8_t* level;
    addr_t entry;
    addr_t next_gfn;
    PRINT_DEBUG("rescan cb 0\n");
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    PRINT_DEBUG("rescan cb 1\n");
    for (GSList* i = plugin->rescan_list; i != NULL; i = i->next)
    {
        // read the trap pa to get the next gfn, do the recurse add
        trap_pa = (addr_t*) i->data;
        if (VMI_FAILURE == vmi_read_64_pa(vmi, *trap_pa, &entry)) {
            continue;
        }
        gfn = *trap_pa >> 12;
        level = (uint8_t*) g_hash_table_lookup(plugin->gfn_pagetable_tracker, &gfn);
        // validate the entry, if good, then recurse on the entry's specified gfn
        next_gfn = (entry & (~0ul >> (64 - plugin->maxphyaddr))) >> 12;
        if ( !(entry & 0x1) || !next_gfn) { continue; }
        // level - 1 beacuse it's the phy addr of the entry of the current page
        recurse_create_page_table_traps(drakvuf, vmi, plugin, next_gfn, *level - 1);
    }
    g_slist_free_full(plugin->rescan_list, g_free);
    plugin->rescan_list = NULL; // reset the list
    drakvuf_release_vmi(drakvuf);
    PRINT_DEBUG("rescan cb 2\n");
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t write_trap_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    // when a write has occured
    // update table to know that write occured
    xowmon* plugin = (xowmon*) info->trap->data;
    addr_t gfn = info->trap_pa >> 12;
    addr_t* tmp_gfn;
    uint8_t* level;

    drakvuf_lock_and_get_vmi(drakvuf);

    level = (uint8_t*) g_hash_table_lookup(plugin->gfn_pagetable_tracker, &gfn);
    if (level == NULL) {
        goto done;
    }

    // the page we are tracking does not correspond to sample.exe -> stop tracking
    if (info->proc_data.pid != plugin->pid)
    {
        // add trap to list of traps to be removed. maybe the issue is we can't remove traps that we're currently in?
        g_hash_table_remove(plugin->write_traps, &gfn);
        g_hash_table_remove(plugin->execute_traps, &gfn);
        g_hash_table_remove(plugin->gfn_pagetable_tracker, &gfn);
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        goto done;
    }

    // if level is 0, then it's a direct write on a memory page. remove write trap, start execute trap
    if (*level == 0)
    {
        // execute trap already created, ignore.
        if (g_hash_table_contains(plugin->execute_traps, &gfn)) { goto done; }
        drakvuf_trap_t* execute_trap = (drakvuf_trap_t*) malloc(sizeof(drakvuf_trap_t));
        memset(execute_trap, 0, sizeof(drakvuf_trap_t));
        execute_trap->type = MEMACCESS;
        execute_trap->cb = execute_trap_cb;
        execute_trap->data = plugin;
        execute_trap->memaccess.gfn = gfn;
        execute_trap->memaccess.type = PRE;
        execute_trap->memaccess.access = VMI_MEMACCESS_X;
        if (!drakvuf_add_trap(drakvuf, execute_trap))
        {
            free(execute_trap);
            goto done;
        }

        // now execute is trapped, remove write trap
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        g_hash_table_remove(plugin->write_traps, &gfn);

        // track new execute trap
        tmp_gfn = g_new0(addr_t, 1);
        *tmp_gfn = gfn;
        g_hash_table_insert(plugin->execute_traps, tmp_gfn, execute_trap);
    }
    // else, place write trap with level - 1
    else
    {
        // find what what was written to
        // right now, post memaccess is broken
        // can try to interpret the write by reading the instruction and deciphering it. too much work
        // try single stepping. more accurate, but not sure how it will work in drakvuf. doesn't work in drakvuf
        // try accessing from after execution
        //  - track memaccess reads at that specific location. when read, then get value and then recurse
        //  just do a rescan
        //  - add this page to the rescan list
        // try reading rip instruction

        plugin->rescan_list = g_slist_prepend(plugin->rescan_list, g_memdup(&info->trap_pa, sizeof(addr_t)));
        goto done;
    }

done:
    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

// assume drakvuf and vmi already locked
static void recurse_create_page_table_traps(drakvuf_t drakvuf, vmi_instance_t vmi, xowmon* plugin, addr_t gfn, uint8_t level)
{
    // num of entries is 512, 64 bits entries for 4kb pages
    // TODO: make more generic. right now, we are assuming 4kb pages
    addr_t entry;
    addr_t next_gfn;
    addr_t* tmp_gfn;
    uint8_t* tmp_level;

    // if went beyond page table entry, return. we've finished hitting the leaf nodes
    if (level < 0) { return; }
    // check no repeats
    if (g_hash_table_contains(plugin->write_traps, &gfn)) { return; }
    if (g_hash_table_contains(plugin->execute_traps, &gfn)) { return; }
    drakvuf_trap_t* write_trap = (drakvuf_trap_t*) malloc(sizeof(drakvuf_trap_t));
    memset(write_trap, 0, sizeof(drakvuf_trap_t));
    write_trap->type = MEMACCESS;
    write_trap->cb = write_trap_cb;
    write_trap->data = plugin;
    write_trap->memaccess.gfn = gfn;
    // TODO: pre or post here? post gives us some errors, need to debug drakvuf for this
    write_trap->memaccess.type = PRE;
    write_trap->memaccess.access = VMI_MEMACCESS_W;
    if (!drakvuf_add_trap(drakvuf, write_trap)) {
        free(write_trap);
        return;
    }

    tmp_gfn = g_new0(addr_t, 1);
    *tmp_gfn = gfn;
    g_hash_table_insert(plugin->write_traps, tmp_gfn, write_trap);
    tmp_gfn = g_new0(addr_t, 1);
    tmp_level = g_new0(uint8_t, 1);
    *tmp_gfn = gfn;
    *tmp_level = level;
    g_hash_table_insert(plugin->gfn_pagetable_tracker, tmp_gfn, tmp_level);
    // if we are on the actual non-paging phys page, then stop and return
    if (level == 0) { return; }
    // iterate through the current table
    for (uint32_t i = 0; i < 512; i++)
    {
        // get the entry
        if (VMI_FAILURE == vmi_read_64_pa(vmi, (gfn << 12) + (i << 3), &entry))
        {
            continue;
        }
        // validate the entry
        next_gfn = (entry & (~0ul >> (64 - plugin->maxphyaddr))) >> 12;
        if ( !(entry & 0x1) || !next_gfn) { continue; }
        // don't repeat
        if (g_hash_table_contains(plugin->write_traps, &next_gfn)) { continue; }
        // recurse
        recurse_create_page_table_traps(drakvuf, vmi, plugin, next_gfn, level-1);
    }
}

static event_response_t cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    xowmon* plugin = (xowmon*) info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    addr_t gfn;
    // look for the process of sample.exe only
    if (!strstr(info->proc_data.name, "sample.exe")) { goto done; }
    gfn = info->regs->cr3 >> 12;

    // remove cr3 trap
    drakvuf_remove_trap(drakvuf, info->trap, nullptr);
    plugin->pid = info->proc_data.pid;

    // old: add new cr3 trap that does rescan of pagetables
    // new: add memtrap rwx on level 4 gfn
    // TODO: bad, maybe a good idea
    memset(&plugin->rescan_trap, 0, sizeof(drakvuf_trap_t));
    // plugin->rescan_trap.type = MEMACCESS;
    // plugin->rescan_trap.cb = rescan_cb;
    // plugin->rescan_trap.data = plugin;
    // plugin->rescan_trap.memaccess.gfn = gfn;
    // plugin->rescan_trap.memaccess.type = PRE;
    // plugin->rescan_trap.memaccess.access=VMI_MEMACCESS_RWX;

    plugin->rescan_trap.type = REGISTER;
    plugin->rescan_trap.cb = rescan_cb;
    plugin->rescan_trap.reg = CR3;
    plugin->rescan_trap.data = plugin;

    if (!drakvuf_add_trap(drakvuf, &plugin->rescan_trap))
    {
        PRINT_DEBUG("failed to add rescan cr3 trap\n");
    }

    recurse_create_page_table_traps(drakvuf, vmi, plugin, gfn, 4);

done:
    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

xowmon::xowmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    // TODO: this value was manually found by looking at CPUID eax. More generic
    this->maxphyaddr = 46;

    /*
     * Track page tables and when a new phys page gets allocated to it.
     * Track writes on each level of paging
     * When on leaf page, track writes. Once write happens, drop write trap, then trap execute.
     * Once execute happens, print. Unsure if need drop execute trap.
     */

    this->write_traps = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, nullptr);
    this->execute_traps = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, nullptr);
    this->gfn_pagetable_tracker = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    this->rescan_list = NULL;

    memset(&this->cr3_trap, 0, sizeof(drakvuf_trap_t));
    this->cr3_trap.type = REGISTER;
    this->cr3_trap.cb = cr3_cb;
    this->cr3_trap.reg = CR3;
    this->cr3_trap.data = (void*) this;
    if (!drakvuf_add_trap(drakvuf, &this->cr3_trap))
    {
        PRINT_DEBUG("failed to add cr3 trap\n");
    }
}

xowmon::~xowmon()
{
}

