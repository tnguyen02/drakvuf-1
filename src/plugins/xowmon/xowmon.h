#ifndef XOWMON_H
#define XOWMON_H

#include <vector>
#include <memory>

#include <glib.h>
#include <libusermode/userhook.hpp>
#include "plugins/private.h"
#include "plugins/plugins_ex.h"

class xowmon: public pluginex
{
public:
    drakvuf_trap_t cr3_trap; // to keep track of the trap on cr3, released when sample.exe is found
    drakvuf_trap_t rescan_trap; // to keep track of the trap on cr3, released when sample.exe is found

    vmi_pid_t pid;
    // max physical address space in bits
    uint32_t maxphyaddr;

    // to keep track of  gfn -> type of trap (either a page table or a leaf)
    // leaf traps are the gfns that processes write to
    // paging traps are the gfns that contain at least one more level of paging
    GHashTable* write_traps;
    GHashTable* execute_traps;

    GSList* rescan_list; // list of physical addresses (not GFNs) that has been written to. need to do a resurse rescan

    // keeps track of which gfn is what level in the page table
    // 4 - pml4; max 1
    // 3 - pdpt; max 512
    // 2 - pd; max 512**2
    // 1 - pt; max 512**3
    // 0 - pte; max 512**3
    GHashTable* gfn_pagetable_tracker;


//     std::vector<plugin_target_config_entry_t> wanted_hooks;
//     GHashTable* gfn_tracker;

    xowmon(drakvuf_t drakvuf, output_format_t output);
    ~xowmon();
};

#endif

