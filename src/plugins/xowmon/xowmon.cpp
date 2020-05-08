#include <execinfo.h>
#include <stdio.h>
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


// static void free_trap(drakvuf_trap_t* trap)
// {
//     return_hook_target_entry_t* ret_target = (return_hook_target_entry_t*)trap->data;
//     delete ret_target;
//     delete trap;
// }
//
// void xow_print_arguments(drakvuf_t drakvuf, drakvuf_trap_info* info, std::vector < uint64_t > arguments, const std::vector < std::unique_ptr < ArgumentPrinter > > &argument_printers)
// {
//     json_object *jobj = json_object_new_array();
//
//     for (size_t i = 0; i < arguments.size(); i++)
//     {
//         json_object_array_add(jobj, json_object_new_string(argument_printers[i]->print(drakvuf, info, arguments[i]).c_str()));
//     }
//
//     printf("%s", json_object_get_string(jobj));
//
//     json_object_put(jobj);
// }
//
// void xow_print_extra_data(std::map < std::string, std::string > extra_data)
// {
//     size_t i = 0;
//     for (auto it = extra_data.begin(); it != extra_data.end(); it++, i++)
//     {
//         printf("\"%s\": \"%s\"", it->first.c_str(), it->second.c_str());
//         if (i < extra_data.size() - 1)
//             printf(", ");
//     }
// }
//
// static event_response_t usermode_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
// {
//     return_hook_target_entry_t* ret_target = (return_hook_target_entry_t*)info->trap->data;
//
//     // TODO check thread_id and cr3?
//     if (info->proc_data.pid != ret_target->pid)
//         return VMI_EVENT_RESPONSE_NONE;
//
//     auto plugin = (xowmon*)ret_target->plugin;
//
//     std::map < std::string, std::string > extra_data;
//
//     gchar* escaped_pname;
//     switch (plugin->m_output_format)
//     {
//         case OUTPUT_CSV:
//             printf("xowmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",\"%s\",0x%" PRIx64 ",0x%" PRIx64 ",",
//             UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
//             info->proc_data.userid, info->trap->name, info->regs->rax, info->regs->rip);
//             xow_print_arguments(drakvuf, info, ret_target->arguments, ret_target->argument_printers);
//             break;
//         case OUTPUT_KV:
//             printf("xowmon Time=" FORMAT_TIMEVAL ",VCPU=%" PRIu32 ",CR3=0x%" PRIx64 ",PID=%d,PPID=%d,ProcessName=\"%s\",UserID=%" PRIi64 ",Method=\"%s\",CalledFrom=0x%" PRIx64 ",ReturnValue=0x%" PRIx64 ",Arguments=",
//             UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
//             info->proc_data.userid, info->trap->name, info->regs->rip, info->regs->rax);
//             xow_print_arguments(drakvuf, info, ret_target->arguments, ret_target->argument_printers);
//             break;
//         case OUTPUT_JSON:
//             escaped_pname = drakvuf_escape_str(info->proc_data.name);
//             printf( "{"
//                     "\"Plugin\": \"xowmon\", "
//                     "\"TimeStamp\":" "\"" FORMAT_TIMEVAL "\", "
//                     "\"ProcessName\": %s, "
//                     "\"UserName\": \"%s\", "
//                     "\"UserId\": %" PRIu64 ", "
//                     "\"PID\": %d, "
//                     "\"PPID\": %d, "
//                     "\"TID\": %d, "
//                     "\"Method\": \"%s\", "
//                     "\"CalledFrom\": \"0x%" PRIx64 "\", "
//                     "\"ReturnValue\": \"0x%" PRIx64 "\", "
//                     "\"Arguments\": ",
//                     UNPACK_TIMEVAL(info->timestamp),
//                     escaped_pname,
//                     USERIDSTR(drakvuf), info->proc_data.userid,
//                     info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid,
//                     info->trap->name,
//                     info->regs->rip,
//                     info->regs->rax);
//
//             xow_print_arguments(drakvuf, info, ret_target->arguments, ret_target->argument_printers);
//             printf(", "
//                    "\"Extra\": {");
//             xow_print_extra_data(extra_data);
//             printf("}}");
//             g_free(escaped_pname);
//             break;
//         default:
//         case OUTPUT_DEFAULT:
//             printf("[XOWMON-USERHOOK] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 " ProcessName:\"%s\" UserID:%" PRIi64 " Method:\"%s\" CalledFrom:0x%" PRIx64 " ReturnValue:0x%" PRIx64 " Arguments:",
//             UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
//             info->proc_data.userid, info->trap->name, info->regs->rax, info->regs->rip);
//             xow_print_arguments(drakvuf, info, ret_target->arguments, ret_target->argument_printers);
//             break;
//     }
//     printf("\n");
//
//     drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free_trap);
//     return VMI_EVENT_RESPONSE_NONE;
// }
//
// static event_response_t trap_on_return(drakvuf_t drakvuf, drakvuf_trap_info* info, event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*),
//     return_hook_target_entry_t* ret_target)
// {
//     vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
//     std::vector < uint64_t > arguments;
//
//     bool is_syswow = drakvuf_is_wow64(drakvuf, info);
//
//     access_context_t ctx =
//     {
//         .translate_mechanism = VMI_TM_PROCESS_DTB,
//         .dtb = info->regs->cr3,
//         .addr = info->regs->rsp
//     };
//
//     bool success = false;
//     addr_t ret_addr = 0;
//
//     if (is_syswow)
//         success = (vmi_read_32(vmi, &ctx, (uint32_t*) &ret_addr) == VMI_SUCCESS);
//     else
//         success = (vmi_read_64(vmi, &ctx, &ret_addr) == VMI_SUCCESS);
//
//     if (!success)
//     {
//         drakvuf_release_vmi(drakvuf);
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     drakvuf_trap_t* trap = (drakvuf_trap_t*) malloc(sizeof(drakvuf_trap_t));
//     addr_t paddr;
//
//     if (VMI_FAILURE == vmi_pagetable_lookup(vmi, info->regs->cr3, ret_addr, &paddr))
//     {
//         fprintf(stdout, "[XOWMON] fail to get ret paddr for trap on return\n");
//         free(trap);
//         drakvuf_release_vmi(drakvuf);
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     trap->type = BREAKPOINT;
//     trap->cb = cb;
//     trap->data = ret_target;
//     trap->breakpoint.lookup_type = LOOKUP_DTB;
//     trap->breakpoint.dtb = info->regs->cr3;
//     trap->breakpoint.addr_type = ADDR_VA;
//     trap->breakpoint.addr = ret_addr;
//
//     if (!drakvuf_add_trap(drakvuf, trap))
//     {
//         fprintf(stdout, "[XOWMON] fail to add trap for trap on return\n");
//         delete trap;
//         delete ret_target;
//     }
//
//     drakvuf_release_vmi(drakvuf);
//     return VMI_EVENT_RESPONSE_NONE;
// }
//
// static event_response_t allocate_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
// {
//     return_hook_target_entry_t* target = (return_hook_target_entry_t*) info->trap->data;
//
//     // addr_t base_addr_ptr = drakvuf_get_function_argument(drakvuf, info, 2);
//     // addr_t base_addr;
//     // uint32_t protect = drakvuf_get_function_argument(drakvuf, info, 6);
//     // addr_t size_ptr = drakvuf_get_function_argument(drakvuf, info, 4);
//     // uint32_t size;
//     //
//
//     addr_t base_addr_ptr = target->arguments.at(1);
//     addr_t base_addr;
//     addr_t size_ptr = target->arguments.at(3);
//     uint32_t protect = target->arguments.at(5);
//     uint32_t size;
//
//     vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
//     vmi_v2pcache_flush(vmi, info->regs->cr3);
//
//     fprintf(stdout, "[XOWMON] allocate ret base_addr_ptr: %" PRIx64 " size_ptr: %" PRIx64 " protect: %" PRIx32 "\n",
//             base_addr_ptr, size_ptr, protect);
//
//     access_context_t ctx =
//     {
//         .translate_mechanism = VMI_TM_PROCESS_DTB,
//         .dtb = info->regs->cr3,
//         .addr = base_addr_ptr
//     };
//
//     addr_t test_addr = 0xe66000;
//     addr_t test_paddr;
//
//     if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &base_addr))
//     {
//         fprintf(stdout, "[XOWMON] fail get base addr\n");
//         goto done;
//     }
//
//     ctx.addr = size_ptr;
//     if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &size))
//     {
//         fprintf(stdout, "[XOWMON] fail get size\n");
//         goto done;
//     }
//
//     addr_t paddr;
//     if (VMI_FAILURE == vmi_pagetable_lookup(vmi, info->regs->cr3, base_addr, &paddr))
//     {
//         fprintf(stdout, "[XOWMON] fail translate alloc base to physical %" PRIx64 "\n", base_addr);
//         // goto done;
//     }
//
//     fprintf(stdout, "[XOWMON] allocate base: %" PRIx64 " size: %" PRIx32 " paddr: %" PRIx64 "\n", base_addr, size, paddr);
//     fprintf(stdout, "[XOWMON] allocate range: %" PRIx64 " %" PRIx64 "\n", base_addr, base_addr + size);
//
//     fprintf(stdout, "[XOWMON] trying physical for 0xe66000\n");
//     if (VMI_FAILURE == vmi_pagetable_lookup(vmi, info->regs->cr3, test_addr, &test_paddr))
//     {
//     fprintf(stdout, "[XOWMON] trying physical for 0xe66000 fail\n");
//     }
//     fprintf(stdout, "[XOWMON] trying physical for 0xe66000 end %" PRIx64 "\n", test_paddr);
//
// done:
//     drakvuf_remove_trap(drakvuf, info->trap, nullptr);
//     drakvuf_release_vmi(drakvuf);
//     return VMI_EVENT_RESPONSE_NONE;
// }
//
// static event_response_t nt_protect_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
// {
//     addr_t base_addr_ptr = drakvuf_get_function_argument(drakvuf, info, 2);
//     addr_t base_addr;
//     addr_t size_ptr = drakvuf_get_function_argument(drakvuf, info, 3);
//     uint32_t size;
//     uint32_t protect = drakvuf_get_function_argument(drakvuf, info, 4);
//
//     vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
//
//     fprintf(stdout, "[XOWMON] ntprotect cb values base_addr_ptr: %" PRIx64 "\n", base_addr_ptr);
//
//     access_context_t ctx =
//     {
//         .translate_mechanism = VMI_TM_PROCESS_DTB,
//         .dtb = info->regs->cr3,
//         .addr = base_addr_ptr
//     };
//
//     if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &base_addr))
//     {
//         fprintf(stdout, "[XOWMON] fail get base addr\n");
//     }
//
//     ctx.addr = size_ptr;
//     if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &size))
//     {
//         fprintf(stdout, "[XOWMON] fail get size\n");
//     }
//
//     addr_t paddr;
//     if (VMI_FAILURE == vmi_translate_uv2p(vmi, base_addr, info->proc_data.pid, &paddr))
//     {
//         // fprintf(stdout, "[XOWMON] fail translate alloc base to physical\n");
//     }
//
//     fprintf(stdout, "[XOWMON] ntprotect base: %" PRIx64 " size: %" PRIx32 " paddr: %" PRIx64 "\n", base_addr, size, paddr);
//
//     addr_t test_addr = 0xe66000;
//     addr_t test_paddr;
//     // addr_t tmp_paddr;
//     // addr_t dtb_base = info->regs->cr3;
//     // for (int i = 0; i < 61; i ++)
//     // {
//     //     if (VMI_FAILURE == vmi_read_64_pa(vmi, dtb_base + 0xe60 + (i * 8), &tmp_paddr))
//     //     {
//     //         fprintf(stdout, "[XOWMON] print pagetable: %d fail\n", i);
//     //     } else
//     //     {
//     //         fprintf(stdout, "[XOWMON] print pagetable: %d %" PRIx64 "\n", i, tmp_paddr);
//     //     }
//     // }
//     fprintf(stdout, "[XOWMON] trying physical for 0xe66000\n");
//     if (VMI_FAILURE == vmi_pagetable_lookup(vmi, info->regs->cr3, test_addr, &test_paddr))
//     {
//     fprintf(stdout, "[XOWMON] trying physical for 0xe66000 fail\n");
//     }
//     fprintf(stdout, "[XOWMON] trying physical for 0xe66000 end %" PRIx64 "\n", test_paddr);
//
//     fprintf(stdout, "drakvuf info: %d\n", drakvuf_get_page_mode(drakvuf));
//     // repl_start(drakvuf, info);
//
//
//     drakvuf_release_vmi(drakvuf);
//     return VMI_EVENT_RESPONSE_NONE;
// }
//
// /*
//  * CB for when memory is actually accessed with writeute permissions.
//  */
// static event_response_t allocate_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
// {
//     addr_t base_addr_ptr = drakvuf_get_function_argument(drakvuf, info, 2);
//     addr_t base_addr;
//     addr_t size_ptr = drakvuf_get_function_argument(drakvuf, info, 4);
//     uint32_t size;
//     uint32_t protect = drakvuf_get_function_argument(drakvuf, info, 6);
//
//     vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
//     fprintf(stdout, "[XOWMON] allocate cb values base_addr_ptr: %" PRIx64 "\n", base_addr_ptr);
//
//     access_context_t ctx =
//     {
//         .translate_mechanism = VMI_TM_PROCESS_DTB,
//         .dtb = info->regs->cr3,
//         .addr = base_addr_ptr
//     };
//
//     if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &base_addr))
//     {
//         fprintf(stdout, "[XOWMON] fail get base addr\n");
//     }
//
//     ctx.addr = size_ptr;
//     if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &size))
//     {
//         fprintf(stdout, "[XOWMON] fail get size\n");
//     }
//
//     addr_t paddr;
//     if (VMI_FAILURE == vmi_translate_uv2p(vmi, base_addr, info->proc_data.pid, &paddr))
//     {
//         // fprintf(stdout, "[XOWMON] fail translate alloc base to physical\n");
//     }
//
//     fprintf(stdout, "[XOWMON] allocate base: %" PRIx64 " size: %" PRIx32 " paddr: %" PRIx64 "\n", base_addr, size, paddr);
//
//     std::vector< std::unique_ptr < ArgumentPrinter > > arg_vec1;
//     arg_vec1.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter()));
//     arg_vec1.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter()));
//     arg_vec1.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter()));
//     arg_vec1.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter()));
//     arg_vec1.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter()));
//     arg_vec1.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter()));
//     return_hook_target_entry_t* ret_target = new (std::nothrow) return_hook_target_entry_t(info->proc_data.pid, info->trap->data, arg_vec1);
//
//     for (size_t i = 1; i <= ret_target->argument_printers.size(); i++)
//     {
//         uint64_t argument = drakvuf_get_function_argument(drakvuf, info, i);
//         ret_target->arguments.push_back(argument);
//     }
//
//     drakvuf_release_vmi(drakvuf);
//     return trap_on_return(drakvuf, info, allocate_ret_cb, ret_target);
// }
//
// /*
//  * CB for when memory is actually accessed with execute permissions.
//  */
//
// static event_response_t virtual_protect_exec_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
// {
//     vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
//     fprintf(stdout, "[XOWMON] virtual protect exec cb gfn: %" PRIx64 " pa: %" PRIx64 " rip: %" PRIx64 " @@@ \n",
//             info->trap->memaccess.gfn, info->trap_pa,info->regs->rip);
//
//     access_context_t ctx =
//     {
//         .translate_mechanism = VMI_TM_PROCESS_DTB,
//         .dtb = info->regs->cr3,
//         .addr = info->regs->rip
//     };
//
//     uint8_t code[4];
//     for (int i = 0; i < 4; i++)
//     {
//         ctx.addr = info->regs->rip + i;
//         if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &code[i]))
//         {
//             fprintf(stdout, "[XOWMON] failed to get code \n");
//         }
//     }
//     fprintf(stdout, "XOWMON code \n");
//     for (int i = 0; i < 4; i++)
//     {
//         fprintf(stdout, "%02x ", code[i]);
//     }
//     fprintf(stdout, "\n");
//
//
//     drakvuf_release_vmi(drakvuf);
//     return VMI_EVENT_RESPONSE_NONE;
// }
//
// /*
//  * Keep track of write permissions, then make a memory hook cb on memory access with execute
//  */
// static event_response_t virtual_protect_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
// {
//     hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;
//     xowmon* plugin = (xowmon*) target->plugin;
//
//     fprintf(stdout, "[XOWMON] virtual protect cb @@@ \n");
//
//     addr_t base_addr = drakvuf_get_function_argument(drakvuf, info, 1);
// //    addr_t base_addr;
//     uint64_t size = drakvuf_get_function_argument(drakvuf, info, 2);
//     uint32_t newprotect = drakvuf_get_function_argument(drakvuf, info, 3);
//
//     if ((newprotect & (0x40 | 0x80 | 0x04 | 0x8 )) > 0) {
//         fprintf(stdout, "[XOWMON] virtual protect write\n");
//     } else {
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     fprintf(stdout, "[XOWMON] virtual protect base %" PRIx64 " size: %" PRIx64 " newprotect: %" PRIx32"\n",
//             base_addr, size, newprotect);
//
//     vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
//
//     access_context_t ctx =
//     {
//         .translate_mechanism = VMI_TM_PROCESS_DTB,
//         .dtb = info->regs->cr3,
//         .addr = base_addr
//     };
// //
// //    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &base_addr))
// //    {
// //        fprintf(stdout, "[XOWMON] failed to read base virtual address: %" PRIx64 "\n", base_addr_ptr);
// //        drakvuf_release_vmi(drakvuf);
// //        return VMI_EVENT_RESPONSE_NONE;
// //    }
//
// //     addr_t paddr;
// //     if (VMI_FAILURE == vmi_translate_uv2p(vmi, base_addr, info->proc_data.pid, &paddr))
// //     {
// //         fprintf(stdout, "[XOWMON] failed to get physical address: %" PRIx64 " pid %" PRIi32 "\n", base_addr, info->proc_data.pid);
// //         drakvuf_release_vmi(drakvuf);
// //         return VMI_EVENT_RESPONSE_NONE;
// //     } else {
// //         fprintf(stdout, "[XOWMON] physical address: %" PRIx64 " is: %" PRIx64 "\n", base_addr, paddr);
// //     }
//
//     // TODO: try to read the contents of that address to see what is inside that memory
//
//     mmvad_info_t mmvad;
//     if (!drakvuf_find_mmvad(drakvuf, info->proc_data.base_addr, base_addr, &mmvad))
//     {
//         fprintf(stdout, "[XOWMON] failed to find mmvad for memory passsed \n");
//         drakvuf_release_vmi(drakvuf);
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     addr_t gfn_test[2];
//
//     if (VMI_FAILURE == vmi_pagetable_lookup(vmi, info->regs->cr3, base_addr, &gfn_test[0]) ||
//         VMI_FAILURE == vmi_pagetable_lookup(vmi, info->regs->cr3, base_addr + size, &gfn_test[1]))
//     {
//         fprintf(stdout, "[XOWMON] fail to lookup pagetables here \n");
//     } else {
//         fprintf(stdout, "[XOWMON] gfn1 %" PRIx64 " gfn2 %" PRIx64 "\n", gfn_test[0], gfn_test[1]);
//         fprintf(stdout, "[XOWMON] self test pagetables\n");
//
//         if (VMI_PM_IA32E == drakvuf_get_page_mode(drakvuf))
//         {
//             fprintf(stdout, "[XOWMON] linear addr: %" PRIx64 "\n", base_addr);
//             addr_t pml4 = info->regs->cr3;
//             addr_t pml4e;
//             addr_t pdp;
//             addr_t pdpte;
//             addr_t pd;
//             addr_t pde;
//             addr_t pt;
//             addr_t pte;
//             addr_t self_gfn;
//             bool fail = false;
//             // offset 1 (0 - 11)
//             addr_t offset_1 = base_addr & 0xfff;
//             fprintf(stdout, "[XOWMON] offset 1: %" PRIx64 "\n", offset_1);
//             // offset 2 (12 - 20)
//             addr_t offset_2 = (base_addr >> 12) & (0x1ff);
//             fprintf(stdout, "[XOWMON] offset 2: %" PRIx64 "\n", offset_2);
//             // offset 3 (21 - 29)
//             addr_t offset_3 = (base_addr >> 21) & (0x1ff);
//             fprintf(stdout, "[XOWMON] offset 3: %" PRIx64 "\n", offset_3);
//             // offset 4 (30 - 38)
//             addr_t offset_4 = (base_addr >> 30) & (0x1ff);
//             fprintf(stdout, "[XOWMON] offset 4: %" PRIx64 "\n", offset_4);
//             // offset 5 (39 - 47)
//             addr_t offset_5 = (base_addr >> 39) & (0x1ff);
//             fprintf(stdout, "[XOWMON] offset 5: %" PRIx64 "\n", offset_5);
//             // cr3 is the pml4 pointer (drop the last 12 bits)
//
//
//
//             if (!fail) {  pml4e = (((pml4 >> 12) & 0xffffffffff) << 12) + (offset_5 << 3); }
//             if (!fail && VMI_FAILURE == vmi_read_64_pa(vmi, pml4e, &pdp)) { fprintf(stdout, "[XOWMON] test fail 1"); fail = true;}
//             else { fprintf(stdout, "[XOWMON] pml4e: %" PRIx64 "\n", pml4e); }
//             if (!fail) {  pdpte = (((pdp  >> 12) & 0xffffffffff) << 12) + (offset_4 << 3); }
//             if (!fail && VMI_FAILURE == vmi_read_64_pa(vmi, pdpte, &pd)) { fprintf(stdout, "[XOWMON] test fail 2"); fail = true;}
//             else { fprintf(stdout, "[XOWMON] pdpte: %" PRIx64 "\n", pdpte); }
//             if (!fail) {  pde   = (((pd   >> 12) & 0xffffffffff) << 12) + (offset_3 << 3); }
//             if (!fail && VMI_FAILURE == vmi_read_64_pa(vmi, pde, &pt)) { fprintf(stdout, "[XOWMON] test fail 3"); fail = true;}
//             else { fprintf(stdout, "[XOWMON] pde: %" PRIx64 "\n", pde); }
//             if (!fail) {  pte   = (((pt   >> 12) & 0xffffffffff) << 12) + (offset_2 << 3); }
//             if (!fail && VMI_FAILURE == vmi_read_64_pa(vmi, pte, &self_gfn)) { fprintf(stdout, "[XOWMON] test fail 4"); fail = true;}
//             else { fprintf(stdout, "[XOWMON] pte: %" PRIx64 "\n", pte); }
//             if (!fail) { self_gfn = (((self_gfn >> 12) & 0xffffffffff) << 12); fprintf(stdout, "[XOWMON] test pass? %" PRIx64 "\n", self_gfn); }
//
//
//             // if (!fail && VMI_FAILURE == vmi_read_64_pa(vmi, ((pml4 >> 12) + (offset_5 >> 3)), &pdp)) { fprintf(stdout, "[XOWMON] test fail 1\n"); fail = true; }
//             // else { fprintf(stdout, "[XOWMON] pdp: %" PRIx64 "\n", pdp); pdp = pdp & 0xffffffff; }
//             // if (!fail && VMI_FAILURE == vmi_read_64_pa(vmi, ((pdp & 0xfffffffffffff000) + (offset_4 >> 3)), &pd))   { fprintf(stdout, "[XOWMON] test fail 2\n"); fail = true; }
//             // else { fprintf(stdout, "[XOWMON] pd: %" PRIx64 "\n", pd); pd = pd & 0xffffffff; }
//             // if (!fail && VMI_FAILURE == vmi_read_64_pa(vmi, ((pd & 0xfffffffffffff000) + (offset_3 >> 3)), &pt))    { fprintf(stdout, "[XOWMON] test fail 3\n"); fail = true; }
//             // else { fprintf(stdout, "[XOWMON] pt: %" PRIx64 "\n", pt); pt = pt & 0xffffffff; }
//             // if (!fail && VMI_FAILURE == vmi_read_64_pa(vmi, ((pt & 0xfffffffffffff000) + (offset_2 >> 3)), &pte))   { fprintf(stdout, "[XOWMON] test fail 4\n"); fail = true; }
//             // else { fprintf(stdout, "[XOWMON] pte: %" PRIx64 "\n", pte); pte = pte & 0xffffffff; }
//             // if (!fail) { fprintf(stdout, "[XOWMON] gfn: %" PRIx64 "\n", pte); }
//         }
//     }
//
//     ctx.addr = base_addr;
//     uint16_t magic;
//     char* magic_c = (char*)&magic;
//
//     if (VMI_SUCCESS != vmi_read_16(vmi, &ctx, &magic))
//     {
//         drakvuf_release_vmi(drakvuf);
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     if (magic_c[0] == 'M' && magic_c[1] == 'Z')
//     {
//         ctx.addr = mmvad.starting_vpn << 12;
//         size_t len_bytes = (mmvad.ending_vpn - mmvad.starting_vpn + 1) * VMI_PS_4KB;
//     } else {
//         fprintf(stdout, "[XOWMON] fail not MZ %02x %02x\n", magic_c[0], magic_c[1] );
//         drakvuf_release_vmi(drakvuf);
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     uint32_t num_pages = mmvad.ending_vpn - mmvad.starting_vpn + 1;
//     addr_t gfn[num_pages];
//
//     fprintf(stdout, "[XOWMON] num pages %d\n", num_pages);
//
//     for (int i = 0 ; i < num_pages; i++)
//     {
//         if (VMI_FAILURE == vmi_pagetable_lookup(vmi, info->regs->cr3, ((mmvad.starting_vpn + i) << 12), &gfn[i]))
//         {
//             fprintf(stdout, "[XOWMON] vpn to gfn lookup failed %d\n", i);
//         } else {
//             // TODO: if gfn is already tracked by this plugin, ignore
//
//             addr_t* tmp_gfn = (addr_t*) malloc(sizeof(addr_t));
//             memcpy(tmp_gfn, &gfn[i], sizeof(addr_t));
//             if (!g_hash_table_contains(plugin->gfn_tracker, &gfn[i])) {
//                 fprintf(stdout, "[XOWMON] vpn: %" PRIx64 " gfn %" PRIx64 "\n", (mmvad.starting_vpn + i), gfn[i]);
//                 g_hash_table_add(plugin->gfn_tracker, tmp_gfn);
//             } else { free(tmp_gfn); continue; }
//
//             /*
//              * Trap on mem execute. Need to make sure that it's actually the write address too.
//              */
//             drakvuf_trap_t* mem_exec = (drakvuf_trap_t*) malloc(sizeof(drakvuf_trap_t));
//             mem_exec->cb = virtual_protect_exec_cb;
//             mem_exec->data = (void*) plugin;
//             mem_exec->type = MEMACCESS;
//             mem_exec->memaccess.gfn = gfn[i] >> 12;
//             mem_exec->memaccess.type = PRE;
//             mem_exec->memaccess.access = VMI_MEMACCESS_X;
//
//             if (!drakvuf_add_trap(drakvuf, mem_exec))
//             {
//                 fprintf(stdout, "[XOWMON] failed to register memacces trap\n");
//             }
//         }
//     }
//     access_context_t ctx2 =
//     {
//         .translate_mechanism = VMI_TM_PROCESS_DTB,
//         .dtb = info->regs->cr3,
//         .addr = base_addr
//     };
//
//     uint8_t code[200];
//     for (int i = 0; i < 200; i++)
//     {
//         ctx2.addr = base_addr + i;
//         if (VMI_FAILURE == vmi_read_8(vmi, &ctx2, &code[i]))
//         {
//             fprintf(stdout, "[XOWMON] failed to get code \n");
//         }
//     }
//     fprintf(stdout, "XOWMON code \n");
//     for (int i = 0; i < 200; i++)
//     {
//         fprintf(stdout, "%02x ", code[i]);
//     }
//     fprintf(stdout, "\n");
//
//     size_t bytes_read;
//     uint8_t code2[200];
//     memset(code2, 0, 200);
//     if (VMI_FAILURE == vmi_read_pa(vmi, paddr, 200, &code2, &bytes_read))
//     {
//         fprintf(stdout, "[XOWMON] failed to get code2 from PA\n");
//     };
//
//     fprintf(stdout, "XOWMON code2 \n");
//     for (int i = 0; i < 200; i++)
//     {
//         fprintf(stdout, "%02x ", code2[i]);
//     }
//     fprintf(stdout, "\n");
//
//
//
//     drakvuf_release_vmi(drakvuf);
//     return VMI_EVENT_RESPONSE_NONE;
// }
//
// /*
//  * Redirects hooks to correct call backs
//  */
// static event_response_t usermode_handler_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
// {
//     hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;
//     if (strstr(target->target_name.c_str(), "VirtualProtect") != 0)
//     {
//         return virtual_protect_cb(drakvuf, info);
//     }
//     // else if (strstr(target->target_name.c_str(), "NtAllocateVirtualMemory") != 0)
//     // {
//     //     return allocate_cb(drakvuf, info);
//     // }
//     return VMI_EVENT_RESPONSE_NONE;
// }
//
// static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
// {
//     hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;
//
//     if (target->pid != info->proc_data.pid)
//         return VMI_EVENT_RESPONSE_NONE;
//
//     vmi_lock_guard lg(drakvuf);
//     vmi_v2pcache_flush(lg.vmi, info->regs->cr3);
//
//     bool is_syswow = drakvuf_is_wow64(drakvuf, info);
//
//     access_context_t ctx =
//             {
//                     .translate_mechanism = VMI_TM_PROCESS_DTB,
//                     .dtb = info->regs->cr3,
//                     .addr = info->regs->rsp
//             };
//
//     bool success = false;
//     addr_t ret_addr = 0;
//
//     if (is_syswow)
//         success = (vmi_read_32(lg.vmi, &ctx, (uint32_t*)&ret_addr) == VMI_SUCCESS);
//     else
//         success = (vmi_read_64(lg.vmi, &ctx, &ret_addr) == VMI_SUCCESS);
//
//     if (!success)
//     {
//         PRINT_DEBUG("[XOWMON-USER] Failed to read return address from the stack.\n");
//     return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     return_hook_target_entry_t* ret_target = new (std::nothrow) return_hook_target_entry_t(target->pid, target->plugin, target->argument_printers);
//
//     if (!ret_target)
//     {
//         PRINT_DEBUG("[XOWMON-USER] Failed to allocate memory for return_hook_target_entry_t\n");
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     drakvuf_trap_t* trap = new (std::nothrow) drakvuf_trap_t;
//
//     if (!trap)
//     {
//         PRINT_DEBUG("[XOWMON-USER] Failed to allocate memory for drakvuf_trap_t\n");
//         delete ret_target;
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     for (size_t i = 1; i <= target->argument_printers.size(); i++)
//     {
//         uint64_t argument = drakvuf_get_function_argument(drakvuf, info, i);
//         ret_target->arguments.push_back(argument);
//     }
//
//     addr_t paddr;
//
//     if ( VMI_SUCCESS != vmi_pagetable_lookup(lg.vmi, info->regs->cr3, ret_addr, &paddr) )
//     {
//         delete trap;
//         delete ret_target;
//         return VMI_EVENT_RESPONSE_NONE;
//     }
//
//     trap->type = BREAKPOINT;
//     trap->name = target->target_name.c_str();
//     trap->cb = usermode_return_hook_cb;
//     trap->data = ret_target;
//     trap->breakpoint.lookup_type = LOOKUP_DTB;
//     trap->breakpoint.dtb = info->regs->cr3;
//     trap->breakpoint.addr_type = ADDR_VA;
//     trap->breakpoint.addr = ret_addr;
//
//     if (drakvuf_add_trap(drakvuf, trap))
//     {
//         ret_target->trap = trap;
//     }
//     else
//     {
//         PRINT_DEBUG("[XOWMON-USER] Failed to add trap :(\n");
//         delete trap;
//         delete ret_target;
//     }
//
//     return VMI_EVENT_RESPONSE_NONE;
// }
//
// static void on_dll_discovered(drakvuf_t drakvuf, const dll_view_t* dll, void* extra)
// {
//     xowmon* plugin = (xowmon*)extra;
//
//     vmi_lock_guard lg(drakvuf);
//     unicode_string_t* dll_name = drakvuf_read_unicode_va(lg.vmi, dll->mmvad.file_name_ptr, 0);
//
//     if (dll_name && dll_name->contents)
//     {
//
//         for (auto const& wanted_hook : plugin->wanted_hooks)
//         {
//             if (strstr((const char*)dll_name->contents, wanted_hook.dll_name.c_str()) != 0)
//             {
//                 drakvuf_request_usermode_hook(drakvuf, dll, wanted_hook.function_name.c_str(), usermode_handler_cb, wanted_hook.argument_printers, plugin);
//             }
//         }
//     }
//
//     if (dll_name)
//         vmi_free_unicode_str(dll_name);
// }
//
// static void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, void* extra)
// {
//     PRINT_DEBUG("[XOWMON] DLL hooked - done\n");
// }

static event_response_t execute_trap_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    fprintf(stdout, "fail 7\n");
    fprintf(stdout, "[xowmon] execute trap pa: %" PRIx64 " rip: %" PRIx64 "\n", info->trap_pa, info->regs->rip);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t rescan_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    // get the rescan list
    // call recurse rescan
    fprintf(stdout, "rescan cb\n");
    xowmon* plugin = (xowmon*) info->trap->data;
    addr_t* trap_pa;
    addr_t gfn;
    uint8_t* level;
    addr_t entry;
    addr_t next_gfn;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    fprintf(stdout, "fail 0\n");
    for (GSList* i = plugin->rescan_list; i != NULL; i = i->next)
    {
        // read the trap pa to get the next gfn, do the recurse add
        trap_pa = (addr_t*) i->data;
        if (VMI_FAILURE == vmi_read_64_pa(vmi, *trap_pa, &entry)) { fprintf(stderr, "rescan fail @ %" PRIx64 "\n", *trap_pa); continue; }
        gfn = *trap_pa >> 12;
        level = (uint8_t*) g_hash_table_lookup(plugin->gfn_pagetable_tracker, &gfn);
        // validate the entry, if good, then recurse on the entry's specified gfn
        next_gfn = (entry & (~0ul >> (64 - plugin->maxphyaddr))) >> 12;
        if ( !(entry & 0x1) || !next_gfn) { continue; }
        // level - 1 beacuse it's the phy addr of the entry of the current page
        recurse_create_page_table_traps(drakvuf, vmi, plugin, next_gfn, *level - 1);
        g_free(trap_pa);
    }
    plugin->rescan_list = NULL; // reset the list
    drakvuf_release_vmi(drakvuf);
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
    // drakvuf_trap_t* tmp_trap;

    fprintf(stdout, "write trap cb gfn %" PRIx64 "\n", gfn);

    // vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    drakvuf_lock_and_get_vmi(drakvuf);

    level = (uint8_t*) g_hash_table_lookup(plugin->gfn_pagetable_tracker, &gfn);
    if (level == NULL) { fprintf(stdout, "write trap get level failed gfn %" PRIx64 "\n", gfn); goto done;}
    // fprintf(stdout, "write trap cb plugin->pid %d proc_data.pid %d gfn %" PRIx64 " level %d\n", plugin->pid, info->proc_data.pid, gfn, *level);

    // the page we are tracking does not correspond to sample.exe -> stop tracking
    if (info->proc_data.pid != plugin->pid)
    {
        fprintf(stdout, "bad pid gfn %" PRIx64 "\n", gfn);
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
        execute_trap->type = MEMACCESS;
        execute_trap->cb = execute_trap_cb;
        execute_trap->data = plugin;
        execute_trap->memaccess.gfn = gfn;
        // TODO: pre or post here? post gives us some errors, need to debug drakvuf for this
        execute_trap->memaccess.type = PRE;
        execute_trap->memaccess.access = VMI_MEMACCESS_X;
        if (!drakvuf_add_trap(drakvuf, execute_trap))
        {
            fprintf(stderr, "[XOWMON] cannot add execute trap gfn: %" PRIx64 "\n", gfn);
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
        fprintf(stdout, "[xowmon] write to page level >= 1 pa: %" PRIx64 "\n", info->trap_pa);
        plugin->rescan_list = g_slist_prepend(plugin->rescan_list, g_memdup(&info->trap_pa, sizeof(addr_t)));
        // try reading rip instruction
        // access_context_t ctx =
        // {
        //     .translate_mechanism = VMI_TM_PROCESS_DTB,
        //     .dtb = info->regs->cr3,
        //     .addr = info->regs->rip
        // };

        // uint64_t instr;
        // if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &instr))
        // {
        //     fprintf(stdout, "fail to get rip code\n");
        // }
        // fprintf(stdout, "rip code found %" PRIx64 "\n", instr);
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
    if (g_hash_table_contains(plugin->write_traps, &gfn)) { fprintf(stdout, "write trap repeat %" PRIx64 "\n", gfn); return; }
    if (g_hash_table_contains(plugin->execute_traps, &gfn)) { fprintf(stdout, "exec trap repeat %" PRIx64 "\n", gfn); return; }
    drakvuf_trap_t* write_trap = (drakvuf_trap_t*) malloc(sizeof(drakvuf_trap_t));
    write_trap->type = MEMACCESS;
    write_trap->cb = write_trap_cb;
    write_trap->data = plugin;
    write_trap->memaccess.gfn = gfn;
    // TODO: pre or post here? post gives us some errors, need to debug drakvuf for this
    write_trap->memaccess.type = PRE;
    write_trap->memaccess.access = VMI_MEMACCESS_W;
    if (!drakvuf_add_trap(drakvuf, write_trap)) {
        fprintf(stderr, "[XOWMON] cannot add write trap gfn: %" PRIx64 "\n", gfn);
        free(write_trap);
        return;
    }
    // fprintf(stdout, "[xowmon] gfn %" PRIx64 " level %d\n", gfn, level);

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
            fprintf(stderr, "[XOWMON] fail recurse page table trap gfn: %" PRIx64 " index: %d level: %" PRIu32 "\n", gfn, i, level);
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

    // remove cr3 trap
    drakvuf_remove_trap(drakvuf, info->trap, nullptr);
    plugin->pid = info->proc_data.pid;

    // add new cr3 trap that does rescan of pagetables
    plugin->cr3_trap.type = REGISTER;
    plugin->cr3_trap.cb = rescan_cb;
    plugin->cr3_trap.reg = CR3;
    plugin->cr3_trap.data = plugin;
    if (!drakvuf_add_trap(drakvuf, &plugin->cr3_trap))
    {
        fprintf(stderr, "[XOWMON] failed to add rescan cr3 trap\n");
    }

    gfn = info->regs->cr3 >> 12;
    fprintf(stdout, "[xowmon] start recurse pagetables\n");
    recurse_create_page_table_traps(drakvuf, vmi, plugin, gfn, 4);
    fprintf(stdout, "[xowmon] done recurse pagetables\n");

done:
    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

xowmon::xowmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    setbuf(stdout, NULL);

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

    this->cr3_trap.type = REGISTER;
    this->cr3_trap.cb = cr3_cb;
    this->cr3_trap.reg = CR3;
    this->cr3_trap.data = (void*) this;
    if (!drakvuf_add_trap(drakvuf, &this->cr3_trap))
    {
        fprintf(stderr, "[XOWMON] failed to add cr3 trap\n");
    }
}

xowmon::~xowmon()
{
}

