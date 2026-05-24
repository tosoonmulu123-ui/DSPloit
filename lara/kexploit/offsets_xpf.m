//
//  offsets_xpf.m
//  DSPloit
//
//  Dynamic offset resolution via XPF.
//  Maps XPF dictionary keys → global offset variables.
//
//  Created by Royan | 2026-05-24
//

#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

#include "offsets_xpf.h"
#include "offsets.h"
#include "xpf.h"

static bool g_dynamic_active = false;
static int g_resolved_count = 0;
static int g_failed_count = 0;

// Mapping: XPF dictionary key → pointer to global offset variable
typedef struct {
    const char *xpf_key;     // Key in XPF offset dictionary
    uint32_t *target;        // Pointer to global offset variable
    bool critical;           // If true, failure = abort dynamic resolution
} xpf_offset_map_t;

// XPF struct offset keys (from XPF's "struct" set)
static const xpf_offset_map_t g_offset_map[] = {
    // Process offsets
    {"kernelStruct.proc.p_list.le_next",        &off_proc_p_list_le_next,       true},
    {"kernelStruct.proc.p_list.le_prev",        &off_proc_p_list_le_prev,       false},
    {"kernelStruct.proc.p_proc_ro",             &off_proc_p_proc_ro,            true},
    {"kernelStruct.proc.p_pid",                 &off_proc_p_pid,                true},
    {"kernelStruct.proc.p_fd",                  &off_proc_p_fd,                 true},
    {"kernelStruct.proc.p_flag",                &off_proc_p_flag,               false},
    {"kernelStruct.proc.p_textvp",              &off_proc_p_textvp,             true},
    {"kernelStruct.proc.p_name",                &off_proc_p_name,               false},
    {"kernelStruct.proc_ro.pr_task",            &off_proc_ro_pr_task,           true},
    {"kernelStruct.proc_ro.p_ucred",            &off_proc_ro_p_ucred,           true},
    
    // Thread offsets
    {"kernelStruct.thread.t_tro",               &off_thread_t_tro,              true},
    {"kernelStruct.thread_ro.tro_proc",         &off_thread_ro_tro_proc,        true},
    {"kernelStruct.thread_ro.tro_task",         &off_thread_ro_tro_task,        true},
    {"kernelStruct.thread.machine.upcb",        &off_thread_machine_upcb,       true},
    {"kernelStruct.thread.machine.contextData", &off_thread_machine_contextdata, false},
    {"kernelStruct.thread.ctid",                &off_thread_ctid,               false},
    {"kernelStruct.thread.options",             &off_thread_options,            false},
    {"kernelStruct.thread.machine.kstackptr",   &off_thread_machine_kstackptr,  true},
    {"kernelStruct.thread.machine.jop_pid",     &off_thread_machine_jop_pid,    false},
    {"kernelStruct.thread.machine.rop_pid",     &off_thread_machine_rop_pid,    false},
    {"kernelStruct.thread.ast",                 &off_thread_ast,                false},
    {"kernelStruct.thread.task_threads.next",   &off_thread_task_threads_next,  true},
    
    // Task offsets
    {"kernelStruct.task.itk_space",             &off_task_itk_space,            true},
    {"kernelStruct.task.threads.next",          &off_task_threads_next,         true},
    {"kernelStruct.task.map",                   &off_task_map,                  true},
    
    // Credential offsets
    {"kernelStruct.ucred.cr_label",             &off_ucred_cr_label,            true},
    
    // File descriptor offsets
    {"kernelStruct.filedesc.fd_ofiles",         &off_filedesc_fd_ofiles,        true},
    {"kernelStruct.filedesc.fd_cdir",           &off_filedesc_fd_cdir,          false},
    {"kernelStruct.fileproc.fp_glob",           &off_fileproc_fp_glob,          true},
    {"kernelStruct.fileglob.fg_data",           &off_fileglob_fg_data,          true},
    {"kernelStruct.fileglob.fg_flag",           &off_fileglob_fg_flag,          false},
    
    // Vnode offsets
    {"kernelStruct.vnode.v_ncchildren.tqh_first", &off_vnode_v_ncchildren_tqh_first, true},
    {"kernelStruct.vnode.v_nclinks.lh_first",   &off_vnode_v_nclinks_lh_first,  false},
    {"kernelStruct.vnode.v_parent",             &off_vnode_v_parent,            true},
    {"kernelStruct.vnode.v_data",               &off_vnode_v_data,              true},
    {"kernelStruct.vnode.v_name",               &off_vnode_v_name,              true},
    {"kernelStruct.vnode.v_usecount",           &off_vnode_v_usecount,          false},
    {"kernelStruct.vnode.v_iocount",            &off_vnode_v_iocount,           false},
    {"kernelStruct.vnode.v_flag",               &off_vnode_v_flag,              false},
    {"kernelStruct.vnode.v_mount",              &off_vnode_v_mount,             true},
    {"kernelStruct.mount.mnt_flag",             &off_mount_mnt_flag,            false},
    
    // Namecache offsets
    {"kernelStruct.namecache.nc_vp",            &off_namecache_nc_vp,           true},
    {"kernelStruct.namecache.nc_child.tqe_next", &off_namecache_nc_child_tqe_next, true},
    
    // IPC offsets
    {"kernelStruct.ipc_space.is_table",         &off_ipc_space_is_table,        true},
    {"kernelStruct.ipc_entry.ie_object",        &off_ipc_entry_ie_object,       true},
    {"kernelStruct.ipc_port.ip_kobject",        &off_ipc_port_ip_kobject,       true},
    
    // Socket offsets (darksword-specific)
    {"kernelStruct.inpcb.inp_list.le_next",     &off_inpcb_inp_list_le_next,    true},
    {"kernelStruct.inpcb.inp_pcbinfo",          &off_inpcb_inp_pcbinfo,         false},
    {"kernelStruct.inpcb.inp_socket",           &off_inpcb_inp_socket,          true},
    {"kernelStruct.inpcb.inp6_icmp6filt",       &off_inpcb_inp_depend6_inp6_icmp6filt, true},
    {"kernelStruct.inpcb.inp6_chksum",          &off_inpcb_inp_depend6_inp6_chksum, false},
    {"kernelStruct.socket.so_usecount",         &off_socket_so_usecount,        false},
    {"kernelStruct.socket.so_proto",            &off_socket_so_proto,           false},
    
    // VM offsets
    {"kernelStruct.vm_map.hdr",                 &off_vm_map_hdr,                false},
    {"kernelStruct.vm_map_header.nentries",     &off_vm_map_header_nentries,    false},
    {"kernelStruct.vm_map_entry.links.next",    &off_vm_map_entry_links_next,   false},
    
    // Label offsets
    {"kernelStruct.label.l_perpolicy.amfi",     &off_label_l_perpolicy_amfi,    false},
    {"kernelStruct.label.l_perpolicy.sandbox",  &off_label_l_perpolicy_sandbox, true},
    
    // Saved state
    {"kernelStruct.arm_saved_state64.lr",       &off_arm_saved_state64_lr,      true},
    {"kernelStruct.arm_saved_state64.pc",       &off_arm_saved_state64_pc,      true},
    
    {NULL, NULL, false} // Sentinel
};

static NSString *kcache_doc_path(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [docs stringByAppendingPathComponent:@"kernelcache"];
}

bool offsets_resolve_dynamic(void) {
    g_resolved_count = 0;
    g_failed_count = 0;
    g_dynamic_active = false;
    
    NSString *kcpath = kcache_doc_path();
    if (!kcpath || ![[NSFileManager defaultManager] fileExistsAtPath:kcpath]) {
        printf("(offsets_xpf) no kernelcache file — cannot resolve dynamically\n");
        return false;
    }
    
    // Validate file size
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:kcpath error:nil];
    NSNumber *fileSize = attrs[NSFileSize];
    if (!fileSize || fileSize.longLongValue < 10 * 1024 * 1024) {
        printf("(offsets_xpf) kernelcache too small (%lld bytes)\n",
               fileSize ? fileSize.longLongValue : 0LL);
        return false;
    }
    
    // Start XPF
    if (xpf_start_with_kernel_path(kcpath.UTF8String) != 0) {
        printf("(offsets_xpf) xpf_start failed: %s\n", xpf_get_error());
        return false;
    }
    
    // Request all offset sets
    const char *sets[] = { "base", "translation", "struct", NULL };
    xpc_object_t dict = xpf_construct_offset_dictionary(sets);
    
    if (!dict) {
        printf("(offsets_xpf) xpf_construct_offset_dictionary failed: %s\n",
               xpf_get_error());
        xpf_stop();
        return false;
    }
    
    printf("(offsets_xpf) XPF dictionary constructed, resolving offsets...\n");
    printf("(offsets_xpf) kernel: %s\n", gXPF.kernelVersionString ?: "unknown");
    printf("(offsets_xpf) base: 0x%llx entry: 0x%llx\n", gXPF.kernelBase, gXPF.kernelEntry);
    
    // Resolve t1sz_boot
    uint64_t resolved_t1sz = xpf_gett1szboot();
    if (resolved_t1sz != 0) {
        t1sz_boot = resolved_t1sz;
        printf("(offsets_xpf) t1sz_boot = 0x%llx\n", t1sz_boot);
    }
    
    // Resolve SMR base
    uint64_t resolved_smr = xpf_item_resolve("kernelConstant.smrBase");
    if (resolved_smr) {
        smr_base = resolved_smr;
        printf("(offsets_xpf) smr_base = 0x%llx\n", smr_base);
    }
    
    // Walk the offset map and resolve each one
    int critical_failures = 0;
    
    for (int i = 0; g_offset_map[i].xpf_key != NULL; i++) {
        const xpf_offset_map_t *entry = &g_offset_map[i];
        
        // Try resolving from XPF
        uint64_t value = xpf_item_resolve(entry->xpf_key);
        
        if (value != 0 && value != (uint64_t)-1) {
            // XPF returns absolute values for struct offsets — they're small
            if (value < 0x10000) {
                *entry->target = (uint32_t)value;
                g_resolved_count++;
            } else {
                // Might be an address, not an offset — skip
                printf("(offsets_xpf) %s = 0x%llx (too large for offset, skipping)\n",
                       entry->xpf_key, value);
                g_failed_count++;
                if (entry->critical) critical_failures++;
            }
        } else {
            // Try alternate key formats
            // XPF sometimes uses different naming conventions
            char alt_key[256];
            snprintf(alt_key, sizeof(alt_key), "struct.%s",
                     entry->xpf_key + strlen("kernelStruct."));
            value = xpf_item_resolve(alt_key);
            
            if (value != 0 && value != (uint64_t)-1 && value < 0x10000) {
                *entry->target = (uint32_t)value;
                g_resolved_count++;
            } else {
                g_failed_count++;
                if (entry->critical) {
                    critical_failures++;
                    printf("(offsets_xpf) CRITICAL: %s not resolved\n", entry->xpf_key);
                }
            }
        }
    }
    
    // Also resolve sizeof_ipc_entry
    uint64_t ipc_entry_size = xpf_item_resolve("kernelStruct.ipc_entry.struct_size");
    if (ipc_entry_size && ipc_entry_size < 0x100) {
        sizeof_ipc_entry = (uint32_t)ipc_entry_size;
        printf("(offsets_xpf) sizeof_ipc_entry = 0x%x\n", sizeof_ipc_entry);
    }
    
    xpf_stop();
    
    printf("(offsets_xpf) resolved: %d, failed: %d (critical: %d)\n",
           g_resolved_count, g_failed_count, critical_failures);
    
    // Consider success if we resolved at least 70% and no critical failures
    int total = g_resolved_count + g_failed_count;
    double ratio = total > 0 ? (double)g_resolved_count / total : 0;
    
    if (critical_failures == 0 && ratio >= 0.5) {
        g_dynamic_active = true;
        printf("(offsets_xpf) ✅ Dynamic offsets active (%.0f%% resolved)\n", ratio * 100);
        
        // Refresh PAC mask
        if (t1sz_boot != 0 && t1sz_boot < 64) {
            extern uint64_t pac_mask;
            pac_mask = ~((1ULL << (64 - t1sz_boot)) - 1ULL);
        }
        
        // Save resolved offsets to UserDefaults for next launch
        savealloffsets();
        
        return true;
    }
    
    printf("(offsets_xpf) ❌ Too many failures — falling back to hardcoded\n");
    g_dynamic_active = false;
    return false;
}

bool offsets_are_dynamic(void) {
    return g_dynamic_active;
}

int offsets_dynamic_count(void) {
    return g_resolved_count;
}

int offsets_failed_count(void) {
    return g_failed_count;
}

uint32_t offsets_xpf_resolve32(const char *xpf_name) {
    if (!xpf_name) return OFFSET_INVALID;
    uint64_t val = xpf_item_resolve(xpf_name);
    if (val == 0 || val == (uint64_t)-1 || val >= 0x10000) return OFFSET_INVALID;
    return (uint32_t)val;
}

uint64_t offsets_xpf_resolve64(const char *xpf_name) {
    if (!xpf_name) return OFFSET_INVALID;
    return xpf_item_resolve(xpf_name);
}

void offsets_dump_all(void) {
    printf("=== OFFSET DUMP (dynamic=%s) ===\n", g_dynamic_active ? "YES" : "NO");
    printf("  t1sz_boot = 0x%llx\n", t1sz_boot);
    printf("  smr_base = 0x%llx\n", smr_base);
    printf("  pac_mask = 0x%llx\n", pac_mask);
    printf("  sizeof_ipc_entry = 0x%x\n", sizeof_ipc_entry);
    printf("  off_proc_p_proc_ro = 0x%x\n", off_proc_p_proc_ro);
    printf("  off_proc_p_pid = 0x%x\n", off_proc_p_pid);
    printf("  off_proc_p_fd = 0x%x\n", off_proc_p_fd);
    printf("  off_proc_p_textvp = 0x%x\n", off_proc_p_textvp);
    printf("  off_thread_t_tro = 0x%x\n", off_thread_t_tro);
    printf("  off_thread_machine_kstackptr = 0x%x\n", off_thread_machine_kstackptr);
    printf("  off_task_itk_space = 0x%x\n", off_task_itk_space);
    printf("  off_task_threads_next = 0x%x\n", off_task_threads_next);
    printf("  off_vnode_v_data = 0x%x\n", off_vnode_v_data);
    printf("  off_vnode_v_name = 0x%x\n", off_vnode_v_name);
    printf("  off_vnode_v_parent = 0x%x\n", off_vnode_v_parent);
    printf("  off_ipc_space_is_table = 0x%x\n", off_ipc_space_is_table);
    printf("  off_inpcb_inp_list_le_next = 0x%x\n", off_inpcb_inp_list_le_next);
    printf("  off_inpcb_inp_depend6_inp6_icmp6filt = 0x%x\n", off_inpcb_inp_depend6_inp6_icmp6filt);
    printf("  off_label_l_perpolicy_sandbox = 0x%x\n", off_label_l_perpolicy_sandbox);
    printf("=== END OFFSET DUMP ===\n");
}
