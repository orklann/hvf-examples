#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_arch_vmx.h>
#include <Hypervisor/hv_vmx.h>

#define req(x) { \
  hv_return_t ret = (x); \
  if (ret != HV_SUCCESS) { \
    printf("%s exited with code %d\n", #x, (int)ret); \
    exit(1); \
  } \
}

#define cap2ctrl(cap, ctrl) ((ctrl) | ((cap) & 0xffffffff)) & ((cap) >> 32)
#define VMCS_PRI_PROC_BASED_CTLS_HLT           (1 << 7)

int main() {
  req(hv_vm_create(HV_VM_DEFAULT));

  hv_vcpuid_t vcpu;
  req(hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT));

  uint64_t ctrl_cpu_based;
  req(hv_vmx_vcpu_read_vmcs(vcpu, VMCS_CTRL_CPU_BASED, &ctrl_cpu_based));
  ctrl_cpu_based |= VMCS_PRI_PROC_BASED_CTLS_HLT;
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CPU_BASED, ctrl_cpu_based));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_AR, 0x009B));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xfffff));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_BASE, 0x0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_AR, 0x0093));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xfffff));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_AR, 0x0093));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xfffff));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_AR, 0x0093));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xfffff));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_AR, 0x0093));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xfffff));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_AR, 0x0093));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xfffff));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x10000));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_LIMIT, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_AR, 0x8B));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GDTR_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0));

  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR0, 0x20));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR3, 0x0));
  req(hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR4, 0x2000));

  // loads 0x1234 to ax if in 16-bit mode
  // loads 0x90901234 to eax if in 32-bit mode
  //     mov ax, 0x1234
  //     nop
  //     nop
  //     hlt
  unsigned char code[] = { 0xB8, 0x34, 0x12, 0x90, 0x90, 0xF4 };
  void *vm_mem = valloc(1 << 30);
  memcpy(vm_mem, code, sizeof code);
  req(hv_vm_map(vm_mem, 0, 1 << 30, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC));

  req(hv_vcpu_write_register(vcpu, HV_X86_RIP, 0));
  req(hv_vcpu_write_register(vcpu, HV_X86_RFLAGS, 0x2));
  req(hv_vcpu_write_register(vcpu, HV_X86_RAX, 0));

  for (;;) {
    req(hv_vcpu_run(vcpu));

    uint64_t exit_reason;
    req(hv_vmx_vcpu_read_vmcs(vcpu, VMCS_RO_EXIT_REASON, &exit_reason));
    if (exit_reason == VMX_REASON_EPT_VIOLATION || exit_reason == VMX_REASON_IRQ)
      continue;
    break;
  }

  uint64_t x;
  req(hv_vcpu_read_register(vcpu, HV_X86_RAX, &x));
  printf("rax = 0x%llx\n", x);

  return 0;
}