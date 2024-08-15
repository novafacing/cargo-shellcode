#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic_handle(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

unsafe fn write(fd: u32, bytes: &[u8]) -> isize {
    let mut ret: isize;
    let n: isize = 1;

    asm! {
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") fd,
        in("rsi") bytes.as_ptr(),
        in("rdx") bytes.len(),
        lateout("rcx") _, // rcx is used to store old rip
        lateout("r11") _, // r11 is used to store old rflags
        options(nostack, preserves_flags)
    };

    ret
}

#[no_mangle]
pub unsafe extern "C" fn _start() {
    const MESSAGE: &str = "Hello, World!\n";
    unsafe { write(1, MESSAGE.as_bytes()) };
}
