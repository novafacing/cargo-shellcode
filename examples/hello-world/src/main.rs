#![allow(internal_features)]
#![feature(lang_items)]
#![no_std]
#![no_main]

use core::arch::asm;

#[lang = "eh_personality"]
fn eh_personality() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
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

unsafe fn exit(code: i32) -> ! {
    let n: isize = 60;
    asm! {
        "syscall",
        in("rax") n,
        in("rdi") code,
        options(nostack, noreturn)
    }
}

extern "C" fn main() {
    const MESSAGE: &str = "Hello, World!\n";
    unsafe { write(1, MESSAGE.as_bytes()) };
    // NOTE: Commented out, because this is tested. If you run locally, _start will return but
    // there will be no return address on the stack, so the program will crash, so you should uncomment this exit
    //
    // unsafe { exit(0) };
}

#[no_mangle]
pub unsafe extern "C" fn _start() {
    main()
}
