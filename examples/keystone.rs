extern crate keystone;

use keystone::{Arch, Keystone};

fn main() {
    let engine =
        Keystone::new(Arch::X86, keystone::MODE_64).expect("Could not initialize Keystone engine");

    let assemble = |asm: &str| {
        println!("assemble: {:x?}", asm);
        let i = engine.asm(asm.to_string(), 0).unwrap();
        println!("result: {:x?}", i);
    };

    assemble("lea rbp, [rip + 0x87654321]");
    assemble("lea rbp, [rip + 0x03]");
    assemble("add eax, 3");
    assemble("add rip, 0x12345678");
    assemble("lock");
}
