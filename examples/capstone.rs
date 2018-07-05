extern crate capstone;

use capstone::arch::{ArchDetail, BuildsCapstone, BuildsCapstoneSyntax};
use capstone::prelude::*;
use capstone::InsnDetail;

fn main() {
    let mut cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .unwrap();

    // lea rbp, qword ptr [rip - 0x1b08b9]
    // -0x1b08b9 = 1111_1111_1110_0100_1111_0111_0100_0111
    // target: 140AB8B0B
    let instruction =
        cs.disasm_all(
            &[
                0x48, // 0100_1000 REX.W
                0x8D, // opcode
                0x2D, // 00_101_101 mod/m: register (rbp); [rip + displacement]
                0x47, // 0100_0111 addr
                0xF7, // 1111_0111 addr
                0xE4, // 1110_0100 addr
                0xFF, // 1111_1111 addr
            ],
            0x1_40C6_93BD,
        ).unwrap();
    let instruction = instruction.iter().next().unwrap();

    let detail: InsnDetail = cs.insn_detail(&instruction).unwrap();
    let arch_detail: ArchDetail = detail.arch_detail();
    let ops = arch_detail.operands();

    fn reg_names<T: Iterator<Item = RegId>>(cs: &Capstone, regs: T) -> String {
        let names: Vec<String> = regs.map(|x| cs.reg_name(x).unwrap()).collect();
        names.join(", ")
    }

    let output: &[(&str, String)] = &[
        ("insn id:", format!("{:?}", instruction.id().0)),
        ("bytes:", format!("{:x?}", instruction.bytes())),
        ("read regs:", reg_names(&cs, detail.regs_read())),
        ("write regs:", reg_names(&cs, detail.regs_write())),
    ];

    for &(ref name, ref message) in output.iter() {
        println!("{:4}{:12} {}", "", name, message);
    }

    println!("{:4}operands: {}", "", ops.len());
    for op in ops {
        println!("{:8}{:?}", "", op);
        // if let ArchDetail::X86Detail(x) = detail.arch_detail() {
        //     if let X86OperandType::Reg(reg_id) =
        //     //address size
        //     println!("{:?}", cs.reg_name(reg_id).unwrap());
        // }
    }
}
