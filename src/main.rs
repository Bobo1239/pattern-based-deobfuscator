#![allow(unused)]

extern crate capstone;
extern crate goblin;
extern crate keystone;
extern crate regex;

use std::fs::File;
use std::io::Read;
use std::ops::Range;
use std::path::Path;
use std::str::FromStr;

use capstone::arch::x86::X86OperandType;
use capstone::arch::ArchDetail;
use capstone::prelude::*;
use capstone::InsnDetail;
use goblin::pe::PE;
use goblin::Object;
use keystone::{Arch, Keystone, OptionType};
use regex::bytes::Regex;

// TODO: different types of variables in patterns (diferentiate operand size??)
// TODO: allow user to specify blacklist regions which may not be touched
// TODO: match pattern; verify variables are actually same content later; avoid pcre

// 0x140C693BD:
// lea     rbp, loc_140AB8B0B
// xchg    rbp, [rsp]
// retn
// =>
// jmp loc_140AB8B0B

// $mem:var1, $reg: reg1

// jumpchain; check that jump target only gets jumped from here (also check all other addresses in the block)
// basic block only have one entrance/leader...

fn main() {
    let database = vec![(
        // retn replaced with ret
        // See: https://github.com/keystone-engine/keypatch/blob/master/keypatch.py#L541
        vec!["lea rbp, [rip - 0x1b08b9]", "xchg rbp, [rsp]", "ret"],
        "jmp [rip - 0x1b08b9]",
    )];

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .unwrap();

    // lea rbp, qword ptr [rip - 0x1b08b9]
    // -0x1b08b9 = 1111_1111_1110_0100_1111_0111_0100_0111
    // target: 140AB8B0B
    let insns = cs.disasm_all(
        &[
            0x48, // 0100_1000 REX.W
            0x8D, // opcode
            0x2D, // 00_101_101 mod/m: register (rbp); [rip + displacement]
            0x47, // 0100_0111 addr
            0xF7, // 1111_0111 addr
            0xE4, // 1110_0100 addr
            0xFF, // 1111_1111 addr
        ],
        0x140C693BD,
    ).unwrap();
    let i = insns.iter().next().unwrap();

    let detail: InsnDetail = cs.insn_detail(&i).unwrap();
    let arch_detail: ArchDetail = detail.arch_detail();
    let ops = arch_detail.operands();

    fn reg_names<T, I>(cs: &Capstone, regs: T) -> String
    where
        T: Iterator<Item = I>,
        I: Into<RegId>,
    {
        let names: Vec<String> = regs.map(|x| cs.reg_name(x.into()).unwrap()).collect();
        names.join(", ")
    }

    let output: &[(&str, String)] = &[
        ("insn id:", format!("{:?}", i.id().0)),
        ("bytes:", format!("{:x?}", i.bytes())),
        (
            "read regs:",
            reg_names(&cs, cs.read_register_ids(&i).unwrap()),
        ),
        (
            "write regs:",
            reg_names(&cs, cs.write_register_ids(&i).unwrap()),
        ),
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
    // println!("dis: {}", insns.iter().next().unwrap());

    let input = "sample.exe";
    let path = Path::new(input);
    let mut fd = File::open(path).unwrap();
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer).unwrap();
    let spans = match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => {
            panic!("elf: {:#?}", &elf);
        }
        Object::PE(pe) => get_code_segments(pe, &buffer),
        Object::Mach(mach) => {
            panic!("mach: {:#?}", &mach);
        }
        Object::Archive(archive) => {
            panic!("archive: {:#?}", &archive);
        }
        Object::Unknown(magic) => panic!("unknown magic: {:#x}", magic),
    };

    let engine =
        Keystone::new(Arch::X86, keystone::MODE_64).expect("Could not initialize Keystone engine");
    engine
        .option(OptionType::SYNTAX, keystone::OPT_SYNTAX_NASM)
        .expect("Could not set option to nasm syntax");

    let mut regex = "(?-u)".to_string();
    for instruction in &database[0].0 {
        let result = engine
            .asm(instruction.to_string(), 0)
            .expect("Could not assemble");
        for byte in result.bytes {
            regex += &format!(r"\x{:02x}", byte);
        }
    }
    println!("{}", regex);
    // let regex = Regex::new(&regex).unwrap();
    let regex = Regex::new(r"(?-u)\x48\x8d\x2d....\x48\x87\x2c\x24\xc3").unwrap();
    for span in spans {
        for (i, matchh) in regex.find_iter(&span.code).enumerate() {
            println!(
                "{}: 0x{:x} - 0x{:x}",
                i,
                matchh.start() + span.vaddr as usize,
                matchh.end() + span.vaddr as usize
            );
        }
    }

    let i = engine
        .asm("lea rbp, [rip + 0x87654321]".to_string(), 0)
        .expect("Could not assemble");
    println!("{:x?}", i);
    let i = engine
        .asm("lea rbp, [rip + 0x03]".to_string(), 0)
        .expect("Could not assemble");
    println!("{:x?}", i);
    let i = engine
        .asm("add rip, 3".to_string(), 0)
        .expect("Could not assemble");
    println!("{:x?}", i);
    let i = engine
        .asm("add rip, 0x12345678".to_string(), 0)
        .expect("Could not assemble");
    println!("{:x?}", i);
}

// Assuming little-endian

struct Span<'a> {
    // range_in_file: Range<usize>,
    vaddr: usize,
    code: &'a [u8],
}

fn get_code_segments<'a>(pe: PE, buffer: &'a [u8]) -> Vec<Span<'a>> {
    use goblin::pe::section_table::*;

    println!("{:?}", pe.entry);
    let mut vec = Vec::new();
    for section in pe.sections {
        if section.characteristics & IMAGE_SCN_CNT_CODE > 0 {
            // println!("{:#x?}", section);
            // println!("{:?}", section.characteristics & IMAGE_SCN_CNT_CODE > 0);
            // println!(
            //     "{:08} {:032b}",
            //     section.name().unwrap(),
            //     section.characteristics
            // );
            let range_in_file = section.pointer_to_raw_data as usize
                ..(section.pointer_to_raw_data + section.size_of_raw_data) as usize;
            let code = &buffer[range_in_file];
            vec.push(Span {
                // range_in_file,
                code,
                vaddr: section.virtual_address as usize + pe.image_base,
            })
        }
    }
    vec
}
