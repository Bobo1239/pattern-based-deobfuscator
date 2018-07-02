extern crate env_logger;
extern crate goblin;
extern crate regex;
extern crate unhappy_arxan;

use std::fs;

use goblin::pe::PE;
use goblin::Object;
use regex::bytes::Regex;

use unhappy_arxan::pattern::*;

// TODO:
//     - allow user to specify blacklist regions which may not be touched
//     - match pattern; verify variables are actually same content later; avoid pcre
//     - Some instructions have 64 bit immeditates/displacements
//     - how to handle SIB
//     - ignore NOPs when matching pattern (also add NOP patterns which get replaced with a normal NOP)
//     - determine basic blocks (only one entrace/leader) -> simplify jump chains ->
//     - match in these "real" basic blocks (make this a sub-pass)
//     - multi-pass

// NOTE:
//     - LOCK works as Keystone just emits the lock prefix which automatically gets recognized as a prefix for the next instruction

// FUTURE:
//     - pattern consisting of labeled blocks (for switches etc.)
//     - arbitrary NOPs (multiple ways to encode NOP?) between pattern instructions
//         - This will get resolved if we have NOP patterns and multi-pass deobfuscation
//     - Segmented memory addressing
//     - How to generically handle obfuscation which manually loads up e.g. AL,then AH ,and then uses EAX...

// DOCUMENTATION:
//     - Variable operands may not be negated in the pattern specifiation (e.g. `lea rbp, [rip - $num:var_name1]`)
//     - $num only supported for operand/displacement; not usable for e.g. scaled addressing
//     - retn replaced with ret (https://github.com/keystone-engine/keypatch/blob/master/keypatch.py#L541)

fn main() {
    env_logger::init();

    let database = vec![
        (
            vec!["lea rbp, [rip + $num:var_name1]", "xchg rbp, [rsp]", "ret"],
            vec!["jmp [rip + $num:var_name1]"],
        ),
        (vec!["add eax, $num:var"], vec!["add eax, $num:var"]),
    ];

    let buffer = fs::read("sample.exe").unwrap();
    let spans = match Object::parse(&buffer).unwrap() {
        Object::PE(pe) => get_code_segments(pe, &buffer),
        Object::Elf(_) | Object::Mach(_) | Object::Archive(_) => {
            unimplemented!("Only PE files are supported atm!");
        }
        Object::Unknown(magic) => panic!("unknown magic: {:#x}", magic),
    };

    // TODO: disambiguate capture group names for the same variable name
    let mut final_regex = "(?s-u)".to_string();
    for instruction in &database[0].0 {
        println!("instruction: {:?}", instruction);
        let _pattern: InstructionPattern = instruction.parse().expect("Failed to parse pattern!");
        final_regex += "";
        // final_regex += &encodings_to_regex(&pattern.find_encodings().unwrap()); // FIXME
    }

    println!("REGEX: {}", final_regex);
    let final_regex = Regex::new(&final_regex).unwrap();
    for span in spans {
        for (i, matchh) in final_regex.find_iter(&span.code).enumerate() {
            println!(
                "{}: 0x{:x} - 0x{:x}",
                i,
                matchh.start() + span.vaddr as usize,
                matchh.end() + span.vaddr as usize
            );
        }
    }
    println!("REGEX: {}", final_regex);
}

struct Span<'a> {
    // range_in_file: Range<usize>,
    vaddr: usize,
    code: &'a [u8],
}

fn get_code_segments<'a>(pe: PE, buffer: &'a [u8]) -> Vec<Span<'a>> {
    use goblin::pe::section_table::IMAGE_SCN_CNT_CODE;

    println!("{:?}", pe.entry);
    let mut vec = Vec::new();
    for section in pe.sections {
        // println!("{:#x?}", section);
        // println!("{:?}", section.characteristics & IMAGE_SCN_CNT_CODE > 0);
        // println!(
        //     "{:08} {:032b}",
        //     section.name().unwrap(),
        //     section.characteristics
        // );
        if section.characteristics & IMAGE_SCN_CNT_CODE > 0 {
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
