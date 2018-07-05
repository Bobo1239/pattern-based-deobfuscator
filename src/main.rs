extern crate env_logger;
extern crate goblin;
extern crate pattern_based_deobfuscator;
#[macro_use]
extern crate structopt;

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use goblin::pe::PE;
use goblin::Object;
use structopt::StructOpt;

use pattern_based_deobfuscator::pattern::*;

#[derive(Debug, StructOpt)]
#[structopt()]
struct Opt {
    /// Verbose output
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
    /// The pattern database to use
    #[structopt(
        short = "d", long = "database", parse(from_os_str), default_value = "pattern_database.json"
    )]
    pattern_database: PathBuf,
    /// Deobfucated output binary; defaults to <input>.deobf.exe
    #[structopt(parse(from_os_str), short = "o", long = "output")]
    output: Option<PathBuf>,
    /// Obfuscated input
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn main() {
    env_logger::init();

    let opt = Opt::from_args();
    println!("{:?}", opt);

    let database = vec![(
        vec!["lea rbp, [rip + $num:var_name1]", "xchg rbp, [rsp]", "ret"], // pattern
        vec!["jmp [rip + $num:var_name1]"],                                // replacement
    )];

    let buffer = fs::read("sample.exe").unwrap();
    let spans = match Object::parse(&buffer).unwrap() {
        Object::PE(pe) => get_code_segments(pe, &buffer),
        Object::Elf(_) | Object::Mach(_) | Object::Archive(_) => {
            unimplemented!("Only PE files are supported atm!");
        }
        Object::Unknown(magic) => panic!("unknown magic: {:#x}", magic),
    };

    let mut i = 1;
    for entry in database {
        let instruction_patterns = entry
            .0
            .iter()
            .map(|s| InstructionPattern::from_str(s).unwrap())
            .collect();
        let obfuscation_pattern_matcher =
            ObfuscationPatternMatcher::new(instruction_patterns).unwrap();
        for span in &spans {
            for (_variables, start, end) in &obfuscation_pattern_matcher.match_against(span.code) {
                println!(
                    "{}: 0x{:x} - 0x{:x}",
                    i,
                    start + span.vaddr as usize,
                    end + span.vaddr as usize
                );
                i += 1;
            }
        }
    }

    println!(
        "length of code sections: {:.2} MB",
        spans.iter().map(|span| span.code.len()).sum::<usize>() as f64 / 1024.0 / 1024.0
    )
}

struct Span<'a> {
    // range_in_file: Range<usize>,
    vaddr: usize,
    code: &'a [u8],
}

fn get_code_segments<'a>(pe: PE, buffer: &'a [u8]) -> Vec<Span<'a>> {
    use goblin::pe::section_table::IMAGE_SCN_CNT_CODE;

    // println!("{:?}", pe.entry);
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
