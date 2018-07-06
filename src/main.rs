extern crate env_logger;
extern crate goblin;
extern crate pattern_based_deobfuscator;
#[macro_use]
extern crate structopt;
extern crate number_prefix;

use std::fs;
use std::path::PathBuf;

use goblin::pe::PE;
use goblin::Object;
use number_prefix::{Prefixed, Standalone};
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

    let pattern_database = pattern_based_deobfuscator::load_pattern_database_from_json(
        opt.pattern_database,
    ).expect("failed to parse pattern database");

    let buffer = fs::read(&opt.input).unwrap();
    let spans = match Object::parse(&buffer).unwrap() {
        Object::PE(pe) => get_code_segments(pe, &buffer),
        Object::Elf(_) | Object::Mach(_) | Object::Archive(_) => {
            unimplemented!("Only PE files are supported atm!");
        }
        Object::Unknown(magic) => panic!("unknown magic: {:#x}", magic),
    };

    println!(
        "Deobfuscating {} using a database of {} patterns...",
        opt.input.display(),
        pattern_database.patterns().len()
    );

    let code_size = match number_prefix::binary_prefix(
        spans.iter().map(|span| span.code.len()).sum::<usize>() as f64,
    ) {
        Standalone(bytes) => format!("{} bytes", bytes),
        Prefixed(prefix, n) => format!("{:.2} {}B", n, prefix),
    };

    println!("Combined length of code sections: {}", code_size);

    let mut found_total = 0;
    let mut replaced_total = 0;

    for (pattern_n, pattern) in pattern_database.patterns().iter().enumerate() {
        let mut found = 0;
        let mut replaced = 0;

        let instruction_patterns = pattern.instruction_patterns().to_vec();
        let obfuscation_pattern_matcher =
            ObfuscationPatternMatcher::new(instruction_patterns).unwrap();
        for span in &spans {
            for (_variables, start, end) in &obfuscation_pattern_matcher.match_against(span.code) {
                found += 1;
                // println!(
                //     "{}: 0x{:x} - 0x{:x}",
                //     i,
                //     start + span.vaddr as usize,
                //     end + span.vaddr as usize
                // );
                // TODO: replace pattern
            }
        }

        if opt.verbose {
            println!(
                "Pattern {} was found {} times and replaced {} times",
                pattern_n, found, replaced
            );
        }

        found_total += found;
        replaced_total += replaced;
    }

    println!(
        "Total: found {} patterns of which {} were sucessfully replaced",
        found_total, replaced_total
    );
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
