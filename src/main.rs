extern crate env_logger;
extern crate goblin;
extern crate pattern_based_deobfuscator;
#[macro_use]
extern crate structopt;
extern crate number_prefix;
#[macro_use]
extern crate log;

use std::fs;
use std::ops::Range;
use std::path::PathBuf;

use goblin::pe::PE;
use goblin::Object;
use number_prefix::{Prefixed, Standalone};
use structopt::StructOpt;

use pattern_based_deobfuscator::pattern::*;
use pattern_based_deobfuscator::KeystoneError;

#[derive(Debug, StructOpt)]
#[structopt()]
struct Opt {
    /// Verbose output
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
    /// Disable output of deobfuscated binary
    #[structopt(short = "n", long = "no-output")]
    no_output: bool,
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
    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let mut opt = Opt::from_args();
    if opt.output.is_none() {
        let mut new_file_name = opt.input.file_stem().unwrap().to_owned();
        new_file_name.push(".deobf");
        if let Some(ext) = opt.input.extension() {
            new_file_name.push(".");
            new_file_name.push(ext);
        }
        opt.output = Some(opt.input.with_file_name(new_file_name));
    }

    let pattern_database = pattern_based_deobfuscator::load_pattern_database_from_json(
        opt.pattern_database,
    ).expect("failed to parse pattern database");

    let buffer = fs::read(&opt.input).unwrap();
    let mut deobfuscated_binary = buffer.clone();
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

    for (pattern_n, pattern) in pattern_database
        .patterns()
        .iter()
        .enumerate()
        .map(|(i, x)| (i + 1, x))
    {
        println!("Searching for pattern {}...", pattern_n);
        let mut found = 0;
        let mut replaced = 0;

        let instruction_patterns = pattern.instruction_patterns().to_vec();
        let obfuscation_pattern_matcher =
            ObfuscationPatternMatcher::new(instruction_patterns).unwrap();
        for span in &spans {
            for (instantiated_variables, start, end) in
                &obfuscation_pattern_matcher.match_against(span.code)
            {
                found += 1;

                if opt.verbose {
                    println!(
                        "Found pattern {} ({}): 0x{:x} - 0x{:x}",
                        pattern_n,
                        found,
                        start + span.vaddr as usize,
                        end + span.vaddr as usize
                    );
                }

                if opt.no_output {
                    continue;
                }

                let mut replacement_asm = pattern
                    .replacement()
                    .iter()
                    .map(|isn_pat| isn_pat.pattern())
                    .collect::<Vec<_>>()
                    .join("\n");

                for instantiated_variable in instantiated_variables {
                    let variable = instantiated_variable.as_variable();
                    let value = instantiated_variable.value();
                    replacement_asm = replacement_asm.replace(&variable.to_string(), &value);
                }

                match nasm_assemble(replacement_asm.clone()) {
                    Ok(asm) => {
                        if asm.len() > end - start {
                            warn!("Can't replace pattern as replacement is larger than original!");
                        }
                        let offset = span.range_in_file.start;
                        deobfuscated_binary
                            .splice((offset + start)..(offset + end), asm.into_iter());
                        replaced += 1;
                    }
                    Err(_) => {
                        warn!("Failed to assemble replacement: {}", replacement_asm);
                    }
                }
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

    if opt.no_output {
        return;
    }

    let output = opt.output.unwrap();
    if output.exists() {
        println!("File {} exists already. Overwrite? [y/n]", output.display());
        let stdin = std::io::stdin();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        if input.trim() != "y" {
            println!("Aborted");
            std::process::exit(1)
        }
    }

    fs::write(&output, deobfuscated_binary).unwrap();
    println!("Wrote deobfuscated binary to {}", output.display());
}

// Can't use keystone as it doesn't support NASM syntax: $ (refers to current assembly position)
// TODO: this sucks
fn nasm_assemble(asm: String) -> Result<Vec<u8>, KeystoneError> {
    // FIXME: actually use nasm (need to create temp file as nasm doesn't have a library version?)
    pattern_based_deobfuscator::keystone_assemble(asm).map(|result| result.bytes)
}

struct Span<'a> {
    range_in_file: Range<usize>,
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
            let code = &buffer[range_in_file.clone()];
            vec.push(Span {
                range_in_file,
                code,
                vaddr: section.virtual_address as usize + pe.image_base,
            })
        }
    }
    vec
}
