#![warn(rust_2018_idioms)]

#[macro_use]
extern crate log;

use std::fs;
use std::ops::Range;
use std::path::PathBuf;

use goblin::pe::PE;
use goblin::Object;
use number_prefix::NumberPrefix;
use structopt::StructOpt;

use pattern_based_deobfuscator::nasm_assemble;
use pattern_based_deobfuscator::pattern::*;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Verbose output
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbosity: u8,
    /// Disable output of deobfuscated binary
    #[structopt(short = "n", long = "no-output")]
    no_output: bool,
    /// The pattern database to use
    #[structopt(
        short = "d",
        long = "database",
        parse(from_os_str),
        default_value = "pattern_database.json"
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

    let pattern_database =
        pattern_based_deobfuscator::load_pattern_database_from_json(opt.pattern_database)
            .expect("failed to parse pattern database");

    let buffer = fs::read(&opt.input).unwrap();
    let mut deobfuscated_binary = buffer.clone();
    let mut spans = match Object::parse(&buffer).unwrap() {
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

    let code_size = match NumberPrefix::binary(
        spans.iter().map(|span| span.code.len()).sum::<usize>() as f64,
    ) {
        NumberPrefix::Standalone(bytes) => format!("{} bytes", bytes),
        NumberPrefix::Prefixed(prefix, n) => format!("{:.2} {}B", n, prefix),
    };

    println!("Combined length of code sections: {}", code_size);
    let mut found_total_total = 0;
    let mut replaced_total_total = 0;
    let mut found_total;
    let mut replaced_total = 1;
    let mut pass_n = 0;

    while replaced_total > 0 {
        found_total = 0;
        replaced_total = 0;
        pass_n += 1;
        println!("================== Pass {} ==================", pass_n);

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
            for span in &mut spans {
                for (instantiated_variables, start, end) in
                    &obfuscation_pattern_matcher.match_against(&span.code)
                {
                    found += 1;

                    if opt.verbosity >= 2 {
                        println!(
                            "Found pattern {} ({}): 0x{:x} - 0x{:x}",
                            pattern_n,
                            found,
                            start + span.vaddr,
                            end + span.vaddr
                        );
                    }

                    if opt.no_output {
                        continue;
                    }

                    let mut replacement_asm = pattern
                        .replacement()
                        .iter()
                        .map(InstructionPattern::pattern)
                        .collect::<Vec<_>>()
                        .join("\n");

                    trace!("Variable instantiations: {:?}", instantiated_variables);

                    for instantiated_variable in instantiated_variables {
                        let variable = instantiated_variable.as_variable();
                        let value = instantiated_variable.value();
                        replacement_asm = replacement_asm.replace(&variable.to_string(), &value);
                    }

                    // let offset = span.range_in_file.start;
                    match nasm_assemble(&replacement_asm, *start as u64 + span.vaddr as u64) {
                        Ok(mut asm) => {
                            if asm.len() > end - start {
                                warn!(
                                    "Can't replace pattern as replacement is larger than original!"
                                );
                            }
                            asm.resize(end - start, 0x90); // 0x90 = xchg eax, eax = nop
                            span.code.splice(start..end, asm.into_iter());
                            replaced += 1;
                        }
                        Err(_) => {
                            warn!(
                                "Failed to assemble replacement:\n{}\n(pattern location: 0x{:x})",
                                replacement_asm,
                                span.vaddr + start
                            );
                        }
                    }
                }
            }

            if opt.verbosity >= 1 {
                println!(
                    "Pattern {} was found {} times and replaced {} times",
                    pattern_n, found, replaced
                );
            }

            found_total += found;
            replaced_total += replaced;

            found_total_total += found;
            replaced_total_total += replaced;
        }

        println!(
            "This pass: found {} pattern occurences of which {} were sucessfully replaced",
            found_total, replaced_total
        );
    }

    println!("=============================================");
    println!(
        "Total: found {} pattern occurences of which {} were sucessfully replaced",
        found_total_total, replaced_total_total
    );

    if opt.no_output {
        return;
    }

    let output = opt.output.unwrap();

    for span in spans {
        let offset = span.range_in_file.start;
        deobfuscated_binary.splice(
            offset..(offset + span.code.len()),
            span.code.iter().cloned(),
        );
    }

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

// fn deobfuscate(spans: &[Span], bi)

struct Span {
    range_in_file: Range<usize>,
    vaddr: usize,
    code: Vec<u8>,
}

fn get_code_segments<'a>(pe: PE<'_>, buffer: &'a [u8]) -> Vec<Span> {
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
                code: code.to_vec(),
                vaddr: section.virtual_address as usize + pe.image_base,
            })
        }
    }
    vec
}
