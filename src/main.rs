#![feature(iter_intersperse)]
#![feature(iterator_try_collect)]

mod asm;
mod dis;

use asm::{parse_module, MoveAssemblyErrorInner};
use dis::print_module;

use move_binary_format::CompiledModule;
use move_bytecode_verifier::{self, VerifierConfig};

use lalrpop_util::lalrpop_mod;

use std::env::{self};
use std::io::{self, Read, Write};

lalrpop_mod!(pub mvasm);

fn usage(progname: &str) {
    println!("usage: {} asm < <file>", progname);
    println!("usage: {} dis < <file>", progname);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage(&args[0][..]);
        return;
    };

    let mut stdin = io::stdin();
    let mut stdout = std::io::stdout();

    match &args[1][..] {
        "asm" => {
            let mut buf = Vec::new();
            stdin.read_to_end(&mut buf).unwrap();
            let module = match parse_module(&buf) {
                Ok(module) => module,
                Err(err) => {
                    print!("line {}: ", err.line_no);
                    use MoveAssemblyErrorInner::*;
                    match err.inner {
                        InvalidAbility => println!("E0001 invalid ability string"),
                        InvalidNumber => println!("E0002 invalid number"),
                        WrongNumberOfTokens {found, expected} => println!("E0003 wrong number of tokens on line. Expected {}, found {}", expected, found),
                        StructHandleWrongNumberOfTokens {found} => println!("E0004 wrong number of tokens in struct handle. Found {}", found),
                        NotEnoughTokens {found, min} => println!("E0005 not enough tokens on line. Expected at least {}, found {}", min, found),
                        NotUTF8 => println!("E0006 line is not UTF8 decodable"),
                        InvalidStructType => println!("E0007 type of struct is neither \"declared\" nor \"native\""),
                        InvalidInstruction => println!("E0009 invalid instruction"),
                        InvalidBoolean => println!("E0010 invalid boolena"),
                        ExpectedToken {found, expected} => println!("E0011 expected token but found different token. Expected \"{}\", found \"{}\"", String::from_utf8_lossy(expected), String::from_utf8_lossy(&found)),
                        ValueTooLarge => println!("E0011 integer value too large"),
                        ExpectedAcquires => println!("E0012 expected \".acquires\""),
                        ExpectedLocals => println!("E0013 expected \".locals\""),
                        InvalidVisibility {found} => println!("E0014 invalid visibility designator. Found \"{}\"", String::from_utf8_lossy(&found)),
                        InvalidIdentifier => println!("E0015 invalid identifier"),
                        InvalidAddress => println!("E0016 invalid address"),
                        InvalidConstantValue => println!("E0017 invalid constant value"),
                        FieldNameSepNotFound => println!("E0018 expected field name separator."),
                        InvalidMoveVersion => println!("E0019 invalid move version statement."),
                        InvalidSelfModuleHandle => println!("E0020 invalid self module handle"),
                        ExpectedTable => println!("E0021 expected table block at top level."),
                        InvalidTableType {found} => println!("E0022 invalid table type. Found \"{}\"", String::from_utf8_lossy(&found)),
                    };
                    return;
                }
            };
            let mut nbuf = Vec::new();
            module.serialize(&mut nbuf).unwrap();
            stdout.write_all(&nbuf).unwrap();
        }
        "dis" => {
            let mut buf = Vec::new();
            stdin.read_to_end(&mut buf).unwrap();
            let module = CompiledModule::deserialize(&buf[..]).unwrap();
            print_module(&mut stdout, &module).unwrap();
        }
        "verify" => {
            let mut buf = Vec::new();
            stdin.read_to_end(&mut buf).unwrap();
            let module = CompiledModule::deserialize(&buf[..]).unwrap();
            // let res = move_bytecode_verifier::verify_module_unmetered(&module);

            let res = move_bytecode_verifier::verify_module_with_config(
                &VerifierConfig::default(),
                &module,
            );
            println!("{:?}", res);
        }
        _ => usage(&args[0][..]),
    };
}
