#![feature(iter_intersperse)]
#![feature(slice_take)]
#![feature(byte_slice_trim_ascii)]
#![feature(iterator_try_collect)]

mod dis;
mod asm;

use dis::print_module;
use asm::parse_module;

use move_binary_format::CompiledModule;

use lalrpop_util::lalrpop_mod;

use std::io::{self, Write, Read};
use std::env::{self, args};

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
            let module = parse_module(&buf).unwrap();
            let mut nbuf = Vec::new();
            module.serialize(&mut nbuf).unwrap();
            stdout.write_all(&nbuf).unwrap();
        },
        "dis" => {
            let mut buf = Vec::new();
            stdin.read_to_end(&mut buf).unwrap();
            let module = CompiledModule::deserialize(&buf[..]).unwrap();
            print_module(&mut stdout, &module).unwrap();
        },
       _ => usage(&args[0][..]),
    };
}
