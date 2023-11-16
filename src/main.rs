#![feature(iter_intersperse)]
#![feature(slice_take)]
#![feature(byte_slice_trim_ascii)]
#![feature(iterator_try_collect)]

use move_binary_format::{CompiledModule, deserializer, file_format::*};
use lalrpop_util::lalrpop_mod;
use move_core_types::{identifier::Identifier, account_address::AccountAddress};
use mvasm::*;

use std::io::{self, Write};
use std::fs;
use std::str::FromStr;
use hex::FromHex;

lalrpop_mod!(pub mvasm);

fn ability_to_string(abilities: AbilitySet) -> String {
    let mut res = [b'-'; 4];
    if abilities.has_copy() {
        res[0] = b'c';
    };
    if abilities.has_drop() {
        res[1] = b'd';
    };
    if abilities.has_store() {
        res[2] = b's';
    };
    if abilities.has_key() {
        res[3] = b'k';
    };
    unsafe {
        String::from_utf8_unchecked(res.to_vec())
    }
}

fn string_to_ability(buf: &[u8]) -> Option<AbilitySet> {
    if buf.len() != 4 {
        return None;
    };
    let mut res = AbilitySet::EMPTY;
    if buf[0] == b'c' {
        res = res | Ability::Copy;
    } else if buf[0] != b'-' {
        return None;
    };
    if buf[1] == b'd' {
        res = res | Ability::Drop;
    } else if buf[1] != b'-' {
        return None;
    };
    if buf[2] == b's' {
        res = res | Ability::Store;
    } else if buf[2] != b'-' {
        return None;
    };
    if buf[3] == b'k' {
        res = res | Ability::Key;
    } else if buf[3] != b'-' {
        return None;
    };
    Some(res)
}

fn signature_token_to_string(sig: &SignatureToken) -> String {
    match sig {
        SignatureToken::Vector(tok) => format!("vec<{}>", signature_token_to_string(tok)),
        SignatureToken::Struct(idx) => format!("struct({})", idx),
        SignatureToken::StructInstantiation(idx, vec) => format!("struct{}({})", signature_to_string(vec), idx),
        SignatureToken::Reference(tok) => format!("&{}", signature_token_to_string(tok)),
        SignatureToken::MutableReference(tok) => format!("&mut {}", signature_token_to_string(tok)),
        SignatureToken::TypeParameter(idx) => format!("type({})", idx),
        _ => match sig {
            SignatureToken::Bool => "bool",
            SignatureToken::U8 => "u8",
            SignatureToken::U16 => "u16",
            SignatureToken::U32 => "u32",
            SignatureToken::U64 => "u64",
            SignatureToken::U128 => "u128",
            SignatureToken::U256 => "u256",
            SignatureToken::Address => "address",
            SignatureToken::Signer => "signer",
            _ => unreachable!(),
        }.into(),
    }
}

fn signature_to_string(sig: &[SignatureToken]) -> String {
    format!("[{}]", sig.iter().map(&signature_token_to_string).intersperse(", ".into()).collect::<String>())
}

fn visibility_to_string(vis: Visibility) -> &'static str {
    match vis {
        Visibility::Private => "private",
        Visibility::Public => "public",
        Visibility::Friend => "friend",
    }
}

fn print_module<T: Write>(out: &mut T, module: &CompiledModule) -> io::Result<()> {
    writeln!(out, ".type module")?;
    writeln!(out, ".version 6")?;
    writeln!(out, ".self_module_handle_idx {}", module.self_module_handle_idx)?;
    writeln!(out, ".table module_handles")?;
    writeln!(out, "; address_idx identifier_idx")?;
    for handle in &module.module_handles {
        writeln!(out, "{} {}", handle.address, handle.name)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table struct_handles")?;
    writeln!(out, "; abiltiies,cdsk module_idx identifier_idx")?;
    for handle in &module.struct_handles {
        write!(out, "{} {} {}", ability_to_string(handle.abilities), handle.module, handle.name)?;
        for ty in &handle.type_parameters {
            write!(out, " {} {}", ability_to_string(ty.constraints), ty.is_phantom)?;
        };
        writeln!(out)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table function_handles")?;
    writeln!(out, "; module_idx identifier_idx parameters_sig_idx return_sig_idx type_parameters...,cdsk")?;
    for handle in &module.function_handles {
        write!(out, "{} {} {} {}", handle.module, handle.name, handle.parameters, handle.return_)?;
        for ty in &handle.type_parameters {
            write!(out, " {}", ability_to_string(*ty))?;
        };
        writeln!(out)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table field_handles")?;
    writeln!(out, "; struct_def_idx member_count")?;
    for handle in &module.field_handles {
        writeln!(out, "{} {}", handle.owner, handle.field)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table friend_decls")?;
    writeln!(out, "; address_idx identifier_idx")?;
    for handle in &module.friend_decls {
        writeln!(out, "{} {}", handle.address, handle.name)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table struct_def_instantiations")?;
    writeln!(out, "; struct_def_idx type_params_signature_idx")?;
    for handle in &module.struct_def_instantiations {
        writeln!(out, "{} {}", handle.def, handle.type_parameters)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table function_instantiations")?;
    writeln!(out, "; function_handle_idx type_params_signature_idx")?;
    for handle in &module.function_instantiations {
        writeln!(out, "{} {}", handle.handle, handle.type_parameters)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table field_instantiations")?;
    writeln!(out, "; field_handle_idx type_params_signature_idx")?;
    for handle in &module.field_instantiations {
        writeln!(out, "{} {}", handle.handle, handle.type_parameters)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table signatures")?;
    writeln!(out, "; arrays of types, for specifics see source code")?;
    for sig in &module.signatures {
        writeln!(out, "{}", signature_to_string(&sig.0))?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table identifiers")?;
    writeln!(out, "; literal string identifiers")?;
    for id in &module.identifiers {
        writeln!(out, "{}", id)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table address_identifiers")?;
    writeln!(out, "; addresses in hex")?;
    for address in &module.address_identifiers {
        writeln!(out, "{}", address)?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table constant_pool")?;
    writeln!(out, "; type encoded_value_in_hex")?;
    for cons in &module.constant_pool {
        writeln!(out, "{} {}", signature_token_to_string(&cons.type_), hex::encode(&cons.data))?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table metadata")?;
    writeln!(out, "; key value")?;
    for metadatum in &module.metadata {
        writeln!(out, "{} {}", hex::encode(&metadatum.key), hex::encode(&metadatum.value))?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table struct_defs")?;
    writeln!(out, "; structs can be native or declared")?;
    for def in &module.struct_defs {
        match &def.field_information {
            StructFieldInformation::Native => {
                writeln!(out, ".struct native {}", def.struct_handle)?;
            },
            StructFieldInformation::Declared(fields) => {
                writeln!(out, ".struct declared {}", def.struct_handle)?;
                for field in fields {
                    writeln!(out, "{}: {}", field.name, signature_token_to_string(&field.signature.0))?;
                };
            },
        };
        writeln!(out, ".endstruct")?;
    };
    writeln!(out, ".endtable")?;
    writeln!(out, ".table function_defs")?;
    writeln!(out, "; function_handle visibility_public_private_friend is_entry")?;
    for def in &module.function_defs {
        writeln!(out, ".func {} {} {}", def.function, visibility_to_string(def.visibility), def.is_entry)?;
        writeln!(out, "; indices of struct definitions acquired by this function")?;
        write!(out, ".acquires")?;
        for res in &def.acquires_global_resources {
            write!(out, " {}", res)?;
        };
        writeln!(out)?;
        if let Some(code) = &def.code {
            writeln!(out, ".locals {}", code.locals)?;
            for insn in &code.code {
                match insn {
                    Bytecode::Pop => writeln!(out, "pop"),
                    Bytecode::Ret => writeln!(out, "ret"),
                    Bytecode::BrTrue(off) => writeln!(out, "br_true {}", off),
                    Bytecode::BrFalse(off) => writeln!(out, "br_false {}", off),
                    Bytecode::Branch(off) => writeln!(out, "branch {}", off),
                    Bytecode::LdU8(val) => writeln!(out, "ld8 {:#x}", val),
                    Bytecode::LdU64(val) => writeln!(out, "ld64 {:#x}", val),
                    Bytecode::LdU128(val) => writeln!(out, "ld128 {:#x}", val),
                    Bytecode::CastU8 => writeln!(out, "cast_u8"),
                    Bytecode::CastU64 => writeln!(out, "cast_u64"),
                    Bytecode::CastU128 => writeln!(out, "cast_u128"),
                    Bytecode::LdConst(idx) => writeln!(out, "ldconst {}", idx),
                    Bytecode::LdTrue => writeln!(out, "ldtrue"),
                    Bytecode::LdFalse => writeln!(out, "ldfalse"),
                    Bytecode::CopyLoc(idx) => writeln!(out, "copyloc {}", idx),
                    Bytecode::MoveLoc(idx) => writeln!(out, "moveloc {}", idx),
                    Bytecode::StLoc(idx) => writeln!(out, "stloc {}", idx),
                    Bytecode::Call(idx) => writeln!(out, "call {}", idx),
                    Bytecode::CallGeneric(idx) => writeln!(out, "call_generic {}", idx),
                    Bytecode::Pack(idx) => writeln!(out, "pack {}", idx),
                    Bytecode::PackGeneric(idx) => writeln!(out, "pack_generic {}", idx),
                    Bytecode::Unpack(idx) => writeln!(out, "unpack {}", idx),
                    Bytecode::UnpackGeneric(idx) => writeln!(out, "unpack_generic {}", idx),
                    Bytecode::ReadRef => writeln!(out, "read_ref"),
                    Bytecode::WriteRef => writeln!(out, "write_ref"),
                    Bytecode::FreezeRef => writeln!(out, "freeze_ref"),
                    Bytecode::MutBorrowLoc(idx) => writeln!(out, "mut_borrow_loc {}", idx),
                    Bytecode::ImmBorrowLoc(idx) => writeln!(out, "imm_borrow_loc {}", idx),
                    Bytecode::MutBorrowField(idx) => writeln!(out, "mut_borrow_field {}", idx),
                    Bytecode::MutBorrowFieldGeneric(idx) => writeln!(out, "mut_borrow_field_generic {}", idx),
                    Bytecode::ImmBorrowField(idx) => writeln!(out, "imm_borrow_field {}", idx),
                    Bytecode::ImmBorrowFieldGeneric(idx) => writeln!(out, "imm_borrow_field_generic {}", idx),
                    Bytecode::MutBorrowGlobal(idx) => writeln!(out, "mut_borrow_global {}", idx),
                    Bytecode::MutBorrowGlobalGeneric(idx) => writeln!(out, "mut_borrow_global_generic {}", idx),
                    Bytecode::ImmBorrowGlobal(idx) => writeln!(out, "imm_borrow_global {}", idx),
                    Bytecode::ImmBorrowGlobalGeneric(idx) => writeln!(out, "imm_borrow_global_generic {}", idx),
                    Bytecode::Add => writeln!(out, "add"),
                    Bytecode::Sub => writeln!(out, "sub"),
                    Bytecode::Mul => writeln!(out, "mul"),
                    Bytecode::Mod => writeln!(out, "mod"),
                    Bytecode::Div => writeln!(out, "div"),
                    Bytecode::BitOr => writeln!(out, "bit_or"),
                    Bytecode::BitAnd => writeln!(out, "bit_and"),
                    Bytecode::Xor => writeln!(out, "xor"),
                    Bytecode::Or => writeln!(out, "or"),
                    Bytecode::And => writeln!(out, "and"),
                    Bytecode::Not => writeln!(out, "not"),
                    Bytecode::Eq => writeln!(out, "eq"),
                    Bytecode::Neq => writeln!(out, "neq"),
                    Bytecode::Lt => writeln!(out, "lt"),
                    Bytecode::Gt => writeln!(out, "gt"),
                    Bytecode::Le => writeln!(out, "le"),
                    Bytecode::Ge => writeln!(out, "ge"),
                    Bytecode::Abort => writeln!(out, "abort"),
                    Bytecode::Nop => writeln!(out, "nop"),
                    Bytecode::Exists(idx) => writeln!(out, "exists {}", idx),
                    Bytecode::ExistsGeneric(idx) => writeln!(out, "exists_generic {}", idx),
                    Bytecode::MoveFrom(idx) => writeln!(out, "move_from {}", idx),
                    Bytecode::MoveFromGeneric(idx) => writeln!(out, "move_from_generic {}", idx),
                    Bytecode::MoveTo(idx) => writeln!(out, "move_to {}", idx),
                    Bytecode::MoveToGeneric(idx) => writeln!(out, "move_to_generic {}", idx),
                    Bytecode::Shl => writeln!(out, "shl"),
                    Bytecode::Shr => writeln!(out, "shr"),
                    Bytecode::VecPack(idx, len) => writeln!(out, "vec_pack {} {}", idx, len),
                    Bytecode::VecLen(idx) => writeln!(out, "vec_len {}", idx),
                    Bytecode::VecImmBorrow(idx) => writeln!(out, "vec_imm_borrow {}", idx),
                    Bytecode::VecMutBorrow(idx) => writeln!(out, "vec_mut_borrow {}", idx),
                    Bytecode::VecPushBack(idx) => writeln!(out, "vec_push_back {}", idx),
                    Bytecode::VecPopBack(idx) => writeln!(out, "vec_pop_back {}", idx),
                    Bytecode::VecUnpack(idx, len) => writeln!(out, "vec_unpack {} {}", idx, len),
                    Bytecode::VecSwap(idx) => writeln!(out, "vec_swap {}", idx),
                    Bytecode::LdU16(val) => writeln!(out, "ld16 {:#x}", val),
                    Bytecode::LdU32(val) => writeln!(out, "ld32 {:#x}", val),
                    Bytecode::LdU256(val) => writeln!(out, "ld256 {:#x}", val),
                    Bytecode::CastU16 => writeln!(out, "cast_u16"),
                    Bytecode::CastU32 => writeln!(out, "cast_u32"),
                    Bytecode::CastU256 => writeln!(out, "cast_u256"),
                }?;
            };
        };
        writeln!(out, ".endfunc")?;
    };
    writeln!(out, ".endtable")?;

    Ok(())
}

fn bytes_to_number128(buf: &[u8]) -> Option<u128> {
    if buf.len() >= 2 && &buf[..2] == b"0x" {
        Some(u128::from_str_radix(std::str::from_utf8(&buf[2..]).ok()?, 16).ok()?)
    } else {
        Some(u128::from_str(std::str::from_utf8(buf).ok()?).ok()?)
    }
}

fn bytes_to_number(buf: &[u8]) -> Option<u16> {
    bytes_to_number128(buf)?.try_into().ok()
}

fn tokenize(mut buf: &[u8]) -> Vec<&[u8]> {
    let mut res = Vec::new();
    loop {
        let mut it = buf.iter();
        let Some(j) = it.position(|x| !x.is_ascii_whitespace()) else {
            break;
        };
        let optk = it.position(u8::is_ascii_whitespace);
        let k = optk.map(|k| j + k + 1).unwrap_or(buf.len());
        let (first, rest) = buf.split_at(k);
        let (_, tok) = first.split_at(j);
        res.push(tok);
        buf = rest;
        if optk.is_none() {
            break;
        };
    };
    res
}

fn parse_module_handle(line: &[u8]) -> Option<ModuleHandle> {
    let tok = tokenize(line);
    if tok.len() != 2 {
        return None;
    };
    let address = bytes_to_number(tok[0])?;
    let name = bytes_to_number(tok[1])?;
    Some(ModuleHandle {
        address: AddressIdentifierIndex(address),
        name: IdentifierIndex(name),
    })
}

fn parse_module(buf: &[u8]) -> CompiledModule {
    enum Table {
        ModuleHandles,
        StructHandles,
        FunctionHandles,
        FieldHandles,
        FriendDecls,
        StructDefInstantiations,
        FunctionInstantiations,
        FieldInstantiations,
        Signatures,
        Identifiers,
        AddressIdentifiers,
        ConstantPool,
        Metadata,
        StructDefs,
        FunctionDefs,
    };
    enum State {
        TypeModule,
        Version,
        SelfIdx,
        Table,
        InTable,
    };
    enum StructDefState {
        Def,
        Field,
    };
    enum FunctionDefState {
        FunctionSt,
        Acquires,
        Locals,
        Insn,
    };

    let mut version = 0;
    let mut self_module_handle_idx = 0;
    let mut module_handles = Vec::new();
    let mut struct_handles = Vec::new();
    let mut function_handles = Vec::new();
    let mut field_handles = Vec::new();
    let mut friend_decls = Vec::new();
    let mut struct_def_instantiations = Vec::new();
    let mut function_instantiations = Vec::new();
    let mut field_instantiations = Vec::new();
    let mut identifiers = Vec::new();
    let mut address_identifiers = Vec::new();
    let mut constant_pool = Vec::new();
    let mut struct_defs = Vec::new();
    let mut signatures = Vec::new();
    let mut metadata = Vec::new();
    let mut function_defs = Vec::new();

    let mut state = State::TypeModule;
    let mut cur_table = Table::ModuleHandles;

    let mut struct_def_state = StructDefState::Def;
    let mut struct_handle = 0;
    let mut field_definitions = Vec::new();

    let mut function_def_state = FunctionDefState::FunctionSt;
    let mut function = 0;
    let mut visibility = Visibility::Private;
    let mut is_entry = false;
    let mut function_acquires = Vec::new();
    let mut locals = 0;
    let mut code = Vec::new();

    let mut table_can_end = false;

    let token_parser = TokenParser::new();
    let token_arr_parser = TokenArrParser::new();
    for mut line in buf.split(|x| *x == b'\n') {
        let sep = line.iter().position(|x| *x == b';');
        if let Some(sep) = sep {
            line = line.take(..sep).unwrap()
        };
        line = line.trim_ascii();
        if line.is_empty() {
            continue;
        };
        match state {
            State::TypeModule => {
                if line != b".type module" {
                    panic!();
                };
                state = State::Version;
            },
            State::Version => {
                let Some(version_str) = line.strip_prefix(b".version ") else {
                    panic!();
                };
                version = bytes_to_number(version_str).unwrap();
                state = State::SelfIdx;
            },
            State::SelfIdx => {
                let Some(self_idx_str) = line.strip_prefix(b".self_module_handle_idx ") else {
                    panic!();
                };
                self_module_handle_idx = bytes_to_number(self_idx_str).unwrap();
                state = State::Table;
            },
            State::Table => {
                let Some(table_name) = line.strip_prefix(b".table ") else {
                    panic!();
                };
                cur_table = match table_name {
                    b"module_handles" => Table::ModuleHandles,
                    b"struct_handles" => Table::StructHandles,
                    b"function_handles" => Table::FunctionHandles,
                    b"field_handles" => Table::FieldHandles,
                    b"friend_decls" => Table::FriendDecls,
                    b"struct_def_instantiations" => Table::StructDefInstantiations,
                    b"function_instantiations" => Table::FunctionInstantiations,
                    b"field_instantiations" => Table::FieldInstantiations,
                    b"signatures" => Table::Signatures,
                    b"identifiers" => Table::Identifiers,
                    b"address_identifiers" => Table::AddressIdentifiers,
                    b"constant_pool" => Table::ConstantPool,
                    b"metadata" => Table::Metadata,
                    b"struct_defs" => Table::StructDefs,
                    b"function_defs" => Table::FunctionDefs,
                    _ => panic!(),
                };
                table_can_end = true;
                state = State::InTable;
            },
            State::InTable => {
                if line == b".endtable" {
                    if !table_can_end {
                        panic!();
                    };
                    state = State::Table;
                } else {
                    match cur_table {
                        Table::ModuleHandles => {
                            module_handles.push(parse_module_handle(line).unwrap());
                        },
                        Table::StructHandles => {
                            let tok = tokenize(line);
                            assert!(tok.len() >= 3 && (tok.len() - 3) % 2 == 0);
                            let abilities = string_to_ability(tok[0]).unwrap();
                            let module = bytes_to_number(tok[1]).unwrap();
                            let name = bytes_to_number(tok[2]).unwrap();
                            let type_parameters = (&tok[3..]).chunks(2).map(|toks| {
                                let [constraints, is_phantom] = toks else {
                                    unreachable!();
                                };
                                Some(StructTypeParameter {
                                    constraints: string_to_ability(constraints)?,
                                    is_phantom: FromStr::from_str(std::str::from_utf8(is_phantom).ok()?).ok()?,
                                })
                            }).try_collect().unwrap();
                            struct_handles.push(StructHandle {
                                module: ModuleHandleIndex(module),
                                name: IdentifierIndex(name),
                                abilities,
                                type_parameters,
                            });
                        },
                        Table::FunctionHandles => {
                            let tok = tokenize(line);
                            assert!(tok.len() >= 4);
                            let module = bytes_to_number(tok[0]).unwrap();
                            let name = bytes_to_number(tok[1]).unwrap();
                            let parameters = bytes_to_number(tok[2]).unwrap();
                            let return_ = bytes_to_number(tok[3]).unwrap();
                            let mut type_parameters = Vec::new();
                            for t in &tok[4..] {
                                let ability = string_to_ability(t).unwrap();
                                type_parameters.push(ability);
                            };
                            function_handles.push(FunctionHandle {
                                module: ModuleHandleIndex(module),
                                name: IdentifierIndex(name),
                                parameters: SignatureIndex(parameters),
                                return_: SignatureIndex(return_),
                                type_parameters,
                            });
                        },
                        Table::FieldHandles => {
                            let tok = tokenize(line);
                            assert!(tok.len() == 2);
                            let owner = bytes_to_number(tok[0]).unwrap();
                            let field = bytes_to_number(tok[1]).unwrap();
                            field_handles.push(FieldHandle {
                                owner: StructDefinitionIndex(owner),
                                field,
                            });
                        },
                        Table::FriendDecls => {
                            friend_decls.push(parse_module_handle(line).unwrap());
                        },
                        Table::StructDefInstantiations => {
                            let tok = tokenize(line);
                            assert!(tok.len() == 2);
                            let def = bytes_to_number(tok[0]).unwrap();
                            let type_parameters = bytes_to_number(tok[1]).unwrap();
                            struct_def_instantiations.push(StructDefInstantiation {
                                def: StructDefinitionIndex(def),
                                type_parameters: SignatureIndex(type_parameters),
                            });
                        },
                        Table::FunctionInstantiations => {
                            let tok = tokenize(line);
                            assert!(tok.len() == 2);
                            let handle = bytes_to_number(tok[0]).unwrap();
                            let type_parameters = bytes_to_number(tok[1]).unwrap();
                            function_instantiations.push(FunctionInstantiation {
                                handle: FunctionHandleIndex(handle),
                                type_parameters: SignatureIndex(type_parameters),
                            });
                        },
                        Table::FieldInstantiations => {
                            let tok = tokenize(line);
                            assert!(tok.len() == 2);
                            let handle = bytes_to_number(tok[0]).unwrap();
                            let type_parameters = bytes_to_number(tok[1]).unwrap();
                            field_instantiations.push(FieldInstantiation {
                                handle: FieldHandleIndex(handle),
                                type_parameters: SignatureIndex(type_parameters),
                            });
                        },
                        Table::Signatures => {
                            let signature_str = std::str::from_utf8(line).unwrap();
                            let signature = token_arr_parser.parse(signature_str).unwrap();
                            signatures.push(Signature(signature));
                        },
                        Table::Identifiers => {
                            let name = std::str::from_utf8(line).unwrap();
                            let name = Identifier::new(name).unwrap();
                            identifiers.push(name);
                        },
                        Table::AddressIdentifiers => {
                            let address = <[u8; 16]>::from_hex(line).unwrap();
                            let address = AccountAddress::new(address);
                            address_identifiers.push(address);
                        },
                        Table::ConstantPool => {
                            let tok = tokenize(line);
                            assert!(tok.len() == 2);
                            let type_str = std::str::from_utf8(tok[0]).unwrap();
                            let type_ = token_parser.parse(type_str).unwrap();
                            let data = Vec::<u8>::from_hex(tok[1]).unwrap();
                            constant_pool.push(Constant {
                                type_,
                                data,
                            });
                        },
                        Table::Metadata => {
                        },
                        Table::StructDefs => {
                            match struct_def_state {
                                StructDefState::Def => {
                                    let tok = tokenize(line);
                                    assert!(tok.len() == 3);
                                    assert!(tok[0] == b".struct");

                                    if tok[1] == b"native" {
                                        struct_defs.push(StructDefinition {
                                            struct_handle: StructHandleIndex(struct_handle),
                                            field_information: StructFieldInformation::Native,
                                        });
                                    } else if tok[1] == b"declared" {
                                        struct_def_state = StructDefState::Field;
                                        table_can_end = false;
                                    } else {
                                        panic!();
                                    };

                                    struct_handle = bytes_to_number(tok[2]).unwrap();
                                },
                                StructDefState::Field => {
                                    if line == b".endstruct" {
                                        struct_defs.push(StructDefinition {
                                            struct_handle: StructHandleIndex(struct_handle),
                                            field_information: StructFieldInformation::Declared(field_definitions),
                                        });
                                        field_definitions = Vec::new();
                                        struct_def_state = StructDefState::Def;
                                        table_can_end = true;
                                    } else {
                                        let tok = tokenize(line);
                                        assert!(tok.len() == 2);
                                        assert!(*tok[0].last().unwrap() == b':');
                                        let name = bytes_to_number(&tok[0][..tok[0].len() - 1]).unwrap();
                                        let signature_str = std::str::from_utf8(tok[1]).unwrap();
                                        let signature = token_parser.parse(signature_str).unwrap();
                                        field_definitions.push(FieldDefinition {
                                            name: IdentifierIndex(name),
                                            signature: TypeSignature(signature),
                                        });
                                    };
                                },
                            }
                        },
                        Table::FunctionDefs => {
                            match function_def_state {
                                FunctionDefState::FunctionSt => {
                                    let tok = tokenize(line);
                                    assert!(tok.len() == 4);
                                    assert!(tok[0] == b".func");
                                    function = bytes_to_number(tok[1]).unwrap();
                                    visibility = match tok[2] {
                                        b"public" => Visibility::Public,
                                        b"private" => Visibility::Private,
                                        b"friend" => Visibility::Friend,
                                        _ => panic!(),
                                    };
                                    let is_entry_str = std::str::from_utf8(tok[3]).unwrap();
                                    is_entry = FromStr::from_str(is_entry_str).unwrap();
                                    function_def_state = FunctionDefState::Acquires;
                                },
                                FunctionDefState::Acquires => {
                                    let tok = tokenize(line);

                                    assert!(tok[0] == b".acquires");

                                    for t in &tok[1..] {
                                        let def = bytes_to_number(t).unwrap();
                                        function_acquires.push(StructDefinitionIndex(def));
                                    };

                                    function_def_state = FunctionDefState::Locals;
                                },
                                FunctionDefState::Locals => {
                                    let tok = tokenize(line);

                                    assert!(tok.len() == 2);
                                    assert!(tok[0] == b".locals");

                                    locals = bytes_to_number(tok[1]).unwrap();
                                    function_def_state = FunctionDefState::Insn;
                                },
                                FunctionDefState::Insn => {
                                    if line == b".endfunc" {
                                        // TODO: super secret empty code unit
                                        function_defs.push(FunctionDefinition {
                                            function: FunctionHandleIndex(function),
                                            visibility,
                                            is_entry,
                                            acquires_global_resources: function_acquires,
                                            code: Some(CodeUnit {
                                                locals: SignatureIndex(locals),
                                                code,
                                            })
                                        });
                                        function_acquires = Vec::new();
                                        code = Vec::new();
                                        function_def_state = FunctionDefState::FunctionSt;
                                        continue;
                                    };

                                    let tok = tokenize(line);

                                    let insn = if tok.len() == 1 {
                                        match tok[0] {
                                            b"pop" => Bytecode::Pop,
                                            b"ret" => Bytecode::Ret,
                                            b"cast_u8" => Bytecode::CastU8,
                                            b"cast_u64" => Bytecode::CastU64,
                                            b"cast_u128" => Bytecode::CastU128,
                                            b"ldtrue" => Bytecode::LdTrue,
                                            b"ldfalse" => Bytecode::LdFalse,
                                            b"read_ref" => Bytecode::ReadRef,
                                            b"write_ref" => Bytecode::WriteRef,
                                            b"freeze_ref" => Bytecode::FreezeRef,
                                            b"add" => Bytecode::Add,
                                            b"sub" => Bytecode::Sub,
                                            b"mul" => Bytecode::Mul,
                                            b"mod" => Bytecode::Mod,
                                            b"div" => Bytecode::Div,
                                            b"bit_or" => Bytecode::BitOr,
                                            b"bit_and" => Bytecode::BitAnd,
                                            b"xor" => Bytecode::Xor,
                                            b"or" => Bytecode::Or,
                                            b"and" => Bytecode::And,
                                            b"not" => Bytecode::Not,
                                            b"eq" => Bytecode::Eq,
                                            b"neq" => Bytecode::Neq,
                                            b"lt" => Bytecode::Lt,
                                            b"gt" => Bytecode::Gt,
                                            b"le" => Bytecode::Le,
                                            b"ge" => Bytecode::Ge,
                                            b"abort" => Bytecode::Abort,
                                            b"nop" => Bytecode::Nop,
                                            b"shl" => Bytecode::Shl,
                                            b"shr" => Bytecode::Shr,
                                            b"cast_u16" => Bytecode::CastU16,
                                            b"cast_u32" => Bytecode::CastU32,
                                            b"cast_u256" => Bytecode::CastU256,
                                            _ => panic!(),
                                        }
                                    } else if tok.len() == 2 {
                                        match tok[0] {
                                            b"ld256" => {
                                                let val_str = std::str::from_utf8(tok[1]).unwrap();
                                                let val = if val_str.len() >= 2 && &val_str[..2] == "0x" { 
                                                    move_core_types::u256::U256::from_str_radix(&val_str[2..], 16)
                                                } else {
                                                    move_core_types::u256::U256::from_str(val_str)
                                                }.unwrap();
                                                Bytecode::LdU256(val)
                                            },
                                            _ => {
                                                let val = bytes_to_number128(tok[1]).unwrap();
                                                match tok[0] {
                                                    b"ld64" => Bytecode::LdU64(val.try_into().unwrap()),
                                                    b"ld128" => Bytecode::LdU128(val.try_into().unwrap()),
                                                    b"ld32" => Bytecode::LdU32(val.try_into().unwrap()),
                                                    _ => {
                                                        let val: u16 = val.try_into().unwrap();
                                                        match tok[0] {
                                                            b"br_true" => Bytecode::BrTrue(val),
                                                            b"br_false" => Bytecode::BrFalse(val),
                                                            b"branch" => Bytecode::Branch(val),
                                                            b"ld8" => Bytecode::LdU8(val.try_into().unwrap()),
                                                            b"ldconst" => Bytecode::LdConst(ConstantPoolIndex(val)),
                                                            b"copyloc" => Bytecode::CopyLoc(val.try_into().unwrap()),
                                                            b"moveloc" => Bytecode::MoveLoc(val.try_into().unwrap()),
                                                            b"stloc" => Bytecode::StLoc(val.try_into().unwrap()),
                                                            b"call" => Bytecode::Call(FunctionHandleIndex(val)),
                                                            b"call_generic" => Bytecode::CallGeneric(FunctionInstantiationIndex(val)),
                                                            b"pack" => Bytecode::Pack(StructDefinitionIndex(val)),
                                                            b"pack_generic" => Bytecode::PackGeneric(StructDefInstantiationIndex(val)),
                                                            b"unpack" => Bytecode::Unpack(StructDefinitionIndex(val)),
                                                            b"unpack_generic" => Bytecode::UnpackGeneric(StructDefInstantiationIndex(val)),
                                                            b"mut_borrow_loc" => Bytecode::MutBorrowLoc(val.try_into().unwrap()),
                                                            b"imm_borrow_loc" => Bytecode::ImmBorrowLoc(val.try_into().unwrap()),
                                                            b"mut_borrow_field" => Bytecode::MutBorrowField(FieldHandleIndex(val)),
                                                            b"mut_borrow_field_generic" => Bytecode::MutBorrowFieldGeneric(FieldInstantiationIndex(val)),
                                                            b"imm_borrow_field" => Bytecode::ImmBorrowField(FieldHandleIndex(val)),
                                                            b"imm_borrow_field_generic" => Bytecode::ImmBorrowFieldGeneric(FieldInstantiationIndex(val)),
                                                            b"mut_borrow_global" => Bytecode::MutBorrowGlobal(StructDefinitionIndex(val)),
                                                            b"mut_borrow_global_generic" => Bytecode::MutBorrowGlobalGeneric(StructDefInstantiationIndex(val)),
                                                            b"imm_borrow_global" => Bytecode::ImmBorrowGlobal(StructDefinitionIndex(val)),
                                                            b"imm_borrow_global_generic" => Bytecode::ImmBorrowGlobalGeneric(StructDefInstantiationIndex(val)),
                                                            b"exists" => Bytecode::Exists(StructDefinitionIndex(val)),
                                                            b"exists_generic" => Bytecode::ExistsGeneric(StructDefInstantiationIndex(val)),
                                                            b"move_from" => Bytecode::MoveFrom(StructDefinitionIndex(val)),
                                                            b"move_from_generic" => Bytecode::MoveFromGeneric(StructDefInstantiationIndex(val)),
                                                            b"move_to" => Bytecode::MoveTo(StructDefinitionIndex(val)),
                                                            b"move_to_generic" => Bytecode::MoveToGeneric(StructDefInstantiationIndex(val)),
                                                            b"vec_len" => Bytecode::VecLen(SignatureIndex(val)),
                                                            b"vec_imm_borrow" => Bytecode::VecImmBorrow(SignatureIndex(val)),
                                                            b"vec_mut_borrow" => Bytecode::VecMutBorrow(SignatureIndex(val)),
                                                            b"vec_push_back" => Bytecode::VecPushBack(SignatureIndex(val)),
                                                            b"vec_pop_back" => Bytecode::VecPopBack(SignatureIndex(val)),
                                                            b"vec_swap" => Bytecode::VecSwap(SignatureIndex(val)),
                                                            b"ld16" => Bytecode::LdU16(val),
                                                            _ => panic!(),
                                                        }
                                                    },
                                                }
                                            },
                                        }
                                    } else if tok.len() == 3 {
                                        // VecPack(SignatureIndex, u64),
                                        assert!(tok[0] == b"vec_pack");
                                        let ty = bytes_to_number(tok[1]).unwrap();
                                        let num = bytes_to_number128(tok[2]).unwrap();
                                        let num: u64 = num.try_into().unwrap();
                                        Bytecode::VecPack(SignatureIndex(ty), num)
                                    } else {
                                        panic!()
                                    };
                                    code.push(insn);
                                },
                            };
                        },
                    }
                };
            },
            _ => panic!(),
        };
    };

    CompiledModule {
        version: version.into(),
        self_module_handle_idx: ModuleHandleIndex(self_module_handle_idx),
        module_handles,
        struct_handles,
        function_handles,
        field_handles,
        friend_decls,
        struct_def_instantiations,
        function_instantiations,
        field_instantiations,
        signatures,
        identifiers,
        address_identifiers,
        constant_pool,
        metadata,
        struct_defs,
        function_defs,
    }
}

fn main() {
    let buf = fs::read("../testpkg/build/testpkg/bytecode_modules/Math.mv").unwrap();
    let module = CompiledModule::deserialize(&buf[..]).unwrap();
    /*
    dbg!(&module);

    print_module(&mut std::io::stdout(), &module).unwrap();
    */

    /*
    let buf = fs::read("./test.mvasm").unwrap();

    let module = parse_module(&buf);
    dbg!(&module);
    */

    let mut nbuf = Vec::new();

    module.serialize(&mut nbuf).unwrap();

    fs::write("./test.mv", &nbuf).unwrap();
}
