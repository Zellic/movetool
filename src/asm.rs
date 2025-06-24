use crate::mvasm::*;

use move_binary_format::file_format::*;
use move_core_types::{account_address::AccountAddress, identifier::Identifier};

use hex::FromHex;

use std::str::FromStr;

#[derive(Debug)]
pub enum MoveAssemblyErrorInner {
    InvalidAbility,
    InvalidNumber,
    WrongNumberOfTokens {
        found: usize,
        expected: usize,
    },
    StructHandleWrongNumberOfTokens {
        found: usize,
    },
    NotEnoughTokens {
        found: usize,
        min: usize,
    },
    NotUTF8,
    InvalidStructType,
    InvalidInstruction,
    InvalidBoolean,
    ExpectedToken {
        found: Vec<u8>,
        expected: &'static [u8],
    },
    ValueTooLarge,
    ExpectedAcquires,
    ExpectedLocals,
    InvalidVisibility {
        found: Vec<u8>,
    },
    InvalidIdentifier,
    InvalidAddress,
    InvalidConstantValue,
    FieldNameSepNotFound,
    InvalidMoveVersion,
    InvalidSelfModuleHandle,
    ExpectedTable,
    InvalidTableType {
        found: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct MoveAssemblyError {
    pub inner: MoveAssemblyErrorInner,
    pub line_no: usize,
}

struct LineIterator<'a, T: Iterator<Item = &'a [u8]>> {
    it: T,
    pub cnt: usize,
}

impl<'a, T: Iterator<Item = &'a [u8]>> Iterator for LineIterator<'a, T> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut line = self.it.next()?;
            self.cnt += 1;
            let sep = line.iter().position(|x| *x == b';');
            if let Some(sep) = sep {
                line = &line[..sep];
            };
            line = line.trim_ascii();
            if !line.is_empty() {
                break Some(line);
            };
        }
    }
}

fn line_iter_from_buf(buf: &[u8]) -> LineIterator<impl Iterator<Item = &[u8]>> {
    LineIterator {
        it: buf.split(|x| *x == b'\n'),
        cnt: 0,
    }
}

fn bytes_to_number128(buf: &[u8]) -> Option<u128> {
    if buf.len() >= 2 && &buf[..2] == b"0x" {
        Some(u128::from_str_radix(std::str::from_utf8(&buf[2..]).ok()?, 16).ok()?)
    } else {
        Some(u128::from_str(std::str::from_utf8(buf).ok()?).ok()?)
    }
}

fn do_bytes_to_number(buf: &[u8]) -> Option<u16> {
    bytes_to_number128(buf)?.try_into().ok()
}

fn bytes_to_number(buf: &[u8]) -> Result<u16, MoveAssemblyErrorInner> {
    do_bytes_to_number(buf).ok_or(MoveAssemblyErrorInner::InvalidNumber)
}

fn do_string_to_ability(buf: &[u8]) -> Option<AbilitySet> {
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

fn string_to_ability(buf: &[u8]) -> Result<AbilitySet, MoveAssemblyErrorInner> {
    do_string_to_ability(buf).ok_or(MoveAssemblyErrorInner::InvalidAbility)
}

fn do_bytes_to_bool(buf: &[u8]) -> Option<bool> {
    Some(FromStr::from_str(std::str::from_utf8(buf).ok()?).ok()?)
}

fn bytes_to_bool(buf: &[u8]) -> Result<bool, MoveAssemblyErrorInner> {
    do_bytes_to_bool(buf).ok_or(MoveAssemblyErrorInner::InvalidBoolean)
}

fn expect_num_args_eq<T>(tok: &Vec<T>, num: usize) -> Result<(), MoveAssemblyErrorInner> {
    if tok.len() == num {
        Ok(())
    } else {
        Err(MoveAssemblyErrorInner::WrongNumberOfTokens {
            found: tok.len(),
            expected: num,
        })
    }
}

fn expect_token(buf: &[u8], expected: &'static [u8]) -> Result<(), MoveAssemblyErrorInner> {
    if buf == expected {
        Ok(())
    } else {
        Err(MoveAssemblyErrorInner::ExpectedToken {
            found: buf.to_vec(),
            expected,
        })
    }
}

fn try_into<S, T: TryFrom<S>>(x: S) -> Result<T, MoveAssemblyErrorInner> {
    x.try_into()
        .map_err(|_| MoveAssemblyErrorInner::ValueTooLarge)
}

fn from_utf8(buf: &[u8]) -> Result<&str, MoveAssemblyErrorInner> {
    std::str::from_utf8(buf).map_err(|_| MoveAssemblyErrorInner::NotUTF8)
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
    }
    res
}

fn parse_module_handle(line: &[u8]) -> Result<ModuleHandle, MoveAssemblyErrorInner> {
    let tok = tokenize(line);
    expect_num_args_eq(&tok, 2)?;
    let address = bytes_to_number(tok[0])?;
    let name = bytes_to_number(tok[1])?;
    Ok(ModuleHandle {
        address: AddressIdentifierIndex(address),
        name: IdentifierIndex(name),
    })
}

fn insn_zero_args(tok: &[u8]) -> Option<Bytecode> {
    match tok {
        b"pop" => Some(Bytecode::Pop),
        b"ret" => Some(Bytecode::Ret),
        b"cast_u8" => Some(Bytecode::CastU8),
        b"cast_u64" => Some(Bytecode::CastU64),
        b"cast_u128" => Some(Bytecode::CastU128),
        b"ldtrue" => Some(Bytecode::LdTrue),
        b"ldfalse" => Some(Bytecode::LdFalse),
        b"read_ref" => Some(Bytecode::ReadRef),
        b"write_ref" => Some(Bytecode::WriteRef),
        b"freeze_ref" => Some(Bytecode::FreezeRef),
        b"add" => Some(Bytecode::Add),
        b"sub" => Some(Bytecode::Sub),
        b"mul" => Some(Bytecode::Mul),
        b"mod" => Some(Bytecode::Mod),
        b"div" => Some(Bytecode::Div),
        b"bit_or" => Some(Bytecode::BitOr),
        b"bit_and" => Some(Bytecode::BitAnd),
        b"xor" => Some(Bytecode::Xor),
        b"or" => Some(Bytecode::Or),
        b"and" => Some(Bytecode::And),
        b"not" => Some(Bytecode::Not),
        b"eq" => Some(Bytecode::Eq),
        b"neq" => Some(Bytecode::Neq),
        b"lt" => Some(Bytecode::Lt),
        b"gt" => Some(Bytecode::Gt),
        b"le" => Some(Bytecode::Le),
        b"ge" => Some(Bytecode::Ge),
        b"abort" => Some(Bytecode::Abort),
        b"nop" => Some(Bytecode::Nop),
        b"shl" => Some(Bytecode::Shl),
        b"shr" => Some(Bytecode::Shr),
        b"cast_u16" => Some(Bytecode::CastU16),
        b"cast_u32" => Some(Bytecode::CastU32),
        b"cast_u256" => Some(Bytecode::CastU256),
        _ => None,
    }
}

fn insn_one_arg(tok0: &[u8], tok1: &[u8]) -> Result<Bytecode, MoveAssemblyErrorInner> {
    match tok0 {
        b"ld256" => {
            let val_str = from_utf8(tok1)?;
            let Ok(val) = (if val_str.len() >= 2 && &val_str[..2] == "0x" {
                move_core_types::u256::U256::from_str_radix(&val_str[2..], 16)
            } else {
                move_core_types::u256::U256::from_str(val_str)
            }) else {
                return Err(MoveAssemblyErrorInner::InvalidNumber);
            };
            Ok(Bytecode::LdU256(val))
        }
        _ => {
            let Some(val) = bytes_to_number128(tok1) else {
                return Err(MoveAssemblyErrorInner::InvalidNumber);
            };
            match tok0 {
                b"ld64" => Ok(Bytecode::LdU64(try_into(val)?)),
                b"ld128" => Ok(Bytecode::LdU128(try_into(val)?)),
                b"ld32" => Ok(Bytecode::LdU32(try_into(val)?)),
                _ => {
                    let val: u16 = try_into(val)?;
                    match tok0 {
                        b"br_true" => Ok(Bytecode::BrTrue(val)),
                        b"br_false" => Ok(Bytecode::BrFalse(val)),
                        b"branch" => Ok(Bytecode::Branch(val)),
                        b"ld8" => Ok(Bytecode::LdU8(try_into(val)?)),
                        b"ldconst" => Ok(Bytecode::LdConst(ConstantPoolIndex(val))),
                        b"copyloc" => Ok(Bytecode::CopyLoc(try_into(val)?)),
                        b"moveloc" => Ok(Bytecode::MoveLoc(try_into(val)?)),
                        b"stloc" => Ok(Bytecode::StLoc(try_into(val)?)),
                        b"call" => Ok(Bytecode::Call(FunctionHandleIndex(val))),
                        b"call_generic" => {
                            Ok(Bytecode::CallGeneric(FunctionInstantiationIndex(val)))
                        }
                        b"pack" => Ok(Bytecode::Pack(StructDefinitionIndex(val))),
                        b"pack_generic" => {
                            Ok(Bytecode::PackGeneric(StructDefInstantiationIndex(val)))
                        }
                        b"unpack" => Ok(Bytecode::Unpack(StructDefinitionIndex(val))),
                        b"unpack_generic" => {
                            Ok(Bytecode::UnpackGeneric(StructDefInstantiationIndex(val)))
                        }
                        b"mut_borrow_loc" => Ok(Bytecode::MutBorrowLoc(try_into(val)?)),
                        b"imm_borrow_loc" => Ok(Bytecode::ImmBorrowLoc(try_into(val)?)),
                        b"mut_borrow_field" => Ok(Bytecode::MutBorrowField(FieldHandleIndex(val))),
                        b"mut_borrow_field_generic" => Ok(Bytecode::MutBorrowFieldGeneric(
                            FieldInstantiationIndex(val),
                        )),
                        b"imm_borrow_field" => Ok(Bytecode::ImmBorrowField(FieldHandleIndex(val))),
                        b"imm_borrow_field_generic" => Ok(Bytecode::ImmBorrowFieldGeneric(
                            FieldInstantiationIndex(val),
                        )),
                        b"mut_borrow_global" => {
                            Ok(Bytecode::MutBorrowGlobal(StructDefinitionIndex(val)))
                        }
                        b"mut_borrow_global_generic" => Ok(Bytecode::MutBorrowGlobalGeneric(
                            StructDefInstantiationIndex(val),
                        )),
                        b"imm_borrow_global" => {
                            Ok(Bytecode::ImmBorrowGlobal(StructDefinitionIndex(val)))
                        }
                        b"imm_borrow_global_generic" => Ok(Bytecode::ImmBorrowGlobalGeneric(
                            StructDefInstantiationIndex(val),
                        )),
                        b"exists" => Ok(Bytecode::Exists(StructDefinitionIndex(val))),
                        b"exists_generic" => {
                            Ok(Bytecode::ExistsGeneric(StructDefInstantiationIndex(val)))
                        }
                        b"move_from" => Ok(Bytecode::MoveFrom(StructDefinitionIndex(val))),
                        b"move_from_generic" => {
                            Ok(Bytecode::MoveFromGeneric(StructDefInstantiationIndex(val)))
                        }
                        b"move_to" => Ok(Bytecode::MoveTo(StructDefinitionIndex(val))),
                        b"move_to_generic" => {
                            Ok(Bytecode::MoveToGeneric(StructDefInstantiationIndex(val)))
                        }
                        b"vec_len" => Ok(Bytecode::VecLen(SignatureIndex(val))),
                        b"vec_imm_borrow" => Ok(Bytecode::VecImmBorrow(SignatureIndex(val))),
                        b"vec_mut_borrow" => Ok(Bytecode::VecMutBorrow(SignatureIndex(val))),
                        b"vec_push_back" => Ok(Bytecode::VecPushBack(SignatureIndex(val))),
                        b"vec_pop_back" => Ok(Bytecode::VecPopBack(SignatureIndex(val))),
                        b"vec_swap" => Ok(Bytecode::VecSwap(SignatureIndex(val))),
                        b"ld16" => Ok(Bytecode::LdU16(val)),
                        _ => Err(MoveAssemblyErrorInner::InvalidInstruction),
                    }
                }
            }
        }
    }
}

fn table_module_handles<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<ModuleHandle>, MoveAssemblyErrorInner> {
    let mut module_handles = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        module_handles.push(parse_module_handle(line)?);
    }
    Ok(module_handles)
}

fn table_struct_handles<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<StructHandle>, MoveAssemblyErrorInner> {
    let mut struct_handles = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        if !(tok.len() >= 3 && (tok.len() - 3) % 2 == 0) {
            return Err(MoveAssemblyErrorInner::StructHandleWrongNumberOfTokens {
                found: tok.len(),
            });
        };
        let abilities = string_to_ability(tok[0])?;
        let module = bytes_to_number(tok[1])?;
        let name = bytes_to_number(tok[2])?;
        let type_parameters = (&tok[3..])
            .chunks(2)
            .map(|toks| {
                let [constraints, is_phantom] = toks else {
                    unreachable!();
                };
                Ok(StructTypeParameter {
                    constraints: string_to_ability(constraints)?,
                    is_phantom: bytes_to_bool(is_phantom)?,
                })
            })
            .try_collect()?;
        struct_handles.push(StructHandle {
            module: ModuleHandleIndex(module),
            name: IdentifierIndex(name),
            abilities,
            type_parameters,
        });
    }
    Ok(struct_handles)
}

fn table_function_handles<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<FunctionHandle>, MoveAssemblyErrorInner> {
    let mut function_handles = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        if !(tok.len() >= 4) {
            return Err(MoveAssemblyErrorInner::NotEnoughTokens {
                found: tok.len(),
                min: 4,
            });
        };
        let module = bytes_to_number(tok[0])?;
        let name = bytes_to_number(tok[1])?;
        let parameters = bytes_to_number(tok[2])?;
        let return_ = bytes_to_number(tok[3])?;
        let mut type_parameters = Vec::new();
        for t in &tok[4..] {
            let ability = string_to_ability(t)?;
            type_parameters.push(ability);
        }
        function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(module),
            name: IdentifierIndex(name),
            parameters: SignatureIndex(parameters),
            return_: SignatureIndex(return_),
            type_parameters,
            access_specifiers: None,
        });
    }
    Ok(function_handles)
}

fn table_field_handles<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<FieldHandle>, MoveAssemblyErrorInner> {
    let mut field_handles = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        expect_num_args_eq(&tok, 2)?;
        let owner = bytes_to_number(tok[0])?;
        let field = bytes_to_number(tok[1])?;
        field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(owner),
            field,
        });
    }
    Ok(field_handles)
}

fn table_function_defs<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<FunctionDefinition>, MoveAssemblyErrorInner> {
    let mut function_defs = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        expect_num_args_eq(&tok, 4)?;
        expect_token(tok[0], b".func")?;
        let function = bytes_to_number(tok[1])?;
        let visibility = match tok[2] {
            b"public" => Visibility::Public,
            b"private" => Visibility::Private,
            b"friend" => Visibility::Friend,
            _ => {
                return Err(MoveAssemblyErrorInner::InvalidVisibility {
                    found: tok[2].to_vec(),
                })
            }
        };
        let is_entry = bytes_to_bool(tok[3])?;
        let mut function_acquires = Vec::new();

        if let Some(line) = line_it.next() {
            let tok = tokenize(line);

            expect_token(tok[0], b".acquires")?;

            for t in &tok[1..] {
                let def = bytes_to_number(t)?;
                function_acquires.push(StructDefinitionIndex(def));
            }
        } else {
            return Err(MoveAssemblyErrorInner::ExpectedAcquires);
        };

        let locals = if let Some(line) = line_it.next() {
            let tok = tokenize(line);

            expect_num_args_eq(&tok, 2)?;
            expect_token(tok[0], b".locals")?;

            bytes_to_number(tok[1])?
        } else {
            return Err(MoveAssemblyErrorInner::ExpectedLocals);
        };

        let mut code = Vec::new();

        while let Some(line) = line_it.next() {
            if line == b".endfunc" {
                break;
            };

            let tok = tokenize(line);

            let insn = if tok.len() == 1 {
                insn_zero_args(tok[0]).ok_or(MoveAssemblyErrorInner::InvalidInstruction)?
            } else if tok.len() == 2 {
                insn_one_arg(tok[0], tok[1])?
            } else if tok.len() == 3 {
                // VecPack(SignatureIndex, u64),
                expect_token(tok[0], b"vec_pack")?;
                let ty = bytes_to_number(tok[1])?;
                let num =
                    bytes_to_number128(tok[2]).ok_or(MoveAssemblyErrorInner::InvalidNumber)?;
                let num: u64 = try_into(num)?;
                Bytecode::VecPack(SignatureIndex(ty), num)
            } else {
                return Err(MoveAssemblyErrorInner::InvalidInstruction);
            };
            code.push(insn);
        }
        // TODO: super secret empty code unit
        function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex(function),
            visibility,
            is_entry,
            acquires_global_resources: function_acquires,
            code: Some(CodeUnit {
                locals: SignatureIndex(locals),
                code,
            }),
        });
    }
    Ok(function_defs)
}

// friend decls same as module handles

fn table_struct_def_instantiations<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<StructDefInstantiation>, MoveAssemblyErrorInner> {
    let mut struct_def_instantiations = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        expect_num_args_eq(&tok, 2)?;
        let def = bytes_to_number(tok[0])?;
        let type_parameters = bytes_to_number(tok[1])?;
        struct_def_instantiations.push(StructDefInstantiation {
            def: StructDefinitionIndex(def),
            type_parameters: SignatureIndex(type_parameters),
        });
    }
    Ok(struct_def_instantiations)
}

fn table_function_instantiations<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<FunctionInstantiation>, MoveAssemblyErrorInner> {
    let mut function_instantiations = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        expect_num_args_eq(&tok, 2)?;
        let handle = bytes_to_number(tok[0])?;
        let type_parameters = bytes_to_number(tok[1])?;
        function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(handle),
            type_parameters: SignatureIndex(type_parameters),
        });
    }
    Ok(function_instantiations)
}

fn table_field_instantiations<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<FieldInstantiation>, MoveAssemblyErrorInner> {
    let mut field_instantiations = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        expect_num_args_eq(&tok, 2)?;
        let handle = bytes_to_number(tok[0])?;
        let type_parameters = bytes_to_number(tok[1])?;
        field_instantiations.push(FieldInstantiation {
            handle: FieldHandleIndex(handle),
            type_parameters: SignatureIndex(type_parameters),
        });
    }
    Ok(field_instantiations)
}

fn table_signatures<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<Signature>, MoveAssemblyErrorInner> {
    let token_arr_parser = TokenArrParser::new();
    let mut signatures = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let signature_str = from_utf8(line)?;
        // TODO: proper error reporting
        let signature = token_arr_parser.parse(signature_str).unwrap();
        signatures.push(Signature(signature));
    }
    Ok(signatures)
}

fn table_identifiers<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<Identifier>, MoveAssemblyErrorInner> {
    let mut identifiers = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let name = from_utf8(line)?;
        let name = Identifier::new(name).map_err(|_| MoveAssemblyErrorInner::InvalidIdentifier)?;
        identifiers.push(name);
    }
    Ok(identifiers)
}

fn table_address_identifiers<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<AccountAddress>, MoveAssemblyErrorInner> {
    let mut address_identifiers = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let address =
            <[u8; 32]>::from_hex(line).map_err(|_| MoveAssemblyErrorInner::InvalidAddress)?;
        let address = AccountAddress::new(address);
        address_identifiers.push(address);
    }
    Ok(address_identifiers)
}

fn table_constant_pool<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<Constant>, MoveAssemblyErrorInner> {
    let token_parser = TokenParser::new();
    let mut constant_pool = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        expect_num_args_eq(&tok, 2)?;
        let type_str = from_utf8(tok[0])?;
        // TODO: better error handling
        let type_ = token_parser.parse(type_str).unwrap();
        let data = Vec::<u8>::from_hex(tok[1])
            .map_err(|_| MoveAssemblyErrorInner::InvalidConstantValue)?;
        constant_pool.push(Constant { type_, data });
    }
    Ok(constant_pool)
}

fn table_metadata<'a>(line_it: &mut impl Iterator<Item = &'a [u8]>) {
    // TODO metadata table
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
    }
}

fn table_struct_defs<'a>(
    line_it: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<StructDefinition>, MoveAssemblyErrorInner> {
    let token_parser = TokenParser::new();
    let mut struct_defs = Vec::new();
    while let Some(line) = line_it.next() {
        if line == b".endtable" {
            break;
        };
        let tok = tokenize(line);
        expect_num_args_eq(&tok, 3)?;
        expect_token(tok[0], b".struct")?;

        let struct_handle = bytes_to_number(tok[2])?;
        if tok[1] == b"native" {
            struct_defs.push(StructDefinition {
                struct_handle: StructHandleIndex(struct_handle),
                field_information: StructFieldInformation::Native,
            });
        } else if tok[1] == b"declared" {
            let mut field_definitions = Vec::new();
            while let Some(line) = line_it.next() {
                if line == b".endstruct" {
                    break;
                };
                let tok = tokenize(line);
                expect_num_args_eq(&tok, 2)?;
                if !(*tok[0].last().unwrap() == b':') {
                    return Err(MoveAssemblyErrorInner::FieldNameSepNotFound);
                };
                let name = bytes_to_number(&tok[0][..tok[0].len() - 1])?;
                let signature_str = from_utf8(tok[1])?;
                // TODO: error handle
                let signature = token_parser.parse(signature_str).unwrap();
                field_definitions.push(FieldDefinition {
                    name: IdentifierIndex(name),
                    signature: TypeSignature(signature),
                });
            }
            struct_defs.push(StructDefinition {
                struct_handle: StructHandleIndex(struct_handle),
                field_information: StructFieldInformation::Declared(field_definitions),
            });
        } else {
            return Err(MoveAssemblyErrorInner::InvalidStructType);
        };
    }
    Ok(struct_defs)
}

fn wrap_move_asm_error<T>(
    res: Result<T, MoveAssemblyErrorInner>,
    line_no: usize,
) -> Result<T, MoveAssemblyError> {
    res.map_err(|x| MoveAssemblyError { inner: x, line_no })
}

pub fn parse_module(buf: &[u8]) -> Result<CompiledModule, MoveAssemblyError> {
    enum State {
        TypeModule,
        Version,
        SelfIdx,
        Table,
    }

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
    let metadata = Vec::new();
    let mut function_defs = Vec::new();

    let mut state = State::TypeModule;

    let mut line_it = line_iter_from_buf(buf);
    while let Some(line) = line_it.next() {
        match state {
            State::TypeModule => {
                if line != b".type module" {
                    todo!();
                };
                state = State::Version;
            }
            State::Version => {
                let Some(version_str) = line.strip_prefix(b".version ") else {
                    return Err(MoveAssemblyError {
                        inner: MoveAssemblyErrorInner::InvalidMoveVersion,
                        line_no: line_it.cnt,
                    });
                };
                version = wrap_move_asm_error(bytes_to_number(version_str), line_it.cnt)?;
                state = State::SelfIdx;
            }
            State::SelfIdx => {
                let Some(self_idx_str) = line.strip_prefix(b".self_module_handle_idx ") else {
                    return Err(MoveAssemblyError {
                        inner: MoveAssemblyErrorInner::InvalidSelfModuleHandle,
                        line_no: line_it.cnt,
                    });
                };
                self_module_handle_idx =
                    wrap_move_asm_error(bytes_to_number(self_idx_str), line_it.cnt)?;
                state = State::Table;
            }
            State::Table => {
                let Some(table_name) = line.strip_prefix(b".table ") else {
                    return Err(MoveAssemblyError {
                        inner: MoveAssemblyErrorInner::ExpectedTable,
                        line_no: line_it.cnt,
                    });
                };
                match table_name {
                    b"module_handles" => {
                        module_handles =
                            wrap_move_asm_error(table_module_handles(&mut line_it), line_it.cnt)?
                    }
                    b"struct_handles" => {
                        struct_handles =
                            wrap_move_asm_error(table_struct_handles(&mut line_it), line_it.cnt)?
                    }
                    b"function_handles" => {
                        function_handles =
                            wrap_move_asm_error(table_function_handles(&mut line_it), line_it.cnt)?
                    }
                    b"field_handles" => {
                        field_handles =
                            wrap_move_asm_error(table_field_handles(&mut line_it), line_it.cnt)?
                    }
                    b"friend_decls" => {
                        friend_decls =
                            wrap_move_asm_error(table_module_handles(&mut line_it), line_it.cnt)?
                    }
                    b"struct_def_instantiations" => {
                        struct_def_instantiations = wrap_move_asm_error(
                            table_struct_def_instantiations(&mut line_it),
                            line_it.cnt,
                        )?
                    }
                    b"function_instantiations" => {
                        function_instantiations = wrap_move_asm_error(
                            table_function_instantiations(&mut line_it),
                            line_it.cnt,
                        )?
                    }
                    b"field_instantiations" => {
                        field_instantiations = wrap_move_asm_error(
                            table_field_instantiations(&mut line_it),
                            line_it.cnt,
                        )?
                    }
                    b"signatures" => {
                        signatures =
                            wrap_move_asm_error(table_signatures(&mut line_it), line_it.cnt)?
                    }
                    b"identifiers" => {
                        identifiers =
                            wrap_move_asm_error(table_identifiers(&mut line_it), line_it.cnt)?
                    }
                    b"address_identifiers" => {
                        address_identifiers = wrap_move_asm_error(
                            table_address_identifiers(&mut line_it),
                            line_it.cnt,
                        )?
                    }
                    b"constant_pool" => {
                        constant_pool =
                            wrap_move_asm_error(table_constant_pool(&mut line_it), line_it.cnt)?
                    }
                    b"metadata" => table_metadata(&mut line_it),
                    b"struct_defs" => {
                        struct_defs =
                            wrap_move_asm_error(table_struct_defs(&mut line_it), line_it.cnt)?
                    }
                    b"function_defs" => {
                        function_defs =
                            wrap_move_asm_error(table_function_defs(&mut line_it), line_it.cnt)?
                    }
                    name => {
                        return Err(MoveAssemblyError {
                            inner: MoveAssemblyErrorInner::InvalidTableType {
                                found: name.to_vec(),
                            },
                            line_no: line_it.cnt,
                        });
                    }
                };
            }
        };
    }

    Ok(CompiledModule {
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
        struct_variant_handles: vec![],
        struct_variant_instantiations: vec![],
        variant_field_handles: vec![],
        variant_field_instantiations: vec![],
    })
}
