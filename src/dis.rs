use move_binary_format::{file_format::*, CompiledModule};

use std::io::{self, Write};

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
    unsafe { String::from_utf8_unchecked(res.to_vec()) }
}

fn signature_token_to_string(sig: &SignatureToken) -> String {
    match sig {
        SignatureToken::Vector(tok) => format!("vec<{}>", signature_token_to_string(tok)),
        SignatureToken::Struct(idx) => format!("struct({})", idx),
        SignatureToken::StructInstantiation(idx, vec) => {
            format!("struct{}({})", signature_to_string(vec), idx)
        }
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
        }
        .into(),
    }
}

fn signature_to_string(sig: &[SignatureToken]) -> String {
    format!(
        "[{}]",
        sig.iter()
            .map(&signature_token_to_string)
            .intersperse(", ".into())
            .collect::<String>()
    )
}

fn visibility_to_string(vis: Visibility) -> &'static str {
    match vis {
        Visibility::Private => "private",
        Visibility::Public => "public",
        Visibility::Friend => "friend",
    }
}

pub fn print_module<T: Write>(out: &mut T, module: &CompiledModule) -> io::Result<()> {
    writeln!(out, ".type module")?;
    writeln!(out, ".version 6")?;
    writeln!(
        out,
        ".self_module_handle_idx {}",
        module.self_module_handle_idx
    )?;
    writeln!(out, ".table module_handles")?;
    writeln!(out, "; address_idx identifier_idx")?;
    for handle in &module.module_handles {
        writeln!(out, "{} {}", handle.address, handle.name)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table struct_handles")?;
    writeln!(out, "; abiltiies,cdsk module_idx identifier_idx")?;
    for handle in &module.struct_handles {
        write!(
            out,
            "{} {} {}",
            ability_to_string(handle.abilities),
            handle.module,
            handle.name
        )?;
        for ty in &handle.type_parameters {
            write!(
                out,
                " {} {}",
                ability_to_string(ty.constraints),
                ty.is_phantom
            )?;
        }
        writeln!(out)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table function_handles")?;
    writeln!(
        out,
        "; module_idx identifier_idx parameters_sig_idx return_sig_idx type_parameters...,cdsk"
    )?;
    for handle in &module.function_handles {
        write!(
            out,
            "{} {} {} {}",
            handle.module, handle.name, handle.parameters, handle.return_
        )?;
        for ty in &handle.type_parameters {
            write!(out, " {}", ability_to_string(*ty))?;
        }
        writeln!(out)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table field_handles")?;
    writeln!(out, "; struct_def_idx member_count")?;
    for handle in &module.field_handles {
        writeln!(out, "{} {}", handle.owner, handle.field)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table friend_decls")?;
    writeln!(out, "; address_idx identifier_idx")?;
    for handle in &module.friend_decls {
        writeln!(out, "{} {}", handle.address, handle.name)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table struct_def_instantiations")?;
    writeln!(out, "; struct_def_idx type_params_signature_idx")?;
    for handle in &module.struct_def_instantiations {
        writeln!(out, "{} {}", handle.def, handle.type_parameters)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table function_instantiations")?;
    writeln!(out, "; function_handle_idx type_params_signature_idx")?;
    for handle in &module.function_instantiations {
        writeln!(out, "{} {}", handle.handle, handle.type_parameters)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table field_instantiations")?;
    writeln!(out, "; field_handle_idx type_params_signature_idx")?;
    for handle in &module.field_instantiations {
        writeln!(out, "{} {}", handle.handle, handle.type_parameters)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table signatures")?;
    writeln!(out, "; arrays of types, for specifics see source code")?;
    for sig in &module.signatures {
        writeln!(out, "{}", signature_to_string(&sig.0))?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table identifiers")?;
    writeln!(out, "; literal string identifiers")?;
    for id in &module.identifiers {
        writeln!(out, "{}", id)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table address_identifiers")?;
    writeln!(out, "; addresses in hex")?;
    for address in &module.address_identifiers {
        writeln!(out, "{}", address)?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table constant_pool")?;
    writeln!(out, "; type encoded_value_in_hex")?;
    for cons in &module.constant_pool {
        writeln!(
            out,
            "{} {}",
            signature_token_to_string(&cons.type_),
            hex::encode(&cons.data)
        )?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table metadata")?;
    writeln!(out, "; key value")?;
    for metadatum in &module.metadata {
        writeln!(
            out,
            "{} {}",
            hex::encode(&metadatum.key),
            hex::encode(&metadatum.value)
        )?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table struct_defs")?;
    writeln!(out, "; structs can be native or declared")?;
    for def in &module.struct_defs {
        match &def.field_information {
            StructFieldInformation::Native => {
                writeln!(out, ".struct native {}", def.struct_handle)?;
            }
            StructFieldInformation::Declared(fields) => {
                writeln!(out, ".struct declared {}", def.struct_handle)?;
                for field in fields {
                    writeln!(
                        out,
                        "{}: {}",
                        field.name,
                        signature_token_to_string(&field.signature.0)
                    )?;
                }
            }
            _ => {
                writeln!(out, ".struct unknown {}", def.struct_handle)?;
            }
        };
        writeln!(out, ".endstruct")?;
    }
    writeln!(out, ".endtable")?;
    writeln!(out, ".table function_defs")?;
    writeln!(
        out,
        "; function_handle visibility_public_private_friend is_entry"
    )?;
    for def in &module.function_defs {
        writeln!(
            out,
            ".func {} {} {}",
            def.function,
            visibility_to_string(def.visibility),
            def.is_entry
        )?;
        writeln!(
            out,
            "; indices of struct definitions acquired by this function"
        )?;
        write!(out, ".acquires")?;
        for res in &def.acquires_global_resources {
            write!(out, " {}", res)?;
        }
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
                    Bytecode::PackVariant(idx) => writeln!(out, "pack_variant {}", idx),
                    Bytecode::PackVariantGeneric(idx) => {
                        writeln!(out, "pack_variant_generic {}", idx)
                    }
                    Bytecode::PackGeneric(idx) => writeln!(out, "pack_generic {}", idx),
                    Bytecode::Unpack(idx) => writeln!(out, "unpack {}", idx),
                    Bytecode::UnpackVariant(idx) => writeln!(out, "unpack_variant {}", idx),
                    Bytecode::UnpackVariantGeneric(idx) => {
                        writeln!(out, "unpack_variant_generic {}", idx)
                    }
                    Bytecode::UnpackGeneric(idx) => writeln!(out, "unpack_generic {}", idx),
                    Bytecode::ReadRef => writeln!(out, "read_ref"),
                    Bytecode::WriteRef => writeln!(out, "write_ref"),
                    Bytecode::FreezeRef => writeln!(out, "freeze_ref"),
                    Bytecode::MutBorrowLoc(idx) => writeln!(out, "mut_borrow_loc {}", idx),
                    Bytecode::ImmBorrowLoc(idx) => writeln!(out, "imm_borrow_loc {}", idx),
                    Bytecode::MutBorrowField(idx) => writeln!(out, "mut_borrow_field {}", idx),
                    Bytecode::ImmBorrowVariantField(idx) => {
                        writeln!(out, "imm_borrow_variant_field {}", idx)
                    }
                    Bytecode::ImmBorrowVariantFieldGeneric(idx) => {
                        writeln!(out, "imm_borrow_variant_field_generic {}", idx)
                    }
                    Bytecode::MutBorrowVariantField(idx) => {
                        writeln!(out, "mut_borrow_variant_field {}", idx)
                    }
                    Bytecode::MutBorrowVariantFieldGeneric(idx) => {
                        writeln!(out, "mut_borrow_variant_field_generic {}", idx)
                    }
                    Bytecode::MutBorrowFieldGeneric(idx) => {
                        writeln!(out, "mut_borrow_field_generic {}", idx)
                    }
                    Bytecode::ImmBorrowField(idx) => writeln!(out, "imm_borrow_field {}", idx),
                    Bytecode::ImmBorrowFieldGeneric(idx) => {
                        writeln!(out, "imm_borrow_field_generic {}", idx)
                    }
                    Bytecode::MutBorrowGlobal(idx) => writeln!(out, "mut_borrow_global {}", idx),
                    Bytecode::MutBorrowGlobalGeneric(idx) => {
                        writeln!(out, "mut_borrow_global_generic {}", idx)
                    }
                    Bytecode::ImmBorrowGlobal(idx) => writeln!(out, "imm_borrow_global {}", idx),
                    Bytecode::ImmBorrowGlobalGeneric(idx) => {
                        writeln!(out, "imm_borrow_global_generic {}", idx)
                    }
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
                    Bytecode::TestVariant(idx) => writeln!(out, "test_variant {}", idx),
                    Bytecode::TestVariantGeneric(idx) => {
                        writeln!(out, "test_variant_generic {}", idx)
                    }
                }?;
            }
        };
        writeln!(out, ".endfunc")?;
    }
    writeln!(out, ".endtable")?;

    Ok(())
}
