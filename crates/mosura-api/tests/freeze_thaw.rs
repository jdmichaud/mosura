//! `Program` freeze/thaw: every enum code decodes, the type intern and the prototype models
//! round-trip structurally, and freeze→thaw→freeze is byte-identical over the analysis corpus
//! with the thawed snapshot equal to the original's.

use mosura_api::options::DecompileSettings;
use mosura_api::program::{self, freeze, thaw};
use mosura_core::analysis;
use mosura_core::decompile::fspec::{EffectRecord, ParamEntry, ParamList, ProtoModel};
use mosura_core::decompile::space::{Address, RangeList, SpaceId};
use mosura_core::decompile::types::Datatype;
use mosura_core::switches::Knobs;

fn settings() -> DecompileSettings {
    DecompileSettings { global_scope_all_loaded: true, proto_scope: None }
}

#[test]
fn every_enum_code_decodes_and_re_encodes() {
    for c in 0..program::REF_TYPE_CODES {
        assert_eq!(program::ref_type_code(program::ref_type(c).unwrap()), c);
    }
    assert!(program::ref_type(program::REF_TYPE_CODES).is_err());
    for k in 0..5u8 {
        let (kk, rr) = program::flow_kind_code(program::flow_kind(k, 0).unwrap());
        assert_eq!((kk, rr), (k, 0));
    }
    for r in 0..program::REF_TYPE_CODES {
        assert_eq!(program::flow_kind_code(program::flow_kind(5, r).unwrap()), (5, r));
    }
    assert!(program::flow_kind(6, 0).is_err());
    for c in 0..2u8 {
        assert_eq!(program::flow_override_code(program::flow_override(c).unwrap()), c);
    }
    assert!(program::flow_override(2).is_err());
    for c in 0..3u8 {
        assert_eq!(program::symbol_type_code(program::symbol_type(c).unwrap()), c);
    }
    assert!(program::symbol_type(3).is_err());
    for c in 0..5u8 {
        assert_eq!(program::comment_kind_code(program::comment_kind(c).unwrap()), c);
        assert_eq!(program::space_kind_code(program::space_kind(c).unwrap()), c);
    }
    assert!(program::comment_kind(5).is_err());
    assert!(program::space_kind(5).is_err());
}

#[test]
fn datatype_intern_round_trips_nested_and_dedups() {
    let inner = Datatype::Struct(8, vec![(0, Datatype::Uint(2)), (2, Datatype::Bool), (4, Datatype::Float(4))]);
    let t = Datatype::Struct(
        40,
        vec![
            (0, Datatype::Int(4)),
            (4, Datatype::Pointer(4, Box::new(Datatype::Array(Box::new(Datatype::Char), 8)))),
            (8, Datatype::Spacebase(SpaceId(3))),
            (12, Datatype::Float(8)),
            (20, inner.clone()),
            (28, Datatype::Pointer(4, Box::new(Datatype::Code))),
            (32, Datatype::Unknown(3)),
            (36, Datatype::Void),
        ],
    );
    let mut intern = program::TypeIntern::default();
    let a = intern.intern(&t);
    let b = intern.intern(&t);
    assert_eq!(a, b, "structural dedup");
    let i1 = intern.intern(&inner);
    let table = intern.table();
    assert_eq!(program::datatype_at(&table, a).unwrap(), t);
    assert_eq!(program::datatype_at(&table, i1).unwrap(), inner);
    // children come before parents: the struct's own id is the last row
    assert_eq!(a as u64, table.rows() - 1);
}

fn sample_model(name: &str, depth: u32) -> ProtoModel {
    let mut m = ProtoModel::empty();
    m.name = name.to_string();
    m.print_in_decl = depth == 0;
    m.extrapop = if depth == 0 { 4 } else { 0x8000 };
    m.custom_conventions = depth == 1;
    m.input = Some(ParamList {
        entry: vec![
            ParamEntry { group: 0, type_class: 1, space: SpaceId(1), addressbase: 0, size: 4, minsize: 1, alignment: 0 },
            ParamEntry { group: 1, type_class: 1, space: SpaceId(1), addressbase: 8, size: 4, minsize: 1, alignment: 0 },
            ParamEntry { group: 2, type_class: 0, space: SpaceId(3), addressbase: 4, size: 500, minsize: 4, alignment: 4 },
        ],
        resource_start: vec![0, 2],
        is_output: false,
    });
    m.output = if depth == 0 {
        Some(ParamList { entry: vec![ParamEntry { group: 0, type_class: 1, space: SpaceId(1), addressbase: 0, size: 4, minsize: 1, alignment: 0 }], resource_start: vec![0], is_output: true })
    } else {
        None
    };
    m.effectlist = vec![EffectRecord { space: SpaceId(1), offset: 0, size: 4, effect: 1 }, EffectRecord { space: SpaceId(1), offset: 0x14, size: 4, effect: 2 }];
    let mut lr = RangeList::new();
    lr.insert_range(SpaceId(3), 0xffff_ffff_0000_0000, 0xffff_ffff_ffff_ffff);
    m.localrange = lr;
    let mut pr = RangeList::new();
    pr.insert_range(SpaceId(3), 0, 0xffff_ffff);
    pr.insert_range(SpaceId(1), 0x20, 0x23);
    m.paramrange = pr;
    m.likelytrash = vec![(Address::new(SpaceId(1), 0), 4)];
    if depth < 2 {
        m.merged = vec![sample_model(&format!("{name}-a"), depth + 1), sample_model(&format!("{name}-b"), depth + 1)];
    }
    m
}

#[test]
fn proto_models_round_trip_structurally_including_merged() {
    let models = vec![sample_model("__stdcall", 0), sample_model("__cdecl", 1)];
    let set = program::freeze_proto_models(&models);
    // two roots + 2·(2 + 2·2) children of the first, + 2 of the second
    let back0 = program::proto_model_at(&set, 0).unwrap();
    assert_eq!(format!("{back0:?}"), format!("{:?}", models[0]));
    let root1 = (0..set.table("proto_models").unwrap().rows())
        .find(|&r| set.table("proto_models").unwrap().str(r, 2).unwrap() == "__cdecl")
        .map(|r| set.table("proto_models").unwrap().u64(r, 0).unwrap() as u32)
        .unwrap();
    let back1 = program::proto_model_at(&set, root1).unwrap();
    assert_eq!(format!("{back1:?}"), format!("{:?}", models[1]));
    // re-freezing the thawed models is byte-identical
    let again = program::freeze_proto_models(&[back0, back1]);
    assert_eq!(again.digests(), set.digests());
}

fn corpus(name: &str) -> std::path::PathBuf {
    mosura_core::paths::analysis_corpus_dir().join(name)
}

#[test]
fn freeze_thaw_freeze_is_byte_identical_over_the_corpus() {
    for name in ["basic.elf", "switchtab.elf", "m68k_dyn.elf", "watcom_hello.exe", "z80.com"] {
        let p = analysis::analyze_file_with(&corpus(name), &Knobs::default()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let set = freeze(&p, "default");
        let q = thaw(&set, Knobs::default(), &settings()).unwrap_or_else(|e| panic!("{name}: thaw: {e:?}"));
        let set2 = freeze(&q, "default");
        let (d1, d2) = (set.digests(), set2.digests());
        for (k, v) in &d1 {
            assert_eq!(Some(v), d2.get(k), "{name}: table {k} differs after thaw");
        }
        assert_eq!(d1.len(), d2.len(), "{name}: table set size");
        assert_eq!(q.snapshot().render(), p.snapshot().render(), "{name}: snapshot after thaw");
        assert_eq!(program::snapshot_text(&set).unwrap(), p.snapshot().render(), "{name}: snapshot_text");
        // spaces, relocations and the listing are equal as Debug text too
        for i in 0..p.spaces.num_spaces() {
            let id = SpaceId(i as u32);
            assert_eq!(format!("{:?}", q.spaces.get(id)), format!("{:?}", p.spaces.get(id)), "{name}: space {i}");
        }
        assert_eq!(format!("{:?}", q.relocation_table.relocations().collect::<Vec<_>>()), format!("{:?}", p.relocation_table.relocations().collect::<Vec<_>>()), "{name}: relocations");
        assert_eq!(q.listing.code_units().count(), p.listing.code_units().count(), "{name}: listing units");
        assert_eq!(q.function_manager.functions().count(), p.function_manager.functions().count(), "{name}: functions");
        assert!(set.tables["listing"].rows() > 0, "{name}: listing frozen");
    }
}

#[test]
fn the_prototype_pass_world_round_trips() {
    use mosura_core::analysis::interface::{install_prototypes, mark_tail_return_writes};
    // watcom_hello recovers prototypes without a resolved model; mingw_hello32 resolves
    // `__fastcall`/`__thiscall` models with full parameter lists — both shapes round-trip.
    let mut with_model = 0;
    for name in ["watcom_hello.exe", "mingw_hello32.exe"] {
        let mut p = analysis::analyze_file_with(&corpus(name), &Knobs::default()).unwrap();
        let marks = mark_tail_return_writes(&mut p, "x86:LE:32:default", &[]);
        let n = install_prototypes(&mut p, None);
        assert!(n > 0, "{name}: prototypes recovered");
        let set = freeze(&p, "default");
        let q = thaw(&set, Knobs::default(), &settings()).unwrap();
        assert_eq!(q.recovered_protos.len(), p.recovered_protos.len(), "{name}");
        for (va, proto) in &p.recovered_protos {
            let back = q.recovered_protos.get(va).unwrap_or_else(|| panic!("{name}: proto of {va:#x} lost"));
            assert_eq!(format!("{back:?}"), format!("{proto:?}"), "{name}: proto of {va:#x}");
            with_model += proto.model.is_some() as usize;
        }
        assert_eq!(format!("{:?}", q.recovered_sret.iter().collect::<std::collections::BTreeMap<_, _>>()), format!("{:?}", p.recovered_sret.iter().collect::<std::collections::BTreeMap<_, _>>()), "{name}: sret");
        assert_eq!(format!("{:?}", q.sret_callers), format!("{:?}", p.sret_callers), "{name}: sret callers");
        assert_eq!(q.tail_return_writes, p.tail_return_writes, "{name}: tail-return marks");
        assert_eq!(q.tail_return_writes.len(), marks.marked, "{name}: marks count");
        let set2 = freeze(&q, "default");
        assert_eq!(set2.digests(), set.digests(), "{name}: re-freeze");
    }
    assert!(with_model >= 10, "recovered models exercised: {with_model}");
}
