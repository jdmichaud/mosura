use mosura::analysis::fid::{db, store::FidStore};
use std::collections::HashSet;
fn main() {
    let src = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let out = std::path::PathBuf::from(std::env::args().nth(2).unwrap());
    let data = std::fs::read(&src).expect("read");
    let d = db::open_packed(&data).expect("open");
    let strings: std::collections::HashMap<i64, String> = d.records(d.table("Strings Table").unwrap()).unwrap()
        .into_iter().filter_map(|r| r.str_at(0).map(|s| (r.key, s.to_string()))).collect();
    let libs = d.records(d.table("Libraries Table").unwrap()).unwrap();
    let lib = &libs[0];
    let mut st = FidStore {
        language_id: lib.str_at(4).unwrap_or_default().into(),
        compiler_spec_id: lib.str_at(7).unwrap_or_default().into(),
        library_family: lib.str_at(0).unwrap_or_default().into(),
        library_version: lib.str_at(1).unwrap_or_default().into(),
        library_variant: lib.str_at(2).unwrap_or_default().into(),
        ..Default::default()
    };
    for r in d.records(d.table("Functions Table").unwrap()).unwrap() {
        st.functions.push(mosura::analysis::fid::matcher::FunctionRecord {
            key: r.key, code_unit_size: r.i64_at(0).unwrap_or(0) as i16,
            full_hash: r.i64_at(1).unwrap_or(0) as u64,
            specific_hash_additional_size: r.i64_at(2).unwrap_or(0) as i8,
            specific_hash: r.i64_at(3).unwrap_or(0) as u64,
            library_id: 1, name_id: r.key,
            name: strings.get(&r.i64_at(5).unwrap_or(0)).cloned().unwrap_or_default(),
            flags: r.i64_at(8).unwrap_or(0) as u8,
        });
    }
    let keys = |t: &str| -> HashSet<i64> { d.table(t).map(|x| d.records(x).unwrap().into_iter().map(|r| r.key).collect()).unwrap_or_default() };
    st.superior = keys("Superior Table");
    st.inferior = keys("Inferior Table");
    println!("{} functions, {} superior, {} inferior", st.functions.len(), st.superior.len(), st.inferior.len());
    std::fs::write(&out, st.to_text()).unwrap();
}
