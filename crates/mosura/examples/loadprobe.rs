fn main(){
 let p=std::env::args().nth(1).expect("path");
 match mosura::analysis::analyze_le_file(std::path::Path::new(&p)) {
   Ok(prog)=>{
     println!("loaded: {} functions, lang={} cspec={}", prog.function_manager.function_count(), prog.language_id, prog.compiler_spec_id);
     let mut n=0; for b in prog.memory.blocks() { println!("  block {:#x} len={}", b.start().offset, b.bytes.as_ref().map_or(0,|x|x.len())); n+=1; if n>4 {break} }
   }
   Err(e)=>println!("load failed: {e:?}"),
 }
}
