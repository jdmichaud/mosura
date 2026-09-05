//! `ghidra.util.bytesearch` — the multi-pattern byte-search engine, ported from
//! `Ghidra/Features/Base/src/main/java/ghidra/util/bytesearch/`.
//!
//! A *ditted* bit sequence is a byte pattern with don't-care bits ("dits"), written either as
//! hex nibbles (`0x5589e5`, `0x5.`) or as 8-character binary groups (`01010...`). A
//! [`Pattern`](pattern::Pattern) pairs such a sequence with **post rules** (checked after the
//! byte match) and **match actions** (applied when it survives). A whole pattern file is compiled
//! into one Aho-Corasick-style DFA ([`SequenceSearchState`](sequence::SequenceSearchState)) that
//! reports every pattern matching at every offset in a single pass, and
//! [`MemoryBytePatternSearcher`](searcher::MemoryBytePatternSearcher) drives that DFA across a
//! program's memory blocks.
//!
//! The engine is generic over the action type: Ghidra's `PatternFactory` interface builds
//! `MatchAction` objects by XML tag name, and its only implementor in this port is
//! [`FunctionStartAnalyzer`](crate::analysis::analyzers::function_start::FunctionStartAnalyzer).
//! Here that is [`PatternFactory`](pattern::PatternFactory) with an associated `Action` type —
//! the same seam, expressed without Java's interface dispatch.
//!
//! Files ported: `DittedBitSequence.java`, `SequenceSearchState.java`, `Pattern.java`,
//! `PatternPairSet.java`, `Match.java`, `AlignRule.java`, `PostRule.java`, `MatchAction.java`,
//! `MemoryBytePatternSearcher.java`.

pub mod ditted;
pub mod pattern;
pub mod searcher;
pub mod sequence;

pub use ditted::DittedBitSequence;
pub use pattern::{Match, Pattern, PatternFactory, PostRule};
pub use searcher::MemoryBytePatternSearcher;
pub use sequence::SequenceSearchState;
