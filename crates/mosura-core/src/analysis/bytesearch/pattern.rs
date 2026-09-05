//! `Pattern` / `PatternPairSet` / `Match` / `AlignRule` — a port of the like-named files in
//! `Features/Base/.../ghidra/util/bytesearch/`.
//!
//! A [`Pattern`] is a [`DittedBitSequence`] plus a **mark offset** (where in the sequence the
//! reported address lies), a set of **post rules** checked after the byte match, and the
//! **match actions** applied when it survives. `<patternpairs>` is the pre/post factoring:
//! every "pre" sequence (a `ret`, a `nop` run — the filler that precedes a function) is
//! concatenated with every "post" sequence (the prologue itself) to form the real patterns, with
//! the mark landing after the pre part (`createFinalPatterns`, PatternPairSet.java:38).
//!
//! Ghidra builds the action objects through a `PatternFactory` keyed on the XML tag name; here
//! that is the [`PatternFactory`] trait with an associated `Action` type, so the engine stays
//! independent of what the actions mean.

use super::ditted::DittedBitSequence;

/// `PostRule` (PostRule.java:23) — a check applied to a match *after* the bytes agree.
/// `AlignRule` (AlignRule.java:29) is the only implementation Ghidra ships.
#[derive(Clone, Copy, Debug)]
pub enum PostRule {
    /// `AlignRule` — the match address, offset by `align_offset`, must have `alignmask`'s bits
    /// clear (align to 2 → mask 0x1, to 4 → 0x3, …).
    Align { align_offset: i64, alignmask: i64 },
}

impl PostRule {
    /// `AlignRule.apply(pat, matchoffset)` (:63).
    pub fn apply(&self, matchoffset: u64) -> bool {
        match *self {
            PostRule::Align { align_offset, alignmask } => {
                // Java narrows to `int` first (`int off = (int) matchoffset`); the mask only ever
                // covers low bits, so the narrowing is immaterial and is not reproduced.
                ((matchoffset as i64 + align_offset) & alignmask) == 0
            }
        }
    }

    /// `AlignRule.restoreXml` (:70).
    fn restore_xml(node: roxmltree::Node) -> Option<PostRule> {
        if node.tag_name().name() != "align" {
            return None;
        }
        let align_offset = node.attribute("mark").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
        let bits = node.attribute("bits").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
        Some(PostRule::Align { align_offset, alignmask: (1i64 << bits) - 1 })
    }
}

/// `Pattern` (Pattern.java:34) — a sequence, where in it the match is reported, and what to do.
#[derive(Clone, Debug)]
pub struct Pattern<A> {
    /// The bytes to match (Java: `Pattern extends DittedBitSequence`).
    pub seq: DittedBitSequence,
    /// `markOffset` (:36) — the byte within the pattern the match address refers to.
    pub mark_offset: usize,
    /// `postrule` (:37).
    pub post_rules: Vec<PostRule>,
    /// `actions` (:38).
    pub actions: Vec<A>,
}

/// `Match` (Match.java:23) — one hit, resolved against the pattern that produced it.
#[derive(Clone, Copy, Debug)]
pub struct Match<'a, A> {
    pub pattern: &'a Pattern<A>,
    /// `getSequenceIndex()` (:76) — the pattern's index in the list the DFA was built from.
    pub sequence_index: usize,
    /// `getMatchStart()` (:83) — offset of the match within the searched byte stream.
    pub offset: u64,
}

impl<A> Match<'_, A> {
    /// `getMarkOffset()` (:69).
    pub fn mark_offset(&self) -> u64 {
        self.offset + self.pattern.mark_offset as u64
    }

    /// `checkPostRules(streamoffset)` (:96).
    pub fn check_post_rules(&self, streamoffset: u64) -> bool {
        let curoffset = streamoffset.wrapping_add(self.offset);
        self.pattern.post_rules.iter().all(|r| r.apply(curoffset))
    }
}

/// `PatternFactory` (PatternFactory.java:24) — constructs the post rules and match actions named
/// by a pattern file's sub-tags. `&mut self` because Ghidra's implementation
/// (`FunctionStartAnalyzer.restoreXmlAttributes`) records, while parsing, which *kinds* of
/// pre-requisite the file uses — the flags that decide which of the sibling analyzers run at all.
pub trait PatternFactory {
    /// The action type produced (Ghidra's `MatchAction`).
    type Action;

    /// `getMatchActionByName(nm)` (FunctionStartAnalyzer.java:957) + the action's own
    /// `restoreXml`, fused: the node carries both the name and the attributes.
    fn match_action_by_name(&mut self, node: roxmltree::Node) -> Option<Self::Action>;
}

/// `Pattern.readPatterns(file, patlist, pfactory)` (:147) — every `<pattern>` and expanded
/// `<patternpairs>` in one pattern file, in file order.
pub fn read_patterns<F: PatternFactory>(
    xml: &str,
    out: &mut Vec<Pattern<F::Action>>,
    factory: &mut F,
) -> Result<(), String>
where
    F::Action: Clone,
{
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("pattern file XML: {e}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "patternlist" {
        return Err(format!("expected <patternlist>, got <{}>", root.tag_name().name()));
    }
    for el in root.children().filter(|n| n.is_element()) {
        if el.tag_name().name() == "patternpairs" {
            let pairset = PatternPairSet::restore_xml(el, factory)?;
            pairset.create_final_patterns(out);
        } else {
            out.push(restore_pattern_xml(el, factory)?);
        }
    }
    Ok(())
}

/// `Pattern.restoreXml(parser, pfactory)` (:114).
fn restore_pattern_xml<F: PatternFactory>(
    el: roxmltree::Node,
    factory: &mut F,
) -> Result<Pattern<F::Action>, String> {
    if el.tag_name().name() != "pattern" {
        return Err(format!("expected <pattern>, got <{}>", el.tag_name().name()));
    }
    let mut mark_offset: i64 =
        el.attribute("mark").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let data = el
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "data")
        .ok_or("<pattern> has no <data>")?;
    let (seq, moff) = DittedBitSequence::parse(data.text().unwrap_or(""))?;
    if moff >= 0 {
        mark_offset = moff as i64;
    }
    let (post_rules, actions) = restore_xml_attributes(el, factory)?;
    Ok(Pattern { seq, mark_offset: mark_offset.max(0) as usize, post_rules, actions })
}

/// `Pattern.restoreXmlAttributes(postrulelist, actionlist, parser, pfactory)` (:89) — the
/// post-rule and match-action sub-tags that follow the `<data>`.
fn restore_xml_attributes<F: PatternFactory>(
    parent: roxmltree::Node,
    factory: &mut F,
) -> Result<(Vec<PostRule>, Vec<F::Action>), String> {
    let mut post_rules = Vec::new();
    let mut actions = Vec::new();
    for n in parent.children().filter(|n| n.is_element()) {
        let name = n.tag_name().name();
        if name == "data" || name == "prepatterns" || name == "postpatterns" {
            continue; // structure, not a rule/action
        }
        if let Some(rule) = PostRule::restore_xml(n) {
            post_rules.push(rule);
        } else if let Some(action) = factory.match_action_by_name(n) {
            actions.push(action);
        } else {
            return Err(format!("Bad <pattern> subtag: <{name}>"));
        }
    }
    Ok((post_rules, actions))
}

/// `PatternPairSet` (PatternPairSet.java:26).
struct PatternPairSet<A> {
    /// `totalBitsOfCheck` (:27).
    total_bits_of_check: u32,
    /// `postBitsOfCheck` (:28).
    post_bits_of_check: u32,
    /// `preSequences` (:29).
    pre_sequences: Vec<DittedBitSequence>,
    /// `postPatterns` (:30).
    post_patterns: Vec<Pattern<A>>,
}

impl<A: Clone> PatternPairSet<A> {
    /// `restoreXml(parser, pfactory)` (:73).
    fn restore_xml<F: PatternFactory<Action = A>>(
        el: roxmltree::Node,
        factory: &mut F,
    ) -> Result<PatternPairSet<A>, String> {
        let total_bits_of_check =
            el.attribute("totalbits").and_then(|v| v.parse().ok()).unwrap_or(0);
        let post_bits_of_check = el.attribute("postbits").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut pre_sequences = Vec::new();
        let mut post_patterns = Vec::new();
        for child in el.children().filter(|n| n.is_element()) {
            match child.tag_name().name() {
                "prepatterns" => {
                    for d in child.children().filter(|n| n.is_element()) {
                        let (seq, _) = DittedBitSequence::parse(d.text().unwrap_or(""))?;
                        pre_sequences.push(seq);
                    }
                }
                "postpatterns" => {
                    // Every `<data>` in this block shares the block's rules and actions (:96-116).
                    let mut postdit = Vec::new();
                    for d in child.children().filter(|n| n.is_element()) {
                        if d.tag_name().name() != "data" {
                            continue;
                        }
                        let (seq, _) = DittedBitSequence::parse(d.text().unwrap_or(""))?;
                        if seq.num_fixed_bits() >= post_bits_of_check {
                            postdit.push(seq);
                        }
                    }
                    let (post_rules, actions) = restore_xml_attributes(child, factory)?;
                    for seq in postdit {
                        post_patterns.push(Pattern {
                            seq,
                            mark_offset: 0,
                            post_rules: post_rules.clone(),
                            actions: actions.clone(),
                        });
                    }
                }
                other => return Err(format!("Bad <patternpairs> subtag: <{other}>")),
            }
        }
        Ok(PatternPairSet {
            total_bits_of_check,
            post_bits_of_check,
            pre_sequences,
            post_patterns,
        })
    }

    /// `createFinalPatterns(finalpats)` (:38) — the cross product, filtered by the two
    /// bits-of-check thresholds. The mark lands at the end of the pre part, so the reported
    /// address is the start of the *post* sequence: the function entry, not the filler.
    fn create_final_patterns(self, finalpats: &mut Vec<Pattern<A>>) {
        for postpattern in &self.post_patterns {
            let postcheck = postpattern.seq.num_fixed_bits();
            if postcheck < self.post_bits_of_check {
                continue;
            }
            for prepattern in &self.pre_sequences {
                let precheck = prepattern.num_fixed_bits();
                if precheck + postcheck < self.total_bits_of_check {
                    continue;
                }
                finalpats.push(Pattern {
                    seq: prepattern.concatenate(&postpattern.seq),
                    mark_offset: prepattern.size(),
                    post_rules: postpattern.post_rules.clone(),
                    actions: postpattern.actions.clone(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A factory that just records the tag names it was asked for.
    struct TagFactory;
    impl PatternFactory for TagFactory {
        type Action = String;
        fn match_action_by_name(&mut self, node: roxmltree::Node) -> Option<String> {
            Some(node.tag_name().name().to_string())
        }
    }

    #[test]
    fn reads_a_plain_pattern_with_actions() {
        let xml = r#"<patternlist>
          <pattern>
            <data>0x5589e583ec</data>
            <codeboundary/>
            <possiblefuncstart/>
          </pattern>
        </patternlist>"#;
        let mut out: Vec<Pattern<String>> = Vec::new();
        read_patterns(xml, &mut out, &mut TagFactory).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq.size(), 5);
        assert_eq!(out[0].mark_offset, 0);
        assert_eq!(out[0].actions, vec!["codeboundary".to_string(), "possiblefuncstart".into()]);
    }

    /// The `<patternpairs>` expansion is what puts the reported address at the *post* sequence:
    /// `0xc3` + `0x5589e5` matches five bytes but marks byte 1. Getting this wrong would report
    /// every function one byte early, at the previous function's `ret`.
    #[test]
    fn pattern_pairs_expand_and_mark_after_the_pre_sequence() {
        let xml = r#"<patternlist>
          <patternpairs totalbits="32" postbits="16">
            <prepatterns>
              <data>0x90</data>
              <data>0xc3</data>
            </prepatterns>
            <postpatterns>
              <data>0x5589e5</data>
              <data>0xf3</data>
              <codeboundary/>
            </postpatterns>
          </patternpairs>
        </patternlist>"#;
        let mut out: Vec<Pattern<String>> = Vec::new();
        read_patterns(xml, &mut out, &mut TagFactory).unwrap();
        // `0xf3` is 8 fixed bits < postbits=16, so it is dropped at parse; `0x5589e5` (24 bits)
        // survives and crosses with both 8-bit pre sequences for 32 total bits each.
        assert_eq!(out.len(), 2);
        for p in &out {
            assert_eq!(p.seq.size(), 4);
            assert_eq!(p.mark_offset, 1, "the mark must skip the pre sequence");
            assert_eq!(p.actions, vec!["codeboundary".to_string()]);
        }
        assert!(out[0].seq.is_match(0, 0x90) && out[1].seq.is_match(0, 0xc3));
    }

    #[test]
    fn align_post_rule_rejects_unaligned_matches() {
        let xml = r#"<patternlist>
          <pattern>
            <data>0x48</data>
            <align mark="0" bits="4"/>
            <funcstart/>
          </pattern>
        </patternlist>"#;
        let mut out: Vec<Pattern<String>> = Vec::new();
        read_patterns(xml, &mut out, &mut TagFactory).unwrap();
        assert_eq!(out[0].post_rules.len(), 1);
        let m = Match { pattern: &out[0], sequence_index: 0, offset: 0 };
        assert!(m.check_post_rules(0x1000), "16-byte aligned");
        assert!(!m.check_post_rules(0x1008), "not 16-byte aligned");
    }
}
