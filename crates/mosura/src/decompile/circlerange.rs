//! Integer value-range manipulation — a faithful port of Ghidra's `CircleRange`
//! (`rangeutil.cc` / `rangeutil.hh`). A `CircleRange` is a half-open interval `[left,right)`
//! over the integers mod `2^n` (`mask = 2^n-1`), optionally strided (`step`). It is the range
//! representation the switch-recovery subsystem (`JumpBasic::analyzeGuards`) uses to pull a
//! guard condition backward through the defining ops of a switch variable — the step
//! [`CircleRange::pull_back`] performs that mosura's simpler `jumptable.rs` normalize lacks.
//!
//! This is the pull-back half of `CircleRange`. The push-forward / `ValueSet` half
//! (`pushForward*`, `widen`, `translate2Op`, `rangeutil.cc:1093`+ and the `ValueSet*` classes)
//! is intentionally **not** ported — `JumpBasic` recovery only needs pull-back. See
//! `docs/coverage.md` §7 and memory `task8-jumpbasic-port-plan`.
//!
//! mosura is `u64`-only (`uintb`), so Ghidra's `8*sizeof(uintb)` is 64 throughout and no
//! Varnode in scope exceeds 8 bytes.

use super::funcdata::Funcdata;
use super::nzmask::{leastsigbit_set, mostsigbit_set};
use super::op::OpId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Ghidra `calc_mask(int4 size)` (`address.cc`) — the all-ones mask for a `size`-byte value.
fn calc_mask(size: i32) -> u64 {
    super::nzmask::calc_mask(size.max(0) as u32)
}

/// Ghidra `count_leading_zeros(uintb)` (`address.cc:773`) — 64 leading zeros for a zero value,
/// matching Rust's `u64::leading_zeros`.
fn count_leading_zeros(val: u64) -> i32 {
    val.leading_zeros() as i32
}

/// Ghidra `sign_extend(uintb in,int4 sizein,int4 sizeout)` (`address.cc:666`) — the value form
/// (as opposed to the mask form in `nzmask::sign_extend_mask`). Used by the `INT_SEXT` pull-back.
fn sign_extend(inp: u64, sizein: i32, sizeout: i32) -> u64 {
    let sizein = sizein.min(8);
    let sizeout = sizeout.min(8);
    let mut sval = inp as i64;
    sval = sval.wrapping_shl(((8 - sizein) * 8) as u32);
    let mut res = (sval >> ((sizeout - sizein) * 8)) as u64; // arithmetic (signed) shift
    res >>= ((8 - sizeout) * 8) as u32;
    res
}

/// Ghidra `bit_transitions(uintb val,int4 sz)` (`address.cc:818`) — the number of 0->1 / 1->0
/// transitions scanning the `sz`-byte value from bit 0. `<= 2` indicates a flag/mask/range shape.
fn bit_transitions(mut val: u64, sz: i32) -> i32 {
    let mut res = 0;
    let mut last = (val & 1) as i32;
    for _ in 1..(8 * sz) {
        val >>= 1;
        let cur = (val & 1) as i32;
        if cur != last {
            res += 1;
            last = cur;
        }
        if val == 0 {
            break;
        }
    }
    res
}

/// Map from raw boundary-overlap bit patterns to a normalized overlap category ('a'..'g').
/// Ghidra `CircleRange::arrange` (`rangeutil.cc:21`).
const ARRANGE: &[u8; 64] =
    b"gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda";

/// A circular integer range `[left,right)` over the integers mod `mask+1`, with stride `step`.
/// Ghidra `CircleRange` (`rangeutil.hh:50`).
#[derive(Clone, Copy, Debug)]
pub struct CircleRange {
    /// Left boundary of the open range `[left,right)`.
    left: u64,
    /// Right boundary of the open range `[left,right)`.
    right: u64,
    /// Bit mask defining the domain size (modulus) of the range.
    mask: u64,
    /// `true` if the set is empty.
    isempty: bool,
    /// Explicit step size.
    step: i32,
}

impl Default for CircleRange {
    /// Ghidra `CircleRange(void)` — an empty range.
    fn default() -> Self {
        CircleRange { left: 0, right: 0, mask: 0, isempty: true, step: 1 }
    }
}

impl PartialEq for CircleRange {
    /// Ghidra `CircleRange::operator==` (`rangeutil.hh:331`).
    fn eq(&self, op2: &CircleRange) -> bool {
        if self.isempty != op2.isempty {
            return false;
        }
        if self.isempty {
            return true;
        }
        self.left == op2.left && self.right == op2.right && self.mask == op2.mask && self.step == op2.step
    }
}

impl CircleRange {
    /// Ghidra `CircleRange(uintb lft,uintb rgt,int4 size,int4 stp)` (`rangeutil.cc:179`).
    pub fn new(lft: u64, rgt: u64, size: i32, stp: i32) -> Self {
        CircleRange { mask: calc_mask(size), step: stp, left: lft, right: rgt, isempty: false }
    }

    /// Ghidra `CircleRange(bool val)` (`rangeutil.cc:191`) — the single-value boolean range.
    pub fn from_bool(val: bool) -> Self {
        CircleRange {
            mask: 0xff,
            step: 1,
            left: if val { 1 } else { 0 },
            right: val as u64 + 1,
            isempty: false,
        }
    }

    /// Ghidra `CircleRange(uintb val,int4 size)` (`rangeutil.cc:205`) — a single value.
    pub fn from_value(val: u64, size: i32) -> Self {
        let mask = calc_mask(size);
        CircleRange { mask, step: 1, left: val, right: (val + 1) & mask, isempty: false }
    }

    /// Ghidra `CircleRange::setRange(uintb lft,uintb rgt,int4 size,int4 step)` (`rangeutil.cc:219`).
    pub fn set_range(&mut self, lft: u64, rgt: u64, size: i32, step: i32) {
        self.mask = calc_mask(size);
        self.left = lft;
        self.right = rgt;
        self.step = step;
        self.isempty = false;
    }

    /// Ghidra `CircleRange::setRange(uintb val,int4 size)` (`rangeutil.cc:233`).
    pub fn set_value(&mut self, val: u64, size: i32) {
        self.mask = calc_mask(size);
        self.step = 1;
        self.left = val;
        self.right = (val + 1) & self.mask;
        self.isempty = false;
    }

    /// Ghidra `CircleRange::setFull(int4 size)` (`rangeutil.cc:245`).
    pub fn set_full(&mut self, size: i32) {
        self.mask = calc_mask(size);
        self.step = 1;
        self.left = 0;
        self.right = 0;
        self.isempty = false;
    }

    pub fn is_empty(&self) -> bool {
        self.isempty
    }

    /// Ghidra `CircleRange::isFull` — contains all possible values.
    pub fn is_full(&self) -> bool {
        !self.isempty && self.step == 1 && self.left == self.right
    }

    /// Ghidra `CircleRange::isSingle` — contains a single value.
    pub fn is_single(&self) -> bool {
        !self.isempty && self.right == (self.left.wrapping_add(self.step as u64) & self.mask)
    }

    pub fn get_min(&self) -> u64 {
        self.left
    }

    /// Ghidra `CircleRange::getMax` — the right-most contained integer.
    pub fn get_max(&self) -> u64 {
        self.right.wrapping_sub(self.step as u64) & self.mask
    }

    pub fn get_end(&self) -> u64 {
        self.right
    }

    pub fn get_mask(&self) -> u64 {
        self.mask
    }

    pub fn get_step(&self) -> i32 {
        self.step
    }

    /// Ghidra `CircleRange::getNext` — advance an integer within the range; `false` at the end.
    pub fn get_next(&self, val: &mut u64) -> bool {
        *val = val.wrapping_add(self.step as u64) & self.mask;
        *val != self.right
    }

    /// Ghidra `CircleRange::normalize` (`rangeutil.cc:25`) — canonicalize a full/empty `left==right`.
    fn normalize(&mut self) {
        if self.left == self.right {
            if self.step != 1 {
                self.left %= self.step as u64;
            } else {
                self.left = 0;
            }
            self.right = self.left;
        }
    }

    /// Ghidra `CircleRange::complement` (`rangeutil.cc:38`) — set to the complement (step==1 only).
    fn complement(&mut self) {
        if self.isempty {
            self.left = 0;
            self.right = 0;
            self.isempty = false;
            return;
        }
        if self.left == self.right {
            self.isempty = true;
            return;
        }
        let tmp = self.left;
        self.left = self.right;
        self.right = tmp;
    }

    /// Ghidra `CircleRange::convertToBoolean` (`rangeutil.cc:63`) — coerce to a boolean range;
    /// returns `true` if the range contained both 0 and 1.
    fn convert_to_boolean(&mut self) -> bool {
        if self.isempty {
            return false;
        }
        let contains_zero = self.contains_val(0);
        let contains_one = self.contains_val(1);
        self.mask = 0xff;
        self.step = 1;
        if contains_zero && contains_one {
            self.left = 0;
            self.right = 2;
            self.isempty = false;
            true
        } else if contains_zero {
            self.left = 0;
            self.right = 1;
            self.isempty = false;
            false
        } else if contains_one {
            self.left = 1;
            self.right = 2;
            self.isempty = false;
            false
        } else {
            self.isempty = true;
            false
        }
    }

    /// Ghidra `CircleRange::newStride` (`rangeutil.cc:103`) — restrict a range to a new stride.
    /// Returns `true` if the result is empty.
    fn new_stride(mask: u64, step: i32, old_step: i32, rem: u32, myleft: &mut u64, myright: &mut u64) -> bool {
        if old_step != 1 {
            let old_rem = (*myleft % old_step as u64) as u32;
            if old_rem != rem % old_step as u32 {
                return true; // Step is completely off
            }
        }
        let orig_order = *myleft < *myright;
        let left_rem = (*myleft % step as u64) as u32;
        let right_rem = (*myright % step as u64) as u32;
        if left_rem > rem {
            *myleft = myleft.wrapping_add((rem + step as u32 - left_rem) as u64);
        } else {
            *myleft = myleft.wrapping_add((rem - left_rem) as u64);
        }
        if right_rem > rem {
            *myright = myright.wrapping_add((rem + step as u32 - right_rem) as u64);
        } else {
            *myright = myright.wrapping_add((rem - right_rem) as u64);
        }
        *myleft &= mask;
        *myright &= mask;
        let new_order = *myleft < *myright;
        orig_order != new_order
    }

    /// Ghidra `CircleRange::newDomain` (`rangeutil.cc:143`) — fit a range into a new domain.
    /// Returns `true` if the truncated domain is empty.
    fn new_domain(new_mask: u64, new_step: i32, myleft: &mut u64, myright: &mut u64) -> bool {
        let rem = if new_step != 1 { *myleft % new_step as u64 } else { 0 };
        if *myleft > new_mask {
            if *myright > new_mask {
                if *myleft < *myright {
                    return true; // completely out of bounds
                }
                *myleft = rem;
                *myright = rem;
                return false;
            }
            *myleft = rem;
        }
        if *myright > new_mask {
            *myright = rem;
        }
        if *myleft == *myright {
            *myleft = rem;
            *myright = rem;
        }
        false
    }

    /// Ghidra `CircleRange::getSize` (`rangeutil.cc:256`) — the number of integers in the range.
    pub fn get_size(&self) -> u64 {
        if self.isempty {
            return 0;
        }
        let step = self.step as u64;
        if self.left < self.right {
            (self.right - self.left) / step
        } else {
            let mut val = (self.mask.wrapping_sub(self.left.wrapping_sub(self.right)).wrapping_add(step)) / step;
            if val == 0 {
                // Overflow: all uintb values are in the range. Lie by one (fine for jumptables).
                val = self.mask;
                if self.step > 1 {
                    val /= step;
                    val += 1;
                }
            }
            val
        }
    }

    /// Ghidra `CircleRange::getMaxInfo` (`rangeutil.cc:280`) — the maximum information content
    /// (index+1 of the most significant non-zero bit across all values).
    pub fn get_max_info(&self) -> i32 {
        let half_point = self.mask ^ (self.mask >> 1);
        if self.contains_val(half_point) {
            return 64 - count_leading_zeros(half_point);
        }
        let size_left = if (half_point & self.left) == 0 {
            count_leading_zeros(self.left)
        } else {
            count_leading_zeros(!self.left & self.mask)
        };
        let size_right = if (half_point & self.right) == 0 {
            count_leading_zeros(self.right)
        } else {
            count_leading_zeros(!self.right & self.mask)
        };
        64 - if size_right < size_left { size_right } else { size_left }
    }

    /// Ghidra `CircleRange::encodeRangeOverlaps` (`rangeutil.hh:358`) — the overlap category code.
    fn encode_range_overlaps(op1left: u64, op1right: u64, op2left: u64, op2right: u64) -> u8 {
        let mut val: usize = if op1left <= op1right { 0x20 } else { 0 };
        val |= if op1left <= op2left { 0x10 } else { 0 };
        val |= if op1left <= op2right { 0x8 } else { 0 };
        val |= if op1right <= op2left { 4 } else { 0 };
        val |= if op1right <= op2right { 2 } else { 0 };
        val |= if op2left <= op2right { 1 } else { 0 };
        ARRANGE[val]
    }

    /// Ghidra `CircleRange::contains(const CircleRange&)` (`rangeutil.cc:301`).
    pub fn contains_range(&self, op2: &CircleRange) -> bool {
        if self.isempty {
            return op2.isempty;
        }
        if op2.isempty {
            return true;
        }
        if self.step > op2.step {
            // Containment impossible with a larger step, except when op2 is a single element.
            if !op2.is_single() {
                return false;
            }
        }
        if self.left == self.right {
            return true;
        }
        if op2.left == op2.right {
            return false;
        }
        if self.left % self.step as u64 != op2.left % self.step as u64 {
            return false; // Wrong phase
        }
        if self.left == op2.left && self.right == op2.right {
            return true;
        }
        let overlap_code = CircleRange::encode_range_overlaps(self.left, self.right, op2.left, op2.right);
        if overlap_code == b'c' {
            return true;
        }
        if overlap_code == b'b' && self.right == op2.right {
            return true;
        }
        false
    }

    /// Ghidra `CircleRange::contains(uintb)` (`rangeutil.cc:334`).
    pub fn contains_val(&self, val: u64) -> bool {
        if self.isempty {
            return false;
        }
        if self.step != 1 && (self.left % self.step as u64) != (val % self.step as u64) {
            return false; // Phase is wrong
        }
        if self.left < self.right {
            if val < self.left {
                return false;
            }
            if self.right <= val {
                return false;
            }
        } else if self.right < self.left {
            if val < self.right {
                return true;
            }
            if val >= self.left {
                return true;
            }
            return false;
        }
        true
    }

    /// Ghidra `CircleRange::circleUnion` (`rangeutil.cc:360`) — union as a single interval.
    /// Returns 0 if valid, 2 if the union is two pieces (then `self` is unmodified).
    pub fn circle_union(&mut self, op2: &CircleRange) -> i32 {
        if op2.isempty {
            return 0;
        }
        if self.isempty {
            *self = *op2;
            return 0;
        }
        if self.mask != op2.mask {
            return 2; // Cannot union different domains
        }
        let mut a_right = self.right;
        let mut b_right = op2.right;
        let mut new_step = self.step;
        if self.step < op2.step {
            if self.is_single() {
                new_step = op2.step;
                a_right = self.left.wrapping_add(new_step as u64) & self.mask;
            } else {
                return 2;
            }
        } else if op2.step < self.step {
            if op2.is_single() {
                new_step = self.step;
                b_right = op2.left.wrapping_add(new_step as u64) & self.mask;
            } else {
                return 2;
            }
        }
        let rem = if new_step != 1 {
            let r = self.left % new_step as u64;
            if r != op2.left % new_step as u64 {
                return 2;
            }
            r
        } else {
            0
        };
        if self.left == a_right || op2.left == b_right {
            self.left = rem;
            self.right = rem;
            self.step = new_step;
            return 0;
        }
        let overlap_code = CircleRange::encode_range_overlaps(self.left, a_right, op2.left, b_right);
        match overlap_code {
            b'a' | b'f' => {
                if a_right == op2.left {
                    self.right = b_right;
                    self.step = new_step;
                    return 0;
                }
                if self.left == b_right {
                    self.left = op2.left;
                    self.right = a_right;
                    self.step = new_step;
                    return 0;
                }
                2
            }
            b'b' => {
                self.right = b_right;
                self.step = new_step;
                0
            }
            b'c' => {
                self.right = a_right;
                self.step = new_step;
                0
            }
            b'd' => {
                self.left = op2.left;
                self.right = b_right;
                self.step = new_step;
                0
            }
            b'e' => {
                self.left = op2.left;
                self.right = a_right;
                self.step = new_step;
                0
            }
            b'g' => {
                self.left = rem;
                self.right = rem;
                self.step = new_step;
                0
            }
            _ => -1, // Never reached
        }
    }

    /// Ghidra `CircleRange::minimalContainer` (`rangeutil.cc:454`) — a minimal range containing
    /// both `self` and `op2`. Returns `true` if the container is everything.
    pub fn minimal_container(&mut self, op2: &CircleRange, max_step: i32) -> bool {
        if self.is_single() && op2.is_single() {
            let (min, max) = if self.get_min() < op2.get_min() {
                (self.get_min(), op2.get_min())
            } else {
                (op2.get_min(), self.get_min())
            };
            let diff = max - min;
            if diff > 0 && diff <= max_step as u64 && leastsigbit_set(diff) == mostsigbit_set(diff) {
                self.step = diff as i32;
                self.left = min;
                self.right = (max + self.step as u64) & self.mask;
                return false;
            }
        }
        let a_right = self.right.wrapping_sub(self.step as u64).wrapping_add(1); // Treat as step=1
        let b_right = op2.right.wrapping_sub(op2.step as u64).wrapping_add(1);
        self.step = 1;
        self.mask |= op2.mask;
        let overlap_code = CircleRange::encode_range_overlaps(self.left, a_right, op2.left, b_right);
        match overlap_code {
            b'a' => {
                let vacant1 = self.left.wrapping_add(self.mask - b_right).wrapping_add(1);
                let vacant2 = op2.left.wrapping_sub(a_right);
                if vacant1 < vacant2 {
                    self.left = op2.left;
                    self.right = a_right;
                } else {
                    self.right = b_right;
                }
            }
            b'f' => {
                let vacant1 = op2.left.wrapping_add(self.mask - a_right).wrapping_add(1);
                let vacant2 = self.left.wrapping_sub(b_right);
                if vacant1 < vacant2 {
                    self.right = b_right;
                } else {
                    self.left = op2.left;
                    self.right = a_right;
                }
            }
            b'b' => self.right = b_right,
            b'c' => self.right = a_right,
            b'd' => {
                self.left = op2.left;
                self.right = b_right;
            }
            b'e' => {
                self.left = op2.left;
                self.right = a_right;
            }
            b'g' => {
                self.left = 0;
                self.right = 0;
            }
            _ => {}
        }
        self.normalize();
        self.left == self.right
    }

    /// Ghidra `CircleRange::invert` (`rangeutil.cc:533`) — convert to the complementary range;
    /// returns the original step.
    pub fn invert(&mut self) -> i32 {
        let res = self.step;
        self.step = 1;
        self.complement();
        res
    }

    /// Ghidra `CircleRange::intersect` (`rangeutil.cc:549`) — intersect as a single interval.
    /// Returns 0 if valid, 2 if the intersection is two pieces (then `self` is unmodified).
    pub fn intersect(&mut self, op2: &CircleRange) -> i32 {
        if self.isempty {
            return 0; // Intersection with empty is empty
        }
        if op2.isempty {
            self.isempty = true;
            return 0;
        }
        let mut myleft = self.left;
        let mut myright = self.right;
        let mut op2left = op2.left;
        let mut op2right = op2.right;
        let new_step;
        if self.step < op2.step {
            new_step = op2.step;
            let rem = (op2left % new_step as u64) as u32;
            if CircleRange::new_stride(self.mask, new_step, self.step, rem, &mut myleft, &mut myright) {
                self.isempty = true;
                return 0;
            }
        } else if op2.step < self.step {
            new_step = self.step;
            let rem = (myleft % new_step as u64) as u32;
            if CircleRange::new_stride(op2.mask, new_step, op2.step, rem, &mut op2left, &mut op2right) {
                self.isempty = true;
                return 0;
            }
        } else {
            new_step = self.step;
        }
        let new_mask = self.mask & op2.mask;
        if self.mask != new_mask {
            if CircleRange::new_domain(new_mask, new_step, &mut myleft, &mut myright) {
                self.isempty = true;
                return 0;
            }
        } else if op2.mask != new_mask
            && CircleRange::new_domain(new_mask, new_step, &mut op2left, &mut op2right)
        {
            self.isempty = true;
            return 0;
        }
        let retval;
        if myleft == myright {
            self.left = op2left;
            self.right = op2right;
            retval = 0;
        } else if op2left == op2right {
            self.left = myleft;
            self.right = myright;
            retval = 0;
        } else {
            let overlap_code = CircleRange::encode_range_overlaps(myleft, myright, op2left, op2right);
            match overlap_code {
                b'a' | b'f' => {
                    self.isempty = true;
                    retval = 0;
                }
                b'b' => {
                    self.left = op2left;
                    self.right = myright;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                    retval = 0;
                }
                b'c' => {
                    self.left = op2left;
                    self.right = op2right;
                    retval = 0;
                }
                b'd' => {
                    self.left = myleft;
                    self.right = myright;
                    retval = 0;
                }
                b'e' => {
                    self.left = myleft;
                    self.right = op2right;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                    retval = 0;
                }
                b'g' => {
                    if myleft == op2right {
                        self.left = op2left;
                        self.right = myright;
                        if self.left == self.right {
                            self.isempty = true;
                        }
                        retval = 0;
                    } else if op2left == myright {
                        self.left = myleft;
                        self.right = op2right;
                        if self.left == self.right {
                            self.isempty = true;
                        }
                        retval = 0;
                    } else {
                        retval = 2;
                    }
                }
                _ => retval = 2,
            }
        }
        if retval != 0 {
            return retval;
        }
        self.mask = new_mask;
        self.step = new_step;
        0
    }

    /// Ghidra `CircleRange::setNZMask` (`rangeutil.cc:672`) — build a range from a putative mask.
    /// Returns `true` if the mask was valid (else `self` is unmodified).
    pub fn set_nz_mask(&mut self, nzmask: u64, size: i32) -> bool {
        let trans = bit_transitions(nzmask, size);
        if trans > 2 {
            return false; // Too many transitions to form a range
        }
        let hasstep = (nzmask & 1) == 0;
        if !hasstep && trans == 2 {
            return false; // Two sections of non-zero bits
        }
        self.isempty = false;
        if trans == 0 {
            self.mask = calc_mask(size);
            self.step = 1;
            if hasstep {
                self.left = 0;
                self.right = 1; // Range containing only zero
            } else {
                self.left = 0;
                self.right = 0; // Everything
            }
            return true;
        }
        let shift = leastsigbit_set(nzmask);
        self.step = 1i32.wrapping_shl(shift as u32);
        self.mask = calc_mask(size);
        self.left = 0;
        self.right = nzmask.wrapping_add(self.step as u64) & self.mask;
        true
    }

    /// Ghidra `CircleRange::setStride` (`rangeutil.cc:707`) — change the step, removing elements.
    pub fn set_stride(&mut self, new_step: i32, rem: u64) {
        let iseverything = !self.isempty && self.left == self.right;
        if new_step == self.step {
            return;
        }
        let mut a_right = self.right.wrapping_sub(self.step as u64);
        self.step = new_step;
        if self.step == 1 {
            return; // No remainder to fill in
        }
        let step = self.step as u64;
        let cur_rem = self.left % step;
        self.left = self.left.wrapping_sub(cur_rem).wrapping_add(rem);
        let cur_rem = a_right % step;
        a_right = a_right.wrapping_sub(cur_rem).wrapping_add(rem);
        self.right = a_right.wrapping_add(step);
        if !iseverything && self.left == self.right {
            self.isempty = true;
        }
    }

    /// Ghidra `CircleRange::pullBackUnary` (`rangeutil.cc:728`) — pull `self` back through a
    /// unary operator. Returns `true` if a valid range is formed.
    pub fn pull_back_unary(&mut self, opc: OpCode, in_size: i32, out_size: i32) -> bool {
        // If there is nothing in the output set, no input maps to it.
        if self.isempty {
            return true;
        }
        match opc {
            OpCode::BoolNegate => {
                if self.convert_to_boolean() {
                    // Both outputs possible => both inputs possible
                } else {
                    self.left ^= 1; // Flip the boolean range
                    self.right = self.left + 1;
                }
            }
            OpCode::Copy => {} // Identity transform on range
            OpCode::Int2comp => {
                let val = (!self.left).wrapping_add(1).wrapping_add(self.step as u64) & self.mask;
                self.left = (!self.right).wrapping_add(1).wrapping_add(self.step as u64) & self.mask;
                self.right = val;
            }
            OpCode::IntNegate => {
                let val = (!self.left).wrapping_add(self.step as u64) & self.mask;
                self.left = (!self.right).wrapping_add(self.step as u64) & self.mask;
                self.right = val;
            }
            OpCode::IntZext => {
                let val = calc_mask(in_size); // (smaller) input mask
                let rem = self.left % self.step as u64;
                let zextrange = CircleRange {
                    left: rem,
                    right: val + 1 + rem, // Biggest possible range of ZEXT
                    mask: self.mask,
                    step: self.step, // Keep the same stride
                    isempty: false,
                };
                if 0 != self.intersect(&zextrange) {
                    return false;
                }
                self.left &= val;
                self.right &= val;
                self.mask &= val; // Preserve the stride
            }
            OpCode::IntSext => {
                let val = calc_mask(in_size); // (smaller) input mask
                let rem = self.left & self.step as u64;
                let mut sextrange = CircleRange {
                    left: (val ^ (val >> 1)) + rem, // High-order bit for (small) input space
                    right: 0,
                    mask: self.mask,
                    step: self.step, // Keep the same stride
                    isempty: false,
                };
                sextrange.right = sign_extend(sextrange.left, in_size, out_size);
                if sextrange.intersect(&*self) != 0 {
                    return false;
                } else if !sextrange.is_empty() {
                    return false;
                } else {
                    self.left &= val;
                    self.right &= val;
                    self.mask &= val; // Preserve the stride
                }
            }
            _ => return false,
        }
        true
    }

    /// Ghidra `CircleRange::pullBackBinary` (`rangeutil.cc:807`) — pull `self` back through a
    /// binary operator with a constant `val` on the other input (`slot` is the variable input's
    /// slot). Returns `true` if a valid range is formed. Note there is deliberately no `SUBPIECE`
    /// case: the driver ([`pull_back`]) handles zero-offset `SUBPIECE` specially via the NZMASK.
    pub fn pull_back_binary(&mut self, opc: OpCode, val: u64, slot: i32, in_size: i32, _out_size: i32) -> bool {
        // If there is nothing in the output set, no input maps to it.
        if self.isempty {
            return true;
        }
        match opc {
            OpCode::IntEqual => {
                let both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(in_size);
                if both_true_false {
                    return true; // All possible outs => all possible ins
                }
                let yescomplement = self.left == 0;
                self.left = val;
                self.right = (val + 1) & self.mask;
                if yescomplement {
                    self.complement();
                }
            }
            OpCode::IntNotequal => {
                let both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(in_size);
                if both_true_false {
                    return true;
                }
                let yescomplement = self.left == 0;
                self.left = (val + 1) & self.mask;
                self.right = val;
                if yescomplement {
                    self.complement();
                }
            }
            OpCode::IntLess => {
                let both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(in_size);
                if both_true_false {
                    return true;
                }
                let yescomplement = self.left == 0;
                if slot == 0 {
                    if val == 0 {
                        self.isempty = true; // X < 0 is always false
                    } else {
                        self.left = 0;
                        self.right = val;
                    }
                } else if val == self.mask {
                    self.isempty = true; // 0xffff < X is always false
                } else {
                    self.left = (val + 1) & self.mask;
                    self.right = 0;
                }
                if yescomplement {
                    self.complement();
                }
            }
            OpCode::IntLessequal => {
                let both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(in_size);
                if both_true_false {
                    return true;
                }
                let yescomplement = self.left == 0;
                if slot == 0 {
                    self.left = 0;
                    self.right = (val + 1) & self.mask;
                } else {
                    self.left = val;
                    self.right = 0;
                }
                if yescomplement {
                    self.complement();
                }
            }
            OpCode::IntSless => {
                let both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(in_size);
                if both_true_false {
                    return true;
                }
                let yescomplement = self.left == 0;
                if slot == 0 {
                    if val == (self.mask >> 1) + 1 {
                        self.isempty = true; // X < -infinity is always false
                    } else {
                        self.left = (self.mask >> 1) + 1; // -infinity
                        self.right = val;
                    }
                } else if val == (self.mask >> 1) {
                    self.isempty = true; // infinity < X is always false
                } else {
                    self.left = (val + 1) & self.mask;
                    self.right = (self.mask >> 1) + 1; // -infinity
                }
                if yescomplement {
                    self.complement();
                }
            }
            OpCode::IntSlessequal => {
                let both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(in_size);
                if both_true_false {
                    return true;
                }
                let yescomplement = self.left == 0;
                if slot == 0 {
                    self.left = (self.mask >> 1) + 1; // -infinity
                    self.right = (val + 1) & self.mask;
                } else {
                    self.left = val;
                    self.right = (self.mask >> 1) + 1; // -infinity
                }
                if yescomplement {
                    self.complement();
                }
            }
            OpCode::IntCarry => {
                let both_true_false = self.convert_to_boolean();
                self.mask = calc_mask(in_size);
                if both_true_false {
                    return true;
                }
                let yescomplement = self.left == 0;
                if val == 0 {
                    self.isempty = true; // Nothing carries adding zero
                } else {
                    self.left = (self.mask - val).wrapping_add(1) & self.mask;
                    self.right = 0;
                }
                if yescomplement {
                    self.complement();
                }
            }
            OpCode::IntAdd => {
                self.left = self.left.wrapping_sub(val) & self.mask;
                self.right = self.right.wrapping_sub(val) & self.mask;
            }
            OpCode::IntSub => {
                if slot == 0 {
                    self.left = self.left.wrapping_add(val) & self.mask;
                    self.right = self.right.wrapping_add(val) & self.mask;
                } else {
                    self.left = val.wrapping_sub(self.left) & self.mask;
                    self.right = val.wrapping_sub(self.right) & self.mask;
                }
            }
            OpCode::IntRight => {
                if self.step != 1 {
                    return false;
                }
                let right_bound = (calc_mask(in_size) >> val).wrapping_add(1); // maximal right bound
                if ((self.left >= right_bound) && (self.right >= right_bound) && (self.left >= self.right))
                    || ((self.left == 0) && (self.right >= right_bound))
                    || (self.left == self.right)
                {
                    self.left = 0; // domain is everything
                    self.right = 0;
                } else {
                    if self.left > right_bound {
                        self.left = right_bound;
                    }
                    if self.right > right_bound {
                        self.right = 0;
                    }
                    self.left = (self.left << val) & self.mask;
                    self.right = (self.right << val) & self.mask;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                }
            }
            OpCode::IntSright => {
                if self.step != 1 {
                    return false;
                }
                let rightb0 = calc_mask(in_size);
                let leftb = rightb0 >> (val + 1);
                let rightb = leftb ^ rightb0; // Smallest negative possible
                let leftb = leftb + 1; // Biggest positive (+1) possible
                if ((self.left >= leftb) && (self.left <= rightb) && (self.right >= leftb)
                    && (self.right <= rightb) && (self.left >= self.right))
                    || (self.left == self.right)
                {
                    self.left = 0; // domain is everything
                    self.right = 0;
                } else {
                    if (self.left > leftb) && (self.left < rightb) {
                        self.left = leftb;
                    }
                    if (self.right > leftb) && (self.right < rightb) {
                        self.right = rightb;
                    }
                    self.left = (self.left << val) & self.mask;
                    self.right = (self.right << val) & self.mask;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                }
            }
            _ => return false,
        }
        true
    }

    /// Ghidra `CircleRange::pullBack` (`rangeutil.cc:1022`) — the driver: pull `self` back through
    /// the given `op` and return the single unknown input Varnode (or `None` if the pull-back does
    /// not form a range). `usenzmask` additionally intersects with the input's NZMASK range.
    ///
    /// Ghidra's `constMarkup` out-param (passing back a constant that carries a `SymbolEntry` equate
    /// so `buildAddresses` can label the switch value) is not modeled: mosura Varnodes carry no
    /// `SymbolEntry` in this context. That equate markup is a follow-up if a fixture needs it.
    pub fn pull_back(&mut self, data: &Funcdata, op: OpId, usenzmask: bool) -> Option<VarnodeId> {
        let opc = data.op(op).code();
        let out_size = data.vn(data.op(op).output?).size as i32;
        let res: VarnodeId;
        if data.op(op).num_inputs() == 1 {
            res = data.op(op).input(0)?;
            if data.vn(res).is_constant() {
                return None;
            }
            if !self.pull_back_unary(opc, data.vn(res).size as i32, out_size) {
                return None;
            }
        } else if data.op(op).num_inputs() == 2 {
            // Find the non-constant input varnode and its slot; the other must be constant.
            let mut slot = 0;
            let mut res_vn = data.op(op).input(0)?;
            let mut constvn = data.op(op).input(1)?;
            if data.vn(res_vn).is_constant() {
                slot = 1;
                constvn = res_vn;
                res_vn = data.op(op).input(1)?;
                if data.vn(res_vn).is_constant() {
                    return None;
                }
            } else if !data.vn(constvn).is_constant() {
                return None;
            }
            res = res_vn;
            let val = data.vn(constvn).constant_value();
            if !self.pull_back_binary(opc, val, slot, data.vn(res).size as i32, out_size) {
                if usenzmask && opc == OpCode::Subpiece && val == 0 {
                    // If everything we are truncating is known zero, we may still have a range.
                    let mut msbset = mostsigbit_set(data.vn(res).get_nzmask());
                    msbset = (msbset + 8) / 8;
                    if out_size < msbset {
                        return None; // Some chopped-off bytes might not be zero
                    }
                    // Keep the range but widen the mask; the NZMASK intersect below re-narrows it.
                    self.mask = calc_mask(data.vn(res).size as i32);
                } else {
                    return None;
                }
            }
        } else {
            return None; // Neither unary nor binary
        }

        if usenzmask {
            let mut nzrange = CircleRange::default();
            if !nzrange.set_nz_mask(data.vn(res).get_nzmask(), data.vn(res).size as i32) {
                return Some(res);
            }
            self.intersect(&nzrange);
            // If the intersect produces two pieces the original range is preserved and we still
            // consider the pull-back successful.
        }
        Some(res)
    }

    /// Ghidra `CircleRange::translate2Op` (`rangeutil.cc:1093`): express this range as a single
    /// comparison against a constant. Returns `(restype, opc, c, cslot)`:
    ///   - `0` — representable: the range is `opc` with the constant `c` in input slot `cslot`
    ///     (the tested Varnode goes in the other slot);
    ///   - `1` — the range covers every value (condition always true);
    ///   - `2` — cannot be represented as a single comparison (a stride, or a two-ended interval);
    ///   - `3` — the range is empty (condition always false).
    ///
    /// `opc`/`c`/`cslot` are meaningful only when `restype == 0`.
    pub fn translate2_op(&self) -> (i32, OpCode, u64, i32) {
        if self.isempty {
            return (3, OpCode::Copy, 0, 0);
        }
        if self.step != 1 {
            return (2, OpCode::Copy, 0, 0); // Not possible with a stride
        }
        if self.right == (self.left.wrapping_add(1) & self.mask) {
            // Single value
            return (0, OpCode::IntEqual, self.left, 0);
        }
        if self.left == (self.right.wrapping_add(1) & self.mask) {
            // All but one value
            return (0, OpCode::IntNotequal, self.right, 0);
        }
        if self.left == self.right {
            return (1, OpCode::Copy, 0, 0); // All outputs are possible
        }
        if self.left == 0 {
            return (0, OpCode::IntLess, self.right, 1);
        }
        if self.right == 0 {
            return (0, OpCode::IntLess, self.left.wrapping_sub(1) & self.mask, 0);
        }
        if self.left == (self.mask >> 1) + 1 {
            return (0, OpCode::IntSless, self.right, 1);
        }
        if self.right == (self.mask >> 1) + 1 {
            return (0, OpCode::IntSless, self.left.wrapping_sub(1) & self.mask, 0);
        }
        (2, OpCode::Copy, 0, 0) // Cannot represent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{Funcdata, SeqNum};

    // ---- Brute-force element-set oracle, ported from Ghidra's `testcirclerange.cc` -------------
    //
    // `CircleRangeTest` holds the *explicit* set of integers a range denotes. Operations are
    // applied element-wise (via the p-code `recoverInput*` behaviours), then the result is
    // reconstructed into (start,stop,step) and compared against the symbolic `CircleRange`. This
    // is an independent reference implementation — matching it proves the symbolic port faithful.

    /// Ghidra `uintb_negate(uintb in,int4 size)` (`address.cc:654`).
    fn uintb_negate(inp: u64, size: i32) -> u64 {
        (!inp) & calc_mask(size)
    }

    struct CircleRangeTest {
        elements: Vec<u64>,
        mask: u64,
        bytes: i32,
    }

    impl CircleRangeTest {
        fn from_range(range: &CircleRange) -> Self {
            let mask = range.get_mask();
            let mut elements = Vec::new();
            if !range.is_empty() {
                let mut start = range.get_min();
                loop {
                    elements.push(start);
                    let next = start.wrapping_add(range.get_step() as u64) & mask;
                    if next == range.get_end() {
                        break;
                    }
                    start = next;
                }
            }
            let temp = mask.wrapping_add(1);
            let bytes = if temp == 0 {
                8
            } else {
                let mut t = temp;
                let mut b = -1;
                while t != 0 {
                    t >>= 1;
                    b += 1;
                }
                b / 8
            };
            CircleRangeTest { elements, mask, bytes }
        }

        fn set_intersect(&mut self, op2: &mut CircleRangeTest) {
            self.elements.sort_unstable();
            op2.elements.sort_unstable();
            let mut res = Vec::new();
            let (mut i, mut j) = (0, 0);
            while i < self.elements.len() && j < op2.elements.len() {
                if self.elements[i] < op2.elements[j] {
                    i += 1;
                } else if op2.elements[j] < self.elements[i] {
                    j += 1;
                } else {
                    res.push(self.elements[i]);
                    i += 1;
                    j += 1;
                }
            }
            self.elements = res;
        }

        fn set_union(&mut self, op2: &mut CircleRangeTest) {
            self.elements.sort_unstable();
            op2.elements.sort_unstable();
            let mut res = Vec::new();
            let (mut i, mut j) = (0, 0);
            while i < self.elements.len() && j < op2.elements.len() {
                if self.elements[i] < op2.elements[j] {
                    res.push(self.elements[i]);
                    i += 1;
                } else if op2.elements[j] < self.elements[i] {
                    res.push(op2.elements[j]);
                    j += 1;
                } else {
                    res.push(self.elements[i]);
                    i += 1;
                    j += 1;
                }
            }
            res.extend_from_slice(&self.elements[i..]);
            res.extend_from_slice(&op2.elements[j..]);
            self.elements = res;
        }

        fn recover_input_unary(opcode: OpCode, _sizeout: i32, out: u64, sizein: i32) -> Option<u64> {
            match opcode {
                OpCode::Copy => Some(out),
                OpCode::IntNegate => Some(uintb_negate(out, sizein)),
                OpCode::Int2comp => Some(uintb_negate(out.wrapping_sub(1), sizein)),
                OpCode::IntZext => {
                    let mask = calc_mask(sizein);
                    if (mask & out) != out {
                        None // Output not in range of zext
                    } else {
                        Some(out)
                    }
                }
                OpCode::IntSext => {
                    let masklong = calc_mask(_sizeout);
                    let maskshort = calc_mask(sizein);
                    if (out & (maskshort ^ (maskshort >> 1))) == 0 {
                        // Positive input
                        if (out & maskshort) != out {
                            return None;
                        }
                    } else {
                        // Negative input
                        if (out & (masklong ^ maskshort)) != (masklong ^ maskshort) {
                            return None;
                        }
                    }
                    Some(out & maskshort)
                }
                _ => panic!("recover_input_unary: unhandled opcode {opcode:?}"),
            }
        }

        fn recover_input_binary(opcode: OpCode, slot: i32, sizeout: i32, out: u64, _sizein: i32, inval: u64) -> Option<u64> {
            match opcode {
                OpCode::IntAdd => Some(out.wrapping_sub(inval) & calc_mask(sizeout)),
                OpCode::IntSub => {
                    let res = if slot == 0 { inval.wrapping_add(out) } else { inval.wrapping_sub(out) };
                    Some(res & calc_mask(sizeout))
                }
                _ => panic!("recover_input_binary: unhandled opcode {opcode:?}"),
            }
        }

        fn pullback_unary(&mut self, opcode: OpCode, insize: i32) {
            let mut res = Vec::new();
            for &e in &self.elements {
                if let Some(v) = CircleRangeTest::recover_input_unary(opcode, self.bytes, e, insize) {
                    res.push(v);
                }
            }
            self.elements = res;
            if insize != self.bytes {
                self.bytes = insize;
                self.mask = calc_mask(insize);
            }
        }

        fn pullback_binary(&mut self, opcode: OpCode, slot: i32, val: u64) {
            let mut res = Vec::new();
            for &e in &self.elements {
                if let Some(v) = CircleRangeTest::recover_input_binary(opcode, slot, self.bytes, e, self.bytes, val) {
                    res.push(v);
                }
            }
            self.elements = res;
        }

        /// Ghidra `CircleRangeTest::getStartStopStep` (`testcirclerange.cc:291`) — reconstruct a
        /// (start,stop,step) range from the element set; returns `false` if it isn't a valid range.
        fn get_start_stop_step(&mut self) -> (bool, u64, u64, i32) {
            if self.elements.is_empty() {
                return (true, 0, 0, 1);
            }
            self.elements.sort_unstable();
            self.elements.dedup();

            if *self.elements.last().unwrap() > self.mask {
                return (false, 0, 0, 1);
            }
            if self.elements.len() == 1 {
                let start = self.elements[0];
                return (true, start, (start + 1) & self.mask, 1);
            }
            if self.elements.len() == 2 {
                let diff = self.elements[0].wrapping_sub(self.elements[1]) & self.mask;
                if diff == 1 || diff == 2 || diff == 4 || diff == 8 {
                    let start = self.elements[1];
                    return (true, start, (start + diff + diff) & self.mask, diff as i32);
                }
            }
            let mut bigpos: i32 = -1;
            let mut biggest1 = 0u64;
            let mut biggest2 = 0u64;
            for i in 1..self.elements.len() {
                let diff = self.elements[i] - self.elements[i - 1];
                if diff >= biggest1 {
                    if diff > biggest1 {
                        biggest2 = biggest1;
                        biggest1 = diff;
                        bigpos = i as i32;
                    }
                } else if diff > biggest2 {
                    biggest2 = diff;
                }
            }
            if biggest1 == 0 {
                return (false, 0, 0, 1);
            }
            if biggest2 == 0 {
                let step = biggest1;
                return (true, self.elements[0], (self.elements.last().unwrap() + step) & self.mask, step as i32);
            }
            let (mut count1, mut count2, mut count3) = (0, 0, 0);
            for i in 1..self.elements.len() {
                let diff = self.elements[i] - self.elements[i - 1];
                if diff == biggest1 {
                    count1 += 1;
                } else if diff == biggest2 {
                    count2 += 1;
                } else {
                    count3 += 1;
                }
            }
            let _ = count2;
            if count3 > 0 {
                return (false, 0, 0, 1);
            }
            if count1 > 1 {
                return (false, 0, 0, 1);
            }
            let step = biggest2;
            let tmp = self.elements.last().unwrap() + step;
            if tmp <= self.mask {
                return (false, 0, 0, 1);
            }
            let tmp = tmp - (self.mask + 1);
            if tmp != self.elements[0] {
                return (false, 0, 0, 1);
            }
            let start = self.elements[bigpos as usize];
            let stop = self.elements[(bigpos - 1) as usize] + step;
            (true, start, stop, step as i32)
        }

        fn test_equal(&mut self, valid: bool, range: &CircleRange) -> bool {
            if self.elements.is_empty() {
                return range.is_empty();
            } else if range.is_empty() {
                return false;
            }
            let (testvalid, start, stop, step) = self.get_start_stop_step();
            if testvalid != valid {
                return false;
            }
            if !valid {
                return true;
            }
            start == range.get_min() && stop == range.get_end() && step == range.get_step()
        }

        fn test_intersect(start1: u64, stop1: u64, start2: u64, stop2: u64, step: i32, bytes: i32) -> bool {
            let mut range1 = CircleRange::new(start1, stop1, bytes, step);
            let range2 = CircleRange::new(start2, stop2, bytes, step);
            let mut t1 = CircleRangeTest::from_range(&range1);
            let mut t2 = CircleRangeTest::from_range(&range2);
            let code = range1.intersect(&range2);
            t1.set_intersect(&mut t2);
            t1.test_equal(code == 0, &range1)
        }

        fn test_union(start1: u64, stop1: u64, start2: u64, stop2: u64, step: i32, bytes: i32) -> bool {
            let mut range1 = CircleRange::new(start1, stop1, bytes, step);
            let range2 = CircleRange::new(start2, stop2, bytes, step);
            let mut t1 = CircleRangeTest::from_range(&range1);
            let mut t2 = CircleRangeTest::from_range(&range2);
            let code = range1.circle_union(&range2);
            t1.set_union(&mut t2);
            t1.test_equal(code == 0, &range1)
        }

        fn test_pullback_unary(start: u64, stop: u64, step: i32, bytes: i32, opcode: OpCode, insize: i32) -> bool {
            let mut range = CircleRange::new(start, stop, bytes, step);
            let mut t = CircleRangeTest::from_range(&range);
            let valid = range.pull_back_unary(opcode, insize, bytes);
            t.pullback_unary(opcode, insize);
            t.test_equal(valid, &range)
        }

        fn test_pullback_binary(start: u64, stop: u64, step: i32, bytes: i32, opcode: OpCode, slot: i32, val: u64) -> bool {
            let mut range = CircleRange::new(start, stop, bytes, step);
            let mut t = CircleRangeTest::from_range(&range);
            let valid = range.pull_back_binary(opcode, val, slot, bytes, bytes);
            t.pullback_binary(opcode, slot, val);
            t.test_equal(valid, &range)
        }
    }

    // ---- Ported Ghidra TEST vectors (testcirclerange.cc). pushForward TESTs are skipped. -------

    #[test]
    fn circlerange_intersect() {
        assert!(CircleRangeTest::test_intersect(1, 20, 10, 30, 1, 4));
        assert!(CircleRangeTest::test_intersect(200, 10, 250, 5, 1, 1));
        assert!(CircleRangeTest::test_intersect(1, 250, 240, 5, 1, 1));
        assert!(CircleRangeTest::test_intersect(4, 100, 248, 52, 4, 1));
        assert!(CircleRangeTest::test_intersect(0x100000, 0x1000fe, 0xfffffffffffffff0, 0xfffffffffffffffe, 2, 8));
        assert!(CircleRangeTest::test_intersect(0x100, 0x110, 0x110, 0x130, 4, 2));
        assert!(CircleRangeTest::test_intersect(0xffe0, 0x20, 0, 0x20, 2, 2));
        assert!(CircleRangeTest::test_intersect(0x80, 0x8, 0xd0, 0x80, 1, 1));
    }

    #[test]
    fn circlerange_union() {
        assert!(CircleRangeTest::test_union(1, 20, 10, 30, 1, 4));
        assert!(CircleRangeTest::test_union(200, 10, 250, 5, 1, 1));
        assert!(CircleRangeTest::test_union(1, 250, 240, 5, 1, 1));
        assert!(CircleRangeTest::test_union(4, 100, 248, 52, 4, 1));
        assert!(CircleRangeTest::test_union(0x100000, 0x1000fe, 0xfffffffffffffff0, 0xfffffffffffffffe, 2, 8));
        assert!(CircleRangeTest::test_union(0x100, 0x110, 0x110, 0x130, 4, 2));
        assert!(CircleRangeTest::test_union(0xffe0, 0x20, 0, 0x20, 2, 2));
        assert!(CircleRangeTest::test_union(0x80, 0x8, 0xd0, 0x80, 1, 1));
    }

    #[test]
    fn circlerange_pullback_negate() {
        assert!(CircleRangeTest::test_pullback_unary(1, 20, 1, 4, OpCode::IntNegate, 4));
        assert!(CircleRangeTest::test_pullback_unary(0xf0, 0x10, 1, 1, OpCode::IntNegate, 1));
        assert!(CircleRangeTest::test_pullback_unary(0x10, 0x30, 4, 4, OpCode::IntNegate, 4));
        assert!(CircleRangeTest::test_pullback_unary(0xfff0, 0x0, 4, 2, OpCode::IntNegate, 2));
        assert!(CircleRangeTest::test_pullback_unary(0xd1, 0x11, 4, 1, OpCode::IntNegate, 1));
        assert!(CircleRangeTest::test_pullback_unary(0, 0x30, 4, 1, OpCode::IntNegate, 1));
    }

    #[test]
    fn circlerange_pullback_2comp() {
        assert!(CircleRangeTest::test_pullback_unary(1, 20, 1, 4, OpCode::Int2comp, 4));
        assert!(CircleRangeTest::test_pullback_unary(0xf0, 0x10, 1, 1, OpCode::Int2comp, 1));
        assert!(CircleRangeTest::test_pullback_unary(0x10, 0x30, 4, 4, OpCode::Int2comp, 4));
        assert!(CircleRangeTest::test_pullback_unary(0xfff0, 0x0, 4, 2, OpCode::Int2comp, 2));
        assert!(CircleRangeTest::test_pullback_unary(0xd1, 0x11, 4, 1, OpCode::Int2comp, 1));
        assert!(CircleRangeTest::test_pullback_unary(0, 0x30, 4, 1, OpCode::Int2comp, 1));
    }

    #[test]
    fn circlerange_pullback_zext() {
        assert!(CircleRangeTest::test_pullback_unary(1, 20, 1, 4, OpCode::IntZext, 2));
        assert!(CircleRangeTest::test_pullback_unary(0xfff0, 0xff10, 1, 2, OpCode::IntZext, 1));
        assert!(CircleRangeTest::test_pullback_unary(0x10, 0x30, 4, 4, OpCode::IntZext, 1));
        assert!(CircleRangeTest::test_pullback_unary(0xfff0, 0x0, 4, 2, OpCode::IntZext, 1));
        assert!(CircleRangeTest::test_pullback_unary(0xffd1, 0x11, 4, 2, OpCode::IntZext, 1));
        assert!(CircleRangeTest::test_pullback_unary(0, 0x30, 4, 4, OpCode::IntZext, 2));
    }

    #[test]
    fn circlerange_pullback_sext() {
        assert!(CircleRangeTest::test_pullback_unary(1, 20, 1, 4, OpCode::IntSext, 2));
        assert!(CircleRangeTest::test_pullback_unary(0xfff0, 0x10, 1, 2, OpCode::IntSext, 1));
        assert!(CircleRangeTest::test_pullback_unary(0x10, 0x30, 4, 4, OpCode::IntSext, 2));
        assert!(CircleRangeTest::test_pullback_unary(0xfff0, 0x0, 4, 2, OpCode::IntSext, 1));
        assert!(CircleRangeTest::test_pullback_unary(0xffd1, 0x11, 4, 2, OpCode::IntSext, 1));
        assert!(CircleRangeTest::test_pullback_unary(0, 0x30, 4, 2, OpCode::IntSext, 1));
    }

    #[test]
    fn circlerange_pullback_add() {
        assert!(CircleRangeTest::test_pullback_binary(1, 20, 1, 4, OpCode::IntAdd, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0xf0, 0x10, 1, 1, OpCode::IntAdd, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0x10, 0x30, 4, 4, OpCode::IntAdd, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0xfff0, 0x0, 4, 2, OpCode::IntAdd, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0xd1, 0x11, 4, 1, OpCode::IntAdd, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0, 0x30, 4, 1, OpCode::IntAdd, 0, 0xfffffffd));
    }

    #[test]
    fn circlerange_pullback_sub() {
        assert!(CircleRangeTest::test_pullback_binary(1, 20, 1, 4, OpCode::IntSub, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0xf0, 0x10, 1, 1, OpCode::IntSub, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0x10, 0x30, 4, 4, OpCode::IntSub, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0xfff0, 0x0, 4, 2, OpCode::IntSub, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0xd1, 0x11, 4, 1, OpCode::IntSub, 0, 0xfffffffd));
        assert!(CircleRangeTest::test_pullback_binary(0, 0x30, 4, 1, OpCode::IntSub, 0, 0xfffffffd));
    }

    #[test]
    fn circlerange_pullback_right() {
        let mut range = CircleRange::new(0x01, 0x0f, 2, 1);
        assert!(range.pull_back_binary(OpCode::IntRight, 8, 0, 2, 2));
        assert_eq!(range.get_min(), 0x100);
        assert_eq!(range.get_end(), 0xf00);

        let mut range = CircleRange::new(0xf0, 0x10, 2, 1);
        assert!(range.pull_back_binary(OpCode::IntRight, 8, 0, 2, 2));
        assert_eq!(range.get_min(), 0xf000);
        assert_eq!(range.get_end(), 0x1000);

        let mut range = CircleRange::new(0xf0, 0x10, 1, 1);
        assert!(range.pull_back_binary(OpCode::IntRight, 1, 0, 1, 1));
        assert_eq!(range.get_min(), 0);
        assert_eq!(range.get_end(), 0x20);

        let mut range = CircleRange::new(0x01, 0x0f, 2, 2);
        assert!(!range.pull_back_binary(OpCode::IntRight, 8, 0, 2, 2));
    }

    #[test]
    fn circlerange_pullback_sright() {
        let mut range = CircleRange::new(0x01, 0x0f, 2, 1);
        assert!(range.pull_back_binary(OpCode::IntSright, 8, 0, 2, 2));
        assert_eq!(range.get_min(), 0x100);
        assert_eq!(range.get_end(), 0xf00);

        let mut range = CircleRange::new(0xf0, 0x10, 1, 1);
        assert!(range.pull_back_binary(OpCode::IntSright, 2, 0, 1, 1));
        assert_eq!(range.get_min(), 0xc0);
        assert_eq!(range.get_end(), 0x40);

        let mut range = CircleRange::new(0x10, 0x30, 1, 1);
        assert!(range.pull_back_binary(OpCode::IntSright, 2, 0, 1, 1));
        assert_eq!(range.get_min(), 0x40);
        assert_eq!(range.get_end(), 0x80);

        let mut range = CircleRange::new(0x01, 0x0f, 2, 2);
        assert!(!range.pull_back_binary(OpCode::IntSright, 8, 0, 2, 2));
    }

    #[test]
    fn circlerange_pullback_equal() {
        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_binary(OpCode::IntEqual, 0x1234, 0, 4, 1));
        assert_eq!(range.get_min(), 0x1234);
        assert_eq!(range.get_end(), 0x1235);

        let mut range = CircleRange::from_bool(false);
        assert!(range.pull_back_binary(OpCode::IntEqual, 0x1234, 0, 2, 1));
        assert_eq!(range.get_min(), 0x1235);
        assert_eq!(range.get_end(), 0x1234);
    }

    #[test]
    fn circlerange_pullback_notequal() {
        let mut range = CircleRange::from_bool(false);
        assert!(range.pull_back_binary(OpCode::IntNotequal, 0x1234, 0, 4, 1));
        assert_eq!(range.get_min(), 0x1234);
        assert_eq!(range.get_end(), 0x1235);

        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_binary(OpCode::IntNotequal, 0x1234, 0, 2, 1));
        assert_eq!(range.get_min(), 0x1235);
        assert_eq!(range.get_end(), 0x1234);
    }

    #[test]
    fn circlerange_pullback_carry() {
        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_binary(OpCode::IntCarry, 0x1234, 0, 2, 1));
        assert_eq!(range.get_min(), 0xedcc);
        assert_eq!(range.get_end(), 0);

        let mut range = CircleRange::from_bool(false);
        assert!(range.pull_back_binary(OpCode::IntCarry, 0x1234, 0, 2, 1));
        assert_eq!(range.get_min(), 0);
        assert_eq!(range.get_end(), 0xedcc);
    }

    #[test]
    fn circlerange_pullback_less() {
        let mut range = CircleRange::from_bool(false);
        assert!(range.pull_back_binary(OpCode::IntLess, 0x1234, 0, 4, 1));
        assert_eq!(range.get_min(), 0x1234);
        assert_eq!(range.get_end(), 0);

        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_binary(OpCode::IntLess, 0x1234, 0, 2, 1));
        assert_eq!(range.get_min(), 0);
        assert_eq!(range.get_end(), 0x1234);
    }

    #[test]
    fn circlerange_pullback_lessequal() {
        let mut range = CircleRange::from_bool(false);
        assert!(range.pull_back_binary(OpCode::IntLessequal, 0x1234, 0, 4, 1));
        assert_eq!(range.get_min(), 0x1235);
        assert_eq!(range.get_end(), 0);

        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_binary(OpCode::IntLessequal, 0x1234, 0, 2, 1));
        assert_eq!(range.get_min(), 0);
        assert_eq!(range.get_end(), 0x1235);
    }

    #[test]
    fn circlerange_pullback_sless() {
        let mut range = CircleRange::from_bool(false);
        assert!(range.pull_back_binary(OpCode::IntSless, 0x1234, 0, 4, 1));
        assert_eq!(range.get_min(), 0x1234);
        assert_eq!(range.get_end(), 0x80000000);

        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_binary(OpCode::IntSless, 0x1234, 0, 2, 1));
        assert_eq!(range.get_min(), 0x8000);
        assert_eq!(range.get_end(), 0x1234);
    }

    #[test]
    fn circlerange_pullback_slessequal() {
        let mut range = CircleRange::from_bool(false);
        assert!(range.pull_back_binary(OpCode::IntSlessequal, 0x1234, 0, 4, 1));
        assert_eq!(range.get_min(), 0x1235);
        assert_eq!(range.get_end(), 0x80000000);

        let mut range = CircleRange::from_bool(true);
        assert!(range.pull_back_binary(OpCode::IntSlessequal, 0x1234, 0, 2, 1));
        assert_eq!(range.get_min(), 0x8000);
        assert_eq!(range.get_end(), 0x1235);
    }

    // ---- mosura's own tests: the key `(index-1) < 8` pull-back and driver end-to-end -----------

    /// The task-defining case: `INT_LESS(INT_ADD(index,-1), 8)` being true pulls back to `[1,9)`
    /// on `index`. `{1}` (bool true) --thru INT_LESS,8--> `[0,8)` on `index-1` --thru INT_ADD,-1-->
    /// `[1,9)` on `index`. Built directly via `pull_back_binary` (no NZMASK intersect).
    #[test]
    fn key_index_minus_one_less_eight_pulls_back_to_1_9() {
        // Start at the CBRANCH condition being true.
        let mut rng = CircleRange::from_bool(true);
        // Pull back through `INT_LESS(_, 8)` (slot 0, const 8), producing [0,8) on `index-1`.
        assert!(rng.pull_back_binary(OpCode::IntLess, 8, 0, 4, 1));
        assert_eq!(rng.get_min(), 0);
        assert_eq!(rng.get_end(), 8);
        // Pull back through `INT_ADD(_, -1)` (const 0xffffffff for size 4), producing [1,9) on `index`.
        assert!(rng.pull_back_binary(OpCode::IntAdd, 0xffff_ffff, 0, 4, 4));
        assert_eq!(rng.get_min(), 1);
        assert_eq!(rng.get_end(), 9);
        assert_eq!(rng.get_step(), 1);
        assert!(rng.contains_val(1));
        assert!(rng.contains_val(8));
        assert!(!rng.contains_val(0));
        assert!(!rng.contains_val(9));
    }

    fn fd() -> Funcdata {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        Funcdata::new("t", Address::new(ram, 0), spaces)
    }

    /// The same `(index-1) < 8` chain driven through the [`CircleRange::pull_back`] driver over a
    /// real `Funcdata`: it must locate the constant slot, pull the range back through each op, and
    /// hand back the varnode being restricted. Two `pull_back` calls reach `index` with range [1,9).
    #[test]
    fn pull_back_driver_walks_the_add_less_chain() {
        let mut f = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // index:4  (a free input register)
        let index = f.new_input(4, Address::new(reg, 0x10));
        // idxm1:4 = INT_ADD(index, -1)
        let negone = f.new_const(4, 0xffff_ffff);
        let add = f.new_op(OpCode::IntAdd, seq, vec![index, negone]);
        let idxm1 = f.new_output(add, 4, Address::new(reg, 0x18));
        // cond:1 = INT_LESS(idxm1, 8)
        let eight = f.new_const(4, 8);
        let less = f.new_op(OpCode::IntLess, seq, vec![idxm1, eight]);
        let cond = f.new_output(less, 1, Address::new(reg, 0x20));
        let _ = cond;

        // Start from the condition being true and pull back through INT_LESS then INT_ADD.
        let mut rng = CircleRange::from_bool(true);
        let v1 = rng.pull_back(&f, less, false).expect("pull back through INT_LESS");
        assert_eq!(v1, idxm1);
        assert_eq!(rng.get_min(), 0);
        assert_eq!(rng.get_end(), 8);

        let v2 = rng.pull_back(&f, add, false).expect("pull back through INT_ADD");
        assert_eq!(v2, index);
        assert_eq!(rng.get_min(), 1);
        assert_eq!(rng.get_end(), 9);
    }

    /// `set_nz_mask` builds a strided/contiguous range from a putative mask, and rejects masks
    /// with too many bit transitions. Exercises the NZMASK path that `pull_back` uses.
    #[test]
    fn set_nz_mask_forms_and_rejects_ranges() {
        // 0xff => contiguous [0, 0x100), step 1.
        let mut r = CircleRange::default();
        assert!(r.set_nz_mask(0xff, 4));
        assert_eq!(r.get_min(), 0);
        assert_eq!(r.get_end(), 0x100);
        assert_eq!(r.get_step(), 1);

        // 0x6 (bits 1..2 set) => step 2, right = (0x6 + 2) = 0x8.
        let mut r = CircleRange::default();
        assert!(r.set_nz_mask(0x6, 4));
        assert_eq!(r.get_step(), 2);
        assert_eq!(r.get_min(), 0);
        assert_eq!(r.get_end(), 0x8);

        // 0 => only zero.
        let mut r = CircleRange::default();
        assert!(r.set_nz_mask(0, 4));
        assert_eq!(r.get_min(), 0);
        assert_eq!(r.get_end(), 1);

        // 0b1010_0101 has 4 transitions => not a valid range.
        let mut r = CircleRange::default();
        assert!(!r.set_nz_mask(0xa5, 4));
    }

    /// `get_size` counts elements for both the ordinary and the wrapped interval.
    #[test]
    fn get_size_counts_elements() {
        assert_eq!(CircleRange::new(1, 20, 4, 1).get_size(), 19);
        assert_eq!(CircleRange::new(0x10, 0x30, 4, 4).get_size(), 8);
        assert_eq!(CircleRange::default().get_size(), 0);
        // Wrapped range [0xffe0, 0x20) mod 2^16, step 2: 16 elements 0xffe0..0xfffe plus
        // 16 elements 0x0..0x1e.
        assert_eq!(CircleRange::new(0xffe0, 0x20, 2, 2).get_size(), 32);
    }

    /// `translate2_op` round-trips each representable form back to a comparison against a constant.
    #[test]
    fn translate2_op_forms() {
        // {5}: single value => v == 5, constant in slot 0.
        assert_eq!(CircleRange::new(5, 6, 4, 1).translate2_op(), (0, OpCode::IntEqual, 5, 0));
        // all-but-{6}: [7, 6) => v != 6, constant in slot 0.
        assert_eq!(CircleRange::new(7, 6, 4, 1).translate2_op(), (0, OpCode::IntNotequal, 6, 0));
        // [0, 10): unsigned less => v < 10, constant in slot 1.
        assert_eq!(CircleRange::new(0, 10, 4, 1).translate2_op(), (0, OpCode::IntLess, 10, 1));
        // [0x80000000, 10): signed less => v s< 10, constant in slot 1 (the `jle` union result).
        assert_eq!(CircleRange::new(0x8000_0000, 10, 4, 1).translate2_op(), (0, OpCode::IntSless, 10, 1));
        // [7, 0x80000000): signed greater => 6 s< v, constant in slot 0 (the `jg` intersect result).
        assert_eq!(CircleRange::new(7, 0x8000_0000, 4, 1).translate2_op(), (0, OpCode::IntSless, 6, 0));
    }

    /// `translate2_op` reports the non-comparison outcomes: 1 = always true (whole domain),
    /// 2 = cannot represent (a stride, or an interior two-ended interval), 3 = always false (empty).
    #[test]
    fn translate2_op_non_comparison_outcomes() {
        assert_eq!(CircleRange::new(3, 3, 4, 1).translate2_op().0, 1); // left==right => whole domain
        assert_eq!(CircleRange::default().translate2_op().0, 3); // empty
        assert_eq!(CircleRange::new(0, 10, 4, 2).translate2_op().0, 2); // stride
        assert_eq!(CircleRange::new(5, 20, 4, 1).translate2_op().0, 2); // interior interval
    }
}
