use std::sync::Arc;

use memchr::memrchr;
use smallvec::SmallVec;

use crate::tracy;

/// A chain of gitignore matchers from root to current directory
/// Uses Arc to enable cheap cloning when passing work between threads
#[derive(Default, Clone)]
pub struct GitignoreChain {
    /// Stack of (depth, gitignore) pairs
    /// Stored in Arc so cloning is cheap (just refcount bump)
    stack: SmallVec<[(u16, Arc<Gitignore>); 8]>,
}

impl GitignoreChain {
    #[inline]
    pub fn from_root(gi: Gitignore) -> Self {
        let mut stack = SmallVec::new();
        stack.push((0, Arc::new(gi)));
        Self {
            stack
        }
    }

    /// Add a gitignore at the given depth
    /// This creates a NEW chain (copy-on-write via Arc)
    #[inline]
    pub fn with_gitignore(self, depth: u16, gi: Gitignore) -> Self {
        let _span = tracy::span!("GitignoreChain::with_gitignore");

        let mut new_stack = self.stack;

        // Remove any gitignores deeper than current depth
        new_stack.retain(|(d, _)| *d <= depth);

        new_stack.push((depth, Arc::new(gi)));

        Self { stack: new_stack }
    }

    #[inline]
    pub fn is_ignored(&self, path: &[u8], is_dir: bool) -> bool {
        if self.stack.is_empty() {
            return false;
        }

        // Single gitignore - fast path (90% of cases)
        if self.stack.len() == 1 {
            return unsafe { self.stack.get_unchecked(0).1.is_ignored(path, is_dir) };
        }

        // Multiple gitignores - check if any have negations
        let mut has_negations = false;
        for (_, gi) in self.stack.iter() {
            if gi.has_negations {
                has_negations = true;
                break;
            }
        }

        if !has_negations {
            // NO NEGATIONS - can early exit on first match!
            for (_, gi) in self.stack.iter() {
                if gi.is_ignored(path, is_dir) {
                    return true;
                }
            }
            return false;
        }

        // HAS NEGATIONS - must check all (slow path)
        let mut result = false;
        for (_, gi) in self.stack.iter() {
            if gi.is_ignored(path, is_dir) {
                result = true;
            }
        }
        result
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}

// ============================================================================
// CACHE-OPTIMIZED GITIGNORE
// ============================================================================

#[derive(Clone)]
pub struct Gitignore {
    /// Pre-computed: does this gitignore have any negations?
    has_negations: bool,

    /// Literal patterns: packed SOA layout
    literal_data: Box<[u8]>,
    literal_meta: Box<[u32]>,

    /// Wildcard patterns (rare, kept separate)
    wildcards: Box<[WildcardPattern]>,

    /// Pattern execution order for correct semantics
    /// Each u32 packs: type(2 bits) | index(14 bits) | flags(16 bits)
    order: Box<[u32]>,
}

#[derive(Clone)]
struct WildcardPattern {
    bytes: Box<[u8]>,
    flags: u8, // bit 0: negated, bit 1: anchored, bit 2: dir_only
}

// Order entry bit layout: [type:2][index:14][flags:16]
const ORDER_TYPE_MASK: u32  = 0b11 << 30;
const ORDER_INDEX_MASK: u32 = 0x3FFF << 16;
const ORDER_TYPE_LITERAL: u32 = 0 << 30;
const ORDER_TYPE_WILDCARD: u32 = 1 << 30;

impl Gitignore {
    pub fn from_bytes(content: &[u8]) -> Self {
        let mut literal_data = Vec::with_capacity(256);
        let mut literal_meta = Vec::with_capacity(32);
        let mut wildcards = Vec::new();
        let mut order = Vec::new();
        let mut has_negations = false;

        for line in content.split(|&b| b == b'\n') {
            if line.is_empty() || line[0] == b'#' {
                continue;
            }

            let line = trim_bytes(line);
            if line.is_empty() {
                continue;
            }

            let (pattern_bytes, negated) = if line[0] == b'!' {
                has_negations = true;
                (&line[1..], true)
            } else {
                (line, false)
            };

            if pattern_bytes.is_empty() {
                continue;
            }

            let (pattern_bytes, anchored) = if pattern_bytes[0] == b'/' {
                (&pattern_bytes[1..], true)
            } else if pattern_bytes.starts_with(b"**/") {
                (&pattern_bytes[3..], false)
            } else {
                (pattern_bytes, pattern_bytes.contains(&b'/'))
            };

            let dir_only = pattern_bytes.last() == Some(&b'/');
            let pattern_bytes = if dir_only {
                &pattern_bytes[..pattern_bytes.len() - 1]
            } else {
                pattern_bytes
            };

            let has_wildcards = pattern_bytes.contains(&b'*') ||
                               pattern_bytes.contains(&b'?') ||
                               pattern_bytes.contains(&b'[');

            if !has_wildcards {
                // LITERAL PATTERN
                let offset = literal_data.len() as u32;
                let len = pattern_bytes.len() as u32;

                if len <= 255 && offset <= 0xFFFF {
                    let index = literal_meta.len() as u32;
                    literal_data.extend_from_slice(pattern_bytes);

                    // Pack: offset(16) | len(8) | negated(1) | anchored(1) | dir_only(1)
                    let meta = offset
                        | (len << 16)
                        | ((negated as u32) << 24)
                        | ((anchored as u32) << 25)
                        | ((dir_only as u32) << 26);

                    literal_meta.push(meta);

                    // Pack order entry
                    order.push(ORDER_TYPE_LITERAL | (index << 16));
                } else {
                    // Too long, treat as wildcard
                    let index = wildcards.len() as u32;
                    let flags = (negated as u8) | ((anchored as u8) << 1) | ((dir_only as u8) << 2);
                    wildcards.push(WildcardPattern {
                        bytes: pattern_bytes.to_vec().into_boxed_slice(),
                        flags,
                    });
                    order.push(ORDER_TYPE_WILDCARD | (index << 16));
                }
            } else {
                // WILDCARD PATTERN
                let index = wildcards.len() as u32;
                let flags = (negated as u8) | ((anchored as u8) << 1) | ((dir_only as u8) << 2);
                wildcards.push(WildcardPattern {
                    bytes: pattern_bytes.to_vec().into_boxed_slice(),
                    flags,
                });
                order.push(ORDER_TYPE_WILDCARD | (index << 16));
            }
        }

        Self {
            has_negations,
            literal_data: literal_data.into_boxed_slice(),
            literal_meta: literal_meta.into_boxed_slice(),
            wildcards: wildcards.into_boxed_slice(),
            order: order.into_boxed_slice(),
        }
    }

    /// NUCLEAR HOT PATH - inline always, unsafe everywhere
    #[inline(always)]
    pub fn is_ignored(&self, path: &[u8], is_dir: bool) -> bool {
        if self.order.is_empty() {
            return false;
        }

        // Extract filename ONCE
        let filename_start = memrchr(b'/', path).map_or(0, |i| i + 1);
        let filename = unsafe { path.get_unchecked(filename_start..) };

        let mut result = false;

        // TIER 1: Pattern matching loop - manually optimized
        let order_ptr = self.order.as_ptr();
        let order_len = self.order.len();

        for i in 0..order_len {
            let entry = unsafe { *order_ptr.add(i) };
            let typ = entry & ORDER_TYPE_MASK;
            let index = ((entry & ORDER_INDEX_MASK) >> 16) as usize;

            if typ == ORDER_TYPE_LITERAL {
                // LITERAL - ultra hot path
                let meta = unsafe { *self.literal_meta.get_unchecked(index) };
                let offset = (meta & 0xFFFF) as usize;
                let len = ((meta >> 16) & 0xFF) as usize;
                let negated = (meta >> 24) & 1 != 0;
                let anchored = (meta >> 25) & 1 != 0;
                let dir_only = (meta >> 26) & 1 != 0;

                if dir_only && !is_dir {
                    continue;
                }

                let pattern = unsafe { self.literal_data.get_unchecked(offset..offset + len) };

                let matched = if anchored {
                    len <= path.len() && {
                        let prefix = unsafe { path.get_unchecked(..len) };
                        prefix == pattern && (path.len() == len || unsafe { *path.get_unchecked(len) } == b'/')
                    }
                } else {
                    filename == pattern
                };

                if matched {
                    result = !negated;
                }
            } else {
                // WILDCARD - cold path
                let pattern = unsafe { self.wildcards.get_unchecked(index) };
                let negated = pattern.flags & 1 != 0;
                let anchored = (pattern.flags >> 1) & 1 != 0;
                let dir_only = (pattern.flags >> 2) & 1 != 0;

                if dir_only && !is_dir {
                    continue;
                }

                let matched = if anchored {
                    glob_match(&pattern.bytes, path)
                } else {
                    glob_match(&pattern.bytes, filename)
                };

                if matched {
                    result = !negated;
                }
            }
        }

        result
    }
}

#[inline]
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    // Fast reject: no wildcards
    if !pattern.contains(&b'*') && !pattern.contains(&b'?') && !pattern.contains(&b'[') {
        return pattern == text;
    }

    let plen = pattern.len();
    let tlen = text.len();

    if plen == 0 {
        return tlen == 0;
    }

    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = usize::MAX; // Use MAX as "None"
    let mut match_idx = 0;

    while t_idx < tlen {
        if p_idx < plen {
            let p_char = unsafe { *pattern.get_unchecked(p_idx) };

            match p_char {
                b'*' => {
                    star_idx = p_idx;
                    match_idx = t_idx;
                    p_idx += 1;
                    continue;
                }
                b'?' => {
                    p_idx += 1;
                    t_idx += 1;
                    continue;
                }
                b'[' => {
                    if let Some(new_p) = match_char_class(pattern, p_idx, unsafe { *text.get_unchecked(t_idx) }) {
                        p_idx = new_p;
                        t_idx += 1;
                        continue;
                    }
                }
                c if c == unsafe { *text.get_unchecked(t_idx) } => {
                    p_idx += 1;
                    t_idx += 1;
                    continue;
                }
                _ => {}
            }
        }

        if star_idx != usize::MAX {
            p_idx = star_idx + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    // Skip trailing stars
    while p_idx < plen && unsafe { *pattern.get_unchecked(p_idx) } == b'*' {
        p_idx += 1;
    }

    p_idx == plen
}

#[inline]
fn match_char_class(pattern: &[u8], start: usize, ch: u8) -> Option<usize> {
    let plen = pattern.len();
    if start + 2 >= plen || unsafe { *pattern.get_unchecked(start) } != b'[' {
        return None;
    }

    let negated = unsafe { *pattern.get_unchecked(start + 1) } == b'!';
    let mut i = if negated { start + 2 } else { start + 1 };

    // Find closing ]
    let mut end = i;
    while end < plen && unsafe { *pattern.get_unchecked(end) } != b']' {
        end += 1;
    }
    if end >= plen {
        return None;
    }

    let mut matched = false;
    while i < end {
        if i + 2 < end && unsafe { *pattern.get_unchecked(i + 1) } == b'-' {
            // Range
            let lo = unsafe { *pattern.get_unchecked(i) };
            let hi = unsafe { *pattern.get_unchecked(i + 2) };
            if ch >= lo && ch <= hi {
                matched = true;
                break;
            }
            i += 3;
        } else {
            // Single char
            if ch == unsafe { *pattern.get_unchecked(i) } {
                matched = true;
                break;
            }
            i += 1;
        }
    }

    if matched != negated {
        Some(end + 1)
    } else {
        None
    }
}

#[inline(always)]
fn trim_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| !b.is_ascii_whitespace()).unwrap_or(0);
    let end = bytes.iter().rposition(|&b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    if start <= end {
        &bytes[start..end]
    } else {
        &[]
    }
}

#[inline]
pub fn build_gitignore_from_bytes(content: &[u8]) -> Gitignore {
    Gitignore::from_bytes(content)
}

/// Build gitignore from a file path
/// Returns None if file doesn't exist or can't be read
#[inline]
pub fn build_gitignore_from_file(gitignore_path: &str) -> Option<Gitignore> {
    use std::fs;
    use std::path::Path;

    let path = Path::new(gitignore_path);

    // Read file contents
    let content = fs::read(path).ok()?;

    Some(Gitignore::from_bytes(&content))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_patterns_fast_path() {
        let gi = Gitignore::from_bytes(b"target\nnode_modules\ndist\n");

        assert!(gi.is_ignored(b"target", true));
        assert!(gi.is_ignored(b"node_modules", true));
        assert!(gi.is_ignored(b"dist", true));
        assert!(gi.is_ignored(b"src/target", true));
        assert!(gi.is_ignored(b"foo/node_modules", true));
    }

    #[test]
    fn test_literal_patterns() {
        let gi = Gitignore::from_bytes(b"target\n*.log\n");

        assert!(gi.is_ignored(b"target", true));
        assert!(gi.is_ignored(b"src/target", true));
        assert!(gi.is_ignored(b"test.log", false));
        assert!(!gi.is_ignored(b"target.rs", false));
    }

    #[test]
    fn test_wildcard_patterns() {
        let gi = Gitignore::from_bytes(b"*.tmp\n*.log\ntest_*\n");

        assert!(gi.is_ignored(b"file.tmp", false));
        assert!(gi.is_ignored(b"src/file.log", false));
        assert!(gi.is_ignored(b"test_foo", false));
        assert!(!gi.is_ignored(b"file.txt", false));
    }

    #[test]
    fn test_anchored_patterns() {
        let gi = Gitignore::from_bytes(b"/build\nsrc/gen\n");

        assert!(gi.is_ignored(b"build", true));
        assert!(gi.is_ignored(b"build/output", false));
        assert!(!gi.is_ignored(b"other/build", true));
    }

    #[test]
    fn test_negation() {
        let gi = Gitignore::from_bytes(b"*.log\n!important.log\n");

        assert!(gi.is_ignored(b"test.log", false));
        assert!(!gi.is_ignored(b"important.log", false));
    }

    #[test]
    fn test_dir_only() {
        let gi = Gitignore::from_bytes(b"bin/\n");

        assert!(gi.is_ignored(b"bin", true));
        assert!(!gi.is_ignored(b"bin", false));
    }

    #[test]
    fn test_complex_wildcards() {
        let gi = Gitignore::from_bytes(b"test_*.rs\n*.min.js\n**/node_modules\n");

        assert!(gi.is_ignored(b"test_foo.rs", false));
        assert!(gi.is_ignored(b"test_bar.rs", false));
        assert!(!gi.is_ignored(b"test.rs", false));
        assert!(gi.is_ignored(b"bundle.min.js", false));
        assert!(gi.is_ignored(b"src/bundle.min.js", false));
        assert!(!gi.is_ignored(b"bundle.js", false));
    }

    #[test]
    fn test_double_star() {
        let gi = Gitignore::from_bytes(b"**/logs\n**/build/**\n");

        assert!(gi.is_ignored(b"logs", true));
        assert!(gi.is_ignored(b"src/logs", true));
        assert!(gi.is_ignored(b"src/foo/logs", true));
    }

    #[test]
    fn test_character_classes() {
        let gi = Gitignore::from_bytes(b"test[0-9].txt\nfile[abc].log\n");

        assert!(gi.is_ignored(b"test0.txt", false));
        assert!(gi.is_ignored(b"test5.txt", false));
        assert!(gi.is_ignored(b"test9.txt", false));
        assert!(!gi.is_ignored(b"testa.txt", false));

        assert!(gi.is_ignored(b"filea.log", false));
        assert!(gi.is_ignored(b"fileb.log", false));
        assert!(gi.is_ignored(b"filec.log", false));
        assert!(!gi.is_ignored(b"filed.log", false));
    }

    #[test]
    fn test_negated_character_class() {
        let gi = Gitignore::from_bytes(b"file[!0-9].txt\n");

        assert!(!gi.is_ignored(b"file0.txt", false));
        assert!(!gi.is_ignored(b"file5.txt", false));
        assert!(gi.is_ignored(b"filea.txt", false));
        assert!(gi.is_ignored(b"filex.txt", false));
    }

    #[test]
    fn test_multiple_negations() {
        let gi = Gitignore::from_bytes(b"*.log\n!important.log\n!critical.log\n");

        assert!(gi.is_ignored(b"test.log", false));
        assert!(gi.is_ignored(b"debug.log", false));
        assert!(!gi.is_ignored(b"important.log", false));
        assert!(!gi.is_ignored(b"critical.log", false));
    }

    #[test]
    fn test_last_pattern_wins() {
        let gi = Gitignore::from_bytes(b"*.log\n!debug.log\n*.log\n");

        // Last *.log should re-ignore debug.log
        assert!(gi.is_ignored(b"debug.log", false));
    }

    #[test]
    fn test_comments_and_blank_lines() {
        let gi = Gitignore::from_bytes(b"# This is a comment\n*.tmp\n\n# Another comment\n*.log\n\n");

        assert!(gi.is_ignored(b"file.tmp", false));
        assert!(gi.is_ignored(b"file.log", false));
        assert!(!gi.is_ignored(b"file.txt", false));
    }

    #[test]
    fn test_whitespace_handling() {
        let gi = Gitignore::from_bytes(b"  *.tmp  \n\t*.log\t\n");

        assert!(gi.is_ignored(b"file.tmp", false));
        assert!(gi.is_ignored(b"file.log", false));
    }

    #[test]
    fn test_nested_paths() {
        let gi = Gitignore::from_bytes(b"src/generated\ntarget/debug\n");

        assert!(gi.is_ignored(b"src/generated", true));
        assert!(gi.is_ignored(b"src/generated/file.rs", false));
        assert!(!gi.is_ignored(b"other/src/generated", true));
        assert!(gi.is_ignored(b"target/debug", true));
    }

    #[test]
    fn test_root_only_patterns() {
        let gi = Gitignore::from_bytes(b"/TODO\n/README.md\n");

        assert!(gi.is_ignored(b"TODO", false));
        assert!(gi.is_ignored(b"README.md", false));
        assert!(!gi.is_ignored(b"docs/TODO", false));
        assert!(!gi.is_ignored(b"src/README.md", false));
    }

    #[test]
    fn test_question_mark_wildcard() {
        let gi = Gitignore::from_bytes(b"test?.log\nfile??.txt\n");

        assert!(gi.is_ignored(b"test1.log", false));
        assert!(gi.is_ignored(b"testa.log", false));
        assert!(!gi.is_ignored(b"test.log", false));
        assert!(!gi.is_ignored(b"test12.log", false));

        assert!(gi.is_ignored(b"fileab.txt", false));
        assert!(gi.is_ignored(b"file12.txt", false));
        assert!(!gi.is_ignored(b"file1.txt", false));
        assert!(!gi.is_ignored(b"fileabc.txt", false));
    }

    #[test]
    fn test_mixed_patterns() {
        let gi = Gitignore::from_bytes(b"*.log\n/build\ntarget/\n!important.log\nsrc/gen\n");

        assert!(gi.is_ignored(b"test.log", false));
        assert!(!gi.is_ignored(b"important.log", false));
        assert!(gi.is_ignored(b"build", true));
        assert!(!gi.is_ignored(b"src/build", true));
        assert!(gi.is_ignored(b"target", true));
        assert!(!gi.is_ignored(b"target", false));
        assert!(gi.is_ignored(b"src/gen", true));
    }

    #[test]
    fn test_empty_gitignore() {
        let gi = Gitignore::from_bytes(b"");

        assert!(!gi.is_ignored(b"anything", false));
        assert!(!gi.is_ignored(b"file.txt", false));
    }

    #[test]
    fn test_star_matches_multiple() {
        let gi = Gitignore::from_bytes(b"*.backup.*\n");

        assert!(gi.is_ignored(b"file.backup.txt", false));
        assert!(gi.is_ignored(b"data.backup.json", false));
        assert!(!gi.is_ignored(b"file.txt", false));
    }

    #[test]
    fn test_performance_many_patterns() {
        let mut patterns = Vec::new();
        for i in 0..100 {
            patterns.push(format!("pattern{}.txt\n", i));
        }
        let content = patterns.join("");

        let gi = Gitignore::from_bytes(content.as_bytes());

        assert!(gi.is_ignored(b"pattern0.txt", false));
        assert!(gi.is_ignored(b"pattern50.txt", false));
        assert!(gi.is_ignored(b"pattern99.txt", false));
        assert!(!gi.is_ignored(b"pattern100.txt", false));
    }

    #[test]
    fn test_common_gitignore_patterns() {
        let gi = Gitignore::from_bytes(b"
# OS files
.DS_Store
Thumbs.db

# IDEs
.vscode/
.idea/
*.swp

# Build output
/target
/dist
/build
*.o
*.so

# Dependencies
node_modules/
vendor/

# Logs
*.log
logs/
");

        assert!(gi.is_ignored(b".DS_Store", false));
        assert!(gi.is_ignored(b"Thumbs.db", false));
        assert!(gi.is_ignored(b".vscode", true));
        assert!(gi.is_ignored(b".idea", true));
        assert!(gi.is_ignored(b"test.swp", false));
        assert!(gi.is_ignored(b"target", true));
        assert!(!gi.is_ignored(b"src/target", true));
        assert!(gi.is_ignored(b"file.o", false));
        assert!(gi.is_ignored(b"lib.so", false));
        assert!(gi.is_ignored(b"node_modules", true));
        assert!(gi.is_ignored(b"vendor", true));
        assert!(gi.is_ignored(b"app.log", false));
        assert!(gi.is_ignored(b"logs", true));
    }
}
