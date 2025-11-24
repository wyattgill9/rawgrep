#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::sync::Arc;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::{self, Read, Seek, SeekFrom, Write};

use regex::bytes::Regex;
use nohash_hasher::IntMap;
use smallvec::{SmallVec, smallvec};

const MAX_TRAVERSE_DEPTH: usize = 40;

const BINARY_PROBE_BYTE_SIZE: usize = 0x2000;
const MAX_FILE_BYTE_SIZE: usize = 5 * 1024 * 1024;

const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_SIZE: usize = 1024;
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const EXT4_MAGIC_OFFSET: usize = 56;
const EXT4_INODE_SIZE_OFFSET: usize = 88;
const EXT4_INODES_PER_GROUP_OFFSET: usize = 40;
const EXT4_BLOCKS_PER_GROUP_OFFSET: usize = 32;
const EXT4_BLOCK_SIZE_OFFSET: usize = 24;
const EXT4_INODE_TABLE_OFFSET: usize = 8;
const EXT4_ROOT_INODE: u32 = 2;
const EXT4_DESC_SIZE_OFFSET: usize = 254;

const EXT4_INODE_MODE_OFFSET: usize = 0;
const EXT4_INODE_SIZE_OFFSET_LOW: usize = 4;
const EXT4_INODE_BLOCK_OFFSET: usize = 40;
const EXT4_INODE_FLAGS_OFFSET: usize = 32;
const EXT4_S_IFMT: u16 = 0xF000;
const EXT4_S_IFREG: u16 = 0x8000;
const EXT4_S_IFDIR: u16 = 0x4000;
const EXT4_EXTENTS_FL: u32 = 0x80000;

const COLOR_RED: &[u8] = b"\x1b[1;31m";
const COLOR_GREEN: &[u8] = b"\x1b[1;32m";
const COLOR_CYAN: &[u8] = b"\x1b[1;36m";
const COLOR_RESET: &[u8] = b"\x1b[0m";

const CURSOR_HIDE: &[u8] = b"\x1b[?25l";
const CURSOR_UNHIDE: &[u8] = b"\x1b[?25h";

#[derive(Debug)]
struct Ext4SuperBlock {
    block_size: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    desc_size: u16,
}

impl Display for Ext4SuperBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Block size: {} bytes", self.block_size)?;
        writeln!(f, "Blocks per group: {}", self.blocks_per_group)?;
        writeln!(f, "Inodes per group: {}", self.inodes_per_group)?;
        writeln!(f, "Inode size: {} bytes", self.inode_size)?;
        write!  (f, "Descriptor size: {} bytes\n", self.desc_size)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Ext4Inode {
    mode: u16,
    size: u64,
    flags: u32,
    blocks: [u32; 15],
}

#[derive(Debug, Clone, Copy)]
struct Ext4Extent {
    block: u32,
    start_lo: u32,
    len: u16,
}

struct FileMatch {
    line_num: usize,
    line_start: usize,
    line_len: usize,
    matches: SmallVec<[(usize, usize); 4]>,
}

struct Ext4Reader {
    device_file: File,
    superblock: Ext4SuperBlock,

    block_cache: IntMap<u64, Vec<u8>>,

    // ----- reused buffers
    file_matches: Vec<FileMatch>,
    extent_buf: Vec<Ext4Extent>,
    output_buf: Vec<u8>,
    content_buf: Vec<u8>,
}

impl Ext4Reader {
    fn new(device_path: &str) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(device_path)?;

        let mut sb_bytes = [0u8; EXT4_SUPERBLOCK_SIZE];
        file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))?;
        file.read_exact(&mut sb_bytes)?;

        // ----------- Validate ext4 magic number
        let magic = u16::from_le_bytes([
            sb_bytes[EXT4_MAGIC_OFFSET + 0],
            sb_bytes[EXT4_MAGIC_OFFSET + 1],
        ]);

        if magic != EXT4_SUPER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Not an ext4 filesystem (magic: 0x{magic:X}, expected: 0x{EXT4_SUPER_MAGIC:X})")
            ));
        }

        let superblock = Self::parse_superblock(&sb_bytes)?;

        eprintln!("\x1b[1;36mDetected ext4 filesystem:\x1b[0m\n{superblock}");

        Ok(Ext4Reader {
            device_file: file,
            superblock,
            block_cache: IntMap::with_capacity_and_hasher(4096, nohash_hasher::BuildNoHashHasher::new()),
            extent_buf: Vec::with_capacity(256),
            output_buf: Vec::with_capacity(64 * 1024),
            file_matches: Vec::with_capacity(256),
            content_buf: Vec::with_capacity(1024 * 1024),
        })
    }

    #[inline]
    fn parse_superblock(data: &[u8]) -> io::Result<Ext4SuperBlock> {
        let block_size_log = u32::from_le_bytes([
            data[EXT4_BLOCK_SIZE_OFFSET + 0],
            data[EXT4_BLOCK_SIZE_OFFSET + 1],
            data[EXT4_BLOCK_SIZE_OFFSET + 2],
            data[EXT4_BLOCK_SIZE_OFFSET + 3],
        ]);
        let block_size = 1024 << block_size_log;

        let blocks_per_group = u32::from_le_bytes([
            data[EXT4_BLOCKS_PER_GROUP_OFFSET + 0],
            data[EXT4_BLOCKS_PER_GROUP_OFFSET + 1],
            data[EXT4_BLOCKS_PER_GROUP_OFFSET + 2],
            data[EXT4_BLOCKS_PER_GROUP_OFFSET + 3],
        ]);

        let inodes_per_group = u32::from_le_bytes([
            data[EXT4_INODES_PER_GROUP_OFFSET + 0],
            data[EXT4_INODES_PER_GROUP_OFFSET + 1],
            data[EXT4_INODES_PER_GROUP_OFFSET + 2],
            data[EXT4_INODES_PER_GROUP_OFFSET + 3],
        ]);

        let inode_size = u16::from_le_bytes([
            data[EXT4_INODE_SIZE_OFFSET + 0],
            data[EXT4_INODE_SIZE_OFFSET + 1],
        ]);

        let desc_size = if data.len() > EXT4_DESC_SIZE_OFFSET + 1 {
            let ds = u16::from_le_bytes([
                data[EXT4_DESC_SIZE_OFFSET + 0],
                data[EXT4_DESC_SIZE_OFFSET + 1],
            ]);
            if ds >= 32 { ds } else { 32 }
        } else {
            32
        };

        Ok(Ext4SuperBlock {
            block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            desc_size,
        })
    }

    #[inline]
    fn read_block_cached(&mut self, block_num: u32) -> io::Result<()> {
        let block_offset = block_num as u64 * self.superblock.block_size as u64;

        if self.block_cache.contains_key(&block_offset) {
            return Ok(());
        }

        let block_size = self.superblock.block_size as usize;
        let mut block = vec![0u8; block_size];
        self.device_file.seek(SeekFrom::Start(block_offset))?;
        self.device_file.read_exact(&mut block)?;

        self.block_cache.insert(block_offset, block);
        Ok(())
    }

    #[inline]
    fn get_block(&self, block_num: u32) -> Option<&[u8]> {
        let block_offset = block_num as u64 * self.superblock.block_size as u64;
        self.block_cache.get(&block_offset).map(|v| v.as_slice())
    }

    #[inline]
    fn read_inode(&mut self, inode_num: u32) -> io::Result<Ext4Inode> {
        if inode_num == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid inode number 0"));
        }

        let group = (inode_num - 1) / self.superblock.inodes_per_group;
        let index = (inode_num - 1) % self.superblock.inodes_per_group;

        let bg_desc_offset = if self.superblock.block_size == 1024 {
            2048u64
        } else {
            self.superblock.block_size as u64
        } + (group as u64 * self.superblock.desc_size as u64);

        let mut bg_desc: SmallVec<[u8; 64]> = smallvec![0; self.superblock.desc_size as usize];
        self.device_file.seek(SeekFrom::Start(bg_desc_offset))?;
        self.device_file.read_exact(&mut bg_desc)?;

        let inode_table_block = u32::from_le_bytes([
            bg_desc[EXT4_INODE_TABLE_OFFSET + 0],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 1],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 2],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 3],
        ]);

        if inode_table_block == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid inode table"));
        }

        let inode_offset = inode_table_block as u64 *
            self.superblock.block_size as u64 +
            index as u64 *
            self.superblock.inode_size as u64;

        let mut inode_bytes: SmallVec<[u8; 512]> = smallvec![0; self.superblock.inode_size as usize];
        self.device_file.seek(SeekFrom::Start(inode_offset))?;
        self.device_file.read_exact(&mut inode_bytes)?;

        let mode = u16::from_le_bytes([
            inode_bytes[EXT4_INODE_MODE_OFFSET + 0],
            inode_bytes[EXT4_INODE_MODE_OFFSET + 1],
        ]);

        let size_low = u32::from_le_bytes([
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 0],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 1],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 2],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 3],
        ]);

        let flags = u32::from_le_bytes([
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 0],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 1],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 2],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 3],
        ]);

        let mut blocks = [0u32; 15];
        for (i, block) in blocks.iter_mut().enumerate() {
            let offset = EXT4_INODE_BLOCK_OFFSET + i * 4;
            *block = u32::from_le_bytes([
                inode_bytes[offset + 0],
                inode_bytes[offset + 1],
                inode_bytes[offset + 2],
                inode_bytes[offset + 3],
            ]);
        }

        Ok(Ext4Inode { mode, size: size_low as u64, flags, blocks })
    }

    #[inline]
    fn parse_extents(&mut self, inode: &Ext4Inode) -> io::Result<()> {
        self.extent_buf.clear();

        let mut block_bytes: SmallVec<[u8; 64]> = smallvec![0; 60];
        for (i, bytes) in inode.blocks.into_iter().map(u32::to_le_bytes).enumerate() {
            block_bytes[i * 4 + 0] = bytes[0];
            block_bytes[i * 4 + 1] = bytes[1];
            block_bytes[i * 4 + 2] = bytes[2];
            block_bytes[i * 4 + 3] = bytes[3];
        }

        self.parse_extent_node(&block_bytes, 0)?;
        Ok(())
    }

    fn parse_extent_node(&mut self, data: &[u8], level: usize) -> io::Result<()> {
        if data.len() < 12 {
            return Ok(());
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != 0xF30A {
            return Ok(());
        }

        let entries = u16::from_le_bytes([data[2], data[3]]);
        let depth = u16::from_le_bytes([data[6], data[7]]);

        if depth == 0 {
            // -------- Leaf node
            for i in 0..entries {
                let base = 12 + (i as usize * 12);
                if base + 12 > data.len() {
                    break;
                }

                let ee_block = u32::from_le_bytes([
                    data[base + 0],
                    data[base + 1],
                    data[base + 2],
                    data[base + 3]
                ]);
                let ee_len = u16::from_le_bytes([data[base + 4], data[base + 5]]);
                let ee_start_hi = u16::from_le_bytes([data[base + 6], data[base + 7]]);
                let ee_start_lo = u32::from_le_bytes([
                    data[base + 08],
                    data[base + 09],
                    data[base + 10],
                    data[base + 11]
                ]);

                let start_block = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);

                if ee_len > 0 && ee_len <= 32768 {
                    self.extent_buf.push(Ext4Extent {
                        block: ee_block,
                        start_lo: start_block as u32,
                        len: ee_len,
                    });
                }
            }
        } else {
            // -------- Internal node - collect block numbers first
            let mut child_blocks = SmallVec::<[u32; 16]>::new();
            for i in 0..entries {
                let base = 12 + (i as usize * 12);
                if base + 12 > data.len() {
                    break;
                }

                let ei_leaf_lo = u32::from_le_bytes([
                    data[base + 4],
                    data[base + 5],
                    data[base + 6],
                    data[base + 7]
                ]);
                let ei_leaf_hi = u16::from_le_bytes([data[base + 8], data[base + 9]]);

                let leaf_block = ((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64);
                child_blocks.push(leaf_block as u32);
            }

            for child_block in child_blocks {
                self.read_block_cached(child_block)?;
                if let Some(block_data) = self.get_block(child_block) {
                    let block_copy: SmallVec<[u8; 4096]> = SmallVec::from_slice(block_data);
                    self.parse_extent_node(&block_copy, level + 1)?;
                }
            }
        }

        Ok(())
    }

    fn read_file_content(
        &mut self,
        inode: &Ext4Inode,
        max_size: usize,
        try_to_skip_binaries: bool
    ) -> io::Result<()> {
        self.content_buf.clear();

        let size_to_read = std::cmp::min(inode.size as usize, max_size);
        self.content_buf.reserve(size_to_read);

        let block_size = self.superblock.block_size as usize;

        let mut bytes_probed = 0;

        let mut append_block = |cached: &[u8], content: &mut Vec<u8>| -> bool {
            let remaining = size_to_read - content.len();
            let to_read = core::cmp::min(block_size, remaining);

            let meaningful = &cached[..to_read];

            if try_to_skip_binaries && bytes_probed < BINARY_PROBE_BYTE_SIZE {
                let probe_len = core::cmp::min(BINARY_PROBE_BYTE_SIZE - bytes_probed, meaningful.len());
                if memchr::memchr(b'\0', &meaningful[..probe_len]).is_some() {
                    // this looks like a binary file, skip it..
                    content.clear();
                    return false;
                }

                bytes_probed += probe_len;
            }

            content.extend_from_slice(meaningful);
            true
        };

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            self.parse_extents(inode)?;

            let extents = self.extent_buf.clone();

            // cache all needed blocks first
            for extent in &extents {
                for i in 0..extent.len {
                    let phys_block = extent.start_lo + i as u32;
                    _ = self.read_block_cached(phys_block);
                }
            }

            // copy data from cache
            for extent in &extents {
                if self.content_buf.len() >= size_to_read {
                    break;
                }

                for i in 0..extent.len {
                    if self.content_buf.len() >= size_to_read {
                        break;
                    }

                    let phys_block = extent.start_lo + i as u32;
                    let block_offset = phys_block as u64 * self.superblock.block_size as u64;

                    if let Some(cached) = self.block_cache.get(&block_offset)
                        && !append_block(cached, &mut self.content_buf)
                    {
                        return Ok(())
                    }
                }
            }
        } else {
            // cache direct blocks first
            for i in 0..12 {
                if inode.blocks[i] != 0 {
                    _ = self.read_block_cached(inode.blocks[i]);
                }
            }

            // copy from cache
            for i in 0..12 {
                if inode.blocks[i] == 0 || self.content_buf.len() >= size_to_read {
                    break;
                }

                let block_offset = inode.blocks[i] as u64 * self.superblock.block_size as u64;

                if let Some(cached) = self.block_cache.get(&block_offset)
                    && !append_block(cached, &mut self.content_buf)
                {
                    return Ok(())
                }
            }
        }

        self.content_buf.truncate(size_to_read);
        Ok(())
    }

    fn read_directory_entries(&mut self, inode: &Ext4Inode) -> io::Result<Vec<(u32, SmallVec<[u8; 256]>)>> {
        self.read_file_content(inode, 1024 * 1024, false)?;

        let mut entries = Vec::with_capacity(16);
        let mut offset = 0;

        while offset < self.content_buf.len() {
            if offset + 8 > self.content_buf.len() {
                break;
            }

            let entry_inode = u32::from_le_bytes([
                self.content_buf[offset + 0],
                self.content_buf[offset + 1],
                self.content_buf[offset + 2],
                self.content_buf[offset + 3],
            ]);

            if entry_inode == 0 {
                break;
            }

            let rec_len = u16::from_le_bytes([
                self.content_buf[offset + 4],
                self.content_buf[offset + 5],
            ]);

            let name_len = self.content_buf[offset + 6];

            if rec_len == 0 || rec_len < 8 || offset + rec_len as usize > self.content_buf.len() {
                break;
            }

            if name_len > 0 && offset + 8 + name_len as usize <= offset + rec_len as usize {
                let name_bytes = &self.content_buf[offset + 8..offset + 8 + name_len as usize];
                let mut name = SmallVec::new();
                name.extend_from_slice(name_bytes);
                entries.push((entry_inode, name));
            }

            offset += rec_len as usize;
        }

        Ok(entries)
    }

    fn search_recursive(
        &mut self,
        inode_num: u32,
        path: &mut Vec<u8>,
        pattern: &Regex,
        running: &Arc<AtomicBool>,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_TRAVERSE_DEPTH || !running.load(Ordering::Relaxed) {
            return Ok(());
        }

        let Ok(inode) = self.read_inode(inode_num) else {
            return Ok(());
        };

        let file_type = inode.mode & EXT4_S_IFMT;

        if file_type == EXT4_S_IFREG {
            if inode.size > MAX_FILE_BYTE_SIZE as u64 {
                return Ok(());
            }

            if self.read_file_content(&inode, MAX_FILE_BYTE_SIZE, true).is_ok() {
                self.find_and_print_matches(pattern, path)?;
            }
        } else if file_type == EXT4_S_IFDIR {
            let Ok(entries) = self.read_directory_entries(&inode) else {
                return Ok(())
            };

            let path_len = path.len();

            for (entry_inode, name) in entries {
                if name.as_slice() == b"." || name.as_slice() == b".." {
                    continue;
                }

                if path_len == 1 {
                    path.extend_from_slice(&name);
                } else {
                    path.push(b'/');
                    path.extend_from_slice(&name);
                }

                _ = self.search_recursive(entry_inode, path, pattern, running, depth + 1);

                path.truncate(path_len);
            }
        }

        Ok(())
    }

    // TODO: Stop collecting matches like that and print them to output_buf right away
    #[inline]
    fn collect_matches(
        &self,
        pattern: &Regex,
        line: &[u8],
        line_start: usize,
        line_num: usize,
    ) -> Option<FileMatch> {
        if !pattern.is_match(line) {
            return None;
        }

        let mut matches = SmallVec::new();
        for m in pattern.find_iter(line) {
            matches.push((m.start(), m.end()));
        }

        if matches.is_empty() {
            return None;
        }

        Some(FileMatch {
            line_num,
            line_start,
            line_len: line.len(),
            matches,
        })
    }

    fn find_and_print_matches(
        &mut self,
        pattern: &Regex,
        path: &[u8],
    ) -> io::Result<()> {
        #[inline]
        fn truncate_utf8(s: &[u8], max: usize) -> &[u8] {
            if s.len() <= max {
                return s;
            }

            let mut end = max;
            while end > 0 && (s[end] & 0b1100_0000) == 0b1000_0000 {
                end -= 1;
            }

            &s[..end]
        }

        self.file_matches.clear();

        let buf = &self.content_buf;

        // --------------------------------------------------------
        // ------------------ Look for matches
        // --------------------------------------------------------

        let mut line_start = 0;
        let mut line_num = 1;

        for nl in memchr::memchr_iter(b'\n', buf) {
            let line = &buf[line_start..nl];

            if let Some(match_) = self.collect_matches(pattern, line, line_start, line_num) {
                self.file_matches.push(match_);
            }

            line_start = nl + 1;
            line_num += 1;
        }

        // scan last line without newline
        if line_start < buf.len() {
            let line = &buf[line_start..];
            if let Some(match_) = self.collect_matches(pattern, line, line_start, line_num) {
                self.file_matches.push(match_);
            }
        }

        if self.file_matches.is_empty() {
            return Ok(());
        }

        // --------------------------------------------------------
        // ----------------------- Output
        // --------------------------------------------------------
        self.output_buf.clear();

        // print:  file_path:
        self.output_buf.extend_from_slice(COLOR_GREEN);
        self.output_buf.extend_from_slice(path);
        self.output_buf.extend_from_slice(COLOR_RESET);
        self.output_buf.push(b':');
        self.output_buf.push(b'\n');

        for m in &self.file_matches {
            // line number
            self.output_buf.extend_from_slice(COLOR_CYAN);
            self.output_buf.extend_from_slice(m.line_num.to_string().as_bytes());
            self.output_buf.extend_from_slice(COLOR_RESET);
            self.output_buf.extend_from_slice(b": ");

            let line = &buf[m.line_start..m.line_start + m.line_len];
            let display = truncate_utf8(line, 500);

            let mut last = 0;
            for &(s, e) in &m.matches {
                if s >= display.len() {
                    break;
                }
                let e = e.min(display.len());

                // print normal chunk
                self.output_buf.extend_from_slice(&display[last..s]);

                // print highlighted
                self.output_buf.extend_from_slice(COLOR_RED);
                self.output_buf.extend_from_slice(&display[s..e]);
                self.output_buf.extend_from_slice(COLOR_RESET);

                last = e;
            }

            self.output_buf.extend_from_slice(&display[last..]);
            self.output_buf.push(b'\n');
        }

        {
            let mut handle = io::stdout().lock();
            handle.write_all(&self.output_buf)?;
        }

        Ok(())
    }
}

fn setup_signal_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
        _ = io::stdout().lock().write_all(CURSOR_UNHIDE);
        _ = io::stdout().flush();
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    running
}

struct CursorHide;

impl CursorHide {
    fn new() -> io::Result<Self> {
        io::stdout().lock().write_all(CURSOR_HIDE)?;
        io::stdout().flush()?;
        Ok(CursorHide)
    }
}

impl Drop for CursorHide {
    fn drop(&mut self) {
        _ = io::stdout().lock().write_all(CURSOR_UNHIDE);
        _ = io::stdout().flush();
    }
}

fn main() -> io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 3 {
        eprintln!("usage: {} <device> <pattern>", args[0]);
        eprintln!("example: {} /dev/sda1 'error|warning'", args[0]);
        eprintln!("note: Requires root/sudo to read raw devices");
        std::process::exit(1);
    }

    let device = &args[1];
    let pattern_str = &args[2];

    let pattern = Regex::new(pattern_str).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid regex: {e}"))
    })?;

    let running = setup_signal_handler();

    // TODO: Detect the partition automatically
    let mut reader = match Ext4Reader::new(device) {
        Ok(ok) => ok,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    eprintln!("error: device or partition not found: {device}");
                }
                std::io::ErrorKind::PermissionDenied => {
                    eprintln!("error: permission denied. Try running with sudo/root to read raw devices.");
                }
                std::io::ErrorKind::InvalidData => {
                    eprintln!("error: invalid ext4 filesystem on this path: {e}");
                    eprintln!("help: make sure the path points to a partition (e.g., /dev/sda1) and not a whole disk (e.g., /dev/sda)");
                    eprintln!("tip: try running `df -Th /` to find your root partition");
                }
                _ => {
                    eprintln!("error: failed to initialize ext4 reader: {e}");
                }
            }

            std::process::exit(1);
        }
    };

    eprintln!("\x1b[1;36mSearching\x1b[0m '{device}' for pattern: \x1b[1;31m'{pattern_str}'\x1b[0m\n");

    let _cur = CursorHide::new();

    let mut path = vec![b'/'];
    reader.search_recursive(EXT4_ROOT_INODE, &mut path, &pattern, &running, 0)?;

    eprintln!("\n\x1b[1;32mSearch complete\x1b[0m");

    Ok(())
}
