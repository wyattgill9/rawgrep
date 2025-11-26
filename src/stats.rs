use std::fmt::Display;

use crate::{COLOR_BLUE, COLOR_GREEN, COLOR_RESET};

#[derive(Default)]
pub struct Stats {
    pub bytes_searched: usize,

    pub symlinks_followed: usize,
    pub symlinks_broken: usize,

    pub files_encountered: usize,
    pub files_searched: usize,
    pub files_contained_matches: usize,
    pub files_skipped_large: usize,
    pub files_skipped_unreadable: usize,
    pub files_skipped_as_binary_due_to_ext: usize,
    pub files_skipped_as_binary_due_to_probe: usize,
    pub files_skipped_gitignore: usize,

    pub dirs_skipped_common: usize,
    pub dirs_skipped_gitignore: usize,
    pub dirs_encountered: usize,
}

impl Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_files = self.files_encountered;

        let total_dirs = self.dirs_encountered
            + self.dirs_skipped_common
            + self.dirs_skipped_gitignore;

        let total_symlinks = self.symlinks_followed + self.symlinks_broken;

        writeln!(f, "\n{COLOR_GREEN}Search complete{COLOR_RESET}")?;

        writeln!(f, "{COLOR_BLUE}Files Summary:{COLOR_RESET}")?;
        macro_rules! file_row {
            ($label:expr, $count:expr) => {
                let pct = if total_files == 0 { 0.0 } else { ($count as f64 / total_files as f64) * 100.0 };
                writeln!(f, "  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct)?;
            };
        }

        file_row!("Files encountered", self.files_encountered);
        file_row!("Files searched", self.files_searched);
        file_row!("Files contained matches", self.files_contained_matches);
        file_row!("Skipped (large)", self.files_skipped_large);
        file_row!("Skipped (binary ext)", self.files_skipped_as_binary_due_to_ext);
        file_row!("Skipped (binary probe)", self.files_skipped_as_binary_due_to_probe);
        file_row!("Skipped (unreadable)", self.files_skipped_unreadable);
        file_row!("Skipped (gitignore)", self.files_skipped_gitignore);

        if total_symlinks > 0 {
            writeln!(f, "\n{COLOR_BLUE}Symlinks Summary:{COLOR_RESET}")?;
            macro_rules! symlink_row {
                ($label:expr, $count:expr) => {
                    let pct = if total_symlinks == 0 { 0.0 } else { ($count as f64 / total_symlinks as f64) * 100.0 };
                    writeln!(f, "  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct)?;
                };
            }
            symlink_row!("Total symlinks", total_symlinks);
            symlink_row!("Followed successfully", self.symlinks_followed);
            symlink_row!("Broken/skipped", self.symlinks_broken);
        }

        writeln!(f, "\n{COLOR_BLUE}Bytes Summary:{COLOR_RESET}")?;
        macro_rules! bytes_row {
            ($label:expr, $count:expr) => {
                writeln!(f, "  {:<25} {:>12}", $label, $crate::util::format_bytes($count))?;
            };
        }

        bytes_row!("Bytes searched", self.bytes_searched);

        writeln!(f, "\n{COLOR_BLUE}Directories Summary:{COLOR_RESET}")?;
        macro_rules! dir_row {
            ($label:expr, $count:expr) => {
                let pct = if total_dirs == 0 { 0.0 } else { ($count as f64 / total_dirs as f64) * 100.0 };
                writeln!(f, "  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct)?;
            };
        }

        dir_row!("Dirs encountered", self.dirs_encountered);
        dir_row!("Skipped (common)", self.dirs_skipped_common);
        dir_row!("Skipped (gitignore)", self.dirs_skipped_gitignore);

        Ok(())
    }
}


