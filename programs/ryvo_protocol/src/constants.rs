use anchor_lang::prelude::*;
use arcium_anchor::comp_def_offset;

#[constant]
pub const SEED: &str = "arcium";

pub const COMP_DEF_OFFSET_ADD_TOGETHER: u32 = comp_def_offset("add_together");
