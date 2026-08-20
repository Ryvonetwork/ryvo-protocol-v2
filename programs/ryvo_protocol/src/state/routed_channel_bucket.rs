use anchor_lang::prelude::*;

/// Routed agent-to-gateway channels stored in one shared account.
///
/// A bucket contains 256 permanent slots. Channel ids are reserved as one contiguous range when
/// the bucket is initialized, so `channel_id = base_channel_id + slot`. Slots are never reused.
/// This keeps routed settlement to one writable bucket account for as many as 256 agent channels.
#[account(zero_copy)]
#[repr(C)]
pub struct RoutedChannelBucket {
    /// Gateway `Participant` PDA shared by every occupied slot.
    pub gateway: Pubkey,
    /// Mint shared by every occupied slot.
    pub mint: Pubkey,
    /// Channel id assigned to slot zero.
    pub base_channel_id: u64,
    /// Account layout version. Starts at one and never changes in place.
    pub version: u8,
    /// Header-only growth room. Increasing per-slot state still requires a new bucket version.
    pub _reserved: [u8; 63],
    /// One bit per slot. A set bit is permanent.
    pub occupied: [u8; 32],
    /// Payer `Participant` PDA for each slot.
    pub payers: [Pubkey; ROUTED_BUCKET_SLOTS],
    /// Arcis verifying keys, packed as two 32-byte circuit slots per channel.
    pub signer_slot_0: [[u8; 32]; ROUTED_BUCKET_SLOTS],
    pub signer_slot_1: [[u8; 32]; ROUTED_BUCKET_SLOTS],
    pub settled_cumulative: [u64; ROUTED_BUCKET_SLOTS],
    pub locked_balance: [u64; ROUTED_BUCKET_SLOTS],
    pub pending_unlock_amount: [u64; ROUTED_BUCKET_SLOTS],
    pub pending_unlock_at: [i64; ROUTED_BUCKET_SLOTS],
}

pub const ROUTED_BUCKET_SLOTS: usize = 256;
pub const ROUTED_BUCKET_VERSION: u8 = 1;

impl RoutedChannelBucket {
    pub const SPACE: usize = 8 + core::mem::size_of::<Self>();

    pub fn is_occupied(&self, slot: usize) -> bool {
        slot < ROUTED_BUCKET_SLOTS && self.occupied[slot / 8] & (1u8 << (slot % 8)) != 0
    }

    pub fn occupy(&mut self, slot: usize) {
        self.occupied[slot / 8] |= 1u8 << (slot % 8);
    }

    pub fn channel_id(&self, slot: usize) -> Option<u64> {
        if slot >= ROUTED_BUCKET_SLOTS {
            return None;
        }
        self.base_channel_id.checked_add(slot as u64)
    }

    pub fn slot_for_channel_id(&self, channel_id: u64) -> Option<usize> {
        let slot = channel_id.checked_sub(self.base_channel_id)? as usize;
        (slot < ROUTED_BUCKET_SLOTS && self.is_occupied(slot)).then_some(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routed_bucket_layout_is_pinned() {
        assert_eq!(core::mem::align_of::<RoutedChannelBucket>(), 8);
        assert_eq!(core::mem::size_of::<RoutedChannelBucket>(), 32_936);
        assert_eq!(RoutedChannelBucket::SPACE, 32_944);
    }

    #[test]
    fn channel_ids_map_to_permanent_slots() {
        let mut bytes = vec![0u8; core::mem::size_of::<RoutedChannelBucket>()];
        let bucket = bytemuck::from_bytes_mut::<RoutedChannelBucket>(&mut bytes);
        bucket.base_channel_id = 100;
        bucket.occupy(0);
        bucket.occupy(255);

        assert_eq!(bucket.channel_id(0), Some(100));
        assert_eq!(bucket.channel_id(255), Some(355));
        assert_eq!(bucket.channel_id(256), None);
        assert_eq!(bucket.slot_for_channel_id(100), Some(0));
        assert_eq!(bucket.slot_for_channel_id(355), Some(255));
        assert_eq!(bucket.slot_for_channel_id(101), None);
    }
}
