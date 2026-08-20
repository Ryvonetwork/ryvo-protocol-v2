use anchor_lang::prelude::*;

/// Up to 256 permanent payer-to-payee channels sharing one account.
///
/// A bucket has one payee, mint, and channel kind. Direct providers own direct buckets; gateways
/// own routed buckets. Channel ids are reserved as one contiguous range at initialization, so
/// `channel_id = base_channel_id + slot`. Occupied slots are never reused.
#[account(zero_copy)]
#[repr(C)]
pub struct ChannelBucket {
    /// Payee `Participant` PDA shared by every occupied slot.
    pub payee: Pubkey,
    /// Mint shared by every occupied slot.
    pub mint: Pubkey,
    /// Channel id assigned to slot zero.
    pub base_channel_id: u64,
    /// Account layout version. Starts at one and never changes in place.
    pub version: u8,
    /// `CHANNEL_KIND_DIRECT` or `CHANNEL_KIND_ROUTED` for every slot.
    pub kind: u8,
    /// Header-only growth room. Increasing per-slot state requires a new bucket version.
    pub _reserved: [u8; 62],
    /// One permanent occupancy bit per slot.
    pub occupied: [u8; 32],
    /// Payer `Participant` PDA for each slot.
    pub payers: [Pubkey; CHANNEL_BUCKET_SLOTS],
    /// Arcis verifying keys, packed as two 32-byte circuit slots per channel.
    pub signer_slot_0: [[u8; 32]; CHANNEL_BUCKET_SLOTS],
    pub signer_slot_1: [[u8; 32]; CHANNEL_BUCKET_SLOTS],
    pub settled_cumulative: [u64; CHANNEL_BUCKET_SLOTS],
    pub locked_balance: [u64; CHANNEL_BUCKET_SLOTS],
    pub pending_unlock_amount: [u64; CHANNEL_BUCKET_SLOTS],
    pub pending_unlock_at: [i64; CHANNEL_BUCKET_SLOTS],
}

pub const CHANNEL_BUCKET_SLOTS: usize = 256;
pub const CHANNEL_BUCKET_VERSION: u8 = 1;

impl ChannelBucket {
    pub const SPACE: usize = 8 + core::mem::size_of::<Self>();

    pub fn is_occupied(&self, slot: usize) -> bool {
        slot < CHANNEL_BUCKET_SLOTS && self.occupied[slot / 8] & (1u8 << (slot % 8)) != 0
    }

    pub fn occupy(&mut self, slot: usize) {
        self.occupied[slot / 8] |= 1u8 << (slot % 8);
    }

    pub fn channel_id(&self, slot: usize) -> Option<u64> {
        if slot >= CHANNEL_BUCKET_SLOTS {
            return None;
        }
        self.base_channel_id.checked_add(slot as u64)
    }

    pub fn slot_for_channel_id(&self, channel_id: u64) -> Option<usize> {
        let slot = channel_id.checked_sub(self.base_channel_id)? as usize;
        (slot < CHANNEL_BUCKET_SLOTS && self.is_occupied(slot)).then_some(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_bucket_layout_is_pinned() {
        assert_eq!(core::mem::align_of::<ChannelBucket>(), 8);
        assert_eq!(core::mem::size_of::<ChannelBucket>(), 32_936);
        assert_eq!(ChannelBucket::SPACE, 32_944);
    }

    #[test]
    fn channel_ids_map_to_permanent_slots() {
        let mut bytes = vec![0u8; core::mem::size_of::<ChannelBucket>()];
        let bucket = bytemuck::from_bytes_mut::<ChannelBucket>(&mut bytes);
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
