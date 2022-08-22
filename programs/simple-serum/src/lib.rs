use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{Mint, Token, TokenAccount, Transfer},
};
use enumflags2::{bitflags, make_bitflags, BitFlags};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod simple_serum {
    use super::*;

    pub fn initialize_market(ctx: Context<InitializeMarket>) -> Result<()> {
        let market = &mut ctx.accounts.market;
        market.coin_vault = ctx.accounts.coin_vault.key();
        market.pc_vault = ctx.accounts.pc_vault.key();
        market.coin_mint = ctx.accounts.coin_mint.key();
        market.pc_mint = ctx.accounts.pc_mint.key();
        market.coin_lot_size = 1;
        market.pc_lot_size = 1;
        market.coin_deposits_total = 0;
        market.pc_deposits_total = 0;
        // market.bids = ctx.accounts.bids.key();
        // market.asks = ctx.accounts.asks.key();
        market.req_q = ctx.accounts.req_q.key();
        // market.event_q = ctx.accounts.event_q.key();
        market.authority = ctx.accounts.authority.key();

        Ok(())
    }

    pub fn new_order(
        ctx: Context<NewOrder>,
        side: Side,
        limit_price: u64,
        max_coin_qty: u64,
        max_native_pc_qty: u64,
        order_type: OrderType,
    ) -> Result<()> {
        let open_orders = &mut ctx.accounts.open_orders;
        let market = &mut ctx.accounts.market;
        let coin_vault = &ctx.accounts.coin_vault;
        let pc_vault = &ctx.accounts.pc_vault;
        let payer = &ctx.accounts.payer;
        let req_q = &mut ctx.accounts.req_q;
        // TODO:
        // let event_q = &mut ctx.accounts.event_q;
        let authority = &ctx.accounts.authority;
        let token_program = &ctx.accounts.token_program;

        if !open_orders.is_initialized {
            open_orders.init(market.key(), authority.key())?;
        }

        let deposit_amount;
        let deposit_vault;
        match side {
            Side::Bid => {
                let lock_qty_native = max_native_pc_qty;
                let free_qty_to_lock = lock_qty_native.min(open_orders.native_pc_free);
                deposit_amount = lock_qty_native - free_qty_to_lock;
                deposit_vault = pc_vault;
                require!(payer.amount >= deposit_amount, ErrorCode::InsufficientFunds);
                open_orders.native_pc_free -= free_qty_to_lock;
                open_orders.native_pc_total += deposit_amount;
                market.pc_deposits_total += deposit_amount;
            }
            Side::Ask => {
                let lock_qty_native = max_coin_qty * market.coin_lot_size;
                let free_qty_to_lock = lock_qty_native.min(open_orders.native_coin_free);
                deposit_amount = lock_qty_native - free_qty_to_lock;
                deposit_vault = coin_vault;
                require!(payer.amount >= deposit_amount, ErrorCode::InsufficientFunds);
                open_orders.native_coin_free -= free_qty_to_lock;
                open_orders.native_coin_total += deposit_amount;
                market.coin_deposits_total += deposit_amount;
            }
        }

        let order_id = req_q.gen_order_id(limit_price, side);
        let owner_slot = open_orders.add_order(order_id, side);
        // TODO:

        if deposit_amount != 0 {
            let transfer_ix = Transfer {
                from: payer.to_account_info(),
                to: deposit_vault.to_account_info(),
                authority: authority.to_account_info(),
            };
            let cpi_ctx = CpiContext::new(token_program.to_account_info(), transfer_ix);
            anchor_spl::token::transfer(cpi_ctx, deposit_amount).map_err(|err| match err {
                _ => error!(ErrorCode::TransferFailed),
            })?
        }

        Ok(())
    }
}

#[account]
pub struct Market {
    coin_vault: Pubkey,
    pc_vault: Pubkey,

    coin_mint: Pubkey,
    pc_mint: Pubkey,

    coin_lot_size: u64,
    pc_lot_size: u64,

    coin_deposits_total: u64,
    pc_deposits_total: u64,

    bids: Pubkey,
    asks: Pubkey,

    req_q: Pubkey,
    event_q: Pubkey,

    authority: Pubkey,
}

impl Market {
    #[inline]
    fn check_payer_mint(&self, payer_mint: Pubkey, side: Side) -> Result<()> {
        match side {
            Side::Bid => {
                if payer_mint == self.pc_mint {
                    Ok(())
                } else {
                    Err(error!(ErrorCode::WrongPayerMint))
                }
            }
            Side::Ask => {
                if payer_mint == self.coin_mint {
                    Ok(())
                } else {
                    Err(error!(ErrorCode::WrongPayerMint))
                }
            }
        }
    }
}

pub trait QueueHeader {
    type Item: Copy + Default + anchor_lang::AnchorSerialize + anchor_lang::AnchorDeserialize;

    fn head(&self) -> u64;
    fn set_head(&mut self, value: u64);
    fn count(&self) -> u64;
    fn set_count(&mut self, value: u64);

    fn incr_event_id(&mut self);
    fn decr_event_id(&mut self, n: u64);
}

#[account]
#[derive(Default)]
pub struct Queue<
    H: QueueHeader + Default + anchor_lang::AnchorSerialize + anchor_lang::AnchorDeserialize,
> {
    header: H,
    buf: [H::Item; 32],
}

impl<H: QueueHeader + Default + anchor_lang::AnchorSerialize + anchor_lang::AnchorDeserialize>
    Queue<H>
{
    pub fn new(header: H, buf: [H::Item; 32]) -> Self {
        Self { header, buf }
    }

    #[inline]
    pub fn len(&self) -> u64 {
        self.header.count()
    }

    #[inline]
    pub fn full(&self) -> bool {
        self.header.count() as usize == self.buf.len()
    }

    #[inline]
    pub fn empty(&self) -> bool {
        self.header.count() == 0
    }

    #[inline]
    pub fn push_back(&mut self, value: H::Item) -> Result<()> {
        if self.full() {
            return Err(error!(ErrorCode::QueueAlreadyFull));
        }
        let slot = ((self.header.head() + self.header.count()) as usize) % self.buf.len();
        self.buf[slot] = value;

        let count = self.header.count();
        self.header.set_count(count + 1);

        self.header.incr_event_id();

        Ok(())
    }

    #[inline]
    pub fn peek_front(&self) -> Option<&H::Item> {
        if self.empty() {
            return None;
        }
        Some(&self.buf[self.header.head() as usize])
    }

    #[inline]
    pub fn peek_front_mut(&mut self) -> Option<&mut H::Item> {
        if self.empty() {
            return None;
        }
        Some(&mut self.buf[self.header.head() as usize])
    }

    #[inline]
    pub fn pop_front(&mut self) -> Result<H::Item> {
        if self.empty() {
            return Err(error!(ErrorCode::EmptyQueue));
        }
        let value = self.buf[self.header.head() as usize];

        let count = self.header.count();
        self.header.set_count(count - 1);

        let head = self.header.head();
        self.header.set_head((head + 1) % self.buf.len() as u64);

        Ok(value)
    }

    // #[inline]
    // pub fn revert_pushes(&mut self, desired_len: u64) -> DexResult<()> {
    //     check_assert!(desired_len <= self.header.count())?;
    //     let len_diff = self.header.count() - desired_len;
    //     self.header.set_count(desired_len);
    //     self.header.decr_event_id(len_diff);
    //     Ok(())
    // }

    pub fn iter(&self) -> impl Iterator<Item = &H::Item> {
        QueueIterator {
            queue: self,
            index: 0,
        }
    }
}

struct QueueIterator<
    'a,
    H: QueueHeader + Default + anchor_lang::AnchorSerialize + anchor_lang::AnchorDeserialize,
> {
    queue: &'a Queue<H>,
    index: u64,
}

impl<
        'a,
        H: QueueHeader + Default + anchor_lang::AnchorSerialize + anchor_lang::AnchorDeserialize,
    > Iterator for QueueIterator<'a, H>
{
    type Item = &'a H::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.queue.len() {
            None
        } else {
            let item = &self.queue.buf
                [(self.queue.header.head() + self.index) as usize % self.queue.buf.len()];
            self.index += 1;
            Some(item)
        }
    }
}

// #[repr(packed)]
#[derive(Copy, Clone, Default, AnchorSerialize, AnchorDeserialize)]
pub struct RequestQueueHeader {
    head: u64,
    count: u64,
    next_seq_num: u64,
}

impl QueueHeader for RequestQueueHeader {
    type Item = Request;

    fn head(&self) -> u64 {
        self.head
    }
    fn set_head(&mut self, value: u64) {
        self.head = value;
    }
    fn count(&self) -> u64 {
        self.count
    }
    fn set_count(&mut self, value: u64) {
        self.count = value;
    }
    #[inline(always)]
    fn incr_event_id(&mut self) {}
    #[inline(always)]
    fn decr_event_id(&mut self, _n: u64) {}
}

pub type RequestQueue = Queue<RequestQueueHeader>;

impl RequestQueue {
    fn gen_order_id(&mut self, limit_price: u64, side: Side) -> u128 {
        let seq_num = self.gen_seq_num();
        let upper = (limit_price as u128) << 64;
        let lower = match side {
            Side::Bid => !seq_num,
            Side::Ask => seq_num,
        };
        upper | (lower as u128)
    }

    fn gen_seq_num(&mut self) -> u64 {
        let seq_num = self.header.next_seq_num;
        self.header.next_seq_num += 1;
        seq_num
    }
}

#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, AnchorSerialize, AnchorDeserialize)]
enum RequestFlag {
    NewOrder = 0x01,
    CancelOrder = 0x02,
    Bid = 0x04,
    // PostOnly = 0x08,
    // ImmediateOrCancel = 0x10,
    // DecrementTakeOnSelfTrade = 0x20,
}

pub enum RequestView {
    NewOrder {
        side: Side,
        order_type: OrderType,
        owner_slot: u8,
        order_id: u128,
        max_coin_qty: u64,
        native_pc_qty_locked: Option<u64>,
        owner: Pubkey,
    },
    CancelOrder {
        side: Side,
        order_id: u128,
        cancel_id: u64,
        expected_owner_slot: u8,
        expected_owner: Pubkey,
    },
}

// #[repr(packed)]
#[derive(Copy, Clone, Default, AnchorSerialize, AnchorDeserialize)]
pub struct Request {
    request_flags: u8,
    owner_slot: u8,
    max_coin_qty_or_cancel_id: u64,
    native_pc_qty_locked: u64,
    order_id: u128,
    owner: Pubkey,
}

impl Request {
    #[inline(always)]
    pub fn new(view: RequestView) -> Self {
        match view {
            RequestView::NewOrder {
                side,
                order_type,
                owner_slot,
                order_id,
                owner,
                max_coin_qty,
                native_pc_qty_locked,
            } => {
                let mut flags = make_bitflags!(RequestFlag::{NewOrder});
                if side == Side::Bid {
                    flags |= RequestFlag::Bid;
                }
                match order_type {
                    OrderType::Limit => (),
                };

                Request {
                    request_flags: flags.bits(),
                    owner_slot,
                    order_id,
                    owner,
                    max_coin_qty_or_cancel_id: max_coin_qty,
                    native_pc_qty_locked: native_pc_qty_locked.unwrap(),
                }
            }
            RequestView::CancelOrder {
                side,
                expected_owner_slot,
                order_id,
                expected_owner,
                cancel_id,
            } => {
                let mut flags = make_bitflags!(RequestFlag::{CancelOrder});
                if side == Side::Bid {
                    flags |= RequestFlag::Bid;
                }

                Request {
                    request_flags: flags.bits(),
                    max_coin_qty_or_cancel_id: cancel_id,
                    order_id,
                    owner_slot: expected_owner_slot,
                    owner: expected_owner,
                    native_pc_qty_locked: 0,
                }
            }
        }
    }

    // #[inline(always)]
    // pub fn as_view(&self) -> DexResult<RequestView> {
    //     let flags = BitFlags::from_bits(self.request_flags).unwrap();
    //     let side = if flags.contains(RequestFlag::Bid) {
    //         Side::Bid
    //     } else {
    //         Side::Ask
    //     };
    //     if flags.contains(RequestFlag::NewOrder) {
    //         let allowed_flags = {
    //             use RequestFlag::*;
    //             NewOrder | Bid | PostOnly | ImmediateOrCancel
    //         };
    //         check_assert!(allowed_flags.contains(flags))?;
    //         let post_only = flags.contains(RequestFlag::PostOnly);
    //         let ioc = flags.contains(RequestFlag::ImmediateOrCancel);
    //         let order_type = match (post_only, ioc) {
    //             (true, false) => OrderType::PostOnly,
    //             (false, true) => OrderType::ImmediateOrCancel,
    //             (false, false) => OrderType::Limit,
    //             (true, true) => unreachable!(),
    //         };
    //         Ok(RequestView::NewOrder {
    //             side,
    //             order_type,
    //             owner_slot: self.owner_slot,
    //             order_id: self.order_id,
    //             owner: self.owner,
    //             max_coin_qty: NonZeroU64::new(self.max_coin_qty_or_cancel_id).unwrap(),
    //             native_pc_qty_locked: NonZeroU64::new(self.native_pc_qty_locked),
    //         })
    //     } else {
    //         check_assert!(flags.contains(RequestFlag::CancelOrder))?;
    //         let allowed_flags = {
    //             use RequestFlag::*;
    //             CancelOrder | Bid
    //         };
    //         check_assert!(allowed_flags.contains(flags))?;
    //         Ok(RequestView::CancelOrder {
    //             side,
    //             cancel_id: self.max_coin_qty_or_cancel_id,
    //             order_id: self.order_id,
    //             expected_owner_slot: self.owner_slot,
    //             expected_owner: self.owner,
    //         })
    //     }
    // }
}

// #[repr(packed)]
#[derive(Copy, Clone, Default, AnchorSerialize, AnchorDeserialize)]
pub struct EventQueueHeader {
    head: u64,
    count: u64,
    seq_num: u64,
}

impl QueueHeader for EventQueueHeader {
    type Item = Event;

    fn head(&self) -> u64 {
        self.head
    }
    fn set_head(&mut self, value: u64) {
        self.head = value;
    }
    fn count(&self) -> u64 {
        self.count
    }
    fn set_count(&mut self, value: u64) {
        self.count = value;
    }
    fn incr_event_id(&mut self) {
        self.seq_num += 1;
    }
    fn decr_event_id(&mut self, n: u64) {
        self.seq_num -= n;
    }
}

pub type EventQueue = Queue<EventQueueHeader>;

#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, AnchorSerialize, AnchorDeserialize)]
enum EventFlag {
    Fill = 0x1,
    Out = 0x2,
    Bid = 0x4,
    Maker = 0x8,
    ReleaseFunds = 0x10,
}

impl EventFlag {
    #[inline]
    fn from_side(side: Side) -> BitFlags<Self> {
        match side {
            Side::Bid => EventFlag::Bid.into(),
            Side::Ask => BitFlags::empty(),
        }
    }

    #[inline]
    fn flags_to_side(flags: BitFlags<Self>) -> Side {
        if flags.contains(EventFlag::Bid) {
            Side::Bid
        } else {
            Side::Ask
        }
    }
}

pub enum EventView {
    Fill {
        side: Side,
        maker: bool,
        native_qty_paid: u64,
        native_qty_received: u64,
        order_id: u128,
        owner: Pubkey,
        owner_slot: u8,
    },
    Out {
        side: Side,
        release_funds: bool,
        native_qty_unlocked: u64,
        native_qty_still_locked: u64,
        order_id: u128,
        owner: Pubkey,
        owner_slot: u8,
    },
}

impl EventView {
    fn side(&self) -> Side {
        match self {
            &EventView::Fill { side, .. } | &EventView::Out { side, .. } => side,
        }
    }
}

// #[repr(packed)]
#[derive(Copy, Clone, Default, AnchorSerialize, AnchorDeserialize)]
pub struct Event {
    event_flags: u8,
    owner_slot: u8,

    native_qty_released: u64,
    native_qty_paid: u64,

    order_id: u128,
    pub owner: Pubkey,
}

impl Event {
    #[inline(always)]
    pub fn new(view: EventView) -> Self {
        match view {
            EventView::Fill {
                side,
                maker,
                native_qty_paid,
                native_qty_received,
                order_id,
                owner,
                owner_slot,
            } => {
                let maker_flag = if maker {
                    BitFlags::from_flag(EventFlag::Maker).bits()
                } else {
                    0
                };
                let event_flags =
                    (EventFlag::from_side(side) | EventFlag::Fill).bits() | maker_flag;
                Event {
                    event_flags,
                    owner_slot,
                    native_qty_released: native_qty_received,
                    native_qty_paid,
                    order_id,
                    owner,
                }
            }

            EventView::Out {
                side,
                release_funds,
                native_qty_unlocked,
                native_qty_still_locked,
                order_id,
                owner,
                owner_slot,
            } => {
                let release_funds_flag = if release_funds {
                    BitFlags::from_flag(EventFlag::ReleaseFunds).bits()
                } else {
                    0
                };
                let event_flags =
                    (EventFlag::from_side(side) | EventFlag::Out).bits() | release_funds_flag;
                Event {
                    event_flags,
                    owner_slot,
                    native_qty_released: native_qty_unlocked,
                    native_qty_paid: native_qty_still_locked,
                    order_id,
                    owner,
                }
            }
        }
    }

    // #[inline(always)]
    // pub fn as_view(&self) -> DexResult<EventView> {
    //     let flags = BitFlags::from_bits(self.event_flags).unwrap();
    //     let side = EventFlag::flags_to_side(flags);
    //     let client_order_id = NonZeroU64::new(self.client_order_id);
    //     if flags.contains(EventFlag::Fill) {
    //         let allowed_flags = {
    //             use EventFlag::*;
    //             Fill | Bid | Maker
    //         };
    //         check_assert!(allowed_flags.contains(flags))?;

    //         return Ok(EventView::Fill {
    //             side,
    //             maker: flags.contains(EventFlag::Maker),
    //             native_qty_paid: self.native_qty_paid,
    //             native_qty_received: self.native_qty_released,
    //             native_fee_or_rebate: self.native_fee_or_rebate,

    //             order_id: self.order_id,
    //             owner: self.owner,

    //             owner_slot: self.owner_slot,
    //             fee_tier: self.fee_tier.try_into().or(check_unreachable!())?,
    //             client_order_id,
    //         });
    //     }
    //     let allowed_flags = {
    //         use EventFlag::*;
    //         Out | Bid | ReleaseFunds
    //     };
    //     check_assert!(allowed_flags.contains(flags))?;
    //     Ok(EventView::Out {
    //         side,
    //         release_funds: flags.contains(EventFlag::ReleaseFunds),
    //         native_qty_unlocked: self.native_qty_released,
    //         native_qty_still_locked: self.native_qty_paid,

    //         order_id: self.order_id,
    //         owner: self.owner,

    //         owner_slot: self.owner_slot,
    //         client_order_id,
    //     })
    // }
}

#[derive(Accounts)]
pub struct InitializeMarket<'info> {
    #[account(
        init,
        payer = authority,
        space = 32 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 32 + 32 + 32 + 32 + 32,
        seeds = [b"market".as_ref(), coin_mint.key().as_ref(), pc_mint.key().as_ref()],
        bump,
    )]
    pub market: Account<'info, Market>,

    #[account(
        init,
        payer = authority,
        associated_token::mint = coin_mint,
        associated_token::authority = market,
    )]
    pub coin_vault: Account<'info, TokenAccount>,
    #[account(
        init,
        payer = authority,
        associated_token::mint = pc_mint,
        associated_token::authority = market,
    )]
    pub pc_vault: Account<'info, TokenAccount>,

    pub coin_mint: Account<'info, Mint>,
    pub pc_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = authority,
        space = 8 + 8 + 8 + (1 + 1 + 8 + 8 + 16 + 32) * 32,
        seeds = [b"req_q".as_ref(), market.key().as_ref()],
        bump,
    )]
    pub req_q: Account<'info, RequestQueue>,
    // TODO:
    // #[account(
    //     init,
    //     payer = authority,
    //     space = 8 + 8 + 8 + (1 + 1 + 8 + 8 + 16 + 32) * 32,
    //     seeds = [b"event_q".as_ref(), market.key().as_ref()],
    //     bump,
    // )]
    // pub event_q: Account<'info, EventQueue>,
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,

    pub rent: Sysvar<'info, Rent>,
}

#[derive(Copy, Clone, PartialEq, AnchorSerialize, AnchorDeserialize)]
pub enum Side {
    Bid = 0,
    Ask = 1,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub enum OrderType {
    Limit = 0,
    // ImmediateOrCancel = 1,
    // PostOnly = 2,
}

#[account]
#[derive(Default)]
pub struct OpenOrders {
    is_initialized: bool,

    market: Pubkey,
    authority: Pubkey,

    native_coin_free: u64,
    native_pc_free: u64,

    native_coin_total: u64,
    native_pc_total: u64,

    free_slot_bits: u32,
    is_bid_bits: u32,
    orders: [u128; 32],
}

impl OpenOrders {
    fn init(&mut self, market: Pubkey, authority: Pubkey) -> Result<()> {
        require!(!self.is_initialized, ErrorCode::AlreadyInitialized);

        self.market = market;
        self.authority = authority;
        self.free_slot_bits = std::u32::MAX;

        Ok(())
    }

    // fn credit_locked_coin(&mut self, native_coin_amount: u64) {
    //     self.native_coin_total = self
    //         .native_coin_total
    //         .checked_add(native_coin_amount)
    //         .unwrap();
    // }

    // fn credit_locked_pc(&mut self, native_pc_amount: u64) {
    //     self.native_pc_total = self.native_pc_total.checked_add(native_pc_amount).unwrap();
    // }

    // fn lock_free_coin(&mut self, native_coin_amount: u64) {
    //     self.native_coin_free = self
    //         .native_coin_free
    //         .checked_sub(native_coin_amount)
    //         .unwrap();
    // }

    // fn lock_free_pc(&mut self, native_pc_amount: u64) {
    //     self.native_pc_free = self.native_pc_free.checked_sub(native_pc_amount).unwrap();
    // }

    // pub fn unlock_coin(&mut self, native_coin_amount: u64) {
    //     self.native_coin_free = self
    //         .native_coin_free
    //         .checked_add(native_coin_amount)
    //         .unwrap();
    //     assert!(self.native_coin_free <= self.native_coin_total);
    // }

    // pub fn unlock_pc(&mut self, native_pc_amount: u64) {
    //     self.native_pc_free = self.native_pc_free.checked_add(native_pc_amount).unwrap();
    //     assert!(self.native_pc_free <= self.native_pc_total);
    // }

    // fn slot_is_free(&self, slot: u8) -> bool {
    //     let slot_mask = 1u128 << slot;
    //     self.free_slot_bits & slot_mask != 0
    // }

    // #[inline]
    // fn iter_filled_slots(&self) -> impl Iterator<Item = u8> {
    //     struct Iter {
    //         bits: u128,
    //     }
    //     impl Iterator for Iter {
    //         type Item = u8;
    //         #[inline(always)]
    //         fn next(&mut self) -> Option<Self::Item> {
    //             if self.bits == 0 {
    //                 None
    //             } else {
    //                 let next = self.bits.trailing_zeros();
    //                 let mask = 1u128 << next;
    //                 self.bits &= !mask;
    //                 Some(next as u8)
    //             }
    //         }
    //     }
    //     Iter {
    //         bits: !self.free_slot_bits,
    //     }
    // }

    // #[inline]
    // fn orders_with_client_ids(&self) -> impl Iterator<Item = (NonZeroU64, u128, Side)> + '_ {
    //     self.iter_filled_slots().filter_map(move |slot| {
    //         let client_order_id = NonZeroU64::new(self.client_order_ids[slot as usize])?;
    //         let order_id = self.orders[slot as usize];
    //         let side = self.slot_side(slot).unwrap();
    //         Some((client_order_id, order_id, side))
    //     })
    // }

    // pub fn slot_side(&self, slot: u8) -> Option<Side> {
    //     let slot_mask = 1u128 << slot;
    //     if self.free_slot_bits & slot_mask != 0 {
    //         None
    //     } else if self.is_bid_bits & slot_mask != 0 {
    //         Some(Side::Bid)
    //     } else {
    //         Some(Side::Ask)
    //     }
    // }

    // pub fn remove_order(&mut self, slot: u8) -> DexResult {
    //     check_assert!(slot < 128)?;
    //     check_assert!(!self.slot_is_free(slot))?;

    //     let slot_mask = 1u128 << slot;
    //     self.orders[slot as usize] = 0;
    //     self.client_order_ids[slot as usize] = 0;
    //     self.free_slot_bits |= slot_mask;
    //     self.is_bid_bits &= !slot_mask;

    //     Ok(())
    // }

    fn add_order(&mut self, id: u128, side: Side) -> Result<u8> {
        require!(self.free_slot_bits != 0, ErrorCode::TooManyOpenOrders);
        let slot = self.free_slot_bits.trailing_zeros();
        // check_assert!(self.slot_is_free(slot as u8))?;
        let slot_mask = 1u32 << slot;
        self.free_slot_bits &= !slot_mask;
        match side {
            Side::Bid => {
                self.is_bid_bits |= slot_mask;
            }
            Side::Ask => {
                self.is_bid_bits &= !slot_mask;
            }
        };
        self.orders[slot as usize] = id;
        Ok(slot as u8)
    }
}

#[derive(Accounts)]
#[instruction(side: Side)]
pub struct NewOrder<'info> {
    #[account(
        init_if_needed,
        space = 32 + 32 + 8 + 8 + 16 + 16 + 16 * 16,
        payer = authority,
        seeds = [b"open_orders".as_ref(), market.key().as_ref(), authority.key().as_ref()],
        bump,
        has_one = market,
        has_one = authority,
    )]
    pub open_orders: Account<'info, OpenOrders>,

    #[account(
        seeds = [b"market".as_ref(), coin_mint.key().as_ref(), pc_mint.key().as_ref()],
        bump,
    )]
    pub market: Account<'info, Market>,

    #[account(
        mut,
        associated_token::mint = coin_mint,
        associated_token::authority = market,
    )]
    pub coin_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = pc_mint,
        associated_token::authority = market,
    )]
    pub pc_vault: Account<'info, TokenAccount>,

    pub coin_mint: Account<'info, Mint>,
    pub pc_mint: Account<'info, Mint>,

    #[account(
        mut,
        constraint = (match market.check_payer_mint(payer.mint, side) {
            Ok(_) => true,
            Err(_) => false,
        }),
        token::authority = authority,
    )]
    pub payer: Account<'info, TokenAccount>,

    #[account(mut)]
    pub req_q: Account<'info, RequestQueue>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,

    pub rent: Sysvar<'info, Rent>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Wrong payer mint")]
    WrongPayerMint,

    #[msg("Insufficient funds")]
    InsufficientFunds,

    #[msg("Transfer failed")]
    TransferFailed,

    #[msg("Already initialized")]
    AlreadyInitialized,

    #[msg("Queue already full")]
    QueueAlreadyFull,
    #[msg("Empty queue")]
    EmptyQueue,

    #[msg("Too many open orders")]
    TooManyOpenOrders,
}
