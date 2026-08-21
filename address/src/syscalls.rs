#[cfg(all(
    not(any(target_os = "solana", target_arch = "bpf")),
    feature = "curve25519"
))]
use crate::bytes_are_curve_point;
#[cfg(any(target_os = "solana", target_arch = "bpf", feature = "curve25519"))]
use crate::error::AddressError;
use crate::Address;
/// Syscall definitions used by `solana_address`.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub use solana_define_syscall::definitions::{
    sol_create_program_address, sol_curve_validate_point, sol_log_pubkey,
    sol_try_find_program_address,
};

/// Copied from `solana_program::entrypoint::SUCCESS`
/// to avoid a `solana_program` dependency
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
const SUCCESS: u64 = 0;

/// Grind bump seeds through a multi-buffer SHA-256 kernel rather than one at a
/// time.
///
/// Every candidate hashes `seeds || bump || program_id || PDA_MARKER`, and only
/// the single `bump` byte differs between them. That maps exactly onto
/// [`tape_sha256::Message`]'s three segments: the concatenated seeds are the
/// shared `prefix`, the bump is the `body`, and `program_id || PDA_MARKER` is
/// the shared `tail`. So one lane group of candidates hashes in a single pass
/// without materialising any candidate's message.
///
/// Only the hashing is batched. The on-curve check still runs in descending
/// bump order and stops at the first hit, so this performs exactly as many
/// point decompressions as the serial loop does — it just stops paying for one
/// serial SHA-256 per try.
#[cfg(all(
    not(any(target_os = "solana", target_arch = "bpf")),
    feature = "batch-pda"
))]
fn try_find_program_address_batched(
    seeds: &[&[u8]],
    program_id: &Address,
) -> Option<(Address, u8)> {
    use crate::{ADDRESS_BYTES, MAX_SEEDS, MAX_SEED_LEN, PDA_MARKER};

    // Seed count and length limits do not depend on the bump, so settle them once
    if seeds.len() >= MAX_SEEDS {
        return None;
    }
    if seeds.iter().any(|seed| seed.len() > MAX_SEED_LEN) {
        return None;
    }

    let mut prefix = [0u8; MAX_SEEDS * MAX_SEED_LEN];
    let mut prefix_len = 0usize;
    for seed in seeds {
        prefix[prefix_len..prefix_len + seed.len()].copy_from_slice(seed);
        prefix_len += seed.len();
    }
    let prefix = &prefix[..prefix_len];

    let mut tail = [0u8; ADDRESS_BYTES + PDA_MARKER.len()];
    tail[..ADDRESS_BYTES].copy_from_slice(program_id.as_ref());
    tail[ADDRESS_BYTES..].copy_from_slice(PDA_MARKER);

    // A candidate is off-curve about half the time, so a group of eight
    // settles all but one call in about 4000. Widening past that would hash
    // candidates no one ever looks at.
    const MAX_GROUP: usize = 8;
    let width = tape_sha256::lane_width().clamp(1, MAX_GROUP);

    // Bumps run 255 down to 1 like the serial loop, bump 0 is never reached
    let mut bumps = [0u8; MAX_GROUP];
    let mut digests = [[0u8; 32]; MAX_GROUP];
    let mut next: u8 = u8::MAX;
    let mut remaining = usize::from(u8::MAX);

    while remaining > 0 {
        let group = width.min(remaining);
        for bump in bumps.iter_mut().take(group) {
            *bump = next;
            next = next.wrapping_sub(1);
        }

        // Built at full width; only the first `group` entries are handed over.
        let msgs: [tape_sha256::Message<'_>; MAX_GROUP] =
            core::array::from_fn(|slot| tape_sha256::Message {
                prefix,
                body: core::slice::from_ref(&bumps[slot]),
                tail: &tail,
            });
        tape_sha256::hash_messages(&msgs[..group], &mut digests[..group]);

        for slot in 0..group {
            if !bytes_are_curve_point(digests[slot]) {
                return Some((Address::from(digests[slot]), bumps[slot]));
            }
        }
        remaining -= group;
    }

    None
}

/// The bump grind as a plain descending loop, kept so the batched path can be checked against it
#[cfg(all(
    not(any(target_os = "solana", target_arch = "bpf")),
    feature = "curve25519"
))]
#[cfg_attr(feature = "batch-pda", allow(dead_code))]
fn try_find_program_address_serial(seeds: &[&[u8]], program_id: &Address) -> Option<(Address, u8)> {
    use crate::MAX_SEEDS;

    // Seed limits fail for every bump alike, settling them here keeps the candidates on the stack
    if seeds.len() >= MAX_SEEDS {
        return None;
    }

    let mut bump_seed = [u8::MAX];
    for _ in 0..u8::MAX {
        {
            let mut seeds_with_bump = [&[][..]; MAX_SEEDS];
            seeds_with_bump[..seeds.len()].copy_from_slice(seeds);
            seeds_with_bump[seeds.len()] = &bump_seed;
            match Address::create_program_address(&seeds_with_bump[..=seeds.len()], program_id) {
                Ok(address) => return Some((address, bump_seed[0])),
                Err(AddressError::InvalidSeeds) => (),
                _ => break,
            }
        }
        bump_seed[0] -= 1;
    }
    None
}

impl Address {
    /// Log an `Address` value.
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    pub fn log(&self) {
        unsafe { sol_log_pubkey(self.as_ref() as *const _ as *const u8) };
    }

    /// Find a valid [program derived address][pda] and its corresponding bump seed.
    ///
    /// [pda]: https://solana.com/docs/core/cpi#program-derived-addresses
    ///
    /// Program derived addresses (PDAs) are account keys that only the program,
    /// `program_id`, has the authority to sign. The address is of the same form
    /// as a Solana `Address`, except they are ensured to not be on the ed25519
    /// curve and thus have no associated private key. When performing
    /// cross-program invocations the program can "sign" for the key by calling
    /// [`invoke_signed`] and passing the same seeds used to generate the
    /// address, along with the calculated _bump seed_, which this function
    /// returns as the second tuple element. The runtime will verify that the
    /// program associated with this address is the caller and thus authorized
    /// to be the signer.
    ///
    /// [`invoke_signed`]: https://docs.rs/solana-program/latest/solana_program/program/fn.invoke_signed.html
    ///
    /// The `seeds` are application-specific, and must be carefully selected to
    /// uniquely derive accounts per application requirements. It is common to
    /// use static strings and other addresses as seeds.
    ///
    /// Because the program address must not lie on the ed25519 curve, there may
    /// be seed and program id combinations that are invalid. For this reason,
    /// an extra seed (the bump seed) is calculated that results in a
    /// point off the curve. The bump seed must be passed as an additional seed
    /// when calling `invoke_signed`.
    ///
    /// The processes of finding a valid program address is by trial and error,
    /// and even though it is deterministic given a set of inputs it can take a
    /// variable amount of time to succeed across different inputs.  This means
    /// that when called from an on-chain program it may incur a variable amount
    /// of the program's compute budget.  Programs that are meant to be very
    /// performant may not want to use this function because it could take a
    /// considerable amount of time. Programs that are already at risk
    /// of exceeding their compute budget should call this with care since
    /// there is a chance that the program's budget may be occasionally
    /// and unpredictably exceeded.
    ///
    /// As all account addresses accessed by an on-chain Solana program must be
    /// explicitly passed to the program, it is typical for the PDAs to be
    /// derived in off-chain client programs, avoiding the compute cost of
    /// generating the address on-chain. The address may or may not then be
    /// verified by re-deriving it on-chain, depending on the requirements of
    /// the program. This verification may be performed without the overhead of
    /// re-searching for the bump key by using the [`create_program_address`]
    /// function.
    ///
    /// [`create_program_address`]: Address::create_program_address
    ///
    /// **Warning**: Because of the way the seeds are hashed there is a potential
    /// for program address collisions for the same program id.  The seeds are
    /// hashed sequentially which means that seeds {"abcdef"}, {"abc", "def"},
    /// and {"ab", "cd", "ef"} will all result in the same program address given
    /// the same program id. Since the chance of collision is local to a given
    /// program id, the developer of that program must take care to choose seeds
    /// that do not collide with each other. For seed schemes that are susceptible
    /// to this type of hash collision, a common remedy is to insert separators
    /// between seeds, e.g. transforming {"abc", "def"} into {"abc", "-", "def"}.
    ///
    /// # Panics
    ///
    /// Panics in the statistically improbable event that a bump seed could not be
    /// found. Use [`try_find_program_address`] to handle this case.
    ///
    /// [`try_find_program_address`]: Address::try_find_program_address
    ///
    /// Panics if any of the following are true:
    ///
    /// - the number of provided seeds is greater than, _or equal to_,  [`crate::MAX_SEEDS`],
    /// - any individual seed's length is greater than [`crate::MAX_SEED_LEN`].
    ///
    /// # Examples
    ///
    /// This example illustrates a simple case of creating a "vault" account
    /// which is derived from the payer account, but owned by an on-chain
    /// program. The program derived address is derived in an off-chain client
    /// program, which invokes an on-chain Solana program that uses the address
    /// to create a new account owned and controlled by the program itself.
    ///
    /// By convention, the on-chain program will be compiled for use in two
    /// different contexts: both on-chain, to interpret a custom program
    /// instruction as a Solana transaction; and off-chain, as a library, so
    /// that clients can share the instruction data structure, constructors, and
    /// other common code.
    ///
    /// First the on-chain Solana program:
    ///
    /// ```
    /// # use borsh::{BorshSerialize, BorshDeserialize};
    /// # use solana_account_info::{next_account_info, AccountInfo};
    /// # use solana_program_error::ProgramResult;
    /// # use solana_cpi::invoke_signed;
    /// # use solana_address::Address;
    /// # use solana_system_interface::instruction::create_account;
    /// // The custom instruction processed by our program. It includes the
    /// // PDA's bump seed, which is derived by the client program. This
    /// // definition is also imported into the off-chain client program.
    /// // The computed address of the PDA will be passed to this program via
    /// // the `accounts` vector of the `Instruction` type.
    /// #[derive(BorshSerialize, BorshDeserialize, Debug)]
    /// # #[borsh(crate = "borsh")]
    /// pub struct InstructionData {
    ///     pub vault_bump_seed: u8,
    ///     pub lamports: u64,
    /// }
    ///
    /// // The size in bytes of a vault account. The client program needs
    /// // this information to calculate the quantity of lamports necessary
    /// // to pay for the account's rent.
    /// pub static VAULT_ACCOUNT_SIZE: u64 = 1024;
    ///
    /// // The entrypoint of the on-chain program, as provided to the
    /// // `entrypoint!` macro.
    /// fn process_instruction(
    ///     program_id: &Address,
    ///     accounts: &[AccountInfo],
    ///     instruction_data: &[u8],
    /// ) -> ProgramResult {
    ///     let account_info_iter = &mut accounts.iter();
    ///     let payer = next_account_info(account_info_iter)?;
    ///     // The vault PDA, derived from the payer's address
    ///     let vault = next_account_info(account_info_iter)?;
    ///
    ///     let mut instruction_data = instruction_data;
    ///     let instr = InstructionData::deserialize(&mut instruction_data)?;
    ///     let vault_bump_seed = instr.vault_bump_seed;
    ///     let lamports = instr.lamports;
    ///     let vault_size = VAULT_ACCOUNT_SIZE;
    ///
    ///     // Invoke the system program to create an account while virtually
    ///     // signing with the vault PDA, which is owned by this caller program.
    ///     invoke_signed(
    ///         &create_account(
    ///             &payer.key,
    ///             &vault.key,
    ///             lamports,
    ///             vault_size,
    ///             program_id,
    ///         ),
    ///         &[
    ///             payer.clone(),
    ///             vault.clone(),
    ///         ],
    ///         // A slice of seed slices, each seed slice being the set
    ///         // of seeds used to generate one of the PDAs required by the
    ///         // callee program, the final seed being a single-element slice
    ///         // containing the `u8` bump seed.
    ///         &[
    ///             &[
    ///                 b"vault",
    ///                 payer.key.as_ref(),
    ///                 &[vault_bump_seed],
    ///             ],
    ///         ]
    ///     )?;
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// The client program:
    ///
    /// ```
    /// # use borsh::{BorshSerialize, BorshDeserialize};
    /// # use solana_example_mocks::{solana_sdk, solana_rpc_client};
    /// # use solana_address::Address;
    /// # use solana_instruction::{AccountMeta, Instruction};
    /// # use solana_hash::Hash;
    /// # use solana_sdk::{
    /// #     signature::Keypair,
    /// #     signature::{Signer, Signature},
    /// #     transaction::Transaction,
    /// # };
    /// # use solana_rpc_client::rpc_client::RpcClient;
    /// # use std::convert::TryFrom;
    /// # use anyhow::Result;
    /// #
    /// # #[derive(BorshSerialize, BorshDeserialize, Debug)]
    /// # #[borsh(crate = "borsh")]
    /// # struct InstructionData {
    /// #    pub vault_bump_seed: u8,
    /// #    pub lamports: u64,
    /// # }
    /// #
    /// # pub static VAULT_ACCOUNT_SIZE: u64 = 1024;
    /// #
    /// fn create_vault_account(
    ///     client: &RpcClient,
    ///     program_id: Address,
    ///     payer: &Keypair,
    /// ) -> Result<()> {
    ///     // Derive the PDA from the payer account, a string representing the unique
    ///     // purpose of the account ("vault"), and the address of our on-chain program.
    ///     let (vault_address, vault_bump_seed) = Address::find_program_address(
    ///         &[b"vault", payer.pubkey().as_ref()],
    ///         &program_id
    ///     );
    ///
    ///     // Get the amount of lamports needed to pay for the vault's rent
    ///     let vault_account_size = usize::try_from(VAULT_ACCOUNT_SIZE)?;
    ///     let lamports = client.get_minimum_balance_for_rent_exemption(vault_account_size)?;
    ///
    ///     // The on-chain program's instruction data, imported from that program's crate.
    ///     let instr_data = InstructionData {
    ///         vault_bump_seed,
    ///         lamports,
    ///     };
    ///
    ///     // The accounts required by both our on-chain program and the system program's
    ///     // `create_account` instruction, including the vault's address.
    ///     let accounts = vec![
    ///         AccountMeta::new(payer.pubkey(), true),
    ///         AccountMeta::new(vault_address, false),
    ///         AccountMeta::new(solana_system_interface::program::ID, false),
    ///     ];
    ///
    ///     // Create the instruction by serializing our instruction data via borsh
    ///     let instruction = Instruction::new_with_borsh(
    ///         program_id,
    ///         &instr_data,
    ///         accounts,
    ///     );
    ///
    ///     let blockhash = client.get_latest_blockhash()?;
    ///
    ///     let transaction = Transaction::new_signed_with_payer(
    ///         &[instruction],
    ///         Some(&payer.pubkey()),
    ///         &[payer],
    ///         blockhash,
    ///     );
    ///
    ///     client.send_and_confirm_transaction(&transaction)?;
    ///
    ///     Ok(())
    /// }
    /// # let program_id = Address::new_unique();
    /// # let payer = Keypair::new();
    /// # let client = RpcClient::new(String::new());
    /// #
    /// # create_vault_account(&client, program_id, &payer)?;
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    // If target_os = "solana" or target_arch = "bpf", then the function
    // will use syscalls which bring no dependencies; otherwise, this should
    // be opt-in so users don't need the curve25519 dependency.
    #[cfg(any(target_os = "solana", target_arch = "bpf", feature = "curve25519"))]
    #[inline(always)]
    pub fn find_program_address(seeds: &[&[u8]], program_id: &Address) -> (Address, u8) {
        Self::try_find_program_address(seeds, program_id)
            .unwrap_or_else(|| panic!("Unable to find a viable program address bump seed"))
    }

    /// Find a valid [program derived address][pda] and its corresponding bump seed.
    ///
    /// [pda]: https://solana.com/docs/core/cpi#program-derived-addresses
    ///
    /// The only difference between this method and [`find_program_address`]
    /// is that this one returns `None` in the statistically improbable event
    /// that a bump seed cannot be found; or if any of `find_program_address`'s
    /// preconditions are violated.
    ///
    /// See the documentation for [`find_program_address`] for a full description.
    ///
    /// [`find_program_address`]: Address::find_program_address
    // If target_os = "solana" or target_arch = "bpf", then the function
    // will use syscalls which bring no dependencies; otherwise, this should
    // be opt-in so users don't need the curve25519 dependency.
    #[cfg(any(target_os = "solana", target_arch = "bpf", feature = "curve25519"))]
    #[allow(clippy::same_item_push)]
    #[inline(always)]
    pub fn try_find_program_address(
        seeds: &[&[u8]],
        program_id: &Address,
    ) -> Option<(Address, u8)> {
        // Perform the calculation inline, calling this from within a program is
        // not supported
        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            #[cfg(feature = "batch-pda")]
            {
                try_find_program_address_batched(seeds, program_id)
            }
            #[cfg(not(feature = "batch-pda"))]
            {
                try_find_program_address_serial(seeds, program_id)
            }
        }
        // Call via a system call to perform the calculation
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let mut bytes = core::mem::MaybeUninit::<Address>::uninit();
            let mut bump_seed = u8::MAX;
            let result = unsafe {
                crate::syscalls::sol_try_find_program_address(
                    seeds as *const _ as *const u8,
                    seeds.len() as u64,
                    program_id as *const _ as *const u8,
                    &mut bytes as *mut _ as *mut u8,
                    &mut bump_seed as *mut _ as *mut u8,
                )
            };
            match result {
                // SAFETY: The syscall has initialized the bytes.
                SUCCESS => Some((unsafe { bytes.assume_init() }, bump_seed)),
                _ => None,
            }
        }
    }

    /// Create a valid [program derived address][pda] without searching for a bump seed.
    ///
    /// [pda]: https://solana.com/docs/core/cpi#program-derived-addresses
    ///
    /// Because this function does not create a bump seed, it may unpredictably
    /// return an error for any given set of seeds and is not generally suitable
    /// for creating program derived addresses.
    ///
    /// However, it can be used for efficiently verifying that a set of seeds plus
    /// bump seed generated by [`find_program_address`] derives a particular
    /// address as expected. See the example for details.
    ///
    /// See the documentation for [`find_program_address`] for a full description
    /// of program derived addresses and bump seeds.
    ///
    /// [`find_program_address`]: Address::find_program_address
    ///
    /// # Examples
    ///
    /// Creating a program derived address involves iteratively searching for a
    /// bump seed for which the derived [`Address`] does not lie on the ed25519
    /// curve. This search process is generally performed off-chain, with the
    /// [`find_program_address`] function, after which the client passes the
    /// bump seed to the program as instruction data.
    ///
    /// Depending on the application requirements, a program may wish to verify
    /// that the set of seeds, plus the bump seed, do correctly generate an
    /// expected address.
    ///
    /// The verification is performed by appending to the other seeds one
    /// additional seed slice that contains the single `u8` bump seed, calling
    /// `create_program_address`, checking that the return value is `Ok`, and
    /// that the returned `Address` has the expected value.
    ///
    /// ```
    /// # use solana_address::Address;
    /// # let program_id = Address::new_unique();
    /// let (expected_pda, bump_seed) = Address::find_program_address(&[b"vault"], &program_id);
    /// let actual_pda = Address::create_program_address(&[b"vault", &[bump_seed]], &program_id)?;
    /// assert_eq!(expected_pda, actual_pda);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    // If target_os = "solana" or target_arch = "bpf", then the function
    // will use syscalls which bring no dependencies; otherwise, this should
    // be opt-in so users don't need the curve25519 dependency.
    #[cfg(any(target_os = "solana", target_arch = "bpf", feature = "curve25519"))]
    #[inline(always)]
    pub fn create_program_address(
        seeds: &[&[u8]],
        program_id: &Address,
    ) -> Result<Address, AddressError> {
        use crate::{MAX_SEEDS, MAX_SEED_LEN};

        if seeds.len() > MAX_SEEDS {
            return Err(AddressError::MaxSeedLengthExceeded);
        }
        if seeds.iter().any(|seed| seed.len() > MAX_SEED_LEN) {
            return Err(AddressError::MaxSeedLengthExceeded);
        }

        // Perform the calculation inline, calling this from within a program is
        // not supported
        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            use crate::PDA_MARKER;

            let mut hasher = solana_sha256_hasher::Hasher::default();
            for seed in seeds.iter() {
                hasher.hash(seed);
            }
            hasher.hashv(&[program_id.as_ref(), PDA_MARKER]);
            let hash = hasher.result();

            if bytes_are_curve_point(hash.as_ref()) {
                return Err(AddressError::InvalidSeeds);
            }

            Ok(Address::from(hash.to_bytes()))
        }
        // Call via a system call to perform the calculation
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let mut bytes = core::mem::MaybeUninit::<Address>::uninit();
            let result = unsafe {
                crate::syscalls::sol_create_program_address(
                    seeds as *const _ as *const u8,
                    seeds.len() as u64,
                    program_id as *const _ as *const u8,
                    &mut bytes as *mut _ as *mut u8,
                )
            };
            match result {
                // SAFETY: The syscall has initialized the bytes.
                SUCCESS => Ok(unsafe { bytes.assume_init() }),
                _ => Err(result.into()),
            }
        }
    }
}

#[cfg(all(
    test,
    not(any(target_os = "solana", target_arch = "bpf")),
    feature = "batch-pda"
))]
mod batch_pda_tests {
    use {
        super::{try_find_program_address_batched, try_find_program_address_serial},
        crate::{Address, MAX_SEEDS, MAX_SEED_LEN},
        alloc::vec::Vec,
    };

    /// xorshift64*, so the cases are varied but the failures are reproducible
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn bytes(&mut self, out: &mut [u8]) {
            for byte in out.iter_mut() {
                *byte = self.next() as u8;
            }
        }
    }

    /// Batched and serial grinds must agree on both the address and the bump
    #[test]
    fn batched_matches_serial() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut crossed_a_group = 0usize;

        for _ in 0..2000 {
            let mut program_id = [0u8; 32];
            rng.bytes(&mut program_id);
            let program_id = Address::from(program_id);

            // Up to MAX_SEEDS - 1, since the bump occupies the last slot
            let count = rng.below(MAX_SEEDS);
            let mut storage = [[0u8; MAX_SEED_LEN]; MAX_SEEDS];
            let mut lens = [0usize; MAX_SEEDS];
            for i in 0..count {
                lens[i] = rng.below(MAX_SEED_LEN + 1);
                rng.bytes(&mut storage[i][..lens[i]]);
            }
            let seeds: Vec<&[u8]> = (0..count).map(|i| &storage[i][..lens[i]]).collect();

            let batched = try_find_program_address_batched(&seeds, &program_id);
            let serial = try_find_program_address_serial(&seeds, &program_id);
            assert_eq!(batched, serial, "seeds={seeds:?} program_id={program_id:?}");

            // A bump below 248 means the grind ran past the first lane group
            if let Some((_, bump)) = batched {
                if bump < u8::MAX - 8 {
                    crossed_a_group += 1;
                }
            }
        }

        assert!(
            crossed_a_group > 0,
            "no case exercised the multi-group path; the test is not covering it"
        );
    }

    /// Seed count and length violations return None from both paths
    #[test]
    fn rejections_match() {
        let program_id = Address::from([7u8; 32]);
        let long = [0u8; MAX_SEED_LEN + 1];
        let ok = [1u8; 4];

        // Exactly MAX_SEEDS leaves no room for the bump
        let full: Vec<&[u8]> = core::iter::repeat(&ok[..]).take(MAX_SEEDS).collect();
        assert_eq!(
            try_find_program_address_batched(&full, &program_id),
            try_find_program_address_serial(&full, &program_id),
        );
        assert_eq!(try_find_program_address_batched(&full, &program_id), None);

        // One seed over the length limit
        let over: [&[u8]; 2] = [&ok, &long];
        assert_eq!(
            try_find_program_address_batched(&over, &program_id),
            try_find_program_address_serial(&over, &program_id),
        );
        assert_eq!(try_find_program_address_batched(&over, &program_id), None);

        // No seeds at all is legal
        let none: [&[u8]; 0] = [];
        assert_eq!(
            try_find_program_address_batched(&none, &program_id),
            try_find_program_address_serial(&none, &program_id),
        );
        assert!(try_find_program_address_batched(&none, &program_id).is_some());
    }

    /// Both paths must reproduce a PDA derived by the documented construction
    #[test]
    fn agrees_with_find_program_address() {
        let program_id = Address::from([3u8; 32]);
        let seeds: [&[u8]; 2] = [b"metadata", b"mint"];

        let (expected, bump) = Address::find_program_address(&seeds, &program_id);
        let bump_seed = [bump];
        let with_bump: [&[u8]; 3] = [b"metadata", b"mint", &bump_seed];

        assert_eq!(
            Address::create_program_address(&with_bump, &program_id).unwrap(),
            expected,
        );
        assert_eq!(
            try_find_program_address_batched(&seeds, &program_id),
            Some((expected, bump)),
        );
    }
}
