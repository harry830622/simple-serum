import * as anchor from '@project-serum/anchor';
import * as spl from '@solana/spl-token';
import { assert } from 'chai';
import { SimpleSerum } from '../target/types/simple_serum';

const createMint = async (
  provider: anchor.AnchorProvider,
  mint: anchor.web3.Keypair,
  decimal: number,
) => {
  const tx = new anchor.web3.Transaction();
  tx.add(
    anchor.web3.SystemProgram.createAccount({
      programId: spl.TOKEN_PROGRAM_ID,
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey: mint.publicKey,
      space: spl.MintLayout.span,
      lamports: await provider.connection.getMinimumBalanceForRentExemption(
        spl.MintLayout.span,
      ),
    }),
  );
  tx.add(
    spl.createInitializeMintInstruction(
      mint.publicKey,
      decimal,
      provider.wallet.publicKey,
      provider.wallet.publicKey,
    ),
  );
  await provider.sendAndConfirm(tx, [mint]);
};

const createAssociatedTokenAccount = async (
  provider: anchor.AnchorProvider,
  mint: anchor.web3.PublicKey,
  ata: anchor.web3.PublicKey,
  owner: anchor.web3.PublicKey,
) => {
  const tx = new anchor.web3.Transaction();
  tx.add(
    spl.createAssociatedTokenAccountInstruction(
      provider.wallet.publicKey,
      ata,
      owner,
      mint,
    ),
  );
  await provider.sendAndConfirm(tx, []);
};

const mintTo = async (
  provider: anchor.AnchorProvider,
  mint: anchor.web3.PublicKey,
  ta: anchor.web3.PublicKey,
  amount: bigint,
) => {
  const tx = new anchor.web3.Transaction();
  tx.add(
    spl.createMintToInstruction(
      mint,
      ta,
      provider.wallet.publicKey,
      amount,
      [],
    ),
  );
  await provider.sendAndConfirm(tx, []);
};

describe('simple-serum', () => {
  const provider = anchor.AnchorProvider.env();

  // Configure the client to use the local cluster.
  anchor.setProvider(provider);

  const program = anchor.workspace.SimpleSerum as anchor.Program<SimpleSerum>;

  const coinMint = anchor.web3.Keypair.generate();
  const pcMint = anchor.web3.Keypair.generate();

  let coinVault: anchor.web3.PublicKey;
  let pcVault: anchor.web3.PublicKey;

  let marketPda: anchor.web3.PublicKey;
  let marketPdaBump: number;

  let reqQPda: anchor.web3.PublicKey;
  let reqQPdaBump: number;

  let eventQPda: anchor.web3.PublicKey;
  let eventQPdaBump: number;

  let openOrdersPda: anchor.web3.PublicKey;
  let openOrdersPdaBump: number;

  const authority = anchor.web3.Keypair.generate();

  let authorityCoinTokenAccount: anchor.web3.PublicKey;
  let authorityPcTokenAccount: anchor.web3.PublicKey;

  before(async () => {
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(
        authority.publicKey,
        10 * anchor.web3.LAMPORTS_PER_SOL,
      ),
    );

    await createMint(provider, coinMint, 18);
    await createMint(provider, pcMint, 6);

    [marketPda, marketPdaBump] = await anchor.web3.PublicKey.findProgramAddress(
      [
        Buffer.from('market', 'utf-8'),
        coinMint.publicKey.toBuffer(),
        pcMint.publicKey.toBuffer(),
      ],
      program.programId,
    );

    [reqQPda, reqQPdaBump] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from('req-q', 'utf-8'), marketPda.toBuffer()],
      program.programId,
    );
    [eventQPda, eventQPdaBump] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from('event-q', 'utf-8'), marketPda.toBuffer()],
      program.programId,
    );

    [openOrdersPda, openOrdersPdaBump] =
      await anchor.web3.PublicKey.findProgramAddress(
        [
          Buffer.from('open-orders', 'utf-8'),
          marketPda.toBuffer(),
          authority.publicKey.toBuffer(),
        ],
        program.programId,
      );

    coinVault = await spl.getAssociatedTokenAddress(
      coinMint.publicKey,
      marketPda,
      true,
    );
    pcVault = await spl.getAssociatedTokenAddress(
      pcMint.publicKey,
      marketPda,
      true,
    );

    authorityCoinTokenAccount = await spl.getAssociatedTokenAddress(
      coinMint.publicKey,
      authority.publicKey,
      false,
    );
    authorityPcTokenAccount = await spl.getAssociatedTokenAddress(
      pcMint.publicKey,
      authority.publicKey,
      false,
    );
    await createAssociatedTokenAccount(
      provider,
      coinMint.publicKey,
      authorityCoinTokenAccount,
      authority.publicKey,
    );
    await createAssociatedTokenAccount(
      provider,
      pcMint.publicKey,
      authorityPcTokenAccount,
      authority.publicKey,
    );

    await mintTo(
      provider,
      coinMint.publicKey,
      authorityCoinTokenAccount,
      BigInt('1000000000000000000'),
    );
    await mintTo(
      provider,
      pcMint.publicKey,
      authorityPcTokenAccount,
      BigInt('1000000000'),
    );
  });

  describe('#initialize_market', async () => {
    it('should initialize market successfully', async () => {
      await program.methods
        .initializeMarket()
        .accounts({
          market: marketPda,
          coinVault,
          pcVault,
          coinMint: coinMint.publicKey,
          pcMint: pcMint.publicKey,
          reqQ: reqQPda,
          eventQ: eventQPda,
          authority: authority.publicKey,
        })
        .signers([authority])
        .rpc();

      const market = await program.account.market.fetch(marketPda);
      assert(market.coinVault.equals(coinVault));
      assert(market.pcVault.equals(pcVault));
      assert(market.coinMint.equals(coinMint.publicKey));
      assert(market.pcMint.equals(pcMint.publicKey));
      assert(market.coinDepositsTotal.eq(new anchor.BN(0)));
      assert(market.pcDepositsTotal.eq(new anchor.BN(0)));
      assert(market.reqQ.equals(reqQPda));
      assert(market.eventQ.equals(eventQPda));
      assert(market.authority.equals(authority.publicKey));
    });
  });

  describe('#new_order', async () => {
    it('should new order successfully', async () => {
      await program.methods
        .newOrder(
          { bid: {} },
          new anchor.BN(100),
          new anchor.BN(0),
          new anchor.BN(100),
          { limit: {} },
        )
        .accounts({
          openOrders: openOrdersPda,
          market: marketPda,
          coinVault,
          pcVault,
          coinMint: coinMint.publicKey,
          pcMint: pcMint.publicKey,
          payer: authorityPcTokenAccount,
          reqQ: reqQPda,
          authority: authority.publicKey,
        })
        .signers([authority])
        .rpc();
    });
  });
});
