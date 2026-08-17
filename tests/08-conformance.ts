import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccount,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import * as fs from "fs";
import {
  CANONICAL_LEN,
  MAX_CANONICAL_LEN,
  arcisPublicKey,
  arcisSign,
  arcisVerify,
  commitmentDigest,
  decodeCommitment,
  deriveMessageDomain,
  encodeCommitment,
  standardEd25519,
} from "./commitment-client";
import {
  CHAIN_ID,
  ensureConfig,
  fund,
  localWallet,
  newMint,
  protocolAuthority,
  protocolFeeRecipient,
  setupProvider,
  seeds,
} from "./shared";

const ONE = 1_000_000;

describe("ryvo_protocol / step 8: conformance and solvency", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;
  const authority = protocolAuthority();
  const configPda = seeds.config(program.programId);
  const wallet = localWallet();

  const vectors = JSON.parse(
    fs.readFileSync("tests/vectors/commitment.json", "utf8"),
  );

  before(async () => {
    await ensureConfig(program, provider, authority, protocolFeeRecipient().publicKey);
  });

  // ---------------------------------------------------------------- conformance

  it("agrees with the Rust implementation on every golden vector", () => {
    expect(vectors.canonicalLen).to.equal(CANONICAL_LEN);
    expect(vectors.maxCanonicalLen).to.equal(MAX_CANONICAL_LEN);

    for (const v of vectors.commitments) {
      const c = {
        messageDomain: Buffer.from(v.messageDomain, "hex"),
        channel: new PublicKey(v.channel),
        targetCumulative: BigInt(v.targetCumulative),
        signerEpoch: v.signerEpoch,
        expiryUnix: BigInt(v.expiryUnix),
      };
      expect(encodeCommitment(c).toString("hex"), `encode mismatch: ${v.name}`).to.equal(v.encoded);
      expect(commitmentDigest(c).toString("hex"), `digest mismatch: ${v.name}`).to.equal(v.digest);
      // Round-trip through the decoder too.
      const back = decodeCommitment(Buffer.from(v.encoded, "hex"));
      expect(back.targetCumulative).to.equal(c.targetCumulative);
      expect(back.signerEpoch).to.equal(c.signerEpoch);
      expect(back.channel.toBase58()).to.equal(c.channel.toBase58());
    }
  });

  it("agrees with Rust on every message domain, and with the on-chain config", async () => {
    for (const md of vectors.messageDomains) {
      expect(
        deriveMessageDomain(program.programId, md.chainId).toString("hex"),
        `domain mismatch for chain ${md.chainId}`,
      ).to.equal(md.domain);
    }
    const cfg = await program.account.config.fetch(configPda);
    expect(Buffer.from(cfg.messageDomain).toString("hex")).to.equal(
      deriveMessageDomain(program.programId, CHAIN_ID).toString("hex"),
    );
  });

  it("keeps the canonical message inside the two-permutation SHA3-512 budget", () => {
    // In-circuit Ed25519 hashes R || A || M through SHA3-512, whose rate is 72 bytes.
    expect(64 + CANONICAL_LEN).to.be.at.most(64 + MAX_CANONICAL_LEN);
    expect(Math.ceil((64 + CANONICAL_LEN) / 72)).to.equal(2);
  });

  it("rejects malformed canonical messages", () => {
    const good = Buffer.from(vectors.commitments[0].encoded, "hex");
    expect(() => decodeCommitment(good.subarray(0, 69))).to.throw();
    expect(() => decodeCommitment(Buffer.concat([good, Buffer.alloc(1)]))).to.throw();
    const badKind = Buffer.from(good);
    badKind[16] = 0x02;
    expect(() => decodeCommitment(badKind)).to.throw();
    const badVersion = Buffer.from(good);
    badVersion[17] = 0x02;
    expect(() => decodeCommitment(badVersion)).to.throw();
  });

  // ------------------------------------------------------------ ArcisEd25519

  it("round-trips an ArcisEd25519 signature over a real commitment digest", () => {
    const seed = standardEd25519.utils.randomSecretKey();
    const pub = arcisPublicKey(seed);
    const digest = commitmentDigest({
      messageDomain: deriveMessageDomain(program.programId, CHAIN_ID),
      channel: seeds.config(program.programId),
      targetCumulative: 12345n,
      signerEpoch: 0,
      expiryUnix: 0n,
    });

    const sig = arcisSign(digest, seed);
    expect(sig.length).to.equal(64);
    expect(arcisVerify(sig, digest, pub)).to.be.true;

    // Tampering with the digest must invalidate it.
    const tampered = Buffer.from(digest);
    tampered[0] ^= 1;
    expect(arcisVerify(sig, tampered, pub)).to.be.false;
  });

  it("REFUSES a standard RFC 8032 signature, and vice versa", () => {
    // The load-bearing negative test. If a future contributor "fixes" the signer back to the
    // standard scheme, this fails instead of silently producing commitments the MPC rejects.
    const seed = standardEd25519.utils.randomSecretKey();
    const digest = commitmentDigest({
      messageDomain: deriveMessageDomain(program.programId, CHAIN_ID),
      channel: seeds.config(program.programId),
      targetCumulative: 1n,
      signerEpoch: 0,
      expiryUnix: 0n,
    });

    const arcisPub = arcisPublicKey(seed);
    const stdPub = standardEd25519.getPublicKey(seed);
    const arcisSig = arcisSign(digest, seed);
    const stdSig = standardEd25519.sign(digest, seed);

    expect(Buffer.from(arcisSig).equals(Buffer.from(stdSig))).to.be.false;
    expect(arcisVerify(stdSig, digest, arcisPub), "arcis accepted an RFC 8032 signature").to.be
      .false;
    expect(
      standardEd25519.verify(arcisSig, digest, stdPub),
      "RFC 8032 accepted an arcis signature",
    ).to.be.false;
  });

  it("documents that one seed yields DIFFERENT pubkeys under the two schemes", () => {
    // Ed25519 derives the secret scalar by hashing the seed, so replacing SHA-512 with SHA3-512
    // changes the derived pubkey as well as the signature. Consequence: a channel's
    // authorized_signer must be the ArcisEd25519-derived pubkey, NOT the agent's wallet address.
    //
    // Whether Arcium's own ArcisEd25519 derives keys the same way, or keeps RFC 8032 key
    // derivation and swaps only the challenge hash, is UNVERIFIED here and must be confirmed
    // against the real MPC before mainnet. It decides whether a wallet pubkey can ever be a
    // valid authorized_signer.
    const seed = standardEd25519.utils.randomSecretKey();
    expect(
      Buffer.from(arcisPublicKey(seed)).equals(
        Buffer.from(standardEd25519.getPublicKey(seed)),
      ),
      "if this ever passes, revisit the authorized_signer guidance",
    ).to.be.false;
  });

  // -------------------------------------------------------- solvency property

  it("preserves solvency across a randomized operation sequence", async () => {
    const mints: PublicKey[] = [await newMint(provider, 6), await newMint(provider, 6)];
    const tokenConfigs = new Map<string, PublicKey>();
    const vaults = new Map<string, PublicKey>();

    for (const m of mints) {
      const tc = seeds.tokenConfig(program.programId, m);
      const v = seeds.vault(program.programId, m);
      tokenConfigs.set(m.toBase58(), tc);
      vaults.set(m.toBase58(), v);
      await program.methods
        .registerToken()
        .accounts({
          authority: authority.publicKey, config: configPda, mint: m, tokenConfig: tc, vault: v,
          tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .signers([authority])
        .rpc();
    }

    interface P { owner: Keypair; participant: PublicKey; balances: Map<string, PublicKey>; atas: Map<string, PublicKey>; }
    const parties: P[] = [];
    for (let i = 0; i < 3; i++) {
      const owner = Keypair.generate();
      await fund(provider, owner.publicKey, 5);
      const participant = seeds.participant(program.programId, owner.publicKey);
      await program.methods
        .initializeParticipant()
        .accounts({ owner: owner.publicKey, participant, systemProgram: SystemProgram.programId })
        .signers([owner]).rpc();
      await program.methods
        .updateInboundChannelPolicy({ permissionless: {} } as never)
        .accounts({ owner: owner.publicKey, participant })
        .signers([owner]).rpc();

      const balances = new Map<string, PublicKey>();
      const atas = new Map<string, PublicKey>();
      for (const m of mints) {
        const bal = seeds.balance(program.programId, participant, m);
        await program.methods
          .openBalance()
          .accounts({
            payer: owner.publicKey, participant, mint: m,
            tokenConfig: tokenConfigs.get(m.toBase58())!, balance: bal,
            systemProgram: SystemProgram.programId,
          })
          .signers([owner]).rpc();
        balances.set(m.toBase58(), bal);

        const ata = await createAssociatedTokenAccount(
          provider.connection, wallet, m, owner.publicKey,
          { commitment: "confirmed" }, TOKEN_PROGRAM_ID,
        );
        await mintTo(
          provider.connection, wallet, m, ata, wallet, 500 * ONE, [],
          { commitment: "confirmed" }, TOKEN_PROGRAM_ID,
        );
        atas.set(m.toBase58(), ata);
      }
      parties.push({ owner, participant, balances, atas });
    }

    // One channel per ordered pair, per mint.
    const channels: { key: PublicKey; from: P; mint: PublicKey }[] = [];
    for (const m of mints) {
      for (let i = 0; i < parties.length; i++) {
        const j = (i + 1) % parties.length;
        const from = parties[i], to = parties[j];
        const key = seeds.channel(program.programId, from.participant, to.participant, m);
        await program.methods
          .createChannel(Keypair.generate().publicKey)
          .accounts({
            payerOwner: from.owner.publicKey,
            payerParticipant: from.participant,
            payeeParticipant: to.participant,
            payeeOwner: null,
            mint: m,
            tokenConfig: tokenConfigs.get(m.toBase58())!,
            payerBalance: from.balances.get(m.toBase58())!,
            payeeBalance: to.balances.get(m.toBase58())!,
            channel: key,
            systemProgram: SystemProgram.programId,
          })
          .signers([from.owner]).rpc();
        channels.push({ key, from, mint: m });
      }
    }

    async function assertSolvent(m: PublicKey) {
      const key = m.toBase58();
      const vaultAcc = await getAccount(provider.connection, vaults.get(key)!, "confirmed", TOKEN_PROGRAM_ID);
      const tc = await program.account.tokenConfig.fetch(tokenConfigs.get(key)!);
      const balances = await program.account.balance.all();
      const chans = await program.account.channel.all();
      const sumAvailable = balances
        .filter((b) => b.account.mint.toBase58() === key)
        .reduce((a, b) => a + BigInt(b.account.available.toString()), 0n);
      const sumLocked = chans
        .filter((c) => c.account.mint.toBase58() === key)
        .reduce((a, c) => a + BigInt(c.account.lockedBalance.toString()), 0n);
      expect(vaultAcc.amount.toString(), `solvency violated for mint ${key}`).to.equal(
        (sumAvailable + sumLocked + BigInt(tc.accruedFees.toString())).toString(),
      );
    }

    // Deterministic pseudo-random so a failure is reproducible.
    let state = 0x2545f491;
    const rand = (n: number) => {
      state = (state * 1103515245 + 12345) & 0x7fffffff;
      return state % n;
    };

    let applied = 0;
    for (let step = 0; step < 40; step++) {
      const p = parties[rand(parties.length)];
      const m = mints[rand(mints.length)];
      const mk = m.toBase58();
      const bal = p.balances.get(mk)!;
      const op = rand(4);

      try {
        if (op === 0) {
          await program.methods
            .deposit(new anchor.BN((1 + rand(20)) * ONE))
            .accounts({
              funder: p.owner.publicKey, mint: m, tokenConfig: tokenConfigs.get(mk)!,
              vault: vaults.get(mk)!, funderTokenAccount: p.atas.get(mk)!,
              participant: p.participant, balance: bal, tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([p.owner]).rpc();
        } else if (op === 1) {
          const ch = channels.filter((c) => c.from === p && c.mint.equals(m))[0];
          if (!ch) continue;
          const b = await program.account.balance.fetch(bal);
          const amt = Number(b.available) > 0 ? 1 + rand(Math.max(1, Math.floor(Number(b.available) / ONE))) : 0;
          if (amt === 0) continue;
          await program.methods
            .lockChannelFunds(new anchor.BN(amt * ONE))
            .accounts({
              payerOwner: p.owner.publicKey, payerParticipant: p.participant, config: configPda,
              channel: ch.key, payerBalance: bal, tokenConfig: tokenConfigs.get(mk)!,
            })
            .signers([p.owner]).rpc();
        } else if (op === 2) {
          const ch = channels.filter((c) => c.from === p && c.mint.equals(m))[0];
          if (!ch) continue;
          const c = await program.account.channel.fetch(ch.key);
          if (Number(c.lockedBalance) === 0) continue;
          await program.methods
            .requestUnlockChannelFunds(new anchor.BN(c.lockedBalance.toString()))
            .accounts({
              payerOwner: p.owner.publicKey, payerParticipant: p.participant, config: configPda,
              channel: ch.key, payerBalance: bal, tokenConfig: tokenConfigs.get(mk)!,
            })
            .signers([p.owner]).rpc();
        } else {
          const b = await program.account.balance.fetch(bal);
          if (Number(b.pendingWithdrawalAmount) > 0) {
            await program.methods
              .cancelWithdrawal()
              .accounts({ owner: p.owner.publicKey, participant: p.participant, balance: bal })
              .signers([p.owner]).rpc();
          } else if (Number(b.available) > 0) {
            await program.methods
              .requestWithdrawal(new anchor.BN(1 + rand(Number(b.available))))
              .accounts({
                owner: p.owner.publicKey, config: configPda, participant: p.participant,
                mint: m, balance: bal, destination: p.atas.get(mk)!, vault: vaults.get(mk)!,
              })
              .signers([p.owner]).rpc();
          } else continue;
        }
        applied++;
      } catch {
        // A rejected operation is a valid outcome; solvency must hold regardless.
      }

      await assertSolvent(m);
    }

    expect(applied, "the driver applied too few operations to be meaningful").to.be.greaterThan(15);
    for (const m of mints) await assertSolvent(m);
  });
});
