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
  deriveArcisSigner,
  deriveMessageDomain,
  encodeCommitment,
  signCommitment,
  standardEd25519,
} from "./commitment-client";
import {
  CHAIN_ID,
  ensureConfig,
  fund,
  localWallet,
  newMint,
  protocolAuthority,
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
    await ensureConfig(program, provider, authority);
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
          expiryUnix: BigInt(v.expiryUnix),
      };
      expect(encodeCommitment(c).toString("hex"), `encode mismatch: ${v.name}`).to.equal(v.encoded);
      expect(commitmentDigest(c).toString("hex"), `digest mismatch: ${v.name}`).to.equal(v.digest);
      // Round-trip through the decoder too.
      const back = decodeCommitment(Buffer.from(v.encoded, "hex"));
      expect(back.targetCumulative).to.equal(c.targetCumulative);
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
    expect(() => decodeCommitment(good.subarray(0, CANONICAL_LEN - 1))).to.throw();
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

  it("proves a Solana wallet pubkey can never be a channel authorized_signer", () => {
    // Verified against @arcium-hq/client itself, not a local model of it. Upstream builds the
    // scheme as twistedEdwards({ ...ed25519, hash: sha3_512 }), and that single hash parameter
    // governs key derivation too: Ed25519 derives its scalar as clamp(hash(seed)[0..32]).
    //
    // So one seed gives an agent two different identities. The wallet address is NOT usable as
    // authorized_signer — which is exactly why create_channel requires the signer explicitly
    // rather than defaulting to the payer's wallet.
    const wallet = Keypair.generate();
    const seed = wallet.secretKey.slice(0, 32); // Solana stores seed || pubkey

    // Sanity: the seed really is the wallet's.
    expect(Buffer.from(standardEd25519.getPublicKey(seed)).toString("hex")).to.equal(
      Buffer.from(wallet.publicKey.toBytes()).toString("hex"),
    );

    const arcisPub = arcisPublicKey(seed);
    expect(
      Buffer.from(arcisPub).equals(Buffer.from(wallet.publicKey.toBytes())),
      "if this ever passes, wallet keys became usable and the guidance should change",
    ).to.be.false;

    // And a signature made with that seed verifies only under the Arcis pubkey.
    const digest = commitmentDigest({
      messageDomain: deriveMessageDomain(program.programId, CHAIN_ID),
      channel: seeds.config(program.programId),
      targetCumulative: 7n,
      expiryUnix: 0n,
    });
    const sig = arcisSign(digest, seed);
    expect(arcisVerify(sig, digest, arcisPub)).to.be.true;
    expect(arcisVerify(sig, digest, wallet.publicKey.toBytes())).to.be.false;
  });

  // ------------------------------------------------------- derived signers

  describe("agent signing key", () => {
    const walletSeed = () => Keypair.generate().secretKey.slice(0, 32);
    const channelA = Keypair.generate().publicKey;
    const channelB = Keypair.generate().publicKey;

    it("is deterministic, so an agent stores one secret and recomputes the key", () => {
      const seed = walletSeed();
      const a = deriveArcisSigner(seed);
      const b = deriveArcisSigner(seed);
      expect(a.seed.toString("hex")).to.equal(b.seed.toString("hex"));
      expect(a.publicKey.toString("hex")).to.equal(b.publicKey.toString("hex"));
    });

    it("is one key per wallet, used on every channel that wallet opens", () => {
      const seed = walletSeed();
      const signer = deriveArcisSigner(seed);
      // The same pubkey is registered as authorized_signer on every channel — nothing about the
      // derivation is channel-specific.
      const commitA = {
        messageDomain: deriveMessageDomain(program.programId, CHAIN_ID),
        channel: channelA,
        targetCumulative: 1n,
        expiryUnix: 0n,
      };
      const commitB = { ...commitA, channel: channelB };

      const a = signCommitment(seed, commitA);
      const b = signCommitment(seed, commitB);
      expect(a.publicKey.toString("hex")).to.equal(signer.publicKey.toString("hex"));
      expect(b.publicKey.toString("hex")).to.equal(signer.publicKey.toString("hex"));
    });

    it("gives a different key per wallet", () => {
      expect(deriveArcisSigner(walletSeed()).publicKey.toString("hex")).to.not.equal(
        deriveArcisSigner(walletSeed()).publicKey.toString("hex"),
      );
    });

    it("never equals the wallet address", () => {
      const wallet = Keypair.generate();
      const signer = deriveArcisSigner(wallet.secretKey.slice(0, 32));
      expect(signer.publicKey.toString("hex")).to.not.equal(
        Buffer.from(wallet.publicKey.toBytes()).toString("hex"),
      );
    });

    it("rejects a wallet seed of the wrong length rather than silently truncating", () => {
      expect(() => deriveArcisSigner(new Uint8Array(64))).to.throw(/32 bytes/);
    });

    it("signs a commitment that is bound to one channel by the message, not the key", () => {
      // One key signs for every channel, so channel binding comes from the channel address
      // inside the signed message. A signature for channel A does not verify over channel B's
      // digest even though the same key produced both.
      const seed = walletSeed();
      const base = {
        messageDomain: deriveMessageDomain(program.programId, CHAIN_ID),
        channel: channelA,
        targetCumulative: 500_000n,
        expiryUnix: 0n,
      };

      const { signature, publicKey, digest } = signCommitment(seed, base);
      expect(arcisVerify(signature, digest, publicKey)).to.be.true;

      const otherDigest = commitmentDigest({ ...base, channel: channelB });
      expect(arcisVerify(signature, otherDigest, publicKey)).to.be.false;
    });
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
      const balances = await program.account.balance.all();
      const chans = await program.account.channel.all();
      const sumAvailable = balances
        .filter((b) => b.account.mint.toBase58() === key)
        .reduce((a, b) => a + BigInt(b.account.available.toString()), 0n);
      const sumLocked = chans
        .filter((c) => c.account.mint.toBase58() === key)
        .reduce((a, c) => a + BigInt(c.account.lockedBalance.toString()), 0n);
      expect(vaultAcc.amount.toString(), `solvency violated for mint ${key}`).to.equal(
        (sumAvailable + sumLocked).toString(),
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
          if (Number(b.available) === 0) continue;
          await program.methods
            .withdraw(new anchor.BN(1 + rand(Number(b.available))))
            .accounts({
              owner: p.owner.publicKey, config: configPda, participant: p.participant,
              mint: m, tokenConfig: tokenConfigs.get(mk)!, vault: vaults.get(mk)!,
              balance: bal, destination: p.atas.get(mk)!, tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([p.owner]).rpc();
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
