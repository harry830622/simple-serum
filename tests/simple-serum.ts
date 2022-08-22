import * as anchor from "@project-serum/anchor";
import { Program } from "@project-serum/anchor";
import { SimpleSerum } from "../target/types/simple_serum";

describe("simple-serum", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.SimpleSerum as Program<SimpleSerum>;

  it("Is initialized!", async () => {
    // Add your test here.
    const tx = await program.methods.initialize().rpc();
    console.log("Your transaction signature", tx);
  });
});
