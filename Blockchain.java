/**
 * Blockchain.java
 *
 * Single-file blockchain implementation in Java.
 * Contains all classes as static nested classes:
 *   - CryptoUtils       (key generation, signing, verification, SHA-256)
 *   - Transaction       (data model + sign)
 *   - Block             (data model + hash computation)
 *   - Blockchain        (chain state, add/verify, replay prevention)
 *   - Node              (two-node simulation + fork sync)
 *   - BlockchainTests   (all 7 required validation tests)
 *
 * Consensus  : Toy Proof-of-Work — SHA-256 hash must start with POW_DIFFICULTY '0' chars.
 * Signatures : RSA-PSS via Java standard crypto (java.security + javax.crypto).
 *
 * Compile:  javac Blockchain.java
 * Run demo: java Blockchain demo
 * Run tests:java Blockchain test
 */

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.*;

public class Blockchain {

    // =========================================================================
    // Entry point
    // =========================================================================

    public static void main(String[] args) {
        String mode = (args.length > 0) ? args[0].toLowerCase() : "demo";
        switch (mode) {
            case "test":
                BlockchainTests.runAll();
                break;
            default:
                runDemo();
        }
    }

    // =========================================================================
    // CryptoUtils  — key generation, RSA-PSS sign/verify, SHA-256
    // =========================================================================

    public static final class CryptoUtils {

        private static final String SIG_ALGORITHM  = "RSASSA-PSS";
        private static final PSSParameterSpec PSS_PARAMS = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

        /** Generate a 2048-bit RSA key pair. */
        public static KeyPair generateKeypair() {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048, new SecureRandom());
                return gen.generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * Derive a 32-char hex address from a public key:
         *   SHA-256( publicKey.getEncoded() ) → first 32 hex chars
         */
        public static String publicKeyToAddress(PublicKey pub) {
            byte[] digest = sha256(pub.getEncoded());
            return bytesToHex(digest).substring(0, 32);
        }

        /** Sign arbitrary bytes with an RSA private key (PSS). Returns hex string. */
        public static String sign(PrivateKey priv, String data) {
            try {
                Signature sig = Signature.getInstance(SIG_ALGORITHM);
                sig.setParameter(PSS_PARAMS);
                sig.initSign(priv);
                sig.update(data.getBytes(StandardCharsets.UTF_8));
                return bytesToHex(sig.sign());
            } catch (Exception e) {
                throw new RuntimeException("Signing failed: " + e.getMessage(), e);
            }
        }

        /** Verify an RSA-PSS signature (hex-encoded) over a UTF-8 string. */
        public static boolean verifySignature(PublicKey pub, String data, String hexSig) {
            try {
                byte[] sigBytes = hexToBytes(hexSig);
                Signature sig = Signature.getInstance(SIG_ALGORITHM);
                sig.setParameter(PSS_PARAMS);
                sig.initVerify(pub);
                sig.update(data.getBytes(StandardCharsets.UTF_8));
                return sig.verify(sigBytes);
            } catch (Exception e) {
                return false;
            }
        }

        /** SHA-256 of raw bytes. */
        public static byte[] sha256(byte[] input) {
            try {
                return MessageDigest.getInstance("SHA-256").digest(input);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        /** SHA-256 of a UTF-8 string, returned as lowercase hex. */
        public static String sha256Hex(String input) {
            return bytesToHex(sha256(input.getBytes(StandardCharsets.UTF_8)));
        }

        // ── hex helpers ──────────────────────────────────────────────────────
        public static String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) sb.append(String.format("%02x", b));
            return sb.toString();
        }

        public static byte[] hexToBytes(String hex) {
            int len = hex.length();
            byte[] out = new byte[len / 2];
            for (int i = 0; i < len; i += 2)
                out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
            return out;
        }
    }

    // =========================================================================
    // Transaction
    // =========================================================================

    public static final class Transaction {

        public String txId;
        public String senderId;
        public String recipientId;
        public double amount;
        public double timestamp;   // Unix epoch seconds (double matches Python)
        public String signature;   // hex RSA-PSS signature; empty before signing

        /**
         * Normal constructor — computes txId automatically.
         * Throws IllegalArgumentException for negative amounts.
         */
        public Transaction(String senderId, String recipientId, double amount) {
            this(senderId, recipientId, amount,
                 System.currentTimeMillis() / 1000.0);
        }

        public Transaction(String senderId, String recipientId,
                           double amount, double timestamp) {
            if (amount < 0) throw new IllegalArgumentException("Amount must be non-negative.");
            this.senderId    = senderId;
            this.recipientId = recipientId;
            this.amount      = amount;
            this.timestamp   = timestamp;
            this.txId        = computeTxId();
            this.signature   = "";
        }

        /** Private copy constructor used for replay test. */
        private Transaction() {}

        /** Recompute txId from fields (matches Python formula). */
        private String computeTxId() {
            // Python format: f"{sender}|{recipient}|{amount}|{timestamp}"
            // Python's float representation for whole numbers like 50.0 → "50.0"
            String raw = senderId + "|" + recipientId + "|"
                       + formatDouble(amount) + "|" + formatDouble(timestamp);
            return CryptoUtils.sha256Hex(raw);
        }

        /** Sign this transaction with the sender's private key. */
        public void sign(PrivateKey priv) {
            this.signature = CryptoUtils.sign(priv, txId);
        }

        /** Serialise to a sorted map (for block hash computation). */
        public Map<String, Object> toMap() {
            // Use LinkedHashMap with keys in sorted order to mirror Python's sort_keys=True
            Map<String, Object> m = new TreeMap<>();
            m.put("amount",       amount);
            m.put("recipient_id", recipientId);
            m.put("sender_id",    senderId);
            m.put("signature",    signature);
            m.put("timestamp",    timestamp);
            m.put("tx_id",        txId);
            return m;
        }

        /** Produce the JSON string exactly as Python's json.dumps(..., sort_keys=True). */
        public String toJsonString() {
            return mapToJson(toMap());
        }

        /** Shallow copy with the same txId (for replay test). */
        public Transaction shallowCopy() {
            Transaction t = new Transaction();
            t.txId        = this.txId;
            t.senderId    = this.senderId;
            t.recipientId = this.recipientId;
            t.amount      = this.amount;
            t.timestamp   = this.timestamp;
            t.signature   = this.signature;
            return t;
        }

        @Override
        public String toString() {
            return String.format("TX[%s→%s amt=%.2f]",
                senderId.substring(0, 8), recipientId.substring(0, 8), amount);
        }
    }

    // =========================================================================
    // Algorithm 1 — Transaction Verification
    // =========================================================================

    /**
     * Algorithm: Transaction Verification
     * ─────────────────────────────────────
     * 1. Check required fields are present and non-empty.
     * 2. Verify amount >= 0.
     * 3. Look up sender's public key in publicKeyStore {address → PublicKey}.
     * 4. Verify RSA-PSS signature over tx.txId bytes.
     * 5. Return true only if all checks pass.
     */
    public static boolean verifyTransaction(Transaction tx,
                                            Map<String, PublicKey> publicKeyStore) {
        // Step 1 — required fields
        if (tx.txId == null || tx.txId.isEmpty()
         || tx.senderId == null || tx.senderId.isEmpty()
         || tx.recipientId == null || tx.recipientId.isEmpty()
         || tx.signature == null || tx.signature.isEmpty()) {
            return false;
        }
        // Step 2 — non-negative amount
        if (tx.amount < 0) return false;

        // Step 3 — sender known
        PublicKey pub = publicKeyStore.get(tx.senderId);
        if (pub == null) return false;

        // Step 4 — signature
        return CryptoUtils.verifySignature(pub, tx.txId, tx.signature);
    }

    // =========================================================================
    // Block
    // =========================================================================

    public static final class Block {

        public static final int    POW_DIFFICULTY = 4;
        public static final String GENESIS_PREV   = "0".repeat(64);

        public int               index;
        public double            timestamp;
        public List<Transaction> transactions;
        public String            prevHash;
        public long              nonce;
        public String            blockHash;

        /** Normal constructor: computes initial hash with nonce=0. */
        public Block(int index, List<Transaction> transactions,
                     String prevHash) {
            this(index, transactions, prevHash,
                 System.currentTimeMillis() / 1000.0, 0L);
        }

        public Block(int index, List<Transaction> transactions,
                     String prevHash, double timestamp, long nonce) {
            this.index        = index;
            this.timestamp    = timestamp;
            this.transactions = transactions;
            this.prevHash     = prevHash;
            this.nonce        = nonce;
            this.blockHash    = computeHash();
        }

        /**
         * Hash computation (exact fields, pipe-separated):
         *   SHA-256( index|timestamp|txs_json|prevHash|nonce )
         *
         * txs_json = JSON array of transaction maps, sorted keys,
         *            matching Python's json.dumps([tx.to_dict()…], sort_keys=True).
         */
        public String computeHash() {
            StringBuilder txsJson = new StringBuilder("[");
            for (int i = 0; i < transactions.size(); i++) {
                if (i > 0) txsJson.append(", ");
                txsJson.append(transactions.get(i).toJsonString());
            }
            txsJson.append("]");

            String raw = index + "|" + formatDouble(timestamp) + "|"
                       + txsJson + "|" + prevHash + "|" + nonce;
            return CryptoUtils.sha256Hex(raw);
        }

        /** Recompute hash from current field values (used during mining + verification). */
        public String recomputeHash() {
            return computeHash();
        }

        @Override
        public String toString() {
            return String.format("Block#%d[hash=%s… nonce=%d txs=%d]",
                index, blockHash.substring(0, 12), nonce, transactions.size());
        }
    }

    // =========================================================================
    // Algorithm 2 — Block Creation (PoW Mining)
    // =========================================================================

    /**
     * Algorithm: Block Creation (PoW Mining)
     * ───────────────────────────────────────
     * 1. Assemble candidate block with nonce = 0.
     * 2. Compute hash.
     * 3. While hash does not start with POW_DIFFICULTY leading zeros:
     *      increment nonce, recompute hash.
     * 4. Store final hash in blockHash.
     * 5. Return block.
     */
    public static Block createBlock(int index, List<Transaction> transactions,
                                    String prevHash) {
        Block block = new Block(index, transactions, prevHash);
        String target = "0".repeat(Block.POW_DIFFICULTY);
        while (!block.blockHash.startsWith(target)) {
            block.nonce++;
            block.blockHash = block.recomputeHash();
        }
        return block;
    }

    // =========================================================================
    // Algorithm 3 — Block Verification
    // =========================================================================

    /**
     * Algorithm: Block Verification
     * ──────────────────────────────
     * 1. Recompute block's hash; confirm it matches stored blockHash.
     * 2. Confirm hash satisfies PoW (starts with POW_DIFFICULTY zeros).
     * 3. Verify prevHash links correctly to prevBlock.blockHash
     *    (skip for genesis block where prevBlock is null).
     * 4. For each transaction in block: run verifyTransaction.
     * 5. Return true only if all checks pass.
     */
    public static boolean verifyBlock(Block block, Block prevBlock,
                                      Map<String, PublicKey> publicKeyStore) {
        // Step 1 — hash integrity
        if (!block.recomputeHash().equals(block.blockHash)) return false;

        // Step 2 — PoW
        if (!block.blockHash.startsWith("0".repeat(Block.POW_DIFFICULTY))) return false;

        // Step 3 — chain link
        if (prevBlock == null) {
            // Genesis: prevHash must be all zeros
            if (!block.prevHash.equals(Block.GENESIS_PREV)) return false;
        } else {
            if (!block.prevHash.equals(prevBlock.blockHash)) return false;
        }

        // Step 4 — transactions
        for (Transaction tx : block.transactions) {
            if (!verifyTransaction(tx, publicKeyStore)) return false;
        }
        return true;
    }

    // =========================================================================
    // Blockchain class  (Algorithm 4 — Chain Verification)
    // =========================================================================

    public static final class BlockchainChain {

        public final List<Block>             chain          = new ArrayList<>();
        public final Map<String, PublicKey>  publicKeyStore = new HashMap<>();
        public final Set<String>             seenTxIds      = new HashSet<>();

        public BlockchainChain() {
            createGenesis();
        }

        private void createGenesis() {
            // Genesis: index=0, no transactions, prevHash="000…0", timestamp=0, nonce=0
            Block genesis = new Block(0, new ArrayList<>(), Block.GENESIS_PREV, 0.0, 0L);
            chain.add(genesis);
        }

        public void registerUser(String address, PublicKey pub) {
            publicKeyStore.put(address, pub);
        }

        /**
         * Append a pre-mined block after full verification.
         * Also checks for duplicate tx IDs (replay/double-spend prevention).
         */
        public boolean addBlock(Block block) {
            Block prev = chain.get(chain.size() - 1);
            if (!verifyBlock(block, prev, publicKeyStore)) return false;

            // Double-spend check
            for (Transaction tx : block.transactions) {
                if (seenTxIds.contains(tx.txId)) return false;
            }
            // Commit
            for (Transaction tx : block.transactions) seenTxIds.add(tx.txId);
            chain.add(block);
            return true;
        }

        /**
         * Algorithm: Chain Verification
         * ──────────────────────────────
         * 1. Check genesis block exists and has prevHash = "0"*64.
         * 2. For i = 1 to chain.size()-1:
         *      verifyBlock(chain[i], chain[i-1], publicKeyStore)
         * 3. Return true only if every block passes.
         */
        public boolean verifyChain() {
            if (chain.isEmpty()) return false;
            // Genesis check
            if (!chain.get(0).prevHash.equals(Block.GENESIS_PREV)) return false;
            // Remaining blocks
            for (int i = 1; i < chain.size(); i++) {
                if (!verifyBlock(chain.get(i), chain.get(i - 1), publicKeyStore))
                    return false;
            }
            return true;
        }

        public double getBalance(String address) {
            double balance = 0.0;
            for (Block b : chain) {
                for (Transaction tx : b.transactions) {
                    if (tx.recipientId.equals(address)) balance += tx.amount;
                    if (tx.senderId.equals(address))    balance -= tx.amount;
                }
            }
            return balance;
        }

        public int size() { return chain.size(); }

        public Block tip() { return chain.get(chain.size() - 1); }
    }

    // =========================================================================
    // Algorithm 5 — Fork Resolution (Longest Valid Chain)
    // =========================================================================

    /**
     * Algorithm: Fork Resolution (Longest Valid Chain)
     * ─────────────────────────────────────────────────
     * 1. Verify chainA; record length if valid.
     * 2. Verify chainB; record length if valid.
     * 3. Return the longer valid chain.
     *    If lengths are equal, prefer chainA (tie-break: first seen).
     *    If a chain is invalid, reject it regardless of length.
     */
    public static BlockchainChain resolveFork(BlockchainChain chainA,
                                              BlockchainChain chainB) {
        boolean aValid = chainA.verifyChain();
        boolean bValid = chainB.verifyChain();

        if (aValid && bValid)
            return (chainA.size() >= chainB.size()) ? chainA : chainB;
        if (aValid) return chainA;
        if (bValid) return chainB;
        throw new IllegalStateException("Both chains are invalid — cannot resolve fork.");
    }

    // =========================================================================
    // Node  — two-node simulation
    // =========================================================================

    public static final class Node {

        public final String name;
        public BlockchainChain blockchain;

        public Node(String name) {
            this.name       = name;
            this.blockchain = new BlockchainChain();
        }

        public void registerUser(String address, PublicKey pub) {
            blockchain.registerUser(address, pub);
        }

        public boolean submitBlock(Block block) {
            boolean ok = blockchain.addBlock(block);
            System.out.printf("[%s] Block #%d %s  hash=%s…%n",
                name, block.index, ok ? "ACCEPTED" : "REJECTED",
                block.blockHash.substring(0, 12));
            return ok;
        }

        /**
         * Receive peer's chain and apply fork resolution.
         * Whichever chain is longer (and valid) wins.
         */
        public void syncWith(Node peer) {
            System.out.printf("%n[%s] Syncing with %s…%n", name, peer.name);
            System.out.printf("  Local  chain length: %d%n", blockchain.size());
            System.out.printf("  Remote chain length: %d%n", peer.blockchain.size());

            BlockchainChain winner = resolveFork(this.blockchain, peer.blockchain);
            if (winner == this.blockchain) {
                System.out.printf("  → [%s] kept its own chain (length %d).%n",
                    name, blockchain.size());
            } else {
                this.blockchain = peer.blockchain;
                System.out.printf("  → [%s] adopted %s's chain (length %d).%n",
                    name, peer.name, blockchain.size());
            }
        }

        public void printChain() {
            System.out.println("\n" + "═".repeat(60));
            System.out.printf("  Node: %s  |  Chain length: %d%n", name, blockchain.size());
            System.out.println("═".repeat(60));
            for (Block b : blockchain.chain) {
                System.out.printf("  Block #%d%n", b.index);
                System.out.printf("    hash     : %s…%n", b.blockHash.substring(0, 20));
                System.out.printf("    prev_hash: %s…%n", b.prevHash.substring(0, 20));
                System.out.printf("    nonce    : %d%n", b.nonce);
                System.out.printf("    txs      : %d%n", b.transactions.size());
                for (Transaction tx : b.transactions) {
                    System.out.printf("      %s… → %s…  amt=%.2f%n",
                        tx.senderId.substring(0, 8),
                        tx.recipientId.substring(0, 8),
                        tx.amount);
                }
            }
            System.out.println("═".repeat(60));
        }
    }

    // =========================================================================
    // All 7 Validation Tests
    // =========================================================================

    public static final class BlockchainTests {

        private static int passed = 0;
        private static int failed = 0;

        // Shared identities
        static KeyPair aliceKP, bobKP, carolKP;
        static String  aliceAddr, bobAddr, carolAddr;
        static Map<String, PublicKey> pubStore;

        static {
            aliceKP = CryptoUtils.generateKeypair();
            bobKP   = CryptoUtils.generateKeypair();
            carolKP = CryptoUtils.generateKeypair();

            aliceAddr = CryptoUtils.publicKeyToAddress(aliceKP.getPublic());
            bobAddr   = CryptoUtils.publicKeyToAddress(bobKP.getPublic());
            carolAddr = CryptoUtils.publicKeyToAddress(carolKP.getPublic());

            pubStore = new HashMap<>();
            pubStore.put(aliceAddr, aliceKP.getPublic());
            pubStore.put(bobAddr,   bobKP.getPublic());
            pubStore.put(carolAddr, carolKP.getPublic());
        }

        // ── helpers ──────────────────────────────────────────────────────────

        static BlockchainChain makeFreshChain() {
            BlockchainChain bc = new BlockchainChain();
            pubStore.forEach(bc::registerUser);
            return bc;
        }

        static Transaction makeSignedTx(String senderAddr, PrivateKey priv,
                                        String recipientAddr, double amount) {
            Transaction tx = new Transaction(senderAddr, recipientAddr, amount);
            tx.sign(priv);
            return tx;
        }

        static Block mineAndAppend(BlockchainChain bc, List<Transaction> txs) {
            String prevHash = bc.tip().blockHash;
            int    index    = bc.size();
            Block  block    = createBlock(index, txs, prevHash);
            boolean ok = bc.addBlock(block);
            if (!ok) throw new AssertionError("Failed to append mined block");
            return block;
        }

        static void header(int n, String name) {
            System.out.println("\n" + "─".repeat(60));
            System.out.printf("  TEST %d: %s%n", n, name);
            System.out.println("─".repeat(60));
        }

        static void result(boolean passed, String description) {
            String tag = passed ? "✅ PASS" : "❌ FAIL";
            System.out.printf("  %s  %s%n", tag, description);
            if (passed) BlockchainTests.passed++;
            else        BlockchainTests.failed++;
        }

        // ════════════════════════════════════════════════════════════════════
        // TEST 1: Valid chain passes verification
        // ════════════════════════════════════════════════════════════════════
        static void test1() {
            header(1, "Valid chain passes verification");

            BlockchainChain bc = makeFreshChain();
            Transaction tx = makeSignedTx(aliceAddr, aliceKP.getPrivate(), bobAddr, 30.0);
            mineAndAppend(bc, List.of(tx));

            boolean valid = bc.verifyChain();
            result(valid, "verifyChain() returned " + valid + " for a properly built 2-block chain");
            System.out.println("  Chain length: " + bc.size());
        }

        // ════════════════════════════════════════════════════════════════════
        // TEST 2: Tampering is detected
        // ════════════════════════════════════════════════════════════════════
        static void test2() {
            header(2, "Tampering is detected (modify transaction amount in old block)");

            BlockchainChain bc = makeFreshChain();
            mineAndAppend(bc, List.of(makeSignedTx(aliceAddr, aliceKP.getPrivate(), bobAddr, 10.0)));
            mineAndAppend(bc, List.of(makeSignedTx(bobAddr, bobKP.getPrivate(), carolAddr, 5.0)));

            System.out.println("  Chain valid before tampering: " + bc.verifyChain());

            // Tamper: mutate amount in block 1's first transaction
            bc.chain.get(1).transactions.get(0).amount = 9999.0;

            boolean tamperDetected = !bc.verifyChain();
            result(tamperDetected, "Tampered chain flagged as invalid: " + !bc.verifyChain());
        }

        // ════════════════════════════════════════════════════════════════════
        // TEST 3: Forged / invalid signature is rejected
        // ════════════════════════════════════════════════════════════════════
        static void test3() {
            header(3, "Forged / invalid signature is rejected");

            // Case A: no signature
            Transaction txUnsigned = new Transaction(aliceAddr, bobAddr, 5.0);
            // intentionally not signing
            boolean unsignedOk = verifyTransaction(txUnsigned, pubStore);
            result(!unsignedOk, "Unsigned tx rejected: " + !unsignedOk);

            // Case B: signed by wrong key (Carol signs as Alice)
            Transaction txForged = new Transaction(aliceAddr, bobAddr, 5.0);
            txForged.sign(carolKP.getPrivate());   // wrong key!
            boolean forgedOk = verifyTransaction(txForged, pubStore);
            result(!forgedOk, "Forged-signature tx rejected: " + !forgedOk);

            // Case C: valid signature accepted
            Transaction txGood = new Transaction(aliceAddr, bobAddr, 5.0);
            txGood.sign(aliceKP.getPrivate());
            boolean goodOk = verifyTransaction(txGood, pubStore);
            result(goodOk, "Legitimately signed tx accepted: " + goodOk);
        }

        // ════════════════════════════════════════════════════════════════════
        // TEST 4: Broken prev-hash link is rejected
        // ════════════════════════════════════════════════════════════════════
        static void test4() {
            header(4, "Broken prev-hash link is rejected");

            BlockchainChain bc = makeFreshChain();
            Transaction tx = makeSignedTx(aliceAddr, aliceKP.getPrivate(), carolAddr, 8.0);

            // Craft a block with wrong prevHash but valid PoW
            String badPrev = "deadbeef".repeat(8);   // 64 hex chars, wrong
            Block badBlock = new Block(1, List.of(tx), badPrev);
            String target = "0".repeat(Block.POW_DIFFICULTY);
            while (!badBlock.blockHash.startsWith(target)) {
                badBlock.nonce++;
                badBlock.blockHash = badBlock.recomputeHash();
            }

            boolean accepted = bc.addBlock(badBlock);
            result(!accepted, "Block with wrong prevHash was rejected: " + !accepted);
        }

        // ════════════════════════════════════════════════════════════════════
        // TEST 5: Fork scenario — longest valid chain wins
        // ════════════════════════════════════════════════════════════════════
        static void test5() {
            header(5, "Fork scenario — longest valid chain wins");

            Node nodeA = new Node("NodeA");
            Node nodeB = new Node("NodeB");
            pubStore.forEach(nodeA::registerUser);
            pubStore.forEach(nodeB::registerUser);

            // Shared block 1
            Transaction tx5a = makeSignedTx(aliceAddr, aliceKP.getPrivate(), bobAddr, 15.0);
            Block b1 = createBlock(1, List.of(tx5a), nodeA.blockchain.tip().blockHash);
            nodeA.submitBlock(b1);
            nodeB.submitBlock(b1);

            // Both diverge at block 2
            Block b2a = createBlock(2,
                List.of(makeSignedTx(bobAddr, bobKP.getPrivate(), carolAddr, 3.0)),
                b1.blockHash);
            nodeA.submitBlock(b2a);

            Block b2b = createBlock(2,
                List.of(makeSignedTx(carolAddr, carolKP.getPrivate(), aliceAddr, 1.0)),
                b1.blockHash);
            nodeB.submitBlock(b2b);

            // Node A mines one extra block → longer
            Block b3a = createBlock(3,
                List.of(makeSignedTx(aliceAddr, aliceKP.getPrivate(), carolAddr, 2.0)),
                b2a.blockHash);
            nodeA.submitBlock(b3a);

            int lenBefore = nodeB.blockchain.size();
            nodeB.syncWith(nodeA);
            int lenAfter = nodeB.blockchain.size();

            boolean adoptedLonger = (lenAfter == nodeA.blockchain.size() && lenAfter > lenBefore);
            result(adoptedLonger, "Node B adopted longer chain: " + lenBefore + " → " + lenAfter + " blocks");
        }

        // ════════════════════════════════════════════════════════════════════
        // TEST 6: Replay / double-spend attempt
        // ════════════════════════════════════════════════════════════════════
        static void test6() {
            header(6, "Replay / double-spend attempt");

            BlockchainChain bc = makeFreshChain();
            Transaction tx6 = makeSignedTx(aliceAddr, aliceKP.getPrivate(), bobAddr, 25.0);
            mineAndAppend(bc, List.of(tx6));

            // Replay: same txId
            Transaction replay = tx6.shallowCopy();
            Block replayBlock = createBlock(bc.size(), List.of(replay), bc.tip().blockHash);
            boolean accepted = bc.addBlock(replayBlock);

            result(!accepted, "Replay tx (duplicate txId) was rejected: " + !accepted);
        }

        // ════════════════════════════════════════════════════════════════════
        // TEST 7: Two-node simulation — independent mining then sync
        // ════════════════════════════════════════════════════════════════════
        static void test7() {
            header(7, "Two-node simulation — independent mining then sync");

            Node nodeX = new Node("NodeX");
            Node nodeY = new Node("NodeY");
            pubStore.forEach(nodeX::registerUser);
            pubStore.forEach(nodeY::registerUser);

            // Node X mines 3 blocks
            Block bx1 = createBlock(1,
                List.of(makeSignedTx(aliceAddr, aliceKP.getPrivate(), bobAddr, 10.0)),
                nodeX.blockchain.tip().blockHash);
            nodeX.submitBlock(bx1);

            Block bx2 = createBlock(2,
                List.of(makeSignedTx(bobAddr, bobKP.getPrivate(), carolAddr, 4.0)),
                bx1.blockHash);
            nodeX.submitBlock(bx2);

            Block bx3 = createBlock(3,
                List.of(makeSignedTx(carolAddr, carolKP.getPrivate(), aliceAddr, 1.0)),
                bx2.blockHash);
            nodeX.submitBlock(bx3);

            // Node Y mines only 2 blocks independently
            Block by1 = createBlock(1,
                List.of(makeSignedTx(aliceAddr, aliceKP.getPrivate(), carolAddr, 7.0)),
                nodeY.blockchain.tip().blockHash);
            nodeY.submitBlock(by1);

            Block by2 = createBlock(2,
                List.of(makeSignedTx(carolAddr, carolKP.getPrivate(), bobAddr, 2.0)),
                by1.blockHash);
            nodeY.submitBlock(by2);

            System.out.printf("  Before sync — NodeX: %d blocks, NodeY: %d blocks%n",
                nodeX.blockchain.size(), nodeY.blockchain.size());

            nodeY.syncWith(nodeX);

            boolean tipsMatch = nodeY.blockchain.tip().blockHash
                                    .equals(nodeX.blockchain.tip().blockHash);
            result(tipsMatch, "Node Y synced to Node X's chain (hashes match at tip)");
            result(nodeY.blockchain.verifyChain(), "Synced chain is valid");
        }

        // ════════════════════════════════════════════════════════════════════
        // Run all
        // ════════════════════════════════════════════════════════════════════
        public static void runAll() {
            System.out.println("\nGenerating RSA key pairs for Alice, Bob, Carol…");
            System.out.printf("  Alice : %s%n", aliceAddr);
            System.out.printf("  Bob   : %s%n", bobAddr);
            System.out.printf("  Carol : %s%n", carolAddr);

            test1();
            test2();
            test3();
            test4();
            test5();
            test6();
            test7();

            System.out.println("\n" + "═".repeat(60));
            System.out.printf("  Tests complete: %d passed, %d failed.%n", passed, failed);
            System.out.println("═".repeat(60));
        }
    }

    // =========================================================================
    // Demo (run with: java Blockchain demo)
    // =========================================================================

    private static void runDemo() {
        System.out.println("\n" + "═".repeat(60));
        System.out.println("  BLOCKCHAIN DEMO");
        System.out.println("═".repeat(60));

        // 1. Generate identities
        System.out.println("\n[1] Generating identities…");
        KeyPair aliceKP = CryptoUtils.generateKeypair();
        KeyPair bobKP   = CryptoUtils.generateKeypair();
        KeyPair carolKP = CryptoUtils.generateKeypair();
        String aliceAddr = CryptoUtils.publicKeyToAddress(aliceKP.getPublic());
        String bobAddr   = CryptoUtils.publicKeyToAddress(bobKP.getPublic());
        String carolAddr = CryptoUtils.publicKeyToAddress(carolKP.getPublic());
        System.out.println("  Alice : " + aliceAddr);
        System.out.println("  Bob   : " + bobAddr);
        System.out.println("  Carol : " + carolAddr);

        Map<String, PublicKey> pubStore = new HashMap<>();
        pubStore.put(aliceAddr, aliceKP.getPublic());
        pubStore.put(bobAddr,   bobKP.getPublic());
        pubStore.put(carolAddr, carolKP.getPublic());

        // 2. Node A mines block 1
        System.out.println("\n[2] Node A — mining Block #1 (PoW difficulty=4)…");
        Node nodeA = new Node("NodeA");
        pubStore.forEach(nodeA::registerUser);

        Transaction tx1 = new Transaction(aliceAddr, bobAddr, 50.0);
        tx1.sign(aliceKP.getPrivate());
        Transaction tx2 = new Transaction(bobAddr, carolAddr, 20.0);
        tx2.sign(bobKP.getPrivate());

        long t = System.currentTimeMillis();
        Block block1 = createBlock(1, List.of(tx1, tx2), nodeA.blockchain.tip().blockHash);
        System.out.printf("  Done in %.2fs  nonce=%d%n",
            (System.currentTimeMillis() - t) / 1000.0, block1.nonce);
        nodeA.submitBlock(block1);

        // 3. Node A mines block 2
        System.out.println("\n  Mining Block #2…");
        Transaction tx3 = new Transaction(carolAddr, aliceAddr, 5.0);
        tx3.sign(carolKP.getPrivate());
        t = System.currentTimeMillis();
        Block block2 = createBlock(2, List.of(tx3), block1.blockHash);
        System.out.printf("  Done in %.2fs  nonce=%d%n",
            (System.currentTimeMillis() - t) / 1000.0, block2.nonce);
        nodeA.submitBlock(block2);

        nodeA.printChain();

        // 4. Fork scenario
        System.out.println("\n[3] Node B — fork scenario (diverges after block #1)");
        Node nodeB = new Node("NodeB");
        pubStore.forEach(nodeB::registerUser);
        nodeB.submitBlock(block1);   // shared

        Transaction tx4 = new Transaction(aliceAddr, carolAddr, 10.0);
        tx4.sign(aliceKP.getPrivate());
        System.out.println("  Mining NodeB block 2 (fork)…");
        t = System.currentTimeMillis();
        Block block2b = createBlock(2, List.of(tx4), block1.blockHash);
        System.out.printf("  Done in %.2fs  nonce=%d%n",
            (System.currentTimeMillis() - t) / 1000.0, block2b.nonce);
        nodeB.submitBlock(block2b);

        // Node A mines one more → longer
        Transaction tx5 = new Transaction(bobAddr, aliceAddr, 2.0);
        tx5.sign(bobKP.getPrivate());
        System.out.println("  Node A mining block 3 to break tie…");
        Block block3a = createBlock(3, List.of(tx5), block2.blockHash);
        nodeA.submitBlock(block3a);

        nodeB.syncWith(nodeA);

        // 5. Validate & balances
        System.out.println("\n[4] Chain validation");
        System.out.println("  Node A chain valid: " + nodeA.blockchain.verifyChain());

        System.out.println("\n[5] Account balances (Node A canonical chain)");
        for (String[] p : new String[][]{{"Alice", aliceAddr}, {"Bob", bobAddr}, {"Carol", carolAddr}}) {
            System.out.printf("  %-6s: %.2f%n", p[0], nodeA.blockchain.getBalance(p[1]));
        }

        System.out.println("\n✓ Demo complete.\n");
    }

    // =========================================================================
    // JSON / double formatting helpers
    // =========================================================================

    /**
     * Format a double the same way Python does for these values
     * (e.g., 50.0 → "50.0", not "50" or "5.0E1").
     * Python's repr/str of a float always includes a decimal point.
     */
    static String formatDouble(double v) {
        // If the value is a whole number, force one decimal place
        if (v == Math.floor(v) && !Double.isInfinite(v)) {
            return String.format("%.1f", v);
        }
        // Otherwise use Java's default toString which matches Python closely
        // for values like timestamps (e.g. 1.7349E9 → "1734900000.123")
        return Double.toString(v);
    }

    /**
     * Minimal JSON serialiser that produces output equivalent to Python's
     * json.dumps(dict, sort_keys=True) for the flat maps used in Transaction.toMap().
     *
     * Rules:
     *   - Keys are sorted (TreeMap guarantees this).
     *   - String values are double-quoted.
     *   - Numeric values use formatDouble() for doubles.
     *   - No trailing spaces after colons/commas (Python default separators are ", " and ": ").
     *
     * Python's default json.dumps uses ", " between items and ": " between key/value.
     */
    @SuppressWarnings("unchecked")
    static String mapToJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(", ");
            first = false;
            sb.append('"').append(e.getKey()).append("\": ");
            Object v = e.getValue();
            if (v instanceof String) {
                sb.append('"').append(v).append('"');
            } else if (v instanceof Double) {
                sb.append(formatDouble((Double) v));
            } else if (v instanceof Map) {
                sb.append(mapToJson((Map<String, Object>) v));
            } else {
                sb.append(v);
            }
        }
        sb.append('}');
        return sb.toString();
    }
}