"""The Crypto book: a Bitcoin curriculum, written here rather than borrowed.

WHERE THIS CAME FROM, AND WHERE IT DID NOT
------------------------------------------
This was requested as "lessons based on learnmeabitcoin.com". That site is Greg
Walker's writing, it is copyrighted, and it refuses automated fetches — so none
of its text is here. What IS shared with it is the subject: the topics below are
Bitcoin's own structure, taken from the protocol, the BIPs and the reference
implementation, which are specifications rather than prose. Every chapter links
out to learnmeabitcoin.com as the companion reference, because it is the best
explanation of this material on the web and somebody learning from these pages
should be reading it too.

FORMAT
------
`body` is plain text, not HTML. Blank lines separate paragraphs, "- " starts a
list item, and a line indented four spaces is a code block; see
services/school.py for the twenty lines that render it. Writing HTML here would
have made fifty chapters unreadable in the file that holds them, and the point
of keeping the curriculum in source is that it can be read and corrected in a
diff.

`checks` are the questions at the end of a chapter. They are not scored and not
stored — they are there so a reader can catch themselves skimming, which is the
failure mode of every written course.
"""

REFERENCE = "https://learnmeabitcoin.com"

BOOK = {
    "slug": "crypto",
    "title": "Crypto",
    "reference": REFERENCE,
    "reference_name": "learnmeabitcoin.com",
    "provenance": (
        "Written for this site from the Bitcoin protocol and the BIPs. For a "
        "deeper treatment of the same ground, with interactive diagrams "
        "throughout, read:"
    ),
    "subtitle": "How Bitcoin actually works, from the hash function up.",
    "blurb": (
        "A book, in nine parts. It starts with the problem Bitcoin exists to "
        "solve and ends with reading a raw transaction by hand. Nothing here "
        "asks you to take a step on faith: every claim is something you can "
        "check with the tools in the arcade."
    ),
    "parts": [
        # ------------------------------------------------------------ part 1
        {
            "title": "The problem",
            "blurb": "What Bitcoin is for, before any of the machinery.",
            "chapters": [
                {
                    "slug": "double-spending",
                    "title": "The double-spend problem",
                    "summary": "Why digital money is hard and physical money is not.",
                    "body": """
A digital coin is a number. Numbers copy perfectly and for free, which is
wonderful for music and catastrophic for money: if I can send you a coin by
sending you a copy of it, I still have mine.

Every payment system before Bitcoin solved this the same way — with a referee. A
bank keeps the ledger. When you pay someone, the bank decreases one row and
increases another. The copy problem disappears because nobody is sending
anything; the bank is just editing its own list.

That works, and it costs you three things:

- The referee can refuse. Accounts get frozen, payments get declined, and the
  reason is often not given.
- The referee can be compelled. A court, a government, or an attacker who
  controls the referee controls the ledger.
- The referee must be trusted to keep an honest list. You cannot check it.

Bitcoin's question is narrow and specific: can you stop double-spending WITHOUT
a referee? Not "can you make money digital" — that was solved decades earlier.
Can a group of strangers who do not trust each other agree on one ledger?

The answer turns out to be yes, at a price: the ledger has to be public, it has
to be expensive to rewrite, and everyone has to keep a copy. Almost everything
strange about Bitcoin follows from paying that price.
""",
                    "checks": [
                        "Why can't you fix double-spending by making the coin file harder to copy?",
                        "What exactly does a bank do that stops a double-spend?",
                    ],
                },
                {
                    "slug": "ledger-everyone-keeps",
                    "title": "A ledger everyone keeps",
                    "summary": "Replacing one trusted list with thousands of identical ones.",
                    "body": """
Bitcoin's ledger is a list of every transaction that has ever happened, and
thousands of computers each hold the whole thing. There is no master copy. If
your copy disagrees with everyone else's, yours is the one that is wrong, and
you find out immediately.

This inverts where trust sits. You do not trust a bank's balance because a bank
told you. You verify the chain yourself, from the first block to the last, and
arrive at balances nobody had to assert.

Two consequences fall straight out, and they are the two things people find
hardest about Bitcoin:

- Everything is public. Every amount, every address, forever. Privacy in Bitcoin
  is something you construct, not something you are given.
- Nothing can be undone. There is no chargeback, because there is nobody to
  appeal to. A payment to the wrong address is gone.

Neither of these is a bug being worked on. They are the shape of the trade: the
referee you removed was also the entity that could reverse things and keep
secrets.
""",
                    "checks": [
                        "If there is no master copy, how do you know which chain is the real one?",
                        "Name something a bank does for you that Bitcoin structurally cannot.",
                    ],
                },
                {
                    "slug": "what-decentralised-costs",
                    "title": "What decentralisation costs",
                    "summary": "The bill for removing the referee, itemised.",
                    "body": """
It is worth being blunt about the costs, because most introductions are not.

Storage and bandwidth. Every full node holds the entire history — hundreds of
gigabytes — and relays every transaction to its peers. The system is
deliberately, structurally wasteful: the same data is verified thousands of
times over.

Throughput. Bitcoin settles a few transactions per second. Not a few thousand —
a few. This is not an oversight awaiting optimisation; blocks are capped so that
ordinary people can still afford to verify the chain, and that cap is what keeps
the referee out.

Energy. Making the ledger expensive to rewrite means making it expensive to
write. That expense is electricity, and it is the point rather than a side
effect: it is what an attacker must outspend.

Finality is probabilistic. A transaction is not "confirmed" in a binary sense.
It becomes progressively harder to reverse as blocks pile on top of it. You
choose how many blocks is enough for the amount at stake.

If you do not need to remove the referee, a database is faster, cheaper and
greener. Bitcoin is only worth its costs if the referee is the problem.
""",
                    "checks": [
                        "Why is the block size limit a political choice rather than a technical one?",
                        "What does the energy expenditure actually buy?",
                    ],
                },
            ],
        },
        # ------------------------------------------------------------ part 2
        {
            "title": "The cryptography",
            "blurb": "Four tools. Everything else is built out of them.",
            "chapters": [
                {
                    "slug": "hash-functions",
                    "title": "Hash functions",
                    "summary": "SHA-256: the one-way fingerprint everything is built on.",
                    "body": """
A hash function takes any amount of data and returns a fixed-size fingerprint.
Bitcoin uses SHA-256, which returns 32 bytes — 64 hexadecimal characters — no
matter whether you feed it one byte or a gigabyte.

Four properties matter, and Bitcoin leans on all four:

- Deterministic. The same input always gives the same output. Anyone, anywhere,
  can recompute your hash and get your answer.
- One-way. Given a hash, you cannot work backwards to the input. The only
  approach is guessing.
- Avalanche. Change one bit of the input and roughly half the output bits flip.
  There is no partial similarity — a near-miss looks like an unrelated hash.
- Collision-resistant. Finding two inputs with the same hash is infeasible.

The avalanche property is what makes hashes useful as commitments: you can
publish a hash today and reveal the data later, and nobody can find different
data matching it. And the one-way property is what makes mining work — the only
way to find an input whose hash starts with a run of zeros is to try inputs
until one does.

Try it in the arcade's hash tool. Change a single character of the input and
watch the entire output change.
""",
                    "checks": [
                        "Why can't you reverse a hash by hashing every possible input?",
                        "What would break if SHA-256 were not collision-resistant?",
                    ],
                },
                {
                    "slug": "double-hashing",
                    "title": "Double hashing and HASH160",
                    "summary": "Why Bitcoin hashes twice, and what HASH160 is for.",
                    "body": """
Bitcoin almost never hashes once. Two combinations appear everywhere:

    HASH256(x) = SHA-256(SHA-256(x))
    HASH160(x) = RIPEMD-160(SHA-256(x))

HASH256 is used for transaction IDs, block hashes and merkle trees. The second
pass defends against length-extension: with a plain SHA-256, someone who knows
`SHA256(m)` and the length of `m` can compute `SHA256(m || padding || extra)`
without knowing `m`. Hashing the digest again destroys that structure. Bitcoin
does not obviously need the protection everywhere it uses it — this is partly
belt-and-braces from 2009 — but it is now consensus and cannot change.

HASH160 is used for addresses. It squeezes a public key down to 20 bytes instead
of 32, which makes addresses shorter. The two different functions are also a
hedge: a break in one does not immediately expose the other.

Note the asymmetry. A 20-byte hash offers 160 bits of preimage resistance and
only 80 bits of collision resistance, which is why modern output types (P2WSH,
Taproot) went back to 32-byte hashes for anything where a collision would matter.
""",
                    "checks": [
                        "What is a length-extension attack, in one sentence?",
                        "Why is 20 bytes fine for a P2PKH address but not for P2WSH?",
                    ],
                },
                {
                    "slug": "elliptic-curves",
                    "title": "Elliptic curve keys",
                    "summary": "secp256k1: turning a random number into a public identity.",
                    "body": """
A Bitcoin private key is a random 256-bit number. Nothing more. Its public key
is derived by elliptic curve multiplication on a specific curve called
secp256k1:

    y² = x³ + 7   (over a finite field)

The curve has a fixed starting point G, the generator. Your public key is:

    K = k × G

where k is your private key. That multiplication is repeated point addition, and
it is easy to do forwards and — as far as anyone knows — infeasible to undo.
Recovering k from K means solving the discrete logarithm problem, and nobody
can.

This asymmetry is the whole basis of ownership in Bitcoin. Your public key can
be shouted from a rooftop; your private key is the only thing that can produce
signatures matching it.

A caution about "random": k must come from a cryptographically secure source. A
private key derived from a passphrase, a dice roll you thought was fair, or a
broken random number generator is a key somebody else can also derive. Wallets
have been emptied this way, repeatedly, and there is no recovery.

Valid keys are 1 to n-1 where n is the curve order — very slightly less than
2²⁵⁶. Every practical random 256-bit number is in range.
""",
                    "checks": [
                        "Why is it safe to publish your public key?",
                        "What happens to your coins if two people generate the same private key?",
                    ],
                },
                {
                    "slug": "signatures",
                    "title": "Digital signatures",
                    "summary": "ECDSA: proving you hold a key without revealing it.",
                    "body": """
A signature proves you know a private key, over a specific message, without
revealing the key. In Bitcoin the message is a hash of the transaction being
authorised — which is what stops a signature being lifted off one transaction
and pasted onto another.

ECDSA signing produces two values, r and s, each 32 bytes. Verification takes
the signature, the message hash and the public key, and answers yes or no. There
is no third outcome.

The dangerous part is the nonce. Signing requires a random value k (unrelated to
your private key) and:

- If k is predictable, your private key can be computed from one signature.
- If you reuse k across two different messages, your private key falls out with
  simple algebra.

This is not theoretical. It has drained real wallets, and it broke the PlayStation
3's signing key. Modern wallets use RFC 6979 deterministic nonces — k derived by
hashing the private key together with the message — which removes randomness
from the equation entirely and makes signatures reproducible.

Bitcoin also requires low-s signatures. For every valid (r, s) there is an
equally valid (r, n-s); allowing both meant a third party could flip a signature
and change a transaction's ID without invalidating it. Requiring the lower value
made signatures canonical.
""",
                    "checks": [
                        "Why does signing a transaction hash rather than a fixed message matter?",
                        "Why did allowing both s and n-s cause problems?",
                    ],
                },
                {
                    "slug": "schnorr",
                    "title": "Schnorr signatures",
                    "summary": "What Taproot's signature scheme buys that ECDSA could not.",
                    "body": """
Taproot introduced a second signature scheme, Schnorr (BIP340), on the same
curve. It is simpler than ECDSA and mathematically nicer in one specific way:
Schnorr signatures are linear, so they can be added together.

That linearity gives three things:

- Key aggregation. Several people can combine their public keys into one, and
  their signatures into one signature. A 3-of-3 multisig can look exactly like a
  single-key spend on chain — smaller, cheaper and more private.
- Batch verification. A node can verify many signatures together faster than
  one at a time.
- Provable security under cleaner assumptions than ECDSA.

BIP340 signatures are 64 bytes flat, with no DER encoding and no low-s rule —
the encoding is fixed, so the malleability question does not arise. Public keys
are 32 bytes: x-coordinate only, with the y-coordinate implicitly the even one.

Bitcoin did not use Schnorr originally because ECDSA was the standardised,
patent-clear option in 2008. The patent expired; Schnorr arrived in 2021.
""",
                    "checks": [
                        "What does 'linear' buy in practice?",
                        "Why are BIP340 public keys 32 bytes rather than 33?",
                    ],
                },
            ],
        },
        # ------------------------------------------------------------ part 3
        {
            "title": "Keys, addresses and wallets",
            "blurb": "From a random number to something you can put on an invoice.",
            "chapters": [
                {
                    "slug": "private-keys",
                    "title": "Private keys",
                    "summary": "The number that is the money.",
                    "body": """
A private key is a 256-bit number, usually written as 64 hex characters. It is
not stored anywhere in the blockchain and it is not registered with anyone. You
generate one locally, and from that moment it either exists in your possession
or it does not exist at all.

There is no account creation, no server that knows about you, and no way to ask
whether a key is "taken". The keyspace is 2²⁵⁶ — comfortably more than the atoms
in the observable universe — so collisions do not happen by chance.

Everything that makes Bitcoin custody hard follows from this:

- Lose the key and the coins are unspendable forever. They stay visible on the
  chain, belonging to nobody.
- Copy the key somewhere careless and whoever finds it can spend, immediately
  and irreversibly.
- There is no reset, no support line and no proof of identity that helps.

The corollary is that backups are the entire discipline of self-custody, and
they are a physical problem more than a digital one.
""",
                    "checks": [
                        "Why is there no 'account creation' step in Bitcoin?",
                        "What happens to coins whose private key is lost?",
                    ],
                },
                {
                    "slug": "public-keys",
                    "title": "Public keys and compression",
                    "summary": "33 bytes or 65, and why almost everyone uses 33.",
                    "body": """
A public key is a point on the curve: an x coordinate and a y coordinate, 32
bytes each. The obvious encoding is to write both, prefixed with 0x04:

    04 <x:32> <y:32>          65 bytes, "uncompressed"

But the curve equation means that for any x there are only two possible y values
— one even, one odd. So you can store x alone plus one bit saying which:

    02 <x:32>   (y is even)   33 bytes, "compressed"
    03 <x:32>   (y is odd)

The compressed form is smaller, so it is cheaper to spend, and it is what
everything modern uses. Uncompressed keys still appear in very old outputs.

This is worth internalising because the two forms produce DIFFERENT addresses
from the SAME private key. A wallet importing an old key sometimes has to check
both, and "my coins are missing" is occasionally just the other encoding.

Taproot goes further and uses 32 bytes: x only, with y assumed even. If your key
would have an odd y, you negate the private key.
""",
                    "checks": [
                        "Why are there exactly two valid y values for a given x?",
                        "Can one private key correspond to more than one address?",
                    ],
                },
                {
                    "slug": "base58check",
                    "title": "Base58Check",
                    "summary": "The encoding that made addresses typo-resistant.",
                    "body": """
Raw bytes are terrible to write down. Base58Check is Bitcoin's encoding for
anything a human might copy: addresses, WIF keys, extended keys.

It is base58 — the digits, upper and lower case letters — minus four characters
that are easy to confuse: 0, O, I and l. Then a checksum is appended before
encoding:

    payload  = version_byte || data
    checksum = first 4 bytes of HASH256(payload)
    result   = base58(payload || checksum)

The checksum is what makes a mistyped address fail immediately rather than
sending your money into a void. The chance of a random typo producing a valid
checksum is about 1 in 4 billion.

The version byte determines the leading character, which is why you can tell
what an address is by looking at it:

- 0x00 → mainnet P2PKH, starts with 1
- 0x05 → mainnet P2SH, starts with 3
- 0x6F → testnet P2PKH, starts with m or n
- 0x80 → WIF private key, starts with 5, K or L

Leading zero bytes are encoded as leading '1' characters, which is why P2PKH
addresses all start with 1.
""",
                    "checks": [
                        "Which four characters are missing from base58, and why those?",
                        "What does the version byte control?",
                    ],
                },
                {
                    "slug": "wif",
                    "title": "WIF: private keys you can write down",
                    "summary": "Base58Check applied to the key itself.",
                    "body": """
Wallet Import Format is a private key in Base58Check, so it can be typed,
scanned or written on paper with typos caught.

    0x80 || key(32 bytes) [|| 0x01] || checksum

The optional 0x01 suffix means "this key is used with a COMPRESSED public key".
Its presence changes the leading character:

- No suffix → starts with 5 (uncompressed)
- With suffix → starts with K or L (compressed)

That single byte decides which address your key controls. Importing a WIF into a
wallet that guesses wrongly shows an empty balance for coins that are sitting
there perfectly safely.

Testnet WIF uses version 0xEF and starts with 9 or c.

A WIF string is the private key. Anyone who reads it owns the coins — there is
no second factor. Photographing one, pasting one into a web page, or typing one
into a "balance checker" is the same as handing over the money.
""",
                    "checks": [
                        "What does the trailing 0x01 byte mean?",
                        "Is a WIF safer to share than a raw hex key?",
                    ],
                },
                {
                    "slug": "legacy-addresses",
                    "title": "Legacy addresses (P2PKH)",
                    "summary": "The original address format, built from HASH160.",
                    "body": """
The classic Bitcoin address is a hashed public key in Base58Check:

    1. K   = private key × G                     (public key)
    2. h   = RIPEMD-160(SHA-256(K))              (HASH160, 20 bytes)
    3. addr = Base58Check(0x00 || h)             (starts with 1)

The address is not the public key — it is a hash of it. The public key itself is
only revealed when you SPEND, because the spending input has to provide it so
nodes can check the hash and the signature.

That has a real consequence: an address that has never been spent from has never
exposed its public key, so it is protected by both the hash and the discrete
logarithm problem. An address that has been spent from has revealed its public
key permanently. This is the technical basis of the "don't reuse addresses"
advice, alongside the privacy reason.

Sending to a P2PKH address creates an output with this script:

    OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG

Spending it requires providing a signature and the public key that hashes to
that value.
""",
                    "checks": [
                        "When is a public key revealed on chain?",
                        "Why does an address hash a public key instead of being one?",
                    ],
                },
                {
                    "slug": "bech32",
                    "title": "Bech32 and SegWit addresses",
                    "summary": "The bc1 format, and the error detection Base58Check lacked.",
                    "body": """
SegWit introduced a new address encoding, Bech32 (BIP173), which is what bc1
addresses are.

It is better than Base58Check in ways that matter for humans:

- Lowercase only, so it is unambiguous when spoken and compact as a QR code.
- A BCH checksum that not only detects errors but LOCATES them — a wallet can
  say which character is wrong.
- It guarantees detection of up to four character errors, which Base58Check's
  truncated hash does not.

The structure is: a human-readable part (`bc` for mainnet, `tb` for testnet), a
separator `1`, then the data and a 6-character checksum. Because `1` is the
separator and not in the charset, the last `1` in the string is unambiguous.

Bech32 encodes a witness version and a witness program:

- version 0, 20-byte program → P2WPKH (single key)
- version 0, 32-byte program → P2WSH (script)

Taproot needed a change: a flaw was found where a Bech32 string ending in `p`
could have characters inserted without breaking the checksum. Bech32m (BIP350)
fixes it by changing one constant, and is used for witness version 1 and above.
So Taproot addresses (bc1p...) are Bech32m, while SegWit v0 (bc1q...) remains
Bech32.
""",
                    "checks": [
                        "What can Bech32's checksum do that Base58Check's cannot?",
                        "Why do bc1q and bc1p addresses use different checksum constants?",
                    ],
                },
                {
                    "slug": "hd-wallets",
                    "title": "HD wallets (BIP32)",
                    "summary": "One seed, unlimited keys, one backup.",
                    "body": """
Early wallets generated keys at random and stored a file full of them. Back up
the file, generate a hundred more keys, and your backup is now incomplete —
which lost people money.

Hierarchical Deterministic wallets (BIP32) fix this. One random seed generates
every key you will ever use, deterministically, in a tree. Back up the seed once
and you have backed up the future.

A key at each node is derived from its parent using HMAC-SHA512 over the parent
key and an index, split into a child key and a new chain code. Two kinds of
derivation exist:

- Hardened (index ≥ 2³¹). Requires the parent PRIVATE key.
- Non-hardened. Can be derived from the parent PUBLIC key alone.

Non-hardened derivation is what lets a webshop generate a fresh receiving
address per customer from an extended public key, with no private key on the
server. That is genuinely useful and has a sharp edge: if anyone learns an
extended PUBLIC key AND any one child PRIVATE key beneath it, they can compute
the parent private key and every sibling. Hardened derivation exists precisely
to cut that chain, which is why account-level path components are hardened.
""",
                    "checks": [
                        "What problem did HD wallets solve that random-key wallets had?",
                        "Why is hardened derivation used at the account level?",
                    ],
                },
                {
                    "slug": "mnemonics",
                    "title": "Mnemonics (BIP39)",
                    "summary": "Twelve words that are a 256-bit number.",
                    "body": """
BIP39 turns entropy into words. Generate 128–256 bits of randomness, append a
checksum, split into 11-bit groups, and look each group up in a fixed 2048-word
list. 128 bits gives 12 words; 256 bits gives 24.

The wordlist is chosen so the first four letters of every word are unique, which
means a mnemonic can be typed with autocomplete and recovered from partially
smudged handwriting.

The checksum matters: a mnemonic with a typo is usually rejected outright rather
than silently deriving a different, empty wallet.

Two things people commonly get wrong:

- The words are NOT the seed. They are run through PBKDF2 with 2048 iterations
  of HMAC-SHA512 to produce a 512-bit seed, which is what BIP32 uses.
- The optional passphrase is not a password on the wallet. It is mixed into that
  derivation, so a different passphrase produces a completely different, equally
  valid wallet. Forget it and the coins are gone — there is nothing to crack,
  because nothing is encrypted.

Word order is part of the secret, and the wordlist is public. Twelve words in a
drawer is a bearer instrument.
""",
                    "checks": [
                        "Are the twelve words the seed?",
                        "What does a BIP39 passphrase actually do?",
                    ],
                },
                {
                    "slug": "derivation-paths",
                    "title": "Derivation paths",
                    "summary": "Why the same seed shows different balances in different wallets.",
                    "body": """
A path names a position in the HD tree:

    m / purpose' / coin_type' / account' / change / index

The apostrophe means hardened. BIP44 established the shape, and later standards
reused it with a different purpose number per address type:

- 44' → legacy P2PKH        (addresses start 1)
- 49' → P2SH-wrapped SegWit (addresses start 3)
- 84' → native SegWit       (addresses start bc1q)
- 86' → Taproot             (addresses start bc1p)

`coin_type` is 0' for Bitcoin mainnet, 1' for testnet. `change` is 0 for
receiving addresses and 1 for change.

This is why the same seed restored into two wallets can show different balances:
they are looking at different branches. It is almost never lost money — it is
the wrong path, and the fix is to tell the wallet which one to scan.

It is also why "gap limit" exists. Wallets scan a fixed number of unused
addresses ahead (usually 20) before concluding a branch is empty. Skip past the
gap by generating many addresses without using them, and a restore can miss
funds until you widen the scan.
""",
                    "checks": [
                        "Why might a restored wallet show a zero balance that is not actually lost?",
                        "What is the gap limit protecting against?",
                    ],
                },
                {
                    "slug": "extended-keys",
                    "title": "Extended keys: xpub and xprv",
                    "summary": "What an xpub leaks, which is more than people expect.",
                    "body": """
An extended key is a key plus its chain code — the extra 32 bytes needed to
derive children. Serialized in Base58Check, they start with xprv (private) or
xpub (public); SegWit variants use ypub/zpub prefixes to signal the intended
address type, though the underlying key is the same.

An xpub is genuinely useful: give it to a watch-only wallet, an accountant, or a
payment processor, and they can generate your receiving addresses and see your
balance without ever being able to spend.

The part that surprises people is what "see your balance" means. An xpub reveals
EVERY address in that branch — past, future, receiving and change. Anyone with
your xpub can follow your entire financial history on that account forever. It
is not a spending risk; it is a total privacy loss.

And the sharp edge from BIP32 applies here: xpub + any single non-hardened child
xprv = the parent xprv. Handing out an xpub and separately exporting one child
key "for testing" can hand over the account.
""",
                    "checks": [
                        "What can somebody with your xpub do, and not do?",
                        "How can an xpub plus one child private key become a total compromise?",
                    ],
                },
            ],
        },
        # ------------------------------------------------------------ part 4
        {
            "title": "Transactions",
            "blurb": "What actually moves, and what a 'balance' really is.",
            "chapters": [
                {
                    "slug": "utxos",
                    "title": "UTXOs: there are no accounts",
                    "summary": "Bitcoin has no balances. It has unspent outputs.",
                    "body": """
Bitcoin does not store balances. There is no row anywhere saying your address
holds 0.4 BTC. What exists is a set of Unspent Transaction Outputs — discrete
chunks of coin, each locked to a condition, each created by some earlier
transaction.

Your "balance" is a number your wallet computes by finding every UTXO it can
spend and adding them up.

The model has real consequences:

- Outputs are spent WHOLE. If you hold one 1 BTC output and want to send 0.3,
  you spend the entire 1 BTC and send 0.7 back to yourself as change.
- Many small outputs cost more to spend than one large one, because each input
  adds bytes and you pay by the byte. A wallet full of dust can hold coins that
  cost more in fees than they are worth.
- Coin selection — which UTXOs to spend — is a real decision with privacy
  consequences, because spending two outputs together tells the world one
  person controls both.

This is why the same wallet can show a different fee for sending the same amount
on different days: the fee depends on which and how many outputs it has to
gather.
""",
                    "checks": [
                        "Where is your balance stored?",
                        "Why does sending 0.3 BTC from a 1 BTC output require a change output?",
                    ],
                },
                {
                    "slug": "transaction-anatomy",
                    "title": "Anatomy of a transaction",
                    "summary": "The fields, in order, and what each is for.",
                    "body": """
A legacy transaction serializes as:

    version      4 bytes,  little-endian
    input count  varint
    inputs       each: outpoint(36) + scriptSig(var) + sequence(4)
    output count varint
    outputs      each: amount(8) + scriptPubKey(var)
    locktime     4 bytes,  little-endian

That is the whole format. Everything else — addresses, balances, "senders" — is
interpretation layered on top by wallets.

Note what is NOT in there:

- No sender. Inputs point at previous outputs; who controls them is inferred.
- No fee field. The fee is implicit: inputs minus outputs. Get this wrong and
  you can burn an enormous fee, which has happened publicly more than once.
- No address. Addresses are a wallet-level encoding of a locking script.

SegWit transactions add a marker byte (0x00), a flag byte (0x01) and a witness
section after the outputs — see Part 6.
""",
                    "checks": [
                        "How is the fee expressed in the serialized transaction?",
                        "Why is there no 'sender' field?",
                    ],
                },
                {
                    "slug": "inputs-outpoints",
                    "title": "Inputs and outpoints",
                    "summary": "Pointing at money that already exists.",
                    "body": """
An input identifies which earlier output it is spending, using an outpoint:

    txid   32 bytes, the transaction that created the output
    vout    4 bytes, which output of it (0-indexed)

Then it supplies the unlocking data — scriptSig for legacy, or the witness for
SegWit — proving it is allowed to spend that output.

Two details bite people constantly:

- The txid in an outpoint is stored in REVERSED byte order relative to how
  block explorers display it. This is a historical accident of Bitcoin's
  internal little-endian handling, and it means the hex you see in a raw
  transaction looks nothing like the txid you searched for.
- An output can be referenced exactly once, ever. That single rule is what
  prevents double-spending: two transactions naming the same outpoint conflict,
  and only one can be in the chain.

Each input also carries a 4-byte sequence number, which now controls RBF
signalling and relative timelocks.
""",
                    "checks": [
                        "What stops the same output being spent twice?",
                        "Why does a txid in raw hex look reversed?",
                    ],
                },
                {
                    "slug": "outputs-amounts",
                    "title": "Outputs and amounts",
                    "summary": "Satoshis, locking scripts, and dust.",
                    "body": """
An output is an amount and a condition:

    amount        8 bytes, little-endian, in SATOSHIS
    scriptPubKey  the locking script

There is no decimal point anywhere in the protocol. 1 BTC is 100,000,000
satoshis, and that conversion happens only in user interfaces. Every consensus
rule counts satoshis.

The locking script is the actual "address" — it states what must be provided to
spend this output. An address is a human-friendly encoding a wallet converts
into one of these scripts.

Dust: an output so small that spending it would cost more in fees than it is
worth. Nodes refuse to relay transactions creating dust outputs, using a
threshold derived from the output type and a reference fee rate. This is a relay
policy, not a consensus rule — a miner may include such a transaction, but you
will struggle to broadcast it.

Outputs are also how coins are destroyed: an unspendable script (OP_RETURN, or
simply a wrong address) creates an output nobody can ever claim, and the
satoshis are gone from circulation without leaving the ledger.
""",
                    "checks": [
                        "What unit are amounts stored in?",
                        "Is the dust limit a consensus rule?",
                    ],
                },
                {
                    "slug": "serialization",
                    "title": "Serialization: varints and byte order",
                    "summary": "The two conventions that make raw hex readable.",
                    "body": """
To read raw transactions you need two conventions.

Little-endian. Most numeric fields are stored least-significant byte first.
Version 1 is `01000000`, not `00000001`. Hashes are also byte-reversed relative
to their display form. Get this wrong and every number you read is nonsense.

Varints (compact size). Counts and lengths use a variable-width encoding:

    < 0xFD          1 byte, the value itself
    <= 0xFFFF       0xFD followed by 2 bytes
    <= 0xFFFFFFFF   0xFE followed by 4 bytes
    otherwise       0xFF followed by 8 bytes

So a transaction with 2 inputs stores `02`. One with 300 inputs stores
`FD2C01`.

Together these mean a raw transaction can be parsed left to right with no
lookahead: read the version, read a varint to learn how many inputs follow, then
for each input read 36 bytes of outpoint, a varint length, that many script
bytes, and 4 bytes of sequence. The arcade's transaction decoder does exactly
this, and doing it once by hand is the fastest way to stop finding raw
transactions mysterious.
""",
                    "checks": [
                        "How many bytes does a varint use for the value 300?",
                        "Why does version 1 appear as 01000000?",
                    ],
                },
                {
                    "slug": "txid",
                    "title": "The transaction ID",
                    "summary": "Where a txid comes from, and why it used to be malleable.",
                    "body": """
A txid is:

    txid = HASH256(serialized transaction)

displayed byte-reversed. It is not assigned by anyone — it falls out of the
transaction's own bytes, so changing any byte changes the id.

That used to be a problem. Before SegWit, the scriptSig — which contains
signatures — was part of the hashed data. A third party could alter a signature's
encoding without invalidating it (adding padding, or flipping s to n-s) and
produce a DIFFERENT txid for the same payment. Any system that had recorded the
original id would think the payment had vanished. This is transaction
malleability, and it is why exchanges kept getting confused and why the Lightning
Network could not be built.

SegWit fixes it by moving the signatures out of the data the txid commits to.
For a SegWit transaction there are two ids:

- txid — hash of the transaction WITHOUT witness data. Not malleable.
- wtxid — hash INCLUDING the witness. Used in the block's witness commitment.
""",
                    "checks": [
                        "Who assigns a transaction its id?",
                        "What exactly did SegWit remove from the txid calculation?",
                    ],
                },
                {
                    "slug": "locktime-sequence",
                    "title": "Locktime and sequence",
                    "summary": "Two fields with tangled, overloaded meanings.",
                    "body": """
Locktime says the earliest point a transaction may be mined:

- 0 → no restriction.
- < 500,000,000 → a block height.
- >= 500,000,000 → a Unix timestamp.

Locktime is only enforced if at least one input has a sequence below
0xFFFFFFFF. An input with sequence 0xFFFFFFFF is "final" and disables locktime
entirely — a piece of history that surprises everyone the first time.

Sequence started as a mechanism for replacing unconfirmed transactions, was
disabled, and has since been given two new jobs:

- BIP125 opt-in RBF: any input with sequence below 0xFFFFFFFE signals that this
  transaction may be replaced by a higher-fee version.
- BIP68 relative timelocks: if bit 31 is clear, the value encodes how long after
  the input's confirmation this transaction becomes valid — in blocks, or in
  512-second units if bit 22 is set.

Most wallets set sequence to 0xFFFFFFFD: below FFFFFFFE, so RBF is signalled,
and below FFFFFFFF, so locktime works.
""",
                    "checks": [
                        "Why might a locktime be ignored entirely?",
                        "What does sequence 0xFFFFFFFD signal?",
                    ],
                },
                {
                    "slug": "fees",
                    "title": "Fees",
                    "summary": "You pay for space, not for value.",
                    "body": """
The fee is inputs minus outputs. It is never written down; it is what is left
over, and the miner claims it.

Crucially you pay for SIZE, not amount. Moving 0.001 BTC and moving 1,000 BTC
cost the same if the transactions are the same size. Fees are quoted in
satoshis per virtual byte (sat/vB).

What makes a transaction big:

- Number of inputs. Each is roughly 68 vB (native SegWit) to 148 vB (legacy).
  Inputs dominate.
- Number of outputs. Roughly 31–43 vB each.
- Script complexity. Multisig and script-path spends carry more data.

So consolidating many small UTXOs when fees are low is real saving, and a wallet
that received a hundred tiny payments will be expensive to empty.

Miners order the mempool by fee rate and fill each block from the top. Your
transaction confirms when the backlog above your fee rate clears — which is why
fee estimation is a prediction about other people's behaviour, and why it is
sometimes wrong.
""",
                    "checks": [
                        "Does sending more bitcoin cost a higher fee?",
                        "Which part of a transaction usually dominates its size?",
                    ],
                },
                {
                    "slug": "rbf-cpfp",
                    "title": "RBF and CPFP",
                    "summary": "Two ways to rescue a transaction that is stuck.",
                    "body": """
A transaction with too low a fee can sit in the mempool for days and eventually
be dropped. There are two ways out, depending on which side you are on.

Replace-By-Fee. The SENDER rebroadcasts the same transaction with a higher fee.
Under BIP125 this is allowed if the original signalled it (sequence below
0xFFFFFFFE), the replacement pays a higher absolute fee, and it pays enough
extra to cover its own relay. Nodes then forget the original.

Child-Pays-For-Parent. The RECEIVER — or anyone holding one of its outputs —
spends the unconfirmed output in a new transaction with a large fee. A miner
including the child must include the parent, so they evaluate them as a package.
This works even if the parent did not signal RBF.

RBF has a consequence worth stating plainly: an unconfirmed transaction is a
proposal, not a payment. Accepting zero-confirmation payments for anything of
value is trusting the sender not to replace it. Confirmations are the point at
which that stops being a matter of trust.
""",
                    "checks": [
                        "Who can perform CPFP that cannot perform RBF?",
                        "Why is a zero-confirmation payment not a payment?",
                    ],
                },
                {
                    "slug": "change-and-privacy",
                    "title": "Change outputs and what they leak",
                    "summary": "How chain analysis works, in one chapter.",
                    "body": """
Change is the money you send back to yourself. It is an ordinary output and
looks like any other — which is exactly the problem, because analysts have
reliable heuristics for spotting it:

- Round-number heuristic. If one output is 0.05000000 and the other is
  0.03871442, the untidy one is almost certainly change.
- Address-type heuristic. If the inputs are bech32 and one output is bech32
  while the other is legacy, the matching one is probably change.
- Address reuse. If an output pays an address that has appeared before in your
  history, it is yours.

And above all, the common-input-ownership heuristic: if a transaction spends
several inputs, one entity almost certainly controls all of them. This is how
clusters of addresses get attributed to a single person or exchange.

Practical mitigations: never reuse addresses, keep change in the same address
type as the inputs, avoid consolidating UTXOs from unrelated sources, and treat
any coin you received from an identity-verified exchange as permanently linked
to your identity.

Privacy on Bitcoin is not a setting. It is a practice, and it is easy to lose
retroactively.
""",
                    "checks": [
                        "Name two ways an analyst identifies the change output.",
                        "Why is consolidating UTXOs a privacy decision?",
                    ],
                },
            ],
        },
        # ------------------------------------------------------------ part 5
        {
            "title": "Script",
            "blurb": "The little language that decides who may spend what.",
            "chapters": [
                {
                    "slug": "what-script-is",
                    "title": "What Script is",
                    "summary": "A stack machine with no loops, on purpose.",
                    "body": """
Every output is locked by a program. Spending it means supplying a second
program whose execution leaves the stack in a valid state.

Script is a stack language: push values, then run operations that consume and
produce them. Validation runs the unlocking script, then the locking script, and
succeeds if the stack finishes with a single true value.

The design constraint that matters: Script is NOT Turing-complete. There are no
loops and no jumps. That is deliberate — every script terminates, and its cost
can be bounded before running it. A blockchain where validation might not halt
is a blockchain that can be halted by anyone.

It is also deliberately small. Several opcodes were disabled in 2010 after a
critical bug, and they have never come back. Bitcoin's Script is a shrinking
language, and that conservatism is a feature of a system where a bug is
irreversible.
""",
                    "checks": [
                        "Why does Script have no loops?",
                        "What condition means a script succeeded?",
                    ],
                },
                {
                    "slug": "opcodes",
                    "title": "The opcodes worth knowing",
                    "summary": "A dozen carry almost every real script.",
                    "body": """
There are around 100 opcodes but a handful do nearly all the work.

Stack:
- OP_DUP — duplicate the top item
- OP_DROP, OP_SWAP, OP_ROT — rearrange

Comparison:
- OP_EQUAL — pushes true/false
- OP_EQUALVERIFY — same, but fails the script immediately if not equal

Crypto:
- OP_HASH160 — RIPEMD160(SHA256(x))
- OP_SHA256, OP_HASH256
- OP_CHECKSIG — verify a signature against a public key
- OP_CHECKMULTISIG — verify m of n signatures
- OP_CHECKSIGVERIFY — as above, failing rather than pushing

Flow and time:
- OP_IF / OP_ELSE / OP_ENDIF
- OP_CHECKLOCKTIMEVERIFY (CLTV) — absolute timelock
- OP_CHECKSEQUENCEVERIFY (CSV) — relative timelock
- OP_RETURN — mark the output provably unspendable

The VERIFY suffix is a recurring pattern: rather than leaving true on the stack
for a later check, fail here and now. It saves a byte and removes a way to get
the script subtly wrong.
""",
                    "checks": [
                        "What is the difference between OP_EQUAL and OP_EQUALVERIFY?",
                        "What does OP_RETURN do to an output?",
                    ],
                },
                {
                    "slug": "p2pkh-script",
                    "title": "P2PKH, executed step by step",
                    "summary": "Following the stack through the commonest script.",
                    "body": """
Pay To Public Key Hash. The locking script:

    OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG

The unlocking script:

    <signature> <publicKey>

Execution, stack shown left to right with the top on the right:

    push sig, push pubkey     [sig, pubkey]
    OP_DUP                    [sig, pubkey, pubkey]
    OP_HASH160                [sig, pubkey, hash]
    push pubKeyHash           [sig, pubkey, hash, expected]
    OP_EQUALVERIFY            [sig, pubkey]        (fails here if unequal)
    OP_CHECKSIG               [true]

Two things are proved: the public key hashes to the value in the output, and the
signature is valid for that key over this transaction. Either failing kills it.

P2PK, the older form, skipped the hash and put the public key directly in the
output — which is why coins from 2009 have their public keys already exposed on
chain. Satoshi's early outputs are P2PK.
""",
                    "checks": [
                        "What two facts does a P2PKH spend prove?",
                        "Why do the oldest outputs expose their public keys?",
                    ],
                },
                {
                    "slug": "p2sh",
                    "title": "P2SH: paying to a script's hash",
                    "summary": "Moving the cost and complexity to the spender.",
                    "body": """
Before P2SH, paying into a 2-of-3 multisig meant putting the whole multisig
script in the output — so the SENDER paid for its size and had to be able to
express it. Wallets could not produce such a payment from an address.

P2SH (BIP16) inverts it. The output commits only to a hash:

    OP_HASH160 <20-byte script hash> OP_EQUAL

The spender supplies the real script — the redeem script — plus whatever it
needs. Nodes check the redeem script hashes to the committed value, then run it.

This is why 3-addresses exist and why they can mean almost anything: multisig,
a timelock, an escrow. The chain does not know until it is spent.

Two limits worth carrying:

- The redeem script is capped at 520 bytes.
- The 20-byte hash means only 80 bits of collision resistance. That is enough
  against a single attacker but not against a script that two mutually
  distrusting parties construct together, which is why P2WSH uses 32 bytes.
""",
                    "checks": [
                        "Who pays for the size of a P2SH script — sender or spender?",
                        "What can you tell about a 3-address before it is spent?",
                    ],
                },
                {
                    "slug": "multisig",
                    "title": "Multisig",
                    "summary": "m-of-n, and the off-by-one that is now consensus.",
                    "body": """
A bare multisig locking script:

    OP_m <pubkey1> ... <pubkeyN> OP_n OP_CHECKMULTISIG

OP_CHECKMULTISIG contains Bitcoin's most famous bug: it pops one item more off
the stack than it should. The fix would be a hard fork, so instead every spend
pushes a dummy value that gets consumed and ignored. By convention it is
OP_0 — and BIP147 made that mandatory, because the dummy was the last remaining
piece of third-party malleability.

Bare multisig is rarely used directly. In practice it is wrapped:

- P2SH multisig — the classic, addresses start with 3
- P2WSH multisig — native SegWit, cheaper, 32-byte hash
- Taproot — better still, because a k-of-k can be aggregated into a single
  Schnorr key and look like an ordinary spend

Multisig is what makes shared custody and hardware-wallet redundancy possible: a
2-of-3 across three devices in three places survives losing any one of them,
without any single device being able to spend.
""",
                    "checks": [
                        "Why does every multisig spend push a dummy value?",
                        "What does a 2-of-3 protect you against?",
                    ],
                },
                {
                    "slug": "timelock-scripts",
                    "title": "Timelocks in Script",
                    "summary": "CLTV and CSV: money that cannot move yet.",
                    "body": """
Two opcodes put time inside a script rather than in a transaction field.

OP_CHECKLOCKTIMEVERIFY (BIP65) — absolute. The script fails unless the spending
transaction's locktime is at or past a given block height or timestamp. "Nobody
can spend this before 2027."

OP_CHECKSEQUENCEVERIFY (BIP112) — relative. The script fails unless the input
has been confirmed for a given number of blocks or 512-second units. "Spendable
144 blocks after it was received."

Both work by VERIFYing a field the transaction already carries, which is why the
locktime and sequence fields of Part 4 matter here.

Combined with OP_IF they produce genuinely useful arrangements:

- Inheritance. Spendable by you now, or by your heir after a year of no
  movement.
- Escrow with a deadline. Both parties together, or one alone after a timeout.
- Lightning channels, whose entire safety model is "you can claim this after a
  delay, unless I prove you cheated first".

The delay is enforced by consensus, not by a service. Nobody can shorten it.
""",
                    "checks": [
                        "What is the difference between CLTV and CSV?",
                        "How does an inheritance script avoid needing a third party?",
                    ],
                },
                {
                    "slug": "sighash",
                    "title": "Sighash flags",
                    "summary": "Choosing which parts of a transaction you sign.",
                    "body": """
A signature commits to a specific view of the transaction, selected by a
one-byte sighash flag appended to it.

- SIGHASH_ALL (0x01) — sign all inputs and all outputs. The default and almost
  always what you want: nothing about the transaction can change.
- SIGHASH_NONE (0x02) — sign the inputs but no outputs. You have authorised
  spending your coins to anywhere at all. Rarely correct.
- SIGHASH_SINGLE (0x03) — sign all inputs and only the output at the same index.
- SIGHASH_ANYONECANPAY (0x80) — combine with any of the above; sign only YOUR
  input, letting others add theirs.

ANYONECANPAY | ALL is the useful combination: a crowdfunding pledge that is only
valid if the outputs are exactly as specified, but which anyone may join.

SIGHASH_SINGLE has a legacy bug: if there is no output at the input's index, the
signed hash becomes the value 1, and a signature over it can be reused. SegWit's
signing scheme (BIP143) fixed this along with a quadratic hashing problem that
made large legacy transactions extremely slow to verify.
""",
                    "checks": [
                        "What does SIGHASH_ALL commit to?",
                        "What is ANYONECANPAY actually for?",
                    ],
                },
            ],
        },
        # ------------------------------------------------------------ part 6
        {
            "title": "SegWit and Taproot",
            "blurb": "The two upgrades that changed what a transaction looks like.",
            "chapters": [
                {
                    "slug": "malleability",
                    "title": "The problem SegWit solved",
                    "summary": "Why signatures had to move.",
                    "body": """
Before SegWit, a transaction's id was a hash of everything, signatures included.
Signatures are not unique — the same valid signature can be re-encoded, and
before the low-s rule the value could be flipped — so a third party could change
a transaction's id without changing its meaning or invalidating it.

Consequences:

- A wallet tracking a payment by txid could conclude it had disappeared.
- Exchanges automatically re-sent "failed" withdrawals, sometimes twice.
- Any protocol building a chain of unconfirmed transactions was impossible,
  because a child references its parent BY TXID. If the parent's id can change
  before confirmation, the child becomes permanently invalid.

That last one is the real cost. Payment channels — Lightning — require signing a
transaction that spends an unconfirmed one. Malleability made that unsafe, and
so a whole class of scaling work was blocked until it was fixed.
""",
                    "checks": [
                        "Why does malleability break a chain of unconfirmed transactions?",
                        "Was a malleated transaction invalid?",
                    ],
                },
                {
                    "slug": "segwit",
                    "title": "What SegWit changed",
                    "summary": "Segregated witness, and the trick that made it a soft fork.",
                    "body": """
SegWit moves signatures out of the transaction body into a separate witness
section, and excludes that section from the txid.

The clever part is that it shipped as a SOFT fork — old nodes still accept the
new blocks. A SegWit output looks like this:

    OP_0 <20-byte or 32-byte program>

To an old node, that is a script that pushes two values and ends — no failure
condition — so it is "anyone can spend". Old nodes accept the spend without
checking it. New nodes know to look in the witness and enforce the real rules.

That is a genuine trade: SegWit's security relies on a majority of hash power
enforcing the new rules, because non-upgraded nodes cannot. It is how Bitcoin
upgrades without splitting.

What SegWit delivered:
- Malleability fixed, unlocking Lightning.
- An effective capacity increase, through the weight discount.
- A cleaner signing scheme (BIP143) that removed quadratic hashing.
- Script versioning, which is what allowed Taproot to be added later without
  another trick like this one.
""",
                    "checks": [
                        "Why does an old node think a SegWit output is anyone-can-spend?",
                        "What did script versioning make possible later?",
                    ],
                },
                {
                    "slug": "weight-vbytes",
                    "title": "Weight units and vbytes",
                    "summary": "How the block size limit was raised without raising it.",
                    "body": """
The old limit was 1,000,000 bytes per block. SegWit replaced it with a limit of
4,000,000 WEIGHT UNITS, where:

    witness data      1 weight unit per byte
    everything else   4 weight units per byte

    weight = base_size × 3 + total_size
    vbytes = weight / 4

Non-witness data therefore costs four times as much as witness data. A block of
pure legacy transactions still cannot exceed 1,000,000 bytes — so the old limit
is preserved and old nodes never see an invalid block — while a block full of
SegWit transactions can carry more total data.

This is why fee rates are quoted in sat/vB rather than sat/byte, and why moving
to native SegWit reduced fees by roughly 25–40% depending on the transaction
shape.

It is also a deliberate incentive: it makes witness data cheap, which makes
signature-heavy things like multisig and Lightning cheaper, and it makes creating
new UTXOs relatively more expensive, which discourages bloating the set every
node must keep in memory.
""",
                    "checks": [
                        "Why is witness data discounted?",
                        "How is the old 1MB limit still respected?",
                    ],
                },
                {
                    "slug": "wtxid",
                    "title": "wtxid and the witness commitment",
                    "summary": "How witness data is still committed to, despite leaving the txid.",
                    "body": """
Removing witnesses from the txid raises an obvious question: what stops a miner
altering them?

Nothing in the txid — so SegWit adds a second commitment. Every block contains a
witness merkle root, built from wtxids (hashes INCLUDING witness data), and that
root is placed in an OP_RETURN output of the coinbase transaction:

    OP_RETURN 0xaa21a9ed <32-byte witness root hash>

Old nodes see an OP_RETURN they ignore. New nodes verify it. So witness data is
committed to just as firmly as everything else, via a second tree — again
without changing anything an old node validates.

The coinbase transaction's wtxid is defined as all zeroes, because it would
otherwise have to commit to a value derived from itself.
""",
                    "checks": [
                        "Where is the witness merkle root stored?",
                        "Why is the coinbase wtxid defined as zero?",
                    ],
                },
                {
                    "slug": "taproot",
                    "title": "Taproot",
                    "summary": "Every spend looking the same, whatever the conditions.",
                    "body": """
Taproot (BIPs 340/341/342, activated 2021) combines Schnorr signatures with a
new output type that hides complexity.

A Taproot output commits to a single public key Q:

    Q = P + H(P || merkle_root) × G

where P is an internal key and merkle_root is the root of a tree of alternative
spending scripts. Two ways to spend:

- Key path. Sign with the key. The output looks like an ordinary single-key
  spend and reveals NOTHING about the alternative scripts — nobody can tell
  whether any existed.
- Script path. Reveal one leaf script, satisfy it, and prove it was in the tree.
  Only that branch is revealed; the others stay private forever.

The consequences are large. A 2-of-2 that cooperates looks identical to a
single-key spend. A complex inheritance arrangement, used the happy way, is
indistinguishable from someone spending pocket change. And you only ever pay for
the branch you actually use, instead of publishing the whole contract.

Taproot addresses start bc1p and use Bech32m.
""",
                    "checks": [
                        "What can an observer learn about the unused branches of a Taproot output?",
                        "Why does a cooperative multisig get cheaper under Taproot?",
                    ],
                },
            ],
        },
        # ------------------------------------------------------------ part 7
        {
            "title": "Blocks and the chain",
            "blurb": "How transactions become history that is expensive to rewrite.",
            "chapters": [
                {
                    "slug": "block-structure",
                    "title": "What a block is",
                    "summary": "An 80-byte header, then a list of transactions.",
                    "body": """
A block is:

    header        80 bytes, fixed
    tx count      varint
    transactions  the coinbase first, then the rest

The header is the part that matters most, and its fixed size is deliberate: a
node can verify the chain of work by downloading headers alone — 80 bytes per
block, a few tens of megabytes for the entire history — without any
transactions. That is what makes lightweight verification possible at all.

Transactions live in the block body. They are committed to by a single 32-byte
merkle root inside the header, so the header is a commitment to the entire
contents while staying small enough to be cheap.

The coinbase transaction always comes first. It has one input, which points at
nothing (an all-zero outpoint), because it is creating coins rather than
spending them.
""",
                    "checks": [
                        "Why is the header a fixed 80 bytes?",
                        "What is unusual about the coinbase transaction's input?",
                    ],
                },
                {
                    "slug": "block-header",
                    "title": "The block header, field by field",
                    "summary": "The 80 bytes that mining actually hashes.",
                    "body": """
    version        4 bytes   consensus/signalling bits
    prev block    32 bytes   hash of the previous header
    merkle root   32 bytes   commitment to this block's transactions
    timestamp      4 bytes   Unix time, seconds
    bits           4 bytes   the difficulty target, compactly encoded
    nonce          4 bytes   the number miners vary

    block hash = HASH256(header)

Two of these do the structural work.

`prev block` is what makes it a chain. Changing an old block changes its hash,
which breaks the next block's `prev` field, which breaks every block after it.
Rewriting history means redoing all the work from that point forward.

`merkle root` binds every transaction. Change one transaction anywhere in the
block and the root changes, so the header changes, so the work is void.

The timestamp is only loosely constrained — it must be greater than the median
of the last 11 blocks and no more than 2 hours ahead of network time. Block
timestamps are approximate and can move backwards.
""",
                    "checks": [
                        "Which field makes the chain a chain?",
                        "Can a block's timestamp be earlier than the block before it?",
                    ],
                },
                {
                    "slug": "merkle-trees",
                    "title": "Merkle trees",
                    "summary": "Committing to a thousand transactions in 32 bytes.",
                    "body": """
Hash every transaction. Pair them up and hash each pair. Repeat until one hash
is left — the merkle root.

    root = H(H(H(a)+H(b)) + H(H(c)+H(d)))

If a level has an odd number of nodes, the last is duplicated and paired with
itself. That quirk caused CVE-2012-2459, where different transaction lists could
produce the same root; nodes now reject blocks containing duplicate txids.

The point is the merkle PROOF. To prove transaction X is in a block you do not
need the block — you need X and roughly log₂(n) sibling hashes. A block with
4,096 transactions needs 12 hashes, about 384 bytes, to prove any one of them is
included.

This is what SPV wallets use: download headers, ask a node for a proof, and
verify inclusion without the block. What it does NOT prove is that the
transaction is valid — only that a miner put it in a block. That distinction is
the whole gap between a light client and a full node.
""",
                    "checks": [
                        "How many hashes prove membership in a 1,024-transaction block?",
                        "What does a merkle proof not tell you?",
                    ],
                },
                {
                    "slug": "proof-of-work",
                    "title": "Proof of work",
                    "summary": "Turning electricity into an unforgeable ordering.",
                    "body": """
Miners hash the header repeatedly, changing the nonce, until the result is below
a target number. Because SHA-256 is one-way, there is no way to work out which
nonce will do it — only guessing.

    while HASH256(header) > target:
        nonce += 1

Finding a valid hash is astronomically hard; CHECKING one is instant. That
asymmetry is the whole mechanism: work is expensive to produce, free to verify.

The nonce is only 4 bytes, which is exhausted in milliseconds at modern hash
rates. Miners then change something else — the timestamp, or an "extranonce"
inside the coinbase transaction, which changes the merkle root and yields a
whole new nonce space.

What this buys is ordering that cannot be faked cheaply. To rewrite a block you
must redo its work and beat the honest chain's ongoing progress. It is not that
history is impossible to change; it is that changing it costs more than it is
worth, and the cost is externally verifiable.
""",
                    "checks": [
                        "Why can't a miner calculate the winning nonce directly?",
                        "What do miners vary once the 4-byte nonce is exhausted?",
                    ],
                },
                {
                    "slug": "difficulty",
                    "title": "Difficulty, target and bits",
                    "summary": "How the network holds ten minutes steady.",
                    "body": """
The target is the number a block hash must come in under. Lower target, harder
block. It is stored in the header as `bits`, a compact 4-byte float-like
encoding:

    0x1d00ffff → 0x00ffff × 2^(8 × (0x1d - 3))

Every 2,016 blocks — about two weeks — every node recalculates:

    new_target = old_target × (actual_time_taken / 1,209,600 seconds)

If blocks came too fast, the target drops. Too slow, it rises. Adjustment is
clamped to a factor of 4 either way, so a sudden loss of hash power cannot be
fixed instantly — which is exactly what happened when China banned mining in
2021 and blocks slowed for weeks.

Every node computes this independently from the chain it already has. There is
no authority setting difficulty and no vote. Given the same blocks, everyone
derives the same number.

There is a well-known off-by-one: the calculation uses timestamps 2,016 blocks
apart but only 2,015 intervals. It makes blocks very slightly faster than ten
minutes, it has been there since 2009, and fixing it would be a hard fork.
""",
                    "checks": [
                        "Who decides the difficulty?",
                        "Why can't a huge drop in hash power be corrected immediately?",
                    ],
                },
                {
                    "slug": "coinbase-halving",
                    "title": "The coinbase and the halving",
                    "summary": "Where new bitcoin comes from, and where it stops.",
                    "body": """
The first transaction in every block is the coinbase. It has no real input and
pays the miner:

    reward = subsidy + sum of all fees in the block

The subsidy started at 50 BTC and halves every 210,000 blocks — roughly four
years. 50, 25, 12.5, 6.25, 3.125, and onwards. After about 2140 it rounds to
zero and miners are paid by fees alone.

That schedule is where the 21 million cap comes from. It is not a rule written
somewhere saying "21 million"; it is the sum of a geometric series, enforced by
every node checking that a coinbase does not claim more than it should.

Two details:

- Coinbase outputs cannot be spent for 100 blocks. If a short reorg orphans the
  block, the reward vanishes with it, and the maturity rule stops those coins
  having been spent onwards in the meantime.
- The coinbase input's script is arbitrary data. Since BIP34 it must start with
  the block height; the rest is free, which is where miners put pool names,
  extranonces, and occasionally messages.
""",
                    "checks": [
                        "Where does the 21 million limit actually come from?",
                        "Why must coinbase outputs mature for 100 blocks?",
                    ],
                },
                {
                    "slug": "reorgs",
                    "title": "Reorganisations and confirmations",
                    "summary": "Why 'confirmed' is a probability, not a state.",
                    "body": """
Two miners can find a block at nearly the same time. Both are valid; the network
briefly disagrees. Nodes follow the chain with the most accumulated WORK — not
the longest by count — and when one side extends first, the other is abandoned.
Its transactions return to the mempool.

This is a reorg, and one-block reorgs happen naturally. Deeper ones require
either extraordinary luck or an attacker with serious hash power.

Which is why confirmations are a risk dial:

- 0 confirmations — a proposal. Replaceable, and worth nothing on its own.
- 1 confirmation — in a block. Could still be reorged out.
- 6 confirmations — the customary threshold, an old rule of thumb rather than a
  magic number.

The right depth depends on the amount. A coffee needs zero. A house needs many
more, because the question is always "would rewriting this cost the attacker
less than what they would gain".
""",
                    "checks": [
                        "Is the winning chain the longest or the heaviest?",
                        "What happens to transactions in an orphaned block?",
                    ],
                },
            ],
        },
        # ------------------------------------------------------------ part 8
        {
            "title": "The network",
            "blurb": "How thousands of strangers stay in agreement.",
            "chapters": [
                {
                    "slug": "p2p-network",
                    "title": "The peer-to-peer network",
                    "summary": "No servers, no registry, no map.",
                    "body": """
Bitcoin nodes connect directly to each other. There is no central server and no
list of participants. A new node finds peers by asking DNS seeds — a handful of
hardcoded hostnames returning known-good addresses — then asks those peers for
more, and from that point never needs the seeds again.

A default node keeps around 8 outbound connections and accepts up to 125 total.
It relays what it hears: transactions and blocks propagate by flooding, and any
message reaches most of the network in seconds.

Nothing here is authenticated. Peers are strangers, some are hostile, and the
protocol assumes it. Every node validates everything it receives independently,
so a lying peer accomplishes nothing except getting itself disconnected.

That is the load-bearing idea: the network is not trusted at all. It is a
transport for data that each node checks for itself.
""",
                    "checks": [
                        "How does a brand-new node find its first peers?",
                        "What does a node do about a peer that sends it an invalid block?",
                    ],
                },
                {
                    "slug": "mempool",
                    "title": "The mempool",
                    "summary": "Everyone's waiting room is slightly different.",
                    "body": """
Unconfirmed transactions sit in each node's mempool. There is no single, global
mempool — every node has its own, shaped by what it heard, when it started, its
memory limit, and its relay policy.

A node accepts a transaction into its mempool only if it passes both consensus
rules and POLICY rules. Policy is stricter and is not consensus: minimum relay
fee, dust limits, standard script types, size limits. A transaction can be
perfectly valid and still unrelayable, which is why an unusual transaction may
need to be handed to a miner directly.

When the mempool fills, nodes evict the lowest fee rate transactions and raise
their minimum. During congestion a low-fee transaction is not queued — it is
dropped, quietly, by node after node.

Miners select from their own mempool by fee rate. So the fee estimate your
wallet shows is a guess about what other people are doing, based on one node's
partial view.
""",
                    "checks": [
                        "Is there one mempool or many?",
                        "What is the difference between a consensus rule and a policy rule?",
                    ],
                },
                {
                    "slug": "nodes-vs-spv",
                    "title": "Full nodes and light clients",
                    "summary": "What you give up when you do not verify.",
                    "body": """
A full node downloads every block, checks every rule, and builds the UTXO set
itself. It trusts nothing and nobody. Its answers about your balance come from
its own arithmetic.

A light (SPV) client downloads headers, verifies the proof of work, and asks
full nodes for merkle proofs. It can confirm a transaction was INCLUDED in a
block, which is a real guarantee — but it cannot check that the block was valid,
because it does not have the transactions to check.

So an SPV client trusts miners to have enforced the rules, and trusts the nodes
it queries not to lie by omission. Historically SPV also leaked badly: bloom
filters told the server which addresses were yours.

This is what "verify, don't trust" means concretely. If you never run a node,
somebody else is deciding what is true for you. That may be a perfectly
reasonable trade for small amounts on a phone — but it is a trade, and it is
worth knowing you are making it.
""",
                    "checks": [
                        "What can an SPV client prove, and what can it not?",
                        "Who is a light client trusting?",
                    ],
                },
                {
                    "slug": "forks",
                    "title": "Soft forks and hard forks",
                    "summary": "How rules change in a system with no one in charge.",
                    "body": """
A soft fork TIGHTENS the rules. Everything newly valid was already valid before,
so old nodes still accept new blocks — they just do not understand what they are
looking at. SegWit and Taproot were soft forks, both hiding new meaning inside
something old nodes read as harmlessly permissive.

A hard fork LOOSENS the rules. Something previously invalid becomes valid, so
old nodes reject the new blocks and the chain splits into two networks with
shared history. Raising the block size limit requires a hard fork, which is why
that argument was never merely technical.

Activation is the genuinely hard part, because nobody can order it. Mechanisms
have included miner signalling with a threshold and a deadline (BIP9), and
user-activated approaches where economic nodes simply begin enforcing on a date.
Taproot used Speedy Trial, a short signalling window with a fallback.

The lesson people take from 2017 is that miners produce blocks but do not decide
the rules. Nodes that verify — exchanges, businesses, individuals — decide which
chain they will accept, and miners follow the chain that is worth something.
""",
                    "checks": [
                        "Why does an old node accept blocks made under a soft fork?",
                        "Who ultimately decides which rules count?",
                    ],
                },
            ],
        },
        # ------------------------------------------------------------ part 9
        {
            "title": "Doing it yourself",
            "blurb": "Checking, by hand, that the previous eight parts were true.",
            "chapters": [
                {
                    "slug": "read-a-transaction",
                    "title": "Reading a raw transaction by hand",
                    "summary": "The exercise that makes all of it concrete.",
                    "body": """
Take any raw transaction hex and walk it, left to right. The rules from Part 4
are all you need.

    01000000  version 1 (little-endian)
    01        one input
      <32 bytes>  previous txid, BYTE-REVERSED from its displayed form
      00000000    output index 0
      6a          scriptSig length, 106 bytes
      <106 bytes> signature and public key
      ffffffff    sequence
    02        two outputs
      <8 bytes>   amount in satoshis, little-endian
      19          scriptPubKey length, 25 bytes
      <25 bytes>  76 a9 14 <20-byte hash> 88 ac  → P2PKH
      ... second output ...
    00000000  locktime 0

If the fifth and sixth characters are `0001`, it is a SegWit transaction: that
is the marker and flag, the inputs follow immediately, and a witness section
sits between the last output and the locktime.

Paste a real one into the arcade's transaction decoder and check yourself
against it. Recognising `76a914...88ac` as P2PKH on sight is the moment raw hex
stops being noise.
""",
                    "checks": [
                        "How do you spot a SegWit transaction in raw hex?",
                        "What script pattern marks a P2PKH output?",
                    ],
                },
                {
                    "slug": "verify-an-address",
                    "title": "Deriving an address yourself",
                    "summary": "Key → public key → hash → address, checked at every step.",
                    "body": """
Every step is reproducible, and doing it once removes any mystery about what a
wallet is doing for you.

    1. private key   32 random bytes
    2. public key    K = k × G, compressed to 33 bytes (02/03 prefix)
    3. HASH160       RIPEMD160(SHA256(K)) → 20 bytes
    4. version       prefix 0x00
    5. checksum      first 4 bytes of HASH256(version || hash)
    6. address       Base58Check encode

For a native SegWit address, stop after step 3 and Bech32-encode witness version
0 with that 20-byte program instead.

The arcade tools do each step separately on purpose, so you can stop at any
point and compare against your own wallet. If a wallet's address for a key does
not match yours, the usual culprit is compression: the compressed and
uncompressed public keys give completely different addresses.
""",
                    "checks": [
                        "At which step do P2PKH and P2WPKH addresses diverge?",
                        "Why might your derived address disagree with a wallet's?",
                    ],
                },
                {
                    "slug": "running-a-node",
                    "title": "Running a node",
                    "summary": "What it does for you, and what it does not.",
                    "body": """
Bitcoin Core downloads the chain and verifies every rule from genesis onwards.
Initial sync takes hours to days and several hundred gigabytes; afterwards it is
undemanding.

What it gives you:

- Your own answers. Balances and confirmations computed by you, not reported to
  you.
- A vote that counts. Your node enforces the rules you chose; a fork you refuse
  is a fork you do not follow.
- Privacy. Your wallet queries itself instead of telling a third party which
  addresses are yours.

What it does not give you: mining income (that is unrelated), faster
transactions, or any protection against your own key management.

Pruning is worth knowing about — you can verify the whole chain from genesis and
then discard old blocks, keeping a few gigabytes. You get full verification with
modest storage; what you lose is the ability to serve history to others.
""",
                    "checks": [
                        "Does running a node earn anything?",
                        "What does a pruned node still verify?",
                    ],
                },
                {
                    "slug": "where-to-go-next",
                    "title": "Where to go next",
                    "summary": "The sources worth your time.",
                    "body": """
This book is deliberately compact. When you want depth:

- learnmeabitcoin.com — Greg Walker's technical guide, and the reference this
  curriculum was written alongside. Its explanations of transactions, script and
  mining are the clearest on the web, with interactive diagrams throughout.
- The BIPs (github.com/bitcoin/bips) — the actual specifications. BIP32, 39, 44,
  141, 143, 173, 340, 341 cover most of what is here.
- Bitcoin Core's source. The rules ARE the code; when documentation and code
  disagree, the code is what the network enforces.
- A block explorer, with this book open. Pick a real transaction and account for
  every byte.

The habit worth building: whenever you read a claim about Bitcoin, ask what
would have to be true in the protocol for it to hold, then go and check. Almost
everything is checkable, which is unusual and is the point.
""",
                    "checks": [
                        "When documentation and code disagree, which one is the network's rule?",
                        "What is the one habit this book is trying to leave you with?",
                    ],
                },
            ],
        },
    ],
}
