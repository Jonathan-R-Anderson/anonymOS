"""The Solidity book: write a zombie game contract, one lesson at a time.

WHERE THIS CAME FROM
--------------------
Asked for as "the CryptoZombies lessons". Those lessons are Loom Network's, and
their licence is "All rights reserved" with an explicit claim over derivative
works — so none of their text is here, and none of it has been paraphrased
either, because a paraphrase is the derivative case that licence names.

What IS shared is the idea of teaching Solidity by building a zombie game, which
is a teaching approach rather than a text. The prose, the exercises, the starter
code and the solutions below are written for this site. Every lesson links to
the corresponding cryptozombies.io lesson, because it is the original and it is
free, and somebody learning this should have both.

The contract this course builds is also NOT the arcade's game contract. That was
vendored MIT code from the finished project, and it has been REMOVED along with
the arcade — it was deployable to Ethereum mainnet from the admin console while
being unrelated to anything else in the stack. This course is unaffected: it is
original work that never depended on that vendored copy, and what it shares with
cryptozombies.io is the idea of teaching Solidity by building a zombie game.
This is a teaching contract, written to be read in order.

TARGETING 0.8
-------------
Deliberately modern Solidity, not the 0.4/0.5 the original lessons used. Under
0.8 arithmetic reverts on overflow, so SafeMath is gone — and teaching a library
that exists to fix a problem the compiler now fixes would be teaching history as
if it were practice. Where it matters, the lesson says what changed and why.

FORMAT
------
Same plain-text `body` as the Crypto book, plus the exercise fields:
`task`, `starter`, `solution`, and `validators` — each a regex the learner's
code must match, with the hint shown when it does not. Checks run in the
BROWSER; nothing is compiled and nothing is submitted. They catch the mistake
the lesson is about, which is what a beginner needs, and they will happily pass
code that would not compile — which the page says out loud rather than implying
a green tick means more than it does.
"""

REFERENCE = "https://cryptozombies.io"

BOOK = {
    "slug": "solidity",
    "title": "Solidity",
    "reference": REFERENCE,
    "reference_name": "cryptozombies.io",
    "provenance": (
        "Written for this site. The CryptoZombies lessons are Loom Network's and "
        "their licence reserves all rights including derivative works, so none of "
        "their text is reproduced or paraphrased here \u2014 only the idea of "
        "learning Solidity by building a zombie game. The originals are free:"
    ),
    "subtitle": "Write a zombie game on Ethereum, one lesson at a time.",
    "blurb": (
        "Sixteen lessons that build one contract. You start with an empty file "
        "and finish with a zombie army that can be owned, levelled up, fought "
        "and traded — deployable to Ethereum from the arcade's own console. Each "
        "lesson has an exercise you can check as you go."
    ),
    "parts": [
        {
            "title": "First contact",
            "blurb": "The file, the compiler, and where state lives.",
            "chapters": [
                {
                    "slug": "sol-first-contract",
                    "title": "Your first contract",
                    "summary": "Licence line, pragma, and the contract block.",
                    "body": """
Every Solidity file starts with two lines of bookkeeping before any code:

    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.24;

The SPDX line declares a licence. The compiler warns without it, because
publishing a contract that anyone can read but nobody may legally reuse was
common enough to be worth nagging about.

The pragma pins the compiler. `^0.8.24` means "0.8.24 or later, but not 0.9" —
a caret allows patch and minor bumps within the same major line. This matters
more than it does in most languages: compiler versions change how code behaves,
and a contract is deployed once and lives forever. Pin it.

Then the contract itself, which is roughly a class:

    contract ZombieFactory {
    }

That is a complete, deployable contract. It does nothing, costs gas to put on
chain, and will sit there for as long as the chain exists.
""",
                    "task": "Declare a contract called ZombieFactory, with the MIT licence line and a pragma of ^0.8.24.",
                    "starter": "// SPDX-License-Identifier: MIT\n\n\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n}\n",
                    "validators": [
                        {"pattern": r"pragma\s+solidity\s+\^?0\.8", "hint": "Add a pragma line for ^0.8.24."},
                        {"pattern": r"contract\s+ZombieFactory\s*\{", "hint": "Declare `contract ZombieFactory {`."},
                    ],
                },
                {
                    "slug": "sol-state-variables",
                    "title": "State variables and types",
                    "summary": "Where a contract keeps things, and what it costs.",
                    "body": """
A state variable lives in contract storage — permanently, on chain, paid for in
gas:

    contract ZombieFactory {
        uint dnaDigits = 16;
    }

`uint` is `uint256`: an unsigned integer up to 2²⁵⁶-1. There is no float type.
None. Money is counted in the smallest unit (wei, or satoshis in Bitcoin's case)
precisely so that no fractional arithmetic is ever needed, and dividing integers
truncates.

The types you will actually use:

- `uint` / `uint8` … `uint256` — unsigned integers
- `int` — signed, rarely needed
- `bool`
- `address` — a 20-byte account, and `address payable` if it can receive ether
- `string` and `bytes` — variable length, expensive
- `bytes32` — fixed, much cheaper than a short string

Storage is the expensive resource. Writing a new storage slot costs on the order
of 20,000 gas; reading is cheaper but not free. This is why Solidity code looks
miserly compared to ordinary programming — every variable is a running cost
somebody pays.
""",
                    "task": "Inside ZombieFactory, add a state variable `dnaDigits` of type uint set to 16, and one called `dnaModulus` set to 10 ** dnaDigits.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    uint dnaDigits = 16;\n    uint dnaModulus = 10 ** dnaDigits;\n}\n",
                    "validators": [
                        {"pattern": r"uint\s+dnaDigits\s*=\s*16", "hint": "Declare `uint dnaDigits = 16;`."},
                        {"pattern": r"uint\s+dnaModulus\s*=\s*10\s*\*\*\s*dnaDigits", "hint": "Declare `uint dnaModulus = 10 ** dnaDigits;`."},
                    ],
                },
                {
                    "slug": "sol-structs-arrays",
                    "title": "Structs and arrays",
                    "summary": "Giving a zombie a shape, and somewhere to keep them.",
                    "body": """
A struct groups fields into one type:

    struct Zombie {
        string name;
        uint dna;
    }

An array holds many of them. A public state array gets a free getter, so
anything can read `zombies(3)` without you writing a function:

    Zombie[] public zombies;

Two array flavours:

- Dynamic — `Zombie[]`, grows with `.push()`
- Fixed — `uint[16]`, size known at compile time and cheaper

A note on packing that saves real money. Storage is addressed in 32-byte slots,
and the compiler packs consecutive smaller fields into one slot — but ONLY
inside a struct, and only when they are adjacent. So this uses two slots:

    struct Bad  { uint32 a; uint256 b; uint32 c; }

and this uses one fewer:

    struct Good { uint32 a; uint32 c; uint256 b; }

Field order in a struct is a gas decision, not a style one.
""",
                    "task": "Add a `Zombie` struct with a `string name` and a `uint dna`, then a public dynamic array of them called `zombies`.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    uint dnaDigits = 16;\n    uint dnaModulus = 10 ** dnaDigits;\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    uint dnaDigits = 16;\n    uint dnaModulus = 10 ** dnaDigits;\n\n    struct Zombie {\n        string name;\n        uint dna;\n    }\n\n    Zombie[] public zombies;\n}\n",
                    "validators": [
                        {"pattern": r"struct\s+Zombie\s*\{", "hint": "Declare `struct Zombie {`."},
                        {"pattern": r"string\s+name\s*;", "hint": "The struct needs a `string name;` field."},
                        {"pattern": r"uint\s+dna\s*;", "hint": "The struct needs a `uint dna;` field."},
                        {"pattern": r"Zombie\s*\[\s*\]\s+public\s+zombies", "hint": "Declare `Zombie[] public zombies;`."},
                    ],
                },
            ],
        },
        {
            "title": "The factory",
            "blurb": "Functions, visibility, and making a zombie out of a name.",
            "chapters": [
                {
                    "slug": "sol-functions",
                    "title": "Functions and visibility",
                    "summary": "Four keywords that decide who may call what.",
                    "body": """
    function createZombie(string memory _name, uint _dna) public {
        zombies.push(Zombie(_name, _dna));
    }

Visibility is mandatory and there are four levels:

- `public` — anyone, including other contracts
- `external` — only from outside; slightly cheaper for large arguments
- `internal` — this contract and anything inheriting it
- `private` — this contract only

"Private" means other CONTRACTS cannot call it. It does not mean secret. Every
byte of contract storage is readable by anyone with a node, so a `private`
variable holding a password is a password published on a billboard. This
misunderstanding has cost people real money.

Two conventions you will see everywhere and should follow: function parameters
are prefixed with an underscore (`_name`) to distinguish them from state
variables, and functions are ordered public-then-private within a contract.

Reference types — string, arrays, structs — need a data location in the
signature. `memory` means "a copy that lives for this call only". `calldata` is
similar but read-only and cheaper, and is what `external` functions should use.
""",
                    "task": "Add a private function `_createZombie` taking `string memory _name` and `uint _dna` that pushes a new Zombie onto the array.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie {\n        string name;\n        uint dna;\n    }\n\n    Zombie[] public zombies;\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie {\n        string name;\n        uint dna;\n    }\n\n    Zombie[] public zombies;\n\n    function _createZombie(string memory _name, uint _dna) private {\n        zombies.push(Zombie(_name, _dna));\n    }\n}\n",
                    "validators": [
                        {"pattern": r"function\s+_createZombie\s*\(", "hint": "Declare `function _createZombie(...)`."},
                        {"pattern": r"string\s+memory\s+_name", "hint": "The name parameter needs the `memory` location: `string memory _name`."},
                        {"pattern": r"\bprivate\b", "hint": "Mark the function `private`."},
                        {"pattern": r"zombies\s*\.\s*push\s*\(", "hint": "Push the new Zombie onto the `zombies` array."},
                    ],
                },
                {
                    "slug": "sol-keccak",
                    "title": "Hashing, and pseudo-randomness",
                    "summary": "keccak256, and why on-chain randomness is a trap.",
                    "body": """
Solidity's hash function is `keccak256`, which takes packed bytes:

    uint rand = uint(keccak256(abi.encodePacked(_str)));

`abi.encodePacked` concatenates arguments without padding. That is efficient and
has a sharp edge worth knowing now rather than later: packing two dynamic values
is ambiguous. `("aaa", "bbb")` and `("aaab", "bb")` pack identically, so hashing
them gives the same result. When more than one argument is dynamic, use
`abi.encode` instead.

Now the important part. Hashing block data to get a random number:

    uint rand = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender)));

is NOT random. A miner chooses the timestamp, sees the result before publishing,
and can discard a block whose outcome they dislike. For a game of no value, fine
— the course uses it, and the original does too. For anything with money at
stake it is an exploit waiting to be found, and the fix is a commit-reveal
scheme or an oracle like Chainlink VRF.

Say this out loud when you write it, because the pattern gets copied out of
tutorials into production constantly.
""",
                    "task": "Add a private view function `_generateRandomDna(string memory _str)` returning a uint, which hashes the string and takes it modulo dnaModulus.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    uint dnaModulus = 10 ** 16;\n\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    uint dnaModulus = 10 ** 16;\n\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n\n    function _generateRandomDna(string memory _str) private view returns (uint) {\n        uint rand = uint(keccak256(abi.encodePacked(_str)));\n        return rand % dnaModulus;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"function\s+_generateRandomDna\s*\(", "hint": "Declare `function _generateRandomDna(...)`."},
                        {"pattern": r"keccak256\s*\(", "hint": "Use `keccak256(...)` to hash the string."},
                        {"pattern": r"returns\s*\(\s*uint", "hint": "Declare a `returns (uint)` clause."},
                        {"pattern": r"%\s*dnaModulus", "hint": "Take the hash modulo `dnaModulus` so it fits 16 digits."},
                    ],
                },
                {
                    "slug": "sol-events",
                    "title": "Events",
                    "summary": "How a contract tells the outside world anything.",
                    "body": """
A contract cannot call your front end. Events are how it leaves a message that
anything watching the chain can pick up:

    event NewZombie(uint zombieId, string name, uint dna);

    emit NewZombie(id, _name, _dna);

Events are written to the transaction's logs, which are dramatically cheaper
than storage — a few hundred gas rather than twenty thousand — because contracts
cannot read them back. That is the trade: logs are for observers, storage is for
the contract itself.

Up to three parameters can be `indexed`, which makes them filterable:

    event Transfer(address indexed from, address indexed to, uint value);

Now a wallet can ask a node for "every Transfer where `to` is me" without
scanning every block itself. Indexing costs a little more gas and is almost
always worth it on the fields people will search by.

If your front end needs to know something happened, emit an event. Polling
storage for changes is how people discover their app is slow and expensive.
""",
                    "task": "Declare a `NewZombie` event with `uint zombieId`, `string name` and `uint dna`, and emit it inside _createZombie.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n\n    function _createZombie(string memory _name, uint _dna) private {\n        zombies.push(Zombie(_name, _dna));\n    }\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    event NewZombie(uint zombieId, string name, uint dna);\n\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n\n    function _createZombie(string memory _name, uint _dna) private {\n        zombies.push(Zombie(_name, _dna));\n        uint id = zombies.length - 1;\n        emit NewZombie(id, _name, _dna);\n    }\n}\n",
                    "validators": [
                        {"pattern": r"event\s+NewZombie\s*\(", "hint": "Declare `event NewZombie(uint zombieId, string name, uint dna);`."},
                        {"pattern": r"emit\s+NewZombie\s*\(", "hint": "Use `emit NewZombie(...)` inside _createZombie."},
                        {"pattern": r"zombies\s*\.\s*length", "hint": "The new zombie's id is `zombies.length - 1` after the push."},
                    ],
                },
            ],
        },
        {
            "title": "Ownership",
            "blurb": "Tying zombies to people, and keeping other people out.",
            "chapters": [
                {
                    "slug": "sol-mappings",
                    "title": "Mappings and msg.sender",
                    "summary": "Who owns what, and who is calling.",
                    "body": """
A mapping is a key-value store:

    mapping(uint => address) public zombieToOwner;
    mapping(address => uint) ownerZombieCount;

Mappings are not iterable and have no length. Every possible key exists and
returns the zero value, so there is no distinction between "not set" and "set to
zero" — a fact that causes real bugs. If you need to know whether a key was ever
written, store a companion `mapping(uint => bool) exists`.

`msg.sender` is the address that called this function. It is always available,
cannot be faked, and is the basis of every ownership check in Solidity:

    zombieToOwner[id] = msg.sender;
    ownerZombieCount[msg.sender]++;

One caution that bites people: if a contract calls your contract, `msg.sender`
is that CONTRACT's address, not the human behind it. `tx.origin` gives the
original external account — and using it for authorisation is a well-known
vulnerability, because any contract you interact with can then act as you.
Use `msg.sender`. Always.
""",
                    "task": "Add `zombieToOwner` (uint to address, public) and `ownerZombieCount` (address to uint), and set both in _createZombie.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n\n    function _createZombie(string memory _name, uint _dna) private {\n        zombies.push(Zombie(_name, _dna));\n        uint id = zombies.length - 1;\n    }\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n\n    mapping(uint => address) public zombieToOwner;\n    mapping(address => uint) ownerZombieCount;\n\n    function _createZombie(string memory _name, uint _dna) private {\n        zombies.push(Zombie(_name, _dna));\n        uint id = zombies.length - 1;\n        zombieToOwner[id] = msg.sender;\n        ownerZombieCount[msg.sender]++;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"mapping\s*\(\s*uint\s*=>\s*address\s*\)", "hint": "Declare `mapping(uint => address) public zombieToOwner;`."},
                        {"pattern": r"mapping\s*\(\s*address\s*=>\s*uint\s*\)", "hint": "Declare `mapping(address => uint) ownerZombieCount;`."},
                        {"pattern": r"msg\s*\.\s*sender", "hint": "Use `msg.sender` to record the caller as the owner."},
                    ],
                },
                {
                    "slug": "sol-require",
                    "title": "require, revert and custom errors",
                    "summary": "Refusing to do something, and giving the reason back.",
                    "body": """
`require` checks a condition and reverts the whole transaction if it fails:

    require(ownerZombieCount[msg.sender] == 0, "you already have a zombie");

A revert undoes every state change in the transaction — all or nothing, always.
Gas already burned is not refunded, but nothing is left half-done. That property
is why Solidity code can be written without the defensive rollback logic an
ordinary database application needs.

Since 0.8.4 there are custom errors, which are strictly better for anything
non-trivial:

    error AlreadyHasZombie(address who);

    if (ownerZombieCount[msg.sender] != 0) revert AlreadyHasZombie(msg.sender);

A string message is stored in the contract bytecode and costs gas per character
to deploy and to return. A custom error is a 4-byte selector plus its arguments —
much cheaper, and it can carry structured data a front end can actually act on.

Use `require` for input validation, `assert` only for invariants you believe can
never fail (it signals a bug rather than bad input), and custom errors wherever
you would otherwise write a long string.
""",
                    "task": "Add a public function `createRandomZombie(string memory _name)` that requires the caller has no zombies yet, then creates one.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n    mapping(address => uint) ownerZombieCount;\n\n    function _createZombie(string memory _name, uint _dna) private {}\n    function _generateRandomDna(string memory _str) private view returns (uint) { return 0; }\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n    mapping(address => uint) ownerZombieCount;\n\n    function _createZombie(string memory _name, uint _dna) private {}\n    function _generateRandomDna(string memory _str) private view returns (uint) { return 0; }\n\n    function createRandomZombie(string memory _name) public {\n        require(ownerZombieCount[msg.sender] == 0, \"you already have a zombie\");\n        uint randDna = _generateRandomDna(_name);\n        _createZombie(_name, randDna);\n    }\n}\n",
                    "validators": [
                        {"pattern": r"function\s+createRandomZombie\s*\(", "hint": "Declare `function createRandomZombie(string memory _name) public`."},
                        {"pattern": r"require\s*\(", "hint": "Use `require(...)` to refuse a second zombie."},
                        {"pattern": r"ownerZombieCount\s*\[\s*msg\s*\.\s*sender\s*\]\s*==\s*0", "hint": "Check `ownerZombieCount[msg.sender] == 0`."},
                        {"pattern": r"_createZombie\s*\(", "hint": "Call `_createZombie(...)` once the check passes."},
                    ],
                },
                {
                    "slug": "sol-inheritance",
                    "title": "Inheritance and Ownable",
                    "summary": "Splitting a contract up, and the owner pattern.",
                    "body": """
Contracts inherit with `is`:

    contract ZombieFeeding is ZombieFactory {
    }

The child gets every public and internal member of the parent. This is how the
game is built: a chain of contracts, each adding one capability, with the last
one deployed as the whole thing. It keeps files readable and it keeps each
concern in one place.

The commonest inherited contract is Ownable, which gives you an owner and a
modifier restricting functions to them. In practice you import OpenZeppelin's
rather than writing your own:

    import "@openzeppelin/contracts/access/Ownable.sol";

    contract ZombieHelper is Ownable {
        constructor() Ownable(msg.sender) {}
    }

Two things worth internalising. First, `constructor` runs exactly once, at
deployment, and is where an owner gets set. Second — an owner is a centralisation
point. A contract with an owner who can pause it, change fees or drain it is not
trustless, and pretending otherwise in your documentation is how projects lose
their users' goodwill. If you keep an owner, say what they can do.
""",
                    "task": "Declare `contract ZombieFeeding is ZombieFactory` with a `feedAndMultiply` internal function taking a zombie id and a target dna.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n    function _createZombie(string memory _name, uint _dna) internal {}\n}\n\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n    function _createZombie(string memory _name, uint _dna) internal {}\n}\n\ncontract ZombieFeeding is ZombieFactory {\n    function feedAndMultiply(uint _zombieId, uint _targetDna) internal {\n        Zombie storage myZombie = zombies[_zombieId];\n        uint newDna = (myZombie.dna + _targetDna) / 2;\n        _createZombie(\"NoName\", newDna);\n    }\n}\n",
                    "validators": [
                        {"pattern": r"contract\s+ZombieFeeding\s+is\s+ZombieFactory", "hint": "Declare `contract ZombieFeeding is ZombieFactory {`."},
                        {"pattern": r"function\s+feedAndMultiply\s*\(", "hint": "Declare `function feedAndMultiply(uint _zombieId, uint _targetDna)`."},
                        {"pattern": r"\binternal\b", "hint": "Mark it `internal` — only this contract and its children should call it."},
                    ],
                },
                {
                    "slug": "sol-modifiers",
                    "title": "Modifiers",
                    "summary": "Reusing a check across many functions.",
                    "body": """
A modifier wraps a function with a check:

    modifier onlyOwnerOf(uint _zombieId) {
        require(msg.sender == zombieToOwner[_zombieId], "not your zombie");
        _;
    }

    function changeName(uint _zombieId, string calldata _newName)
        external
        onlyOwnerOf(_zombieId)
    {
        zombies[_zombieId].name = _newName;
    }

The `_;` is where the function body runs. Code before it runs first; code after
it runs on the way out, which is how a reentrancy guard works:

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

Modifiers can take arguments, and they stack — several on one function run in
the order written. Keep them small and about authorisation or invariants; a
modifier containing business logic hides the thing a reader most needs to see.
""",
                    "task": "Add an `onlyOwnerOf` modifier that requires msg.sender owns the zombie, and use it on a `changeName` function.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieHelper {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n    mapping(uint => address) public zombieToOwner;\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieHelper {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n    mapping(uint => address) public zombieToOwner;\n\n    modifier onlyOwnerOf(uint _zombieId) {\n        require(msg.sender == zombieToOwner[_zombieId], \"not your zombie\");\n        _;\n    }\n\n    function changeName(uint _zombieId, string calldata _newName)\n        external\n        onlyOwnerOf(_zombieId)\n    {\n        zombies[_zombieId].name = _newName;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"modifier\s+onlyOwnerOf\s*\(", "hint": "Declare `modifier onlyOwnerOf(uint _zombieId) {`."},
                        {"pattern": r"_\s*;", "hint": "A modifier needs `_;` to mark where the function body runs."},
                        {"pattern": r"function\s+changeName\s*\(", "hint": "Declare `function changeName(...)`."},
                        {"pattern": r"onlyOwnerOf\s*\(\s*_zombieId\s*\)", "hint": "Apply `onlyOwnerOf(_zombieId)` to changeName."},
                    ],
                },
            ],
        },
        {
            "title": "Storage, memory and gas",
            "blurb": "The part that separates code that works from code you can afford.",
            "chapters": [
                {
                    "slug": "sol-storage-memory",
                    "title": "Storage versus memory",
                    "summary": "One keyword that decides whether your write persists.",
                    "body": """
    Zombie storage myZombie = zombies[_zombieId];   // a reference
    myZombie.dna = 42;                               // changes the chain

    Zombie memory copy = zombies[_zombieId];        // a copy
    copy.dna = 42;                                   // changes nothing

`storage` is a pointer into permanent state. `memory` is a temporary copy that
vanishes at the end of the call. Choosing the wrong one is the single commonest
beginner bug in Solidity, and it fails SILENTLY — the code compiles, runs,
returns, and simply did not save anything.

Rules of thumb:

- Modifying state? `storage`.
- Reading a struct once, or passing it around? `memory` — copying is cheaper
  than repeated storage reads.
- A function parameter you will not modify, on an `external` function?
  `calldata` — cheapest of all, because it is read directly from the
  transaction without being copied anywhere.

Locations are required on reference types (structs, arrays, strings, mappings)
and forbidden on value types (uint, bool, address), which is why the compiler
nags about it in exactly the places it matters.
""",
                    "task": "Write `levelUp(uint _zombieId)` that increments the zombie's level in STORAGE so the change persists.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieHelper {\n    struct Zombie { string name; uint dna; uint32 level; }\n    Zombie[] public zombies;\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieHelper {\n    struct Zombie { string name; uint dna; uint32 level; }\n    Zombie[] public zombies;\n\n    function levelUp(uint _zombieId) external {\n        Zombie storage myZombie = zombies[_zombieId];\n        myZombie.level++;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"function\s+levelUp\s*\(", "hint": "Declare `function levelUp(uint _zombieId)`."},
                        {"pattern": r"Zombie\s+storage\s+", "hint": "Take a `Zombie storage` reference — `memory` would discard the change."},
                        {"pattern": r"level\s*(\+\+|\+=)", "hint": "Increment the level."},
                    ],
                },
                {
                    "slug": "sol-view-pure",
                    "title": "view, pure and gas",
                    "summary": "Which functions are free, and which are not.",
                    "body": """
    function getLevel(uint _id) external view returns (uint32) { ... }  // reads state
    function double(uint _n) external pure returns (uint) { return _n * 2; }  // reads nothing

- `view` — reads state, does not write it
- `pure` — neither reads nor writes
- neither — may write state, costs gas, needs a transaction

The saving is real but conditional: calling a `view` function from OUTSIDE the
chain is free, because your node just runs it locally and answers. Calling it
from inside another transaction still costs gas, because it is executing on
every node in the network. "View functions are free" is true exactly half the
time, and the half people get wrong is the expensive one.

Gas facts worth carrying:

- Writing a fresh storage slot: about 20,000 gas. Overwriting: about 5,000.
- Zeroing a slot refunds gas — deleting is cheaper than you expect.
- Loops over unbounded arrays are the classic denial-of-service bug: the array
  grows until the function no longer fits in a block, and it is stuck forever.
  Bound your loops or paginate.
- `external` with `calldata` beats `public` with `memory` for large arguments.
""",
                    "task": "Write a `getZombiesByOwner(address _owner)` view function returning a uint[] memory of the owner's zombie ids.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieHelper {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n    mapping(uint => address) public zombieToOwner;\n    mapping(address => uint) ownerZombieCount;\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieHelper {\n    struct Zombie { string name; uint dna; }\n    Zombie[] public zombies;\n    mapping(uint => address) public zombieToOwner;\n    mapping(address => uint) ownerZombieCount;\n\n    function getZombiesByOwner(address _owner) external view returns (uint[] memory) {\n        uint[] memory result = new uint[](ownerZombieCount[_owner]);\n        uint counter = 0;\n        for (uint i = 0; i < zombies.length; i++) {\n            if (zombieToOwner[i] == _owner) {\n                result[counter] = i;\n                counter++;\n            }\n        }\n        return result;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"function\s+getZombiesByOwner\s*\(", "hint": "Declare `function getZombiesByOwner(address _owner)`."},
                        {"pattern": r"\bview\b", "hint": "Mark it `view` — it reads state but never writes."},
                        {"pattern": r"returns\s*\(\s*uint\s*\[\s*\]\s*memory", "hint": "Return `uint[] memory`."},
                        {"pattern": r"new\s+uint\s*\[\s*\]\s*\(", "hint": "Allocate the array with `new uint[](...)` — memory arrays are fixed size."},
                    ],
                },
                {
                    "slug": "sol-time",
                    "title": "Time and cooldowns",
                    "summary": "block.timestamp, and how far to trust it.",
                    "body": """
    uint32 readyTime;

    function _triggerCooldown(Zombie storage _zombie) internal {
        _zombie.readyTime = uint32(block.timestamp + 1 days);
    }

    function _isReady(Zombie storage _zombie) internal view returns (bool) {
        return _zombie.readyTime <= block.timestamp;
    }

`block.timestamp` is seconds since the epoch, set by whoever mined the block.
Solidity gives you `seconds`, `minutes`, `hours`, `days` and `weeks` as literal
suffixes, which is much clearer than counting zeros.

The caveat: a miner can nudge the timestamp by a few seconds. For a one-day
cooldown that is irrelevant. For anything where a 15-second difference decides
who wins money, it is an attack. The rule is the same as for randomness — the
question is not "is this exact" but "what does an attacker gain by moving it".

`uint32` holds timestamps until 2106, which is why the struct uses it: two
uint32 fields pack into the same storage slot as one uint256, and on a struct
you create for every player that is a meaningful saving.
""",
                    "task": "Add a `readyTime` uint32 to the struct, plus `_triggerCooldown` and `_isReady` internal functions using `1 days`.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFeeding {\n    struct Zombie { string name; uint dna; uint32 level; }\n    Zombie[] public zombies;\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFeeding {\n    struct Zombie { string name; uint dna; uint32 level; uint32 readyTime; }\n    Zombie[] public zombies;\n\n    function _triggerCooldown(Zombie storage _zombie) internal {\n        _zombie.readyTime = uint32(block.timestamp + 1 days);\n    }\n\n    function _isReady(Zombie storage _zombie) internal view returns (bool) {\n        return _zombie.readyTime <= block.timestamp;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"uint32\s+readyTime", "hint": "Add `uint32 readyTime;` to the struct."},
                        {"pattern": r"function\s+_triggerCooldown\s*\(", "hint": "Declare `function _triggerCooldown(Zombie storage _zombie) internal`."},
                        {"pattern": r"1\s+days", "hint": "Use the `1 days` time literal."},
                        {"pattern": r"function\s+_isReady\s*\(", "hint": "Declare `function _isReady(...) internal view returns (bool)`."},
                    ],
                },
            ],
        },
        {
            "title": "Talking to the world",
            "blurb": "Other contracts, ether, and the front end.",
            "chapters": [
                {
                    "slug": "sol-interfaces",
                    "title": "Interfaces",
                    "summary": "Calling a contract you did not write.",
                    "body": """
To call another contract you declare the shape of what you are calling:

    interface KittyInterface {
        function getKitty(uint256 _id) external view returns (uint256 genes);
    }

    KittyInterface kittyContract = KittyInterface(_address);
    uint genes = kittyContract.getKitty(_id);

An interface declares signatures with no bodies. It is not deployed; it exists
so the compiler can encode a call correctly. If your interface disagrees with
the real contract, the call fails at runtime — and often silently, returning
empty data that decodes to zero.

The safety rule that matters here: every external call hands control to code you
do not control. It can call back into you before returning, which is reentrancy —
the bug behind the DAO hack. Follow checks-effects-interactions:

    require(balance[msg.sender] >= amount);   // checks
    balance[msg.sender] -= amount;            // effects, BEFORE the call
    (bool ok,) = msg.sender.call{value: amount}("");   // interactions
    require(ok);

Update your state before you call out, not after. That single ordering closes
most of it.
""",
                    "task": "Declare a `KittyInterface` with a `getKitty(uint256)` view function returning a uint256, and a state variable holding one.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\n\ncontract ZombieFeeding {\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ninterface KittyInterface {\n    function getKitty(uint256 _id) external view returns (uint256 genes);\n}\n\ncontract ZombieFeeding {\n    KittyInterface kittyContract;\n\n    function setKittyContractAddress(address _address) external {\n        kittyContract = KittyInterface(_address);\n    }\n}\n",
                    "validators": [
                        {"pattern": r"interface\s+KittyInterface\s*\{", "hint": "Declare `interface KittyInterface {`."},
                        {"pattern": r"function\s+getKitty\s*\(", "hint": "Declare `function getKitty(uint256 _id) external view returns (uint256);`."},
                        {"pattern": r"KittyInterface\s+\w+\s*;", "hint": "Add a state variable of type KittyInterface."},
                    ],
                },
                {
                    "slug": "sol-payable",
                    "title": "payable and withdrawing",
                    "summary": "Taking ether, and getting it back out safely.",
                    "body": """
A function that receives ether must be `payable`:

    uint levelUpFee = 0.001 ether;

    function levelUp(uint _zombieId) external payable {
        require(msg.value == levelUpFee, "wrong fee");
        zombies[_zombieId].level++;
    }

`msg.value` is how much was sent, in wei. `0.001 ether` is a literal the
compiler converts for you. The contract's own balance is
`address(this).balance`.

Getting ether out is where contracts have historically failed. Three ways to
send, and only one is currently recommended:

    payable(to).transfer(amount);   // 2300 gas, reverts on failure — AVOID
    payable(to).send(amount);       // 2300 gas, returns false — AVOID
    (bool ok,) = to.call{value: amount}("");  // forwards all gas
    require(ok, "send failed");

`transfer` and `send` were the advice for years, and the 2300-gas stipend was
meant to prevent reentrancy. Then gas costs changed and the stipend started
breaking legitimate recipients — smart-contract wallets in particular. The
modern answer is `call`, with a reentrancy guard doing the job the stipend used
to. Some compilers refuse `.transfer` outright, which tells you how settled
this advice is.

Better still is the withdrawal pattern: rather than pushing funds to people,
record what they are owed and let them pull it.
""",
                    "task": "Add a `levelUpFee`, a payable `levelUp` requiring the exact fee, and an owner-only `withdraw` using `call`.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieHelper {\n    address public owner = msg.sender;\n    struct Zombie { string name; uint dna; uint32 level; }\n    Zombie[] public zombies;\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieHelper {\n    address public owner = msg.sender;\n    struct Zombie { string name; uint dna; uint32 level; }\n    Zombie[] public zombies;\n\n    uint levelUpFee = 0.001 ether;\n\n    function levelUp(uint _zombieId) external payable {\n        require(msg.value == levelUpFee, \"wrong fee\");\n        zombies[_zombieId].level++;\n    }\n\n    function withdraw() external {\n        require(msg.sender == owner, \"not owner\");\n        (bool ok, ) = payable(owner).call{value: address(this).balance}(\"\");\n        require(ok, \"withdraw failed\");\n    }\n}\n",
                    "validators": [
                        {"pattern": r"levelUpFee\s*=\s*0\.001\s+ether", "hint": "Declare `uint levelUpFee = 0.001 ether;`."},
                        {"pattern": r"function\s+levelUp\s*\([^)]*\)\s*external\s+payable", "hint": "`levelUp` must be `external payable` to receive ether."},
                        {"pattern": r"msg\s*\.\s*value", "hint": "Check `msg.value` against the fee."},
                        {"pattern": r"call\s*\{\s*value\s*:", "hint": "Withdraw with `call{value: ...}(\"\")`, not `.transfer`."},
                    ],
                },
                {
                    "slug": "sol-erc721",
                    "title": "ERC-721: making zombies tradeable",
                    "summary": "The standard that turns your struct into an NFT.",
                    "body": """
A token standard is an agreed interface. Implement it and every wallet,
marketplace and explorer already knows how to handle your contract:

    function balanceOf(address _owner) external view returns (uint256);
    function ownerOf(uint256 _tokenId) external view returns (address);
    function transferFrom(address _from, address _to, uint256 _tokenId) external;
    function approve(address _approved, uint256 _tokenId) external;

    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);
    event Approval(address indexed _owner, address indexed _approved, uint256 indexed _tokenId);

ERC-721 is the non-fungible one: every token id is distinct, which is exactly
what a zombie is. ERC-20 is the fungible one, where tokens are interchangeable.

Two things to get right:

- Emit `Transfer` on every ownership change, including minting (from the zero
  address). Explorers and marketplaces build their entire view of ownership from
  those events, so a mint that does not emit one is a token nobody can see.
- Use `safeTransferFrom` in production. Plain `transferFrom` to a contract that
  does not know about NFTs locks the token there permanently, and it has
  happened to real collections.

In practice, inherit OpenZeppelin's ERC721 rather than implementing it. The
value of writing it once by hand is understanding what you are inheriting.
""",
                    "task": "Implement `balanceOf` and `ownerOf` against the mappings, and emit a Transfer event in a `_transfer` internal function.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieOwnership {\n    mapping(uint => address) public zombieToOwner;\n    mapping(address => uint) ownerZombieCount;\n\n    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);\n\n}\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieOwnership {\n    mapping(uint => address) public zombieToOwner;\n    mapping(address => uint) ownerZombieCount;\n\n    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);\n\n    function balanceOf(address _owner) external view returns (uint256) {\n        return ownerZombieCount[_owner];\n    }\n\n    function ownerOf(uint256 _tokenId) external view returns (address) {\n        return zombieToOwner[_tokenId];\n    }\n\n    function _transfer(address _from, address _to, uint256 _tokenId) internal {\n        ownerZombieCount[_to]++;\n        ownerZombieCount[_from]--;\n        zombieToOwner[_tokenId] = _to;\n        emit Transfer(_from, _to, _tokenId);\n    }\n}\n",
                    "validators": [
                        {"pattern": r"function\s+balanceOf\s*\(", "hint": "Implement `balanceOf(address) external view returns (uint256)`."},
                        {"pattern": r"function\s+ownerOf\s*\(", "hint": "Implement `ownerOf(uint256) external view returns (address)`."},
                        {"pattern": r"function\s+_transfer\s*\(", "hint": "Add an internal `_transfer(address,address,uint256)`."},
                        {"pattern": r"emit\s+Transfer\s*\(", "hint": "Emit the `Transfer` event — explorers build ownership from it."},
                    ],
                },
                {
                    "slug": "sol-deploying",
                    "title": "Deploying it",
                    "summary": "From a file on your machine to an address on a chain.",
                    "body": """
You now have the whole game. To put it somewhere:

- Testnet first, always. Sepolia costs nothing and behaves like
  mainnet. A contract cannot be patched after deployment — you can only deploy a
  new one and persuade everyone to move.
- Compile with the settings you will actually deploy with. Optimiser on or off
  changes the bytecode, and a verified contract must match exactly.
- Verify the source on the explorer. An unverified contract is a black box, and
  asking people to trust one is asking a lot.

This site has a contracts console at Admin → Contracts that deploys through your
own wallet, and the arcade's CryptoZombies game runs the finished version of a
contract very like this one on Ethereum mainnet.

Before you deploy anything holding real value, sit with this list:

- Is every external call after the state changes it depends on?
- Is any loop unbounded?
- Can the owner do something users would not expect? Is it documented?
- What happens if a function is called twice in the same block?
- Have you tested the failure paths, not just the happy one?

Most exploited contracts were not exotic. They were ordinary code where one of
those five questions had not been asked.
""",
                    "task": "Assemble the final contract: ZombieOwnership inheriting the chain, with a constructor setting the owner.",
                    "starter": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\n// Bring the pieces together.\n",
                    "solution": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\ncontract ZombieFactory {\n    address public owner;\n    constructor() { owner = msg.sender; }\n}\n\ncontract ZombieFeeding is ZombieFactory {}\ncontract ZombieHelper is ZombieFeeding {}\ncontract ZombieAttack is ZombieHelper {}\ncontract ZombieOwnership is ZombieAttack {}\n",
                    "validators": [
                        {"pattern": r"contract\s+ZombieOwnership\s+is\s+\w+", "hint": "Declare `contract ZombieOwnership is ...` at the end of the chain."},
                        {"pattern": r"constructor\s*\(", "hint": "Add a `constructor()` that records the deployer."},
                        {"pattern": r"owner\s*=\s*msg\s*\.\s*sender", "hint": "Set `owner = msg.sender;` in the constructor."},
                    ],
                },
            ],
        },
    ],
}
