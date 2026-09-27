"""AP Computer Science Principles: the five big ideas, taught here.

WHERE THE OUTLINE CAME FROM
---------------------------
The unit structure follows the College Board's published AP CSP course framework
— five big ideas (Creative Development, Data, Algorithms and Programming,
Computer Systems and Networks, Impact of Computing) and the topics under them.
A syllabus is a published specification, not authorship.

Every lesson below is written for this site. Nothing is taken from
csplusplus.com/csp or from any other course's materials.

WHAT THIS COURSE IS FOR
-----------------------
CSP is the breadth course: it asks what computing IS and what it does to people,
and it uses programming as one tool among several rather than as the point. So
these lessons are deliberately conceptual, and the programming ones use
pseudocode close to the exam's rather than any real language — the exam is
language-agnostic and picking one would teach syntax nobody is being assessed on.

The vocabulary section carries the 205 terms this course uses; chapters here
link into it rather than redefining words in place.
"""

REFERENCE = "https://csplusplus.com/csp"

BOOK = {
    "slug": "csp",
    "title": "AP CSP",
    "reference": REFERENCE,
    "reference_name": "csplusplus.com/csp",
    "provenance": (
        "Written for this site, following the College Board's published AP CSP "
        "course framework. The lessons are ours; the syllabus is the exam's. "
        "Another treatment of the same course:"
    ),
    "subtitle": "Computer Science Principles: what computing is, and what it does to people.",
    "blurb": (
        "The five big ideas of AP CSP, in order. It is the breadth course — "
        "programming is one tool here, not the subject — so it runs from how a "
        "number becomes bits to who gets harmed when a system is deployed badly."
    ),
    "parts": [
        {
            "title": "Creative Development",
            "blurb": "How programs get made, and by whom.",
            "chapters": [
                {
                    "slug": "csp-collaboration",
                    "title": "Collaboration",
                    "summary": "Why software is a team activity even when one person writes it.",
                    "body": """
Programs are read far more often than they are written, and almost always by
someone other than the author — including the author six months later, who has
forgotten everything.

That single fact drives most of what looks like ceremony in software:

- Comments explain WHY. The what is already in the code; the reasoning behind it
  is the part that is lost.
- Naming is documentation. `daysUntilExpiry` needs no comment; `d` needs a
  paragraph.
- Consistent style removes a decision from every line, so attention goes to the
  logic instead.

Collaboration also changes what "good" means. Code that is clever in a way only
its author understands is a liability on a team, however elegant. The version
that a stranger can modify without fear is better, even when it is longer.

The wider point the course keeps returning to: a group with different
backgrounds catches problems a uniform group does not. Not as a nicety — as a
practical matter of noticing failure modes that do not affect you personally.
""",
                    "checks": [
                        "Why does the reader matter more than the writer in code style?",
                        "Give an example of a bug a homogeneous team is likely to miss.",
                    ],
                },
                {
                    "slug": "csp-program-design",
                    "title": "Program design and purpose",
                    "summary": "Deciding what you are building before you build it.",
                    "body": """
Every program has a purpose that can be stated in a sentence. Writing that
sentence first is not bureaucracy — it is the thing every later decision gets
judged against, and a project that cannot produce it is usually a project that
has not decided what it is.

The development cycle is investigate, design, implement, test, and then round
again:

- Investigate — who is this for, and what do they actually do now?
- Design — what are the inputs, the outputs, and the parts?
- Implement — build it in pieces small enough to test.
- Test — including the inputs you hope nobody enters.

Incremental and iterative are the two words the course uses for this. Build a
small working thing and grow it, rather than assembling everything and
discovering at the end that a foundational assumption was wrong.

Program input is not only what a user types: it includes files, sensors,
network responses and the clock. Program output is not only the display. Naming
both fully, early, is how you find the parts you had not thought about.
""",
                    "checks": [
                        "What is the difference between incremental and iterative?",
                        "Name three kinds of program input that are not typed by a user.",
                    ],
                },
                {
                    "slug": "csp-errors",
                    "title": "Errors and debugging",
                    "summary": "Four kinds of wrong, and which one should frighten you.",
                    "body": """
- Syntax error — the code breaks the language's grammar. It will not run, and
  the tool tells you where. The friendliest kind.
- Run-time error — it starts, then fails: dividing by zero, reading past the end
  of a list. Loud, and it points at the line.
- Logical error — it runs perfectly and produces the wrong answer. Nothing
  announces it. This is the one to be afraid of.
- Overflow error — a value exceeds what its bits can hold and silently wraps.

Debugging is narrowing down where your BELIEF about the code stopped matching
what it does. The techniques all serve that:

- Print or display values at points where you have a firm expectation.
- Test with the smallest input that still shows the problem.
- Change one thing at a time — two changes and a fix tells you nothing.
- Read the error message. All of it. It is usually more specific than the guess
  you are about to act on instead.

The habit worth building: when something works and you do not know why, that is
also a bug. You just have not been billed for it yet.
""",
                    "checks": [
                        "Why is a logical error more dangerous than a run-time error?",
                        "Why change only one thing at a time when debugging?",
                    ],
                },
            ],
        },
        {
            "title": "Data",
            "blurb": "Turning the world into numbers, and what that costs.",
            "chapters": [
                {
                    "slug": "csp-binary",
                    "title": "Binary and number bases",
                    "summary": "Why two digits, and how to read them.",
                    "body": """
Computers use base 2 because a circuit can reliably distinguish two states —
roughly, voltage or no voltage. Ten states would need ten reliably distinct
levels, and noise would ruin it.

Reading binary is positional, exactly like decimal:

    1 0 1 1  =  8 + 0 + 2 + 1  =  11
    8 4 2 1

Converting decimal to binary: repeatedly halve, recording remainders, then read
them backwards. Or subtract the largest power of two that fits, and repeat.

Hexadecimal exists because binary is unreadable in bulk. One hex digit is
exactly four bits, so `1111 0000` is `F0` — shorter, and losslessly convertible
by eye once you know the sixteen patterns.

Bits and bytes:

- A bit is one binary digit.
- A byte is eight bits, so 256 possible values.
- n bits give 2ⁿ combinations, which is the formula behind almost every "how
  many can we have" question in computing — colours, addresses, characters.
""",
                    "checks": [
                        "How many distinct values can 10 bits represent?",
                        "Why is hexadecimal convenient specifically for binary?",
                    ],
                },
                {
                    "slug": "csp-representation",
                    "title": "Representing text, colour and sound",
                    "summary": "Everything is a number, once you agree on the mapping.",
                    "body": """
Text. A character encoding is an agreed table from characters to numbers. ASCII
covered 128 characters, which was enough for English and nothing else. Unicode
replaced it with a code point for essentially every writing system, encoded on
disk as UTF-8.

Colour. RGB stores the intensity of red, green and blue, usually one byte each —
so 256³, about 16.7 million colours. A pixel is one addressable dot; an image is
a grid of them, which is why doubling the width and height quadruples the file.

Sound. A continuous wave is SAMPLED — measured at intervals — and each sample
stored as a number. Two knobs: the sample rate (how often) and the bit depth
(how precisely). Both decide what survives, and what is discarded is discarded
permanently.

The unifying idea: analog data varies continuously and digital data is discrete.
Digitising always means choosing a resolution, and that choice is where the
losses are. More bits means more fidelity and more storage, and there is no
setting that gives you both.
""",
                    "checks": [
                        "What are the two knobs that determine audio quality when sampling?",
                        "Why can digitising analog data never be perfectly faithful?",
                    ],
                },
                {
                    "slug": "csp-compression",
                    "title": "Compression",
                    "summary": "Lossless, lossy, and when each is the wrong choice.",
                    "body": """
Compression re-encodes data to take less space by exploiting the fact that real
data repeats itself.

Lossless — the original can be reconstructed exactly. Run-length encoding is the
clearest example: `AAAAABBB` becomes `5A3B`. Brilliant on flat images and
diagrams, and on random data it makes the file LARGER, because there are no runs
and you have added counts.

Lossy — information is thrown away permanently to save more space. JPEG and MP3
discard detail chosen to be hard for people to notice.

Choosing between them is not a preference, it is a requirement:

- Text, code, spreadsheets, archives → lossless. One changed byte is a different
  program or a different number.
- Photos, music, video → lossy, usually. The saving is large and the loss is
  designed to be imperceptible.

Two traps worth knowing. Lossy compression applied repeatedly degrades
cumulatively — each save discards more. And no compression scheme shrinks every
input; if it shrinks some, it must enlarge others, which is a counting argument
rather than an engineering limitation.
""",
                    "checks": [
                        "When does run-length encoding make a file bigger?",
                        "Why can no compression algorithm shrink every possible input?",
                    ],
                },
                {
                    "slug": "csp-data-analysis",
                    "title": "Working with data",
                    "summary": "Finding patterns, and the mistake everyone makes.",
                    "body": """
Data becomes information when someone interprets it. The interpretation is where
value and error both enter.

Metadata is data about data — when a photo was taken, where, on which device. It
is often more revealing than the content, and it is routinely forgotten when
people think about what they are sharing.

Big data means datasets large or fast enough that the size itself changes what
techniques work. Scale brings power and two specific hazards:

- Correlation is not causation. Two things moving together says nothing about
  which causes which, or whether a third thing causes both. This is the single
  most common error in data reasoning and it is made constantly by people who
  know better.
- Bias enters through collection. A dataset gathered from one group describes
  that group. A model built on it will work worst for whoever was missing, and
  it will do so confidently.

Cleaning data — filtering, deduplicating, fixing formats — is most of the work
and every cleaning decision is a judgement that shapes the conclusion.
""",
                    "checks": [
                        "Give an example where correlation clearly does not imply causation.",
                        "How does a gap in collection become a biased result?",
                    ],
                },
            ],
        },
        {
            "title": "Algorithms and Programming",
            "blurb": "The largest big idea, and the one the exam weights most.",
            "chapters": [
                {
                    "slug": "csp-variables",
                    "title": "Variables, expressions and assignment",
                    "summary": "Storing values, and the operator everyone misreads.",
                    "body": """
A variable is a named place to store a value that can change. Assignment puts a
value into it:

    total ← 0
    total ← total + 5

The second line reads oddly until you internalise that assignment is not
equality. The right side is evaluated first, then stored. `total ← total + 5`
means "work out total plus five, then make that the new total".

Types you will use: numbers, strings, booleans, and lists.

Operators divide into three groups:

- Arithmetic — `+ - * /` and MOD, the remainder. MOD is the standard way to test
  divisibility (`n MOD 2 = 0` means even) and to wrap a value into a range.
- Comparison — produce a boolean.
- Logical — AND, OR, NOT, combining booleans.

Strings concatenate rather than add: joining "2" and "3" gives "23", not 5. The
`+` symbol doing two jobs is a deliberate convenience and a reliable source of
confusion.
""",
                    "checks": [
                        "What does `x ← x + 1` actually do, step by step?",
                        "How would you test whether a number is divisible by 3?",
                    ],
                },
                {
                    "slug": "csp-control",
                    "title": "Sequence, selection, iteration",
                    "summary": "Three structures, and every program ever written.",
                    "body": """
Every program is built from exactly three control structures:

- Sequence — statements run in order, one after another.
- Selection — a condition chooses between paths (IF / ELSE).
- Iteration — a block repeats, a fixed number of times or until a condition
  changes.

That is the whole vocabulary. Anything more elaborate is these three composed.

Selection nests, and nesting is where bugs live. Conditions are evaluated in
order, so an earlier branch that overlaps a later one means the later one never
runs. When a chain of IFs behaves oddly, check whether an earlier condition is
quietly catching the case.

Iteration has one failure mode above all others: the loop that never ends,
because the condition it tests is never changed inside it. If you write a
condition, ask immediately what changes it.

Off-by-one errors are the other classic — looping one time too many or too few.
They come from being unclear whether a bound is inclusive, and the cure is to
say so out loud before writing the loop.
""",
                    "checks": [
                        "Why might a later branch of an IF chain never execute?",
                        "What is the first thing to check on an infinite loop?",
                    ],
                },
                {
                    "slug": "csp-lists",
                    "title": "Lists and traversal",
                    "summary": "Many values under one name.",
                    "body": """
A list holds an ordered collection of values, each reachable by its index. It
turns "fifty variables" into one thing you can loop over, which is what makes
general-purpose programs possible: the code no longer depends on how many items
there are.

Traversal means visiting every element in turn. It is the pattern behind almost
every list operation — summing, counting matches, finding a maximum, filtering.

The pitfalls are consistent across languages:

- Where the index starts. Some languages count from 0, some from 1, and the
  exam's pseudocode starts at 1. Assuming wrongly gives an off-by-one every
  time.
- Modifying a list while looping over it. Removing an element shifts everything
  after it, so a straightforward loop then skips items.
- Going past the end. Reading index n+1 of an n-element list is a run-time
  error.

The list is also the first place abstraction becomes concrete: `sum(scores)`
says what you mean, and the loop that implements it becomes somebody else's
problem.
""",
                    "checks": [
                        "Why does removing items while looping forwards skip elements?",
                        "What does a list let you write that separate variables cannot?",
                    ],
                },
                {
                    "slug": "csp-procedures",
                    "title": "Procedures and abstraction",
                    "summary": "Naming a block of code, and why that is the whole game.",
                    "body": """
A procedure is a named, reusable block. Define it once, call it anywhere:

    PROCEDURE addTax(amount, rate)
    {
        RETURN amount * (1 + rate)
    }

Parameters are the names in the definition; arguments are the values that
arrive. A return value is what the procedure hands back.

Procedural abstraction is the reason this matters. Once a block has a name, the
caller stops needing to know how it works — and you can replace the inside
entirely without touching anything that uses it. Managing complexity is not a
side benefit of procedures, it is what they are for.

Libraries are the same idea at a larger scale: procedures somebody else wrote
and tested, exposed through an API you call without reading the implementation.

The judgement is where to draw the line. A procedure that does one nameable
thing is useful. One that does three things has a name that is a lie, and the
next person will be surprised by two of them.
""",
                    "checks": [
                        "What is the difference between a parameter and an argument?",
                        "How does naming a block of code reduce complexity for a reader?",
                    ],
                },
                {
                    "slug": "csp-searching-sorting",
                    "title": "Searching and sorting",
                    "summary": "Linear, binary, and why sorted data is worth the trouble.",
                    "body": """
Linear search checks each element in turn. It works on any list, and on average
it looks at half of it. For a million items, that is 500,000 checks.

Binary search requires SORTED data. Look at the middle; if the target is
smaller, discard the upper half; repeat. A million items takes about 20 steps.

The comparison is worth feeling rather than memorising: doubling the data adds
one step to a binary search and doubles the work of a linear one. That gap is
why sorting is worth doing at all — you pay once and then search cheaply
forever.

The precondition is absolute. Binary search on unsorted data does not run
slowly; it returns wrong answers, silently, and it is a classic exam trap.

Sorting itself is a whole field. What CSP asks is that you understand the
trade — an up-front cost that buys much faster access afterwards — and that you
can trace a binary search by hand and say how many steps it takes.
""",
                    "checks": [
                        "How many steps does binary search need for 1,000,000 items?",
                        "What happens if you binary search unsorted data?",
                    ],
                },
                {
                    "slug": "csp-efficiency",
                    "title": "Efficiency, and problems that cannot be solved",
                    "summary": "Reasonable time, unreasonable time, and undecidable.",
                    "body": """
Efficiency is about how work GROWS with input size, not about seconds on your
laptop.

- Reasonable time — the work grows polynomially. Doubling the input multiplies
  the work by a constant factor. Usable.
- Unreasonable time — the work grows exponentially. Adding ONE item multiplies
  the work. Fine for ten items, hopeless for fifty, and no faster computer
  rescues it.

Some problems have no known efficient solution at all. The travelling salesman
problem — shortest route visiting every city once — is the standard example.
These are handled with a HEURISTIC: a method that finds a good-enough answer
quickly, trading the guarantee of the best answer for actually having one.

And some problems cannot be solved by any algorithm for every input. Those are
undecidable, and the halting problem is the canonical case: no program can
determine, for every possible program and input, whether it will eventually
stop. This is proven, not merely unsolved.

Keep the three apart: hard means expensive, unreasonable means impractical,
undecidable means impossible.
""",
                    "checks": [
                        "What is the difference between an unreasonable-time problem and an undecidable one?",
                        "What do you give up by using a heuristic?",
                    ],
                },
            ],
        },
        {
            "title": "Computer Systems and Networks",
            "blurb": "How the machines talk, and why it keeps working.",
            "chapters": [
                {
                    "slug": "csp-internet",
                    "title": "The internet and protocols",
                    "summary": "Packets, addresses, and rules agreed by strangers.",
                    "body": """
The internet is a network of networks that agree on protocols. No one owns it,
and that is a design property rather than an accident.

Data is split into PACKETS, each routed independently and reassembled at the
other end. Packets from one message can take different routes and arrive out of
order. Routers forward them hop by hop.

The protocols divide the work:

- IP addresses and routes packets. It makes no promise they arrive.
- TCP builds a reliable ordered stream on top, by numbering packets,
  acknowledging them and retransmitting what goes missing.
- UDP does not. It sends and forgets, which is right when late data is worse
  than missing data — live video, voice, games.
- DNS turns names into addresses.
- HTTP/HTTPS carry web pages.

IPv4's 32-bit addresses ran out; IPv6's 128-bit addresses will not.

Bandwidth is how much a connection carries per second; latency is how long the
first bit takes to arrive. They are independent, which is why a high-bandwidth
satellite link still feels slow.
""",
                    "checks": [
                        "What does TCP add that IP does not provide?",
                        "When is UDP the better choice, and why?",
                    ],
                },
                {
                    "slug": "csp-fault-tolerance",
                    "title": "Redundancy and fault tolerance",
                    "summary": "Why cutting a cable does not break the internet.",
                    "body": """
A fault-tolerant system keeps working when part of it fails. On the internet
this comes from REDUNDANCY: more than one path between any two points.

If a router fails or a cable is cut, packets are routed around it. Nothing
central notices and reassigns work — each router simply forwards toward the
destination using the routes it currently knows, and those routes update.

The property this buys is scalability alongside resilience. New networks join by
speaking the protocols; nobody grants permission and no central register has to
be updated.

The limits are worth knowing too:

- Redundancy costs money. Two paths is two paths to pay for, which is why it
  thins out at the edges — a home usually has exactly one connection.
- Some things are not redundant. DNS root servers and certificate authorities
  are concentrated, and a failure there is felt widely.
- Redundancy protects against failure, not against attack. A DDoS floods every
  available path at once.
""",
                    "checks": [
                        "What specifically makes the internet fault-tolerant?",
                        "Name a part of the internet that is not redundant.",
                    ],
                },
                {
                    "slug": "csp-parallel",
                    "title": "Parallel and distributed computing",
                    "summary": "Doing several things at once, and the ceiling on that.",
                    "body": """
Sequential computing runs operations strictly one at a time. Parallel computing
runs parts simultaneously on multiple processors. Distributed computing spreads
the work across multiple machines.

Speedup is the sequential time divided by the parallel time. If a task takes 60
seconds alone and 20 with four processors, the speedup is 3 — not 4, and that
gap is the point.

The ceiling comes from the part that cannot be parallelised. If a quarter of the
work is inherently sequential, no number of processors gets you past a 4×
speedup. Adding processors past that spends money for nothing.

The other costs are real: splitting the work, coordinating it, and combining the
results all take time that the sequential version never pays. For small tasks,
parallelising makes things SLOWER.

Distributed computing extends this across machines, which adds network latency
and partial failure — some machines finish, some do not, and the system has to
cope with both.
""",
                    "checks": [
                        "If 20% of a task cannot be parallelised, what is the maximum speedup?",
                        "Why can parallelising a small task make it slower?",
                    ],
                },
            ],
        },
        {
            "title": "Impact of Computing",
            "blurb": "The part of the course that is about people.",
            "chapters": [
                {
                    "slug": "csp-effects",
                    "title": "Beneficial and harmful effects",
                    "summary": "Every innovation does both, usually to different people.",
                    "body": """
A computing innovation is anything new that includes a program as an essential
part. Every one of them has effects its creators did not intend, and the course
asks you to reason about them rather than to score them.

Two things make this hard and worth practising:

- Effects are rarely uniform. A system that benefits most users can harm a
  minority severely, and averages hide that entirely.
- Harm is usually a side effect, not a purpose. Nobody set out to build a
  recommendation system that radicalises people; it optimised for engagement and
  that was what engagement rewarded.

The digital divide is the standing example: unequal access to computing, along
lines of income, geography and age. It widens as more essentials — applications,
benefits, schooling — assume connectivity that not everyone has.

Computing bias is the other. A system reproduces the patterns in its training
data, so historical unfairness comes out the other end wearing the authority of
a computer. The system did not invent the prejudice; it laundered it.
""",
                    "checks": [
                        "Why do averages hide the harms of a computing innovation?",
                        "How does a system reproduce bias without anyone intending it?",
                    ],
                },
                {
                    "slug": "csp-privacy",
                    "title": "Privacy and personal data",
                    "summary": "What is collected, what is inferred, and what leaks.",
                    "body": """
PII is data that can identify a specific person — alone OR combined with other
data. That second half is what people underestimate: a birth date, a postcode
and a gender identify most individuals uniquely, though none is identifying on
its own.

Your digital footprint is everything you leave behind, including the parts you
did not deliberately publish: metadata, timing, location, and the record of what
you looked at.

Two asymmetries define the problem:

- Collection is cheap and permanent; deletion is neither. Data copied to a
  dozen systems is not recalled by deleting your account.
- Aggregation reveals more than the parts. Individually harmless facts combine
  into a profile nobody consented to.

Practical defences are unglamorous and effective: multi-factor authentication,
distinct passwords, minimal permissions, and asking whether a service needs the
data before giving it. Encryption protects data in transit and at rest from
outsiders; it does nothing about the company you handed it to.
""",
                    "checks": [
                        "Why can non-identifying data become PII when combined?",
                        "What does encryption not protect you from?",
                    ],
                },
                {
                    "slug": "csp-legal-ethical",
                    "title": "Ownership, licensing and ethics",
                    "summary": "Who owns code, and what you may do with someone else's.",
                    "body": """
Copyright applies automatically to a creative work at the moment it is made, with
no registration. Intellectual property covers copyright, patents and trademarks.

Licences grant permissions in advance so nobody has to ask:

- Open source — use, study, modify and share, on stated conditions. "Free" here
  means freedom, not price, and copyleft licences require derivative works to
  carry the same terms.
- Creative Commons — a family of licences for creative work, with conditions
  like attribution or non-commercial use.
- EULA — the agreement governing proprietary software, accepted by clicking.

Using a resource because it is publicly reachable is not the same as being
permitted to use it. Public and permitted are different questions, and the
licence answers the second.

Ethically, the course asks a wider question than legality: what does this system
do to people who did not choose it? Legal and right are not the same, and the
gap between them is where most of the interesting cases sit.
""",
                    "checks": [
                        "Does something being publicly available mean you may reuse it?",
                        "What does copyleft require that a permissive licence does not?",
                    ],
                },
                {
                    "slug": "csp-security",
                    "title": "Security: attacks and defences",
                    "summary": "How systems are broken into, and what actually helps.",
                    "body": """
The common attacks on the exam, and what each exploits:

- Phishing — impersonation, exploiting trust. Spear phishing targets one person
  using details about them, and is far harder to spot.
- Malware — viruses, keyloggers, ransomware. Exploits execution you granted.
- DDoS — floods a service so real users cannot reach it. Steals nothing.
- Rogue access point — a wireless network placed to intercept traffic, named to
  look legitimate.

The defences:

- Encryption. Symmetric uses one shared key — fast, but you must exchange the
  key safely. Asymmetric uses a key pair: publish one, keep the other, and
  strangers can send you secrets without a prior arrangement. HTTPS uses
  asymmetric to agree a symmetric key, then symmetric for speed.
- Certificates and certificate authorities bind a public key to an identity, so
  you know whose key you encrypted to.
- Multi-factor authentication, so a stolen password alone is not enough.
- Firewalls and antivirus, which filter known-bad traffic and files.

The recurring theme: most breaches begin with a person being deceived, not with
cryptography being broken.
""",
                    "checks": [
                        "Why does HTTPS use both asymmetric and symmetric encryption?",
                        "What problem does a certificate authority solve?",
                    ],
                },
            ],
        },
    ],
}
