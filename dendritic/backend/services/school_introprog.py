"""Intro Programming: the ideas, in pseudocode, before any one language.

WHERE THE OUTLINE CAME FROM
---------------------------
The topic sequence is the conventional one for an introductory programming
course — decomposition, variables, control flow, procedures, collections,
algorithms and debugging. A standard syllabus rather than anyone's authorship.
Every lesson and exercise here is written for this site.

WHY PSEUDOCODE
--------------
This course teaches the CONCEPTS, and every real language wraps them in syntax
that has to be learned separately. Somebody who learns "a loop" here recognises
it in Python, Java, JavaScript and Solidity — all of which are also taught in
this school — instead of learning one language and assuming its habits are
universal.

The pseudocode is close to the AP CSP exam's, which makes this course a
reasonable companion to it.

The exercises are checked by pattern, and since pseudocode has no compiler, the
checks are looser than the other courses': they look for the SHAPE of the
answer. The page says as much. A learner who writes something valid in a slightly
different style should not be told they are wrong, so where a concept has two
reasonable spellings both are accepted.
"""

REFERENCE = "https://csplusplus.com/introprog"

BOOK = {
    "slug": "introprog",
    "title": "Intro Programming",
    "reference": REFERENCE,
    "reference_name": "csplusplus.com/introprog",
    "provenance": (
        "Written for this site, following the conventional sequence for an "
        "introductory programming course. Another treatment of the same "
        "material:"
    ),
    "subtitle": "The ideas behind every language, in pseudocode.",
    "blurb": (
        "Eleven lessons on what programming actually is, before syntax gets in "
        "the way. Learn a loop here and you will recognise it in Python, Java "
        "and everything else in this school."
    ),
    "parts": [
        {
            "title": "Thinking about problems",
            "blurb": "Before any code at all.",
            "chapters": [
                {
                    "slug": "ip-what-is-a-program",
                    "title": "What a program is",
                    "summary": "Instructions precise enough for something with no judgement.",
                    "body": """
A program is a sequence of instructions a computer follows. The hard part is not
the computer — it is that the instructions must be precise enough to be followed
by something with NO judgement, no context and no willingness to guess what you
meant.

Try writing instructions for making a sandwich. "Put jam on the bread" assumes
the reader knows to open the jar, to use a knife, which side of the bread, and
that "put jam on" does not mean the jar. A person fills those gaps automatically.
A computer does not fill any of them.

That gap is where nearly all bugs live. The computer did exactly what you said;
what you said was not what you meant.

An ALGORITHM is the method — the steps, independent of any language. A PROGRAM
is that method written in a language a machine can run. Getting the algorithm
right on paper first is not an academic exercise; it is much cheaper than
discovering the method was wrong after writing three hundred lines of it.

Every program, at bottom, does the same four things: takes input, stores things,
makes decisions, repeats things. Everything else is arrangement.
""",
                    "checks": [
                        "Why is 'the computer did what I said' usually the explanation for a bug?",
                        "What is the difference between an algorithm and a program?",
                    ],
                },
                {
                    "slug": "ip-decomposition",
                    "title": "Decomposition and abstraction",
                    "summary": "The only technique for problems too big to hold in your head.",
                    "body": """
DECOMPOSITION is breaking a problem into smaller problems until each is small
enough to solve. It is the central skill, and it is what separates people who
can build large things from people who can only build small ones.

"Build a quiz app" is not solvable. Broken down:

- Store the questions
- Show one question
- Read an answer
- Check whether it is right
- Keep the score
- Show the result at the end

Each of those is now something you could actually start.

ABSTRACTION is the other half: once a piece works, you stop thinking about how.
You do not consider how "check whether it is right" works while writing the
scoring; you use it by name and trust it. Holding six things in mind at once is
possible; holding six hundred is not, and abstraction is what keeps the number
at six.

PATTERN RECOGNITION saves the most time of all. "Check whether it is right"
looks a lot like every other comparison you have written. Noticing that means
writing it once.

The practical instruction: when stuck, the problem is nearly always too big.
Break it down further than feels necessary.
""",
                    "checks": [
                        "Why does abstraction let you build bigger things?",
                        "Break 'build a calculator' into five sub-problems.",
                    ],
                },
            ],
        },
        {
            "title": "The building blocks",
            "blurb": "Four ideas that appear in every language.",
            "chapters": [
                {
                    "slug": "ip-variables",
                    "title": "Variables and data types",
                    "summary": "Named boxes, and what they are allowed to hold.",
                    "body": """
A VARIABLE is a named place to keep a value:

    score ← 0
    name ← "Ada"
    isReady ← true

The arrow is assignment: work out the right side, then store it under the name on
the left. This matters because assignment is not equality:

    score ← score + 1

is not a claim about arithmetic. It means "take the current score, add one, put
the result back". Reading it as an equation is confusing; reading it as an
instruction is not.

The common TYPES, present in every language under one name or another:

- Integer — whole numbers
- Real / float — decimals
- String — text
- Boolean — true or false

Types matter because operations depend on them. `+` on two numbers adds; `+` on
two strings joins. So `"2" + "3"` is `"23"`, not 5 — a genuine source of bugs
when a value arrives from a keyboard, since typed input is text until you convert
it.

Give variables names that say what they hold. `daysRemaining` needs no comment;
`d` needs a paragraph and will get neither.
""",
                    "task": "Declare a variable `count` set to 0, `playerName` set to \"Ada\", and `isFinished` set to false.",
                    "starter": "// Three variables.\n",
                    "solution": "count ← 0\nplayerName ← \"Ada\"\nisFinished ← false\n",
                    "validators": [
                        {"pattern": r"count\s*(←|<-|=)\s*0", "hint": "Assign 0 to `count` — the arrow or = are both fine here."},
                        {"pattern": r"playerName\s*(←|<-|=)\s*[\"']Ada", "hint": "Assign the text \"Ada\" to `playerName`, in quotes."},
                        {"pattern": r"isFinished\s*(←|<-|=)\s*false", "hint": "Assign `false` to `isFinished`."},
                    ],
                },
                {
                    "slug": "ip-conditionals",
                    "title": "Making decisions",
                    "summary": "IF, and the conditions that drive it.",
                    "body": """
    IF score >= 50
    {
        DISPLAY "pass"
    }
    ELSE
    {
        DISPLAY "fail"
    }

A CONDITION is anything that evaluates to true or false. The comparison
operators are the same everywhere: `=` or `==` for equal, `≠` or `!=` for not
equal, and `<`, `>`, `≤`, `≥`.

Conditions combine with AND, OR and NOT:

    IF age >= 13 AND age < 20        // a teenager
    IF day = "Saturday" OR day = "Sunday"
    IF NOT isFinished

Three things to get right, and they account for most conditional bugs:

- ORDER. In a chain, the first true branch wins and the rest never run. Put the
  most specific condition first — testing `score >= 50` before `score >= 90`
  means nobody ever gets the top grade.
- BOUNDARIES. Is 50 a pass? `>` and `>=` differ by exactly one case, and it is
  always the case somebody complains about.
- AND versus OR. "Between 10 and 20" is `x > 10 AND x < 20`. With OR it is true
  for every number in existence, which is a bug that looks like it works.
""",
                    "task": "Write an IF/ELSE that displays \"pass\" when score is 50 or more and \"fail\" otherwise.",
                    "starter": "// score already holds a number.\n",
                    "solution": "IF score >= 50\n{\n    DISPLAY \"pass\"\n}\nELSE\n{\n    DISPLAY \"fail\"\n}\n",
                    "validators": [
                        {"pattern": r"IF\s*\(?\s*score\s*>=\s*50", "hint": "Test `IF score >= 50` — 50 itself should pass."},
                        {"pattern": r"ELSE", "hint": "Add an ELSE branch for everything below 50."},
                        {"pattern": r"[\"']pass[\"']", "hint": "Display \"pass\" in the true branch."},
                        {"pattern": r"[\"']fail[\"']", "hint": "Display \"fail\" in the ELSE branch."},
                    ],
                },
                {
                    "slug": "ip-loops",
                    "title": "Repeating things",
                    "summary": "Counted loops, conditional loops, and the one that never stops.",
                    "body": """
Two shapes, and every language has both:

    REPEAT 10 TIMES
    {
        DISPLAY "hello"
    }

    REPEAT UNTIL guess = answer
    {
        guess ← INPUT
    }

Use a counted loop when you know how many times; use a conditional one when you
are waiting for something to become true.

The INFINITE LOOP is the classic failure: a condition that nothing inside the
loop ever changes. The habit that prevents it: the moment you write a condition,
ask what changes it, and check that the change is inside the loop.

OFF-BY-ONE errors are the other. Looping from 1 to 10 runs ten times; from 0 to
10 runs eleven. Decide whether your bounds are inclusive before writing them, and
say so out loud.

Loops NEST, and nesting multiplies. An outer loop of 10 containing an inner loop
of 10 runs the inner body 100 times. That is how a small change to a bound
becomes an enormous change in running time, and it is worth being able to see
before you run it.

An ACCUMULATOR is the pattern behind most useful loops: a variable outside the
loop that the loop adds to. Totals, counts and maximums are all this.
""",
                    "task": "Write a loop that adds the numbers 1 to 10 into a variable `total`, using an accumulator.",
                    "starter": "total ← 0\n",
                    "solution": "total ← 0\nFOR i ← 1 TO 10\n{\n    total ← total + i\n}\nDISPLAY total\n",
                    "validators": [
                        {"pattern": r"total\s*(←|<-|=)\s*0", "hint": "Start the accumulator at 0, before the loop."},
                        {"pattern": r"(FOR|REPEAT|WHILE)", "hint": "Use a loop — FOR, REPEAT or WHILE."},
                        {"pattern": r"total\s*(←|<-|=)\s*total\s*\+", "hint": "Add to the accumulator inside the loop: `total ← total + i`."},
                    ],
                },
                {
                    "slug": "ip-procedures",
                    "title": "Procedures",
                    "summary": "Naming a piece of work so you can stop thinking about it.",
                    "body": """
    PROCEDURE addTax(amount, rate)
    {
        RETURN amount * (1 + rate)
    }

    total ← addTax(100, 0.2)

PARAMETERS are the names in the definition. ARGUMENTS are the values passed in.
The RETURN value is what comes back.

Procedures earn their place three times over:

- No repetition. Write it once; fix it once.
- A name. `addTax(price, rate)` says what is happening where the arithmetic did
  not.
- Abstraction. Once it works you stop thinking about how, which is what keeps a
  large program in your head.

A procedure should do ONE nameable thing. If naming it needs the word "and", it
is two procedures, and the next person will be surprised by whichever half they
were not expecting.

Keep them short enough to read at once. A procedure you have to scroll through
is one you cannot check by eye, and the bugs will be in the part off-screen.

Scope: variables made inside a procedure usually exist only inside it. That is a
feature — it means you can name something `i` without wondering what else in the
program is using `i`.
""",
                    "task": "Write a procedure `area(width, height)` that returns width times height, and call it.",
                    "starter": "// Define, then call.\n",
                    "solution": "PROCEDURE area(width, height)\n{\n    RETURN width * height\n}\n\nDISPLAY area(3, 4)\n",
                    "validators": [
                        {"pattern": r"PROCEDURE\s+area\s*\(", "hint": "Define `PROCEDURE area(width, height)`."},
                        {"pattern": r"RETURN", "hint": "Use RETURN to hand the result back."},
                        {"pattern": r"width\s*\*\s*height|height\s*\*\s*width", "hint": "Multiply the two parameters."},
                        {"pattern": r"area\s*\(\s*\d", "hint": "Call the procedure with actual numbers."},
                    ],
                },
            ],
        },
        {
            "title": "Working with many things",
            "blurb": "Lists, and the algorithms that go with them.",
            "chapters": [
                {
                    "slug": "ip-lists",
                    "title": "Lists",
                    "summary": "One name for many values.",
                    "body": """
    scores ← [70, 85, 90]
    scores[1]              // the first, in this pseudocode
    LENGTH(scores)         // 3
    APPEND(scores, 65)

A list holds many values under one name, each reachable by INDEX. It is what
makes a program independent of how many items there are: the same code handles
three scores or three thousand.

Where indexing starts differs between languages — this pseudocode starts at 1,
Python and Java start at 0 — and assuming the wrong one produces an off-by-one
every time. Check, do not guess.

TRAVERSAL is visiting every element, and it is the pattern behind almost
everything:

    FOR EACH score IN scores
    {
        total ← total + score
    }

Combine traversal with an accumulator and you have summing, counting, finding
the largest, and filtering — which covers most of what beginners are asked to
do with data.

One trap worth knowing early: removing items from a list while looping forwards
over it skips elements, because everything after the removed item shifts down.
Build a new list instead.
""",
                    "task": "Write a loop that counts how many values in `scores` are 50 or more, into `passes`.",
                    "starter": "passes ← 0\n",
                    "solution": "passes ← 0\nFOR EACH score IN scores\n{\n    IF score >= 50\n    {\n        passes ← passes + 1\n    }\n}\nDISPLAY passes\n",
                    "validators": [
                        {"pattern": r"passes\s*(←|<-|=)\s*0", "hint": "Start the counter at 0 before the loop."},
                        {"pattern": r"FOR\s+EACH|FOR\s+\w+\s*(←|<-|=)|REPEAT", "hint": "Traverse the list with a FOR EACH loop."},
                        {"pattern": r"IF\s+", "hint": "Test each value against 50 inside the loop."},
                        {"pattern": r"passes\s*(←|<-|=)\s*passes\s*\+", "hint": "Increase the counter when the test passes."},
                    ],
                },
                {
                    "slug": "ip-algorithms",
                    "title": "Searching and sorting",
                    "summary": "The first two algorithms worth knowing by name.",
                    "body": """
LINEAR SEARCH checks each item in turn until it finds the target. It works on any
list, in any order, and on average looks at half of it.

BINARY SEARCH needs the list SORTED. Look at the middle: if the target is
smaller, throw away the upper half and repeat. A million items takes about
twenty steps instead of half a million.

The comparison is the point, and it is worth feeling rather than memorising:
doubling the data adds ONE step to a binary search and DOUBLES the work of a
linear one.

The precondition is absolute. Binary search on unsorted data does not run
slowly — it returns wrong answers, confidently.

SORTING is what makes binary search possible, and the simple methods share a
shape: repeatedly find something out of place and move it. They are slow on
large lists, and the reason to learn them is that they are traceable by hand,
which is how you build intuition for what an algorithm is doing.

The general lesson beneath both: an up-front cost that makes every later
operation cheaper is usually worth paying, provided there are enough later
operations. Sorting once to search a thousand times is an excellent trade;
sorting once to search once is not.
""",
                    "checks": [
                        "Why does binary search require sorted data?",
                        "When is sorting a list NOT worth the cost?",
                    ],
                },
                {
                    "slug": "ip-debugging",
                    "title": "Debugging",
                    "summary": "A method, not a talent.",
                    "body": """
Everyone's code is wrong at first. Debugging is a procedure, and people who look
fast at it are following it rather than guessing well.

The method:

- REPRODUCE it. A bug you cannot trigger on demand cannot be verified as fixed.
- NARROW IT DOWN. Find the smallest input that still shows it, and the smallest
  region of code it could be in. Displaying values at a few points is the most
  underrated technique there is.
- FORM ONE HYPOTHESIS. "The loop runs one time too many." Then test that one
  thing.
- CHANGE ONE THING AT A TIME. Two changes and a fix tells you nothing about
  which mattered, and you have learned no more than before.
- VERIFY. Re-run the case that failed, and then the ones that worked — fixes
  break things.

The three error kinds, and which to fear:

- SYNTAX — you broke the grammar. It refuses to run and tells you where.
- RUNTIME — it starts and then fails. Loud, and it points at a line.
- LOGIC — it runs perfectly and gives the wrong answer. Nothing announces it,
  and this is the one that matters.

Read the error message. All of it. It is almost always more specific than the
guess you were about to act on instead.
""",
                    "checks": [
                        "Why change only one thing at a time?",
                        "Why is a logic error the most dangerous of the three?",
                    ],
                },
            ],
        },
    ],
}
