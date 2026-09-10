"""Intro Python: the language, with an exercise in every lesson.

WHERE THE OUTLINE CAME FROM
---------------------------
The topic sequence is the standard one for an introductory Python course —
values and variables, control flow, collections, functions, files, errors,
objects — which is a conventional syllabus rather than anyone's authorship.
Every lesson, exercise and solution below is written for this site.

HOW THIS DIFFERS FROM THE OTHER INTRO COURSES HERE
--------------------------------------------------
Four courses in this school could all be called "introductory", so each one has
a job:

  Foundations       how a computer works. No programming.
  Intro Programming the ideas, in pseudocode. Language-agnostic.
  Intro Python      THIS one. A real language, run on your own machine.
  Web Design        HTML and CSS.

So this course assumes the concepts from Intro Programming are either known or
being learned alongside, and spends its attention on Python specifically —
including the places Python differs from what those concepts look like
elsewhere, because that is where a second-language learner trips.

Python 3 throughout, current idiom: f-strings, `with` for files, type hints
where they clarify.
"""

REFERENCE = "https://csplusplus.com/intropython"

BOOK = {
    "slug": "python",
    "title": "Intro Python",
    "reference": REFERENCE,
    "reference_name": "csplusplus.com/intropython",
    "provenance": (
        "Written for this site, following the conventional sequence for an "
        "introductory Python course. Another treatment of the same material:"
    ),
    "subtitle": "Python 3 from the first line, with an exercise every lesson.",
    "blurb": (
        "Fourteen lessons and fourteen exercises. It assumes nothing and ends "
        "with you reading files, handling errors and writing your own classes — "
        "in a language you can install today and keep using."
    ),
    "parts": [
        {
            "title": "Values and names",
            "blurb": "The pieces every program is made of.",
            "chapters": [
                {
                    "slug": "py-values",
                    "title": "Values, types and variables",
                    "summary": "Four types, and a name is just a label.",
                    "body": """
    name = "Ada"
    age = 36
    height = 1.7
    is_active = True

No type declarations: Python infers the type from the value, and a name can
later refer to something of a different type entirely. That is convenient and it
is why reading unfamiliar Python sometimes requires running it.

The four types you start with:

- `str` — text, in single or double quotes
- `int` — whole numbers, of unlimited size (Python does not overflow)
- `float` — decimals, approximate
- `bool` — `True` or `False`, capitalised

`type(x)` tells you which you have. `int("5")` and `str(5)` convert.

A crucial distinction: `=` ASSIGNS, `==` COMPARES. Python will not let you use
`=` inside an `if`, which prevents the classic C bug outright.

Naming convention is `snake_case` for variables and functions,
`SCREAMING_CASE` for constants. Python has no true constants — the convention is
a promise to other readers, not an enforcement.
""",
                    "task": "Create a string `name` set to \"Ada\", an int `age` set to 36, a float `height` set to 1.7, and a bool `is_active` set to True.",
                    "starter": "# Four variables, one of each type.\n",
                    "solution": "name = \"Ada\"\nage = 36\nheight = 1.7\nis_active = True\n",
                    "validators": [
                        {"pattern": r"name\s*=\s*[\"']Ada[\"']", "hint": "Assign the string \"Ada\" to `name`."},
                        {"pattern": r"age\s*=\s*36", "hint": "Assign the integer 36 to `age`."},
                        {"pattern": r"height\s*=\s*1\.7", "hint": "Assign the float 1.7 to `height`."},
                        {"pattern": r"is_active\s*=\s*True", "hint": "Assign `True` to `is_active` — capitalised, unlike most languages."},
                    ],
                },
                {
                    "slug": "py-strings",
                    "title": "Strings and f-strings",
                    "summary": "Text, and the modern way to build it.",
                    "body": """
Strings are immutable: every operation returns a new one.

    text = "hello world"
    text.upper()            # "HELLO WORLD"
    text.split()            # ["hello", "world"]
    text.replace("l", "L")
    len(text)               # 11
    text[0]                 # "h"
    text[-1]                # "d"  — negative indexes count from the end
    text[0:5]               # "hello" — start included, end excluded

Negative indexing and slicing are two things Python gives you that most
languages do not, and both are worth becoming fluent with. `text[::-1]`
reverses a string.

F-STRINGS are how you build text now:

    print(f"{name} is {age} years old")
    print(f"{price:.2f}")          # two decimal places
    print(f"{value=}")             # prints "value=3", handy when debugging

The older `%` and `.format()` styles still work and you will meet them in
existing code, but new code should use f-strings — they are faster and put the
expression where you read it rather than in a list at the end.
""",
                    "task": "Write a function `greet(name, age)` returning a string like \"Ada is 36 years old\" using an f-string.",
                    "starter": "def greet(name, age):\n    pass\n",
                    "solution": "def greet(name, age):\n    return f\"{name} is {age} years old\"\n",
                    "validators": [
                        {"pattern": r"def\s+greet\s*\(\s*name\s*,\s*age\s*\)", "hint": "Define `def greet(name, age):`."},
                        {"pattern": r"f[\"']", "hint": "Use an f-string — prefix the quote with `f`."},
                        {"pattern": r"\{\s*name\s*\}", "hint": "Interpolate `{name}` inside the f-string."},
                        {"pattern": r"return\b", "hint": "Return the string rather than printing it."},
                    ],
                },
                {
                    "slug": "py-numbers",
                    "title": "Numbers and operators",
                    "summary": "Two division operators, and why floats lie.",
                    "body": """
    7 / 2       # 3.5   — true division, ALWAYS a float
    7 // 2      # 3     — floor division
    7 % 2       # 1     — remainder
    2 ** 10     # 1024  — exponent
    -7 // 2     # -4    — floors toward negative infinity, not toward zero

Python 3's `/` always producing a float is a deliberate break from Python 2 and
from most other languages, and it removes a whole category of surprise.

That `-7 // 2` is `-4` rather than `-3` catches people. Floor division floors;
it does not truncate.

FLOATS ARE APPROXIMATE, in Python as everywhere:

    0.1 + 0.2 == 0.3        # False
    0.1 + 0.2               # 0.30000000000000004

This is binary floating point, not a Python defect. Never compare floats with
`==`; compare the absolute difference against a small tolerance, or use
`math.isclose`. For money, use `decimal.Decimal` or count in whole pennies.

Integers, by contrast, are unbounded — `2 ** 1000` is exact. Python has no
integer overflow, which is unusual and pleasant.
""",
                    "task": "Write a function `split_change(pennies)` returning a tuple of (pounds, remaining_pennies) using floor division and modulo.",
                    "starter": "def split_change(pennies):\n    pass\n",
                    "solution": "def split_change(pennies):\n    return pennies // 100, pennies % 100\n",
                    "validators": [
                        {"pattern": r"def\s+split_change\s*\(", "hint": "Define `def split_change(pennies):`."},
                        {"pattern": r"//", "hint": "Use floor division `//` for whole pounds."},
                        {"pattern": r"%", "hint": "Use `%` for the remaining pennies."},
                        {"pattern": r"return\b", "hint": "Return both values."},
                    ],
                },
            ],
        },
        {
            "title": "Control flow",
            "blurb": "Choosing and repeating.",
            "chapters": [
                {
                    "slug": "py-conditionals",
                    "title": "if, elif, else and truthiness",
                    "summary": "Indentation is the syntax, and empty means false.",
                    "body": """
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    else:
        grade = "C"

INDENTATION IS THE SYNTAX. There are no braces; the indentation is not a
convention, it is what defines the block. Four spaces, consistently. Mixing tabs
and spaces is an error in Python 3, deliberately.

Python's comparison chaining reads like maths and works:

    if 0 <= score <= 100:

TRUTHINESS is the part that surprises newcomers. Any value can be tested, and
these are all false:

    False, None, 0, 0.0, "", [], {}, ()

Everything else is true. So `if items:` means "if the list is not empty", which
is the idiomatic form — `if len(items) > 0:` says the same thing more loudly.

Careful with `None`: use `is None` and `is not None`, not `== None`. `is` tests
identity, and for None that is what you mean. This matters because a value can
be falsy without being None, and confusing "empty" with "missing" is a real bug.
""",
                    "task": "Write `classify(n)` returning \"negative\", \"zero\" or \"positive\".",
                    "starter": "def classify(n):\n    pass\n",
                    "solution": "def classify(n):\n    if n < 0:\n        return \"negative\"\n    elif n == 0:\n        return \"zero\"\n    else:\n        return \"positive\"\n",
                    "validators": [
                        {"pattern": r"def\s+classify\s*\(", "hint": "Define `def classify(n):`."},
                        {"pattern": r"if\s+", "hint": "Start with an `if` testing for negative."},
                        {"pattern": r"elif\s+|else\s*:", "hint": "Use `elif` and `else` for the other two cases."},
                        {"pattern": r"[\"']positive[\"']", "hint": "Return \"positive\" for values above zero."},
                    ],
                },
                {
                    "slug": "py-loops",
                    "title": "for and while",
                    "summary": "Iterate over things, not over indexes.",
                    "body": """
Python's `for` loops over a SEQUENCE, not a counter:

    for item in items:
        print(item)

    for i in range(5):        # 0, 1, 2, 3, 4
        print(i)

    for i, item in enumerate(items):     # index and value together
        print(i, item)

`range(a, b)` includes `a` and excludes `b`, so `range(1, 11)` is 1 to 10. The
exclusive end matches slicing, and `range(len(x))` almost always means you
wanted `enumerate`.

`while` repeats until a condition changes:

    while not done:
        ...

`break` leaves a loop; `continue` skips to the next iteration. Python also has a
loop `else`, which runs only if the loop finished WITHOUT breaking — genuinely
useful for search loops, and unique enough that it confuses everyone once.

The one to avoid: modifying a list while looping over it. Removing an element
shifts the rest and the loop skips items. Build a new list instead, which is
what comprehensions are for.
""",
                    "task": "Write `count_vowels(text)` returning how many vowels are in the string.",
                    "starter": "def count_vowels(text):\n    pass\n",
                    "solution": "def count_vowels(text):\n    count = 0\n    for char in text.lower():\n        if char in \"aeiou\":\n            count += 1\n    return count\n",
                    "validators": [
                        {"pattern": r"def\s+count_vowels\s*\(", "hint": "Define `def count_vowels(text):`."},
                        {"pattern": r"for\s+\w+\s+in\s+", "hint": "Loop over the characters with `for char in text:`."},
                        {"pattern": r"in\s+[\"']", "hint": "Test membership with `if char in \"aeiou\":`."},
                        {"pattern": r"return\b", "hint": "Return the count."},
                    ],
                },
            ],
        },
        {
            "title": "Collections",
            "blurb": "Lists, dictionaries, and the comprehension.",
            "chapters": [
                {
                    "slug": "py-lists",
                    "title": "Lists",
                    "summary": "Ordered, mutable, and shared by reference.",
                    "body": """
    items = [3, 1, 4]
    items.append(1)
    items.insert(0, 5)
    items.remove(4)        # by VALUE
    items.pop()            # removes and returns the last
    items.sort()
    len(items)
    items[1:3]             # slicing works as on strings

Lists are MUTABLE, which means two names can refer to one list:

    a = [1, 2, 3]
    b = a
    b.append(4)
    print(a)        # [1, 2, 3, 4]

To copy, use `a.copy()` or `a[:]`. This bites hardest as a default argument —
`def f(items=[])` creates the list ONCE, at definition, and it persists between
calls. Use `def f(items=None)` and build inside.

Tuples are the immutable version, written with parentheses. Use them for
fixed-length groupings — a coordinate, a return of two values — and they can be
dictionary keys, which lists cannot.

`sorted(x)` returns a new sorted list; `x.sort()` sorts in place and returns
None. Assigning the result of `.sort()` to a variable gives you None, and that
is a bug people write repeatedly.
""",
                    "task": "Write `top_three(numbers)` returning a new list of the three largest values, highest first, without modifying the input.",
                    "starter": "def top_three(numbers):\n    pass\n",
                    "solution": "def top_three(numbers):\n    return sorted(numbers, reverse=True)[:3]\n",
                    "validators": [
                        {"pattern": r"def\s+top_three\s*\(", "hint": "Define `def top_three(numbers):`."},
                        {"pattern": r"sorted\s*\(", "hint": "Use `sorted()` — it returns a new list, unlike `.sort()`."},
                        {"pattern": r"reverse\s*=\s*True|\[\s*::\s*-1\s*\]", "hint": "Sort descending with `reverse=True`."},
                        {"pattern": r"\[\s*:\s*3\s*\]", "hint": "Slice the first three with `[:3]`."},
                    ],
                },
                {
                    "slug": "py-dicts",
                    "title": "Dictionaries and sets",
                    "summary": "Lookup by key, and membership without duplicates.",
                    "body": """
    ages = {"Ada": 36, "Alan": 41}
    ages["Grace"] = 45
    ages.get("Nobody")            # None instead of an error
    ages.get("Nobody", 0)         # a default
    "Ada" in ages                 # True — checks KEYS
    for name, age in ages.items():
        ...

`ages["Nobody"]` raises KeyError; `.get()` does not. Which you want depends on
whether a missing key is a bug or an expected case, and choosing deliberately is
the difference between a crash and silent wrong data.

Dictionary lookup is roughly constant time regardless of size, which is why a
dict beats scanning a list whenever you are asking "do I have this".

SETS hold unique values with no order:

    seen = {1, 2, 3}
    seen.add(2)          # no change — already there
    set([1, 1, 2])       # {1, 2} — deduplicates

Sets support union `|`, intersection `&` and difference `-`, which turn several
loops into one readable line. Note `{}` alone is an empty DICT, not an empty
set — use `set()` for that.
""",
                    "task": "Write `word_counts(words)` returning a dict mapping each word to how many times it appears.",
                    "starter": "def word_counts(words):\n    pass\n",
                    "solution": "def word_counts(words):\n    counts = {}\n    for word in words:\n        counts[word] = counts.get(word, 0) + 1\n    return counts\n",
                    "validators": [
                        {"pattern": r"def\s+word_counts\s*\(", "hint": "Define `def word_counts(words):`."},
                        {"pattern": r"=\s*\{\s*\}|dict\s*\(", "hint": "Start with an empty dictionary."},
                        {"pattern": r"for\s+\w+\s+in\s+", "hint": "Loop over the words."},
                        {"pattern": r"\.get\s*\(|in\s+counts", "hint": "Use `.get(word, 0)` so a first sighting starts at zero."},
                    ],
                },
                {
                    "slug": "py-comprehensions",
                    "title": "Comprehensions",
                    "summary": "Building a collection in one readable line.",
                    "body": """
    squares = [n * n for n in range(10)]
    evens = [n for n in numbers if n % 2 == 0]
    names = {person.name for person in people}          # a set
    lookup = {p.id: p.name for p in people}             # a dict

Read it left to right: what to collect, where it comes from, and which ones to
keep. It replaces the three-line build-a-list-in-a-loop pattern.

    result = []                    becomes    result = [f(x) for x in items]
    for x in items:
        result.append(f(x))

Two judgements worth having:

- A comprehension with a condition and a transformation is fine. One with two
  `for` clauses and an `if` is usually less readable than the loop it replaced.
  Readability is the reason to use them, so abandoning it defeats the purpose.
- A GENERATOR expression uses parentheses instead of brackets and produces items
  one at a time rather than building the whole list. For a large file,
  `sum(int(line) for line in f)` uses almost no memory while the list version
  loads everything.

Comprehensions are the most recognisably Pythonic construct there is, which
makes them worth reaching for and worth not overusing.
""",
                    "task": "Write `even_squares(n)` returning a list of the squares of every even number from 0 up to but not including n, using a comprehension.",
                    "starter": "def even_squares(n):\n    pass\n",
                    "solution": "def even_squares(n):\n    return [x * x for x in range(n) if x % 2 == 0]\n",
                    "validators": [
                        {"pattern": r"def\s+even_squares\s*\(", "hint": "Define `def even_squares(n):`."},
                        {"pattern": r"\[.*for\s+\w+\s+in\s+range", "hint": "Use a list comprehension over `range(n)`."},
                        {"pattern": r"if\s+\w+\s*%\s*2\s*==\s*0", "hint": "Filter to even values with `if x % 2 == 0`."},
                    ],
                },
            ],
        },
        {
            "title": "Structure",
            "blurb": "Functions, files, errors and objects.",
            "chapters": [
                {
                    "slug": "py-functions",
                    "title": "Functions",
                    "summary": "Parameters, defaults, and returning more than one thing.",
                    "body": """
    def area(width, height=1):
        \"\"\"Return the area of a rectangle.\"\"\"
        return width * height

    area(3, 4)              # positional
    area(height=4, width=3) # keyword — order stops mattering
    area(3)                 # height defaults to 1

The triple-quoted string is a DOCSTRING, and it is not a comment: it is
attached to the function and shown by `help()`. Write it as what the function
returns, not as what it does internally.

A function with no explicit `return` returns `None`. Returning several values
returns a tuple, which unpacks:

    def min_max(values):
        return min(values), max(values)

    low, high = min_max(scores)

THE DEFAULT ARGUMENT TRAP is worth stating plainly, because it catches everyone
once: default values are evaluated ONCE, when the function is defined. A mutable
default — a list or a dict — is shared by every call and accumulates. Use `None`
as the default and create the object inside the function.

Scope: names assigned inside a function are local to it. Reading an outer name
works; assigning to one creates a new local instead, unless you say otherwise.
""",
                    "task": "Write `min_max(values)` returning a tuple of the smallest and largest, with a docstring.",
                    "starter": "def min_max(values):\n    pass\n",
                    "solution": "def min_max(values):\n    \"\"\"Return (smallest, largest) from a non-empty sequence.\"\"\"\n    return min(values), max(values)\n",
                    "validators": [
                        {"pattern": r"def\s+min_max\s*\(", "hint": "Define `def min_max(values):`."},
                        {"pattern": r"[\"']{3}", "hint": "Add a docstring in triple quotes."},
                        {"pattern": r"return\s+.*,", "hint": "Return both values, comma separated — that makes a tuple."},
                    ],
                },
                {
                    "slug": "py-errors",
                    "title": "Errors and exceptions",
                    "summary": "Failing usefully instead of crashing.",
                    "body": """
    try:
        value = int(text)
    except ValueError:
        print("that was not a number")
    else:
        print("worked")          # only if no exception
    finally:
        cleanup()                # always, exception or not

Catch SPECIFIC exceptions. A bare `except:` catches everything including typos
in your own code and the user pressing Ctrl-C, which turns a clear crash into a
mysterious wrong answer. If you genuinely need everything, `except Exception:`
at least spares the interrupts.

The ones you will meet: `ValueError` (right type, wrong value), `TypeError`
(wrong type), `KeyError`, `IndexError`, `FileNotFoundError`,
`ZeroDivisionError`.

Raise your own when a caller has done something you cannot proceed with:

    if width < 0:
        raise ValueError("width cannot be negative")

Python's convention leans toward trying and handling failure rather than
checking first — it is easier to ask forgiveness than permission. Attempting the
dictionary lookup and catching KeyError is more idiomatic than testing `in`
beforehand, and it avoids the gap between the check and the use.

Never write an empty `except: pass`. It converts a failure into silence, and
you will be debugging the consequence rather than the cause.
""",
                    "task": "Write `safe_int(text, default=0)` that returns the integer value of text, or the default if it cannot be converted.",
                    "starter": "def safe_int(text, default=0):\n    pass\n",
                    "solution": "def safe_int(text, default=0):\n    try:\n        return int(text)\n    except (ValueError, TypeError):\n        return default\n",
                    "validators": [
                        {"pattern": r"def\s+safe_int\s*\(", "hint": "Define `def safe_int(text, default=0):`."},
                        {"pattern": r"try\s*:", "hint": "Wrap the conversion in a `try:` block."},
                        {"pattern": r"except\s+\(?\s*(ValueError|TypeError)", "hint": "Catch ValueError specifically, not a bare except."},
                        {"pattern": r"return\s+default", "hint": "Return the default when conversion fails."},
                    ],
                },
                {
                    "slug": "py-files",
                    "title": "Files",
                    "summary": "Reading and writing, and closing without remembering to.",
                    "body": """
    with open("data.txt") as f:
        for line in f:
            print(line.rstrip("\\n"))

    with open("out.txt", "w") as f:
        f.write("hello\\n")

Always use `with`. It closes the file when the block ends, including when an
exception is raised — which is precisely when you would otherwise forget. A file
left open can mean data still sitting in a buffer and never written.

Modes: `"r"` read (default), `"w"` write (TRUNCATES the file immediately), `"a"`
append, and `"b"` appended for binary. `"w"` destroying the contents before you
write anything catches people, and there is no undo.

Iterating the file object reads a line at a time and uses almost no memory.
`f.read()` loads the whole thing, which is fine for small files and not for
large ones.

Text files have an ENCODING. Pass `encoding="utf-8"` explicitly rather than
relying on the platform default, which differs between machines and produces
files that work for you and fail for somebody else.

For structured data, use the `json` module rather than inventing a format:
`json.load(f)` and `json.dump(obj, f)`.
""",
                    "task": "Write `count_lines(path)` returning the number of lines in a file, using `with`.",
                    "starter": "def count_lines(path):\n    pass\n",
                    "solution": "def count_lines(path):\n    with open(path, encoding=\"utf-8\") as f:\n        return sum(1 for _ in f)\n",
                    "validators": [
                        {"pattern": r"def\s+count_lines\s*\(", "hint": "Define `def count_lines(path):`."},
                        {"pattern": r"with\s+open\s*\(", "hint": "Use `with open(...) as f:` so the file closes itself."},
                        {"pattern": r"encoding\s*=", "hint": "Pass `encoding=\"utf-8\"` rather than relying on the platform default."},
                        {"pattern": r"return\b", "hint": "Return the count."},
                    ],
                },
                {
                    "slug": "py-classes",
                    "title": "Classes",
                    "summary": "Your own types, and what self is.",
                    "body": """
    class Student:
        def __init__(self, name, score=0):
            self.name = name
            self.score = score

        def passed(self):
            return self.score >= 50

        def __repr__(self):
            return f"Student({self.name!r}, {self.score})"

`__init__` runs when the object is created. `self` is the instance, and it is
the FIRST parameter of every method — Python passes it automatically when you
call `student.passed()`, but you must write it in the definition.

Attributes are created by assigning to `self.something`. There is no separate
declaration.

`__repr__` decides how the object prints. Defining it costs one line and makes
every debugging session easier; without it you get an unhelpful memory address.

Python has no private attributes. A leading underscore (`_score`) is a
convention meaning "internal, do not rely on this", enforced by nothing but
agreement — which, in practice, works.

Inheritance:

    class Prefect(Student):
        def __init__(self, name, score, house):
            super().__init__(name, score)
            self.house = house

`super()` calls the parent's version. Reach for inheritance when a genuine "is
a" relationship exists; when it does not, holding an object as an attribute is
usually the better design.
""",
                    "task": "Write a `Student` class with a constructor taking name and score (defaulting to 0), a `passed()` method returning score >= 50, and a `__repr__`.",
                    "starter": "class Student:\n    pass\n",
                    "solution": "class Student:\n    def __init__(self, name, score=0):\n        self.name = name\n        self.score = score\n\n    def passed(self):\n        return self.score >= 50\n\n    def __repr__(self):\n        return f\"Student({self.name!r}, {self.score})\"\n",
                    "validators": [
                        {"pattern": r"class\s+Student", "hint": "Declare `class Student:`."},
                        {"pattern": r"def\s+__init__\s*\(\s*self", "hint": "Define `__init__(self, name, score=0)` — self comes first."},
                        {"pattern": r"self\s*\.\s*name\s*=", "hint": "Store the name with `self.name = name`."},
                        {"pattern": r"def\s+passed\s*\(\s*self", "hint": "Define `passed(self)` returning whether score >= 50."},
                        {"pattern": r"def\s+__repr__\s*\(\s*self", "hint": "Define `__repr__(self)` so the object prints usefully."},
                    ],
                },
                {
                    "slug": "py-modules",
                    "title": "Modules and the standard library",
                    "summary": "Using other people's code, and organising your own.",
                    "body": """
    import math
    from datetime import date
    import json

    math.sqrt(16)
    date.today()

Any `.py` file is a module. `import mine` runs it once and gives you its names.

`from x import *` is best avoided: it fills your namespace with names you did
not list, and a reader cannot tell where anything came from.

The standard library is unusually large, and knowing what is in it saves writing
things badly:

- `math`, `random`, `statistics`
- `datetime` for dates and times
- `json` and `csv` for data
- `pathlib` for filesystem paths — `Path("a") / "b"` beats string concatenation
- `collections` — `Counter` counts things in one line, `defaultdict` removes the
  "first time" special case

The `if __name__ == "__main__":` guard runs a block only when the file is
executed directly, not when it is imported. Put your script's entry point there,
and the file becomes importable for testing without running everything.

Third-party packages install with `pip`, into a VIRTUAL ENVIRONMENT — one per
project, so two projects can want different versions without a fight.
""",
                    "task": "Write a script that imports Counter from collections and defines `most_common_word(words)` returning the single most frequent word.",
                    "starter": "# import Counter, then write the function\n",
                    "solution": "from collections import Counter\n\n\ndef most_common_word(words):\n    return Counter(words).most_common(1)[0][0]\n",
                    "validators": [
                        {"pattern": r"from\s+collections\s+import\s+Counter", "hint": "Import with `from collections import Counter`."},
                        {"pattern": r"def\s+most_common_word\s*\(", "hint": "Define `def most_common_word(words):`."},
                        {"pattern": r"Counter\s*\(", "hint": "Build a `Counter` from the words."},
                        {"pattern": r"most_common\s*\(", "hint": "Use `.most_common(1)` and take the word out of the result."},
                    ],
                },
            ],
        },
    ],
}
