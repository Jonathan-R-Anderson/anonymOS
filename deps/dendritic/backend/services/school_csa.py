"""AP Computer Science A: Java, following the College Board's ten units.

WHERE THE OUTLINE CAME FROM
---------------------------
The unit sequence is the published AP CSA course framework — primitive types,
objects, boolean logic, iteration, classes, arrays, ArrayList, 2D arrays,
inheritance, recursion. A syllabus is a specification, not authorship.

Every lesson is written for this site. Nothing is taken from csplusplus.com/csa
or any other course's materials.

WHY THE EXERCISES ARE PATTERN-CHECKED RATHER THAN COMPILED
-----------------------------------------------------------
Same as the Solidity course: the validators are regexes run in the browser, and
the page says so. Compiling Java would mean shipping a compiler or posting a
student's code to a server, and neither is worth it for exercises whose job is
to catch "you forgot the return type", which a regex catches perfectly well.

A NOTE ON THE JAVA SUBSET
-------------------------
CSA tests a deliberately small slice of Java. These lessons stay inside it —
no generics beyond ArrayList<E>, no interfaces beyond what inheritance needs, no
streams. Teaching more would not help on the exam and would crowd out the parts
that are assessed.
"""

REFERENCE = "https://csplusplus.com/csa"

BOOK = {
    "slug": "csa",
    "title": "AP CSA",
    "reference": REFERENCE,
    "reference_name": "csplusplus.com/csa",
    "provenance": (
        "Written for this site, following the College Board's published AP CSA "
        "course framework. The lessons are ours; the unit sequence is the "
        "exam's. Another treatment of the same course:"
    ),
    "subtitle": "Computer Science A: object-oriented programming in Java.",
    "blurb": (
        "The ten units of AP CSA, in the exam's order, with an exercise in every "
        "programming lesson. It is a depth course — one language, properly — so "
        "it runs from int overflow to recursion and inheritance."
    ),
    "parts": [
        {
            "title": "Primitive types",
            "blurb": "Numbers, and the ways they surprise you.",
            "chapters": [
                {
                    "slug": "csa-variables",
                    "title": "Variables and primitive types",
                    "summary": "Declaring, initialising, and the four types the exam uses.",
                    "body": """
Java is statically typed: every variable declares what it holds, and that never
changes.

    int count = 0;
    double price = 19.99;
    boolean ready = false;
    char grade = 'A';

The exam uses `int`, `double`, `boolean` and `char`. `int` holds whole numbers
in about ±2.1 billion; `double` holds decimals approximately.

Declaration and initialisation are separate ideas. `int x;` declares; `x = 5;`
initialises. Using a local variable before it is assigned is a compile error,
which is Java refusing to let you read garbage.

Naming is assessed. Java convention is camelCase for variables and methods,
PascalCase for classes, and SCREAMING_CASE for constants. `final` marks a value
that cannot change after assignment:

    final int MAX_SCORE = 100;

The habit worth forming now: declare a variable as close as possible to where it
is used, and give it a name that makes a comment unnecessary.
""",
                    "task": "Declare an int `score` set to 0, a double `average` set to 0.0, a boolean `passed` set to false, and a final int `MAX` set to 100.",
                    "starter": "public class Report {\n    public static void main(String[] args) {\n\n    }\n}\n",
                    "solution": "public class Report {\n    public static void main(String[] args) {\n        int score = 0;\n        double average = 0.0;\n        boolean passed = false;\n        final int MAX = 100;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"int\s+score\s*=\s*0", "hint": "Declare `int score = 0;`."},
                        {"pattern": r"double\s+average\s*=\s*0", "hint": "Declare `double average = 0.0;`."},
                        {"pattern": r"boolean\s+passed\s*=\s*false", "hint": "Declare `boolean passed = false;`."},
                        {"pattern": r"final\s+int\s+MAX\s*=\s*100", "hint": "Declare `final int MAX = 100;` — final means it cannot be reassigned."},
                    ],
                },
                {
                    "slug": "csa-arithmetic",
                    "title": "Arithmetic, casting and integer division",
                    "summary": "The two rules that cause most wrong answers on the exam.",
                    "body": """
Two behaviours account for an enormous share of lost marks.

INTEGER DIVISION. Dividing two ints gives an int, with the remainder discarded:

    7 / 2       // 3, not 3.5
    7 % 2       // 1  — the remainder
    7.0 / 2     // 3.5, because one operand is a double

Truncation is toward zero, not rounding. `-7 / 2` is `-3`.

CASTING. To force a double result, cast one operand:

    (double) 7 / 2      // 3.5
    (double) (7 / 2)    // 3.0 — the division already happened

Where the cast goes decides the answer, and the second form is a favourite exam
trap. Casting a double to an int truncates:

    (int) 3.99          // 3

OVERFLOW. `int` wraps silently past its maximum. Adding 1 to `Integer.MAX_VALUE`
gives a large negative number, with no error at all.

Operator precedence follows the usual rules: `*`, `/`, `%` before `+`, `-`.
Compound assignment (`+=`, `-=`, `*=`, `/=`) and the increment operators (`++`,
`--`) are all on the exam.
""",
                    "task": "Write a method `average` taking two ints and returning their true decimal average as a double.",
                    "starter": "public class Maths {\n    // int a, int b -> double average\n\n}\n",
                    "solution": "public class Maths {\n    public static double average(int a, int b) {\n        return (double) (a + b) / 2;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"double\s+average\s*\(", "hint": "The method must return `double`: `public static double average(...)`."},
                        {"pattern": r"\(\s*double\s*\)", "hint": "Cast to double, or integer division will discard the fraction."},
                        {"pattern": r"return\b", "hint": "Return the result."},
                    ],
                },
            ],
        },
        {
            "title": "Using objects",
            "blurb": "Strings, wrappers, and calling methods somebody else wrote.",
            "chapters": [
                {
                    "slug": "csa-objects",
                    "title": "Objects and references",
                    "summary": "What a variable holds when it is not a primitive.",
                    "body": """
A primitive variable holds a value. An object variable holds a REFERENCE — the
address of an object elsewhere in memory.

    Rectangle a = new Rectangle(3, 4);
    Rectangle b = a;          // both refer to the SAME object

Changing through `b` changes what `a` sees, because there is one object. This is
the source of a great many surprises, and the exam tests it directly.

`null` means "refers to nothing". Calling a method on a null reference throws a
NullPointerException at run time.

`new` creates an object and runs a constructor. The constructor's job is to leave
the object in a usable state:

    Rectangle r = new Rectangle(3, 4);

Comparing objects with `==` compares REFERENCES — whether they are the same
object — not contents. To compare contents, use `.equals()`. For Strings this
distinction is the single most tested gotcha in the course.
""",
                    "checks": [
                        "What is the difference between `a == b` and `a.equals(b)` for objects?",
                        "What does a variable of an object type actually store?",
                    ],
                },
                {
                    "slug": "csa-strings",
                    "title": "Strings",
                    "summary": "Immutable, zero-indexed, and full of off-by-one traps.",
                    "body": """
Strings are objects and they are IMMUTABLE: every operation returns a new String
and leaves the original alone.

    String s = "hello";
    s.toUpperCase();          // does nothing useful — result discarded
    s = s.toUpperCase();      // this is what you meant

The methods the exam uses:

    s.length()                    // number of characters
    s.substring(a)                // from index a to the end
    s.substring(a, b)             // from a up to but NOT including b
    s.indexOf("x")                // first position, or -1 if absent
    s.equals(t)                   // content comparison
    s.compareTo(t)                // negative, zero or positive

`substring(a, b)` excluding `b` is deliberate and consistently trips people:
`"hello".substring(1, 3)` is `"el"`, and its length is `b - a`.

Indexing starts at 0, so the last character is at `length() - 1`. Asking for
`length()` itself throws StringIndexOutOfBoundsException.

Concatenation with `+` converts the other operand to a String, which is why
`1 + 2 + "x"` is `"3x"` and `"x" + 1 + 2` is `"x12"`.
""",
                    "task": "Write a method `initials` taking a first and last name and returning the two first letters as a String, e.g. \"Ada\",\"Lovelace\" -> \"AL\".",
                    "starter": "public class Names {\n    // String first, String last -> String initials\n\n}\n",
                    "solution": "public class Names {\n    public static String initials(String first, String last) {\n        return first.substring(0, 1) + last.substring(0, 1);\n    }\n}\n",
                    "validators": [
                        {"pattern": r"String\s+initials\s*\(", "hint": "Declare `public static String initials(String first, String last)`."},
                        {"pattern": r"substring\s*\(", "hint": "Use `substring` to take the first character of each name."},
                        {"pattern": r"return\b", "hint": "Return the joined initials."},
                    ],
                },
            ],
        },
        {
            "title": "Boolean expressions and if",
            "blurb": "Making decisions, and the logic behind them.",
            "chapters": [
                {
                    "slug": "csa-conditionals",
                    "title": "if, else and comparison",
                    "summary": "Branching, and the mistakes that compile anyway.",
                    "body": """
    if (score >= 90) {
        grade = 'A';
    } else if (score >= 80) {
        grade = 'B';
    } else {
        grade = 'C';
    }

The comparison operators are `==`, `!=`, `<`, `>`, `<=`, `>=`. Note `==` for
comparison and `=` for assignment — in Java, writing `if (x = 5)` is a compile
error for ints, which is a mercy other languages do not offer.

Order matters in an else-if chain. Conditions are tested top to bottom and the
first true one wins, so a broad condition placed early makes everything below it
unreachable. If a later branch never seems to run, that is almost always why.

Two habits that prevent real bugs:

- Always use braces, even for one statement. Adding a second line later without
  them silently puts it outside the if.
- Comparing doubles with `==` is unreliable, because 0.1 + 0.2 is not exactly
  0.3. Compare the absolute difference against a small tolerance instead.
""",
                    "task": "Write a method `grade` taking an int score and returning 'A' for 90+, 'B' for 80+, 'C' for 70+, otherwise 'F'.",
                    "starter": "public class Grader {\n    // int score -> char grade\n\n}\n",
                    "solution": "public class Grader {\n    public static char grade(int score) {\n        if (score >= 90) {\n            return 'A';\n        } else if (score >= 80) {\n            return 'B';\n        } else if (score >= 70) {\n            return 'C';\n        } else {\n            return 'F';\n        }\n    }\n}\n",
                    "validators": [
                        {"pattern": r"char\s+grade\s*\(", "hint": "Declare `public static char grade(int score)`."},
                        {"pattern": r"if\s*\(\s*score\s*>=\s*90", "hint": "Test the highest boundary first — order decides which branch wins."},
                        {"pattern": r"else", "hint": "Use else-if branches rather than separate ifs."},
                        {"pattern": r"'F'", "hint": "Return 'F' for anything below 70."},
                    ],
                },
                {
                    "slug": "csa-boolean-logic",
                    "title": "Boolean logic and De Morgan's laws",
                    "summary": "Combining conditions, and short-circuiting.",
                    "body": """
    &&    and
    ||    or
    !     not

SHORT-CIRCUIT evaluation is the part with teeth. `&&` stops at the first false;
`||` stops at the first true. So the right side may never run — which is not
merely an optimisation, it is how you write this safely:

    if (s != null && s.length() > 0)

Reverse those and a null `s` throws. The null check must come first, and the
exam tests exactly this.

De Morgan's laws convert between the forms, and are assessed:

    !(a && b)   is   !a || !b
    !(a || b)   is   !a && !b

Negating a compound condition flips BOTH the operators and the operands.
Forgetting to flip the operator is the standard error.

Truth tables are worth being able to produce quickly. For two variables there
are four rows, and tracing a condition through all four is faster and more
reliable than reasoning about it in prose.
""",
                    "checks": [
                        "Why must a null check come before a method call in an && condition?",
                        "Rewrite !(x > 5 && y < 3) without the outer negation.",
                    ],
                },
            ],
        },
        {
            "title": "Iteration",
            "blurb": "Loops, and how to be sure they end.",
            "chapters": [
                {
                    "slug": "csa-loops",
                    "title": "while and for",
                    "summary": "Two shapes for the same idea.",
                    "body": """
    while (i < 10) {
        i++;
    }

    for (int i = 0; i < 10; i++) {
        // initialise; test; update — all in one line
    }

Use `for` when you know the number of repetitions, `while` when you are waiting
for a condition. They are interchangeable; the choice is about which makes the
intent obvious.

A `for` loop's three parts run in a specific order: initialise once, then test,
body, update, test, body, update… The test happens BEFORE the first body, so a
loop whose condition starts false never runs at all.

Infinite loops come from a condition that nothing inside the loop changes. When
you write the condition, immediately ask what changes it.

Off-by-one errors come from `<` versus `<=`. For a list of n items indexed from
0, the last valid index is n-1, so the condition is `i < n`. Writing `i <= n`
runs one time too many and throws.

Nested loops multiply: an outer loop of n and an inner of m runs the inner body
n × m times. That is how a small change to a bound becomes a large change in
running time.
""",
                    "task": "Write a method `sumTo` that returns the sum of all integers from 1 to n inclusive, using a loop.",
                    "starter": "public class Sums {\n    // int n -> int sum of 1..n\n\n}\n",
                    "solution": "public class Sums {\n    public static int sumTo(int n) {\n        int total = 0;\n        for (int i = 1; i <= n; i++) {\n            total += i;\n        }\n        return total;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"int\s+sumTo\s*\(", "hint": "Declare `public static int sumTo(int n)`."},
                        {"pattern": r"for\s*\(|while\s*\(", "hint": "Use a for or while loop to accumulate the total."},
                        {"pattern": r"<=\s*n", "hint": "The range is inclusive of n, so the test is `i <= n`."},
                        {"pattern": r"return\b", "hint": "Return the accumulated total."},
                    ],
                },
            ],
        },
        {
            "title": "Writing classes",
            "blurb": "Building your own types.",
            "chapters": [
                {
                    "slug": "csa-classes",
                    "title": "Classes, constructors and encapsulation",
                    "summary": "State, behaviour, and keeping the two honest.",
                    "body": """
    public class Student {
        private String name;
        private int score;

        public Student(String name, int score) {
            this.name = name;
            this.score = score;
        }

        public int getScore() { return score; }

        public void setScore(int score) {
            if (score >= 0) { this.score = score; }
        }
    }

Instance variables are `private`. Methods that the outside needs are `public`.
That is ENCAPSULATION, and the reason for it is visible in `setScore`: because
the field is private, the class can enforce that a score is never negative. Make
it public and that guarantee is gone, permanently, everywhere.

`this` distinguishes the instance variable from a parameter with the same name.
Without it, `name = name` assigns the parameter to itself and the field stays
null — a bug that compiles and does nothing.

A constructor has no return type and shares the class's name. If you write none,
Java supplies a no-argument one; if you write any, it does not.

Static members belong to the class rather than to an instance. `main` is static
because it runs before any object exists.
""",
                    "task": "Write a `Student` class with private String name and private int score, a two-argument constructor, and a getScore method.",
                    "starter": "public class Student {\n\n}\n",
                    "solution": "public class Student {\n    private String name;\n    private int score;\n\n    public Student(String name, int score) {\n        this.name = name;\n        this.score = score;\n    }\n\n    public int getScore() {\n        return score;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"private\s+String\s+name", "hint": "Declare `private String name;` — private, so the class controls it."},
                        {"pattern": r"private\s+int\s+score", "hint": "Declare `private int score;`."},
                        {"pattern": r"public\s+Student\s*\(", "hint": "A constructor is `public Student(...)` with no return type."},
                        {"pattern": r"this\s*\.\s*name\s*=", "hint": "Use `this.name = name;` or the parameter shadows the field."},
                        {"pattern": r"public\s+int\s+getScore\s*\(", "hint": "Add `public int getScore()`."},
                    ],
                },
            ],
        },
        {
            "title": "Arrays and ArrayList",
            "blurb": "Collections: fixed, growable, and rectangular.",
            "chapters": [
                {
                    "slug": "csa-arrays",
                    "title": "Arrays",
                    "summary": "Fixed size, zero-indexed, and the enhanced for loop.",
                    "body": """
    int[] scores = new int[5];        // five zeros
    int[] fixed  = {3, 1, 4, 1, 5};   // literal

An array's length is fixed at creation and read with `.length` — a field, not a
method, so no parentheses. Strings use `.length()` with them, and mixing the two
up is a compile error you will meet often.

Valid indices run 0 to `length - 1`. Anything else throws
ArrayIndexOutOfBoundsException.

Two ways to traverse:

    for (int i = 0; i < a.length; i++) { a[i] = a[i] * 2; }   // can modify
    for (int value : a) { sum += value; }                      // read only

The enhanced for loop is cleaner and cannot change the array or tell you where
you are. Use it when you only need the values; use the indexed form when you
need to write, or need the index.

Arrays are objects, so an array variable holds a reference. Passing one to a
method passes the reference, and the method can change the caller's array.
""",
                    "task": "Write a method `max` that returns the largest value in an int array, assuming it has at least one element.",
                    "starter": "public class Stats {\n    // int[] a -> int largest\n\n}\n",
                    "solution": "public class Stats {\n    public static int max(int[] a) {\n        int best = a[0];\n        for (int i = 1; i < a.length; i++) {\n            if (a[i] > best) {\n                best = a[i];\n            }\n        }\n        return best;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"int\s+max\s*\(\s*int\s*\[\s*\]", "hint": "Declare `public static int max(int[] a)`."},
                        {"pattern": r"a\s*\[\s*0\s*\]", "hint": "Start from the first element rather than from 0 — the values may all be negative."},
                        {"pattern": r"\.length", "hint": "Use `a.length` (a field, no parentheses) as the bound."},
                        {"pattern": r"return\b", "hint": "Return the largest value found."},
                    ],
                },
                {
                    "slug": "csa-arraylist",
                    "title": "ArrayList",
                    "summary": "A list that grows, and the loop that breaks when you remove.",
                    "body": """
    ArrayList<String> names = new ArrayList<String>();
    names.add("Ada");
    names.add(0, "Grace");     // insert at index
    names.get(0);
    names.set(0, "Alan");
    names.remove(0);
    names.size();

Note `size()` here where an array uses `length`. Three different spellings for
"how big is it" across String, array and ArrayList is a genuine irritation and
the exam does test it.

ArrayList holds OBJECTS, not primitives, so an ArrayList of numbers is
`ArrayList<Integer>`. Java autoboxes between `int` and `Integer` automatically,
which mostly just works — except that `remove(int)` removes by INDEX while
`remove(Integer)` removes by VALUE.

The classic bug: removing while looping forwards.

    for (int i = 0; i < list.size(); i++) {
        if (test(list.get(i))) { list.remove(i); }   // skips the next element
    }

Removing shifts everything down, so the element that moves into position `i` is
never examined. Loop BACKWARDS when removing, and the problem disappears.
""",
                    "task": "Write a method `countLongerThan` returning how many Strings in an ArrayList have length greater than n.",
                    "starter": "import java.util.ArrayList;\n\npublic class Words {\n    // ArrayList<String> list, int n -> int count\n\n}\n",
                    "solution": "import java.util.ArrayList;\n\npublic class Words {\n    public static int countLongerThan(ArrayList<String> list, int n) {\n        int count = 0;\n        for (String s : list) {\n            if (s.length() > n) {\n                count++;\n            }\n        }\n        return count;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"int\s+countLongerThan\s*\(", "hint": "Declare `public static int countLongerThan(ArrayList<String> list, int n)`."},
                        {"pattern": r"for\s*\(", "hint": "Loop over the list \u2014 an enhanced for loop reads well here."},
                        {"pattern": r"\.length\s*\(\s*\)", "hint": "String uses `length()` with parentheses, unlike an array."},
                        {"pattern": r"return\s+count", "hint": "Return the count."},
                    ],
                },
                {
                    "slug": "csa-2d-arrays",
                    "title": "2D arrays",
                    "summary": "Rows and columns, in that order.",
                    "body": """
    int[][] grid = new int[3][4];      // 3 rows, 4 columns
    grid[1][2] = 7;                    // row 1, column 2

Row first, then column — always, on this exam. `grid.length` is the number of
ROWS; `grid[0].length` is the number of columns in row 0.

Traversing needs nested loops:

    for (int r = 0; r < grid.length; r++) {
        for (int c = 0; c < grid[r].length; c++) {
            sum += grid[r][c];
        }
    }

Using `grid[r].length` rather than `grid[0].length` costs nothing and is correct
even for a ragged array, where rows have different lengths.

Row-major traversal is the loop above: all of row 0, then all of row 1.
Column-major swaps the loops, and the exam asks you to trace both and say what
order elements are visited in.

The enhanced for loop works too, taking each row as an array:

    for (int[] row : grid) {
        for (int value : row) { sum += value; }
    }
""",
                    "task": "Write a method `sumAll` returning the total of every element in a 2D int array.",
                    "starter": "public class Grid {\n    // int[][] grid -> int total\n\n}\n",
                    "solution": "public class Grid {\n    public static int sumAll(int[][] grid) {\n        int total = 0;\n        for (int r = 0; r < grid.length; r++) {\n            for (int c = 0; c < grid[r].length; c++) {\n                total += grid[r][c];\n            }\n        }\n        return total;\n    }\n}\n",
                    "validators": [
                        {"pattern": r"int\s+sumAll\s*\(\s*int\s*\[\s*\]\s*\[\s*\]", "hint": "Declare `public static int sumAll(int[][] grid)`."},
                        {"pattern": r"grid\s*\.\s*length", "hint": "`grid.length` is the number of rows."},
                        {"pattern": r"grid\s*\[\s*\w+\s*\]\s*\.\s*length", "hint": "Use `grid[r].length` for the column bound — correct even for ragged arrays."},
                        {"pattern": r"return\b", "hint": "Return the total."},
                    ],
                },
            ],
        },
        {
            "title": "Inheritance and recursion",
            "blurb": "The last two units, and the two that reward practice most.",
            "chapters": [
                {
                    "slug": "csa-inheritance",
                    "title": "Inheritance and polymorphism",
                    "summary": "extends, super, and which method actually runs.",
                    "body": """
    public class Animal {
        public String speak() { return "..."; }
    }

    public class Dog extends Animal {
        @Override
        public String speak() { return "Woof"; }
    }

A subclass inherits the public and protected members of its superclass and can
OVERRIDE methods to change the behaviour. `super.speak()` calls the version it
replaced; `super(...)` in a constructor calls the superclass constructor, and
must be the first statement.

Polymorphism is the part the exam leans on:

    Animal a = new Dog();
    a.speak();        // "Woof"

The variable's declared type decides what you may CALL — only methods `Animal`
declares. The object's actual type decides which VERSION runs. Compile-time
checking, run-time dispatch, and holding those two apart is most of what this
unit is about.

So `a.fetch()` fails to compile even though the object is a Dog, because
`Animal` has no `fetch`. Casting `((Dog) a).fetch()` compiles and works — and
throws ClassCastException if the object is not really a Dog.

Every class inherits from Object, which is why `toString()` and `equals()` exist
on everything, and why overriding `toString()` is worth doing.
""",
                    "task": "Write an `Animal` class with a speak() returning \"...\", and a `Dog` subclass overriding it to return \"Woof\".",
                    "starter": "public class Animal {\n\n}\n\n",
                    "solution": "public class Animal {\n    public String speak() {\n        return \"...\";\n    }\n}\n\npublic class Dog extends Animal {\n    @Override\n    public String speak() {\n        return \"Woof\";\n    }\n}\n",
                    "validators": [
                        {"pattern": r"class\s+Dog\s+extends\s+Animal", "hint": "Declare `public class Dog extends Animal`."},
                        {"pattern": r"String\s+speak\s*\(\s*\)", "hint": "Both classes need `public String speak()`."},
                        {"pattern": r"Woof", "hint": "Dog's version should return \"Woof\"."},
                    ],
                },
                {
                    "slug": "csa-recursion",
                    "title": "Recursion",
                    "summary": "A method that calls itself, and the base case that stops it.",
                    "body": """
    public static int factorial(int n) {
        if (n <= 1) { return 1; }     // base case
        return n * factorial(n - 1);  // recursive case
    }

Every recursive method needs two things, and omitting either is the whole set of
ways to get it wrong:

- A BASE CASE that returns without recursing.
- A recursive case that moves toward the base case.

Without a base case, or with a recursive call that does not get closer to it,
the calls stack up until the program dies with a StackOverflowError.

Tracing is the skill the exam tests. `factorial(4)` becomes 4 × factorial(3),
which becomes 4 × 3 × factorial(2), and so on until factorial(1) returns 1 and
the whole thing collapses back up. Writing that expansion out by hand is the
fastest way to become confident with it.

Recursion is natural where the problem contains a smaller copy of itself:
traversing a tree, binary search, merge sort. It is a poor choice where a loop
is obvious — recursive counting is slower and uses memory for no gain.

The exam expects you to trace recursive calls, including on arrays and Strings,
and to recognise when a method will not terminate.
""",
                    "task": "Write a recursive method `sumTo(int n)` returning 1 + 2 + ... + n, with a base case.",
                    "starter": "public class Recurse {\n    // recursive, no loops\n\n}\n",
                    "solution": "public class Recurse {\n    public static int sumTo(int n) {\n        if (n <= 1) {\n            return n;\n        }\n        return n + sumTo(n - 1);\n    }\n}\n",
                    "validators": [
                        {"pattern": r"int\s+sumTo\s*\(", "hint": "Declare `public static int sumTo(int n)`."},
                        {"pattern": r"if\s*\(", "hint": "You need a base case, or it never stops."},
                        {"pattern": r"sumTo\s*\(\s*n\s*-\s*1\s*\)", "hint": "Recurse on a smaller value: `sumTo(n - 1)`."},
                        {"pattern": r"return\s+n\s*\+", "hint": "Combine n with the result of the recursive call."},
                    ],
                },
            ],
        },
    ],
}
