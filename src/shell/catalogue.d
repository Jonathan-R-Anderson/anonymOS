module shell.catalogue;

struct LfeFeature
{
    immutable(char)[] title;
    immutable(char)[] detail;
}

struct LfeTranscript
{
    immutable(char)[] title;
    immutable(char)[][] lines;
}

struct LfeCommandDoc
{
    immutable(char)[] command;
    immutable(char)[] description;
}

immutable LfeFeature[] lfeFeatureCatalogue = [
    LfeFeature("LFE REPL", "Evaluate prefix arithmetic, assign variables, define functions and exit with (exit)."),
    LfeFeature("Module loading", "Compile modules with (c \"file.lfe\") and call module:function exports."),
    LfeFeature("Data types", "Work with numbers, atoms, tuples, lists and maps including map updates."),
    LfeFeature("Quoting", "Use quote, backquote, comma and comma-at for constructing code values."),
    LfeFeature("Bindings", "Bind values via (set ...) and scoped (let ...) constructs."),
    LfeFeature("Pattern matching", "Use case, cond and multi-clause defun with guards."),
    LfeFeature("Records", "Define records through defrecord with generated accessors and setters."),
    LfeFeature("Macros", "Create macros using defmacro and inspect with (macroexpand ...)."),
    LfeFeature("Modules", "Structure code with defmodule and reload implementations on demand."),
    LfeFeature("I/O utilities", "Call lfe_io:format and helpers like proplists:get_value for formatted output."),
    LfeFeature("File operations", "Manipulate the filesystem using helpers such as (cp source dest)."),
    LfeFeature("Concurrency", "Spawn processes, link, send messages with ! and receive mailboxes."),
    LfeFeature("Loops", "Demonstrate iterative flows like tut25:demo showcasing continue semantics."),
    LfeFeature("Object system", "Inspect and manipulate objects through resolve, bind, clone and related APIs."),
];

immutable LfeTranscript[] lfeTranscriptCatalogue = [
    LfeTranscript(
        "REPL basics",
        [
            "lfe> (* 2 (+ 1 2 3 4 5 6))",
            "42",
            "lfe> (set multiplier 2)",
            "2",
            "lfe> (* multiplier (+ 1 2 3 4 5 6))",
            "42",
            "lfe> (defun double (x) (* 2 x))",
            "0",
            "lfe> (double 21)",
            "42",
            "lfe> (exit)",
        ],
    ),
    LfeTranscript(
        "Macros and quoting",
        [
            "lfe> (defmacro unless (test body)",
            "      `(if (not ,test) ,body))",
            "0",
            "lfe> (unless (> 3 4) 'yes)",
            "yes",
            "lfe> '(1 2 3)",
            "(1 2 3)",
            "lfe> `(a ,(+ 1 1) c)",
            "(A 2 C)",
        ],
    ),
    LfeTranscript(
        "List processing",
        [
            "lfe> (defun map (fun list)",
            "      (case list",
            "        ('() '())",
            "        ((cons head tail)",
            "         (cons (fun head) (map fun tail)))))",
            "0",
            "lfe> (map #'(lambda (x) (* x x)) '(1 2 3 4))",
            "(1 4 9 16)",
        ],
    ),
    LfeTranscript(
        "Modules and compilation",
        [
            "lfe> (c \"tut10.lfe\")",
            "#(module tut10 ok)",
            "lfe> (tut10:reverse '(1 2 3 4))",
            "(4 3 2 1)",
            "lfe> (tut10:reverse '(a b c d))",
            "(D C B A)",
        ],
    ),
    LfeTranscript(
        "Concurrency",
        [
            "lfe> (set greeter",
            "      (spawn (lambda ()",
            "        (receive",
            "          ((tuple 'greet from)",
            "           (io:format \"Greetings, ~p!~n\" (tuple from)))",
            "          (after 5000",
            "            (io:format \"timeout~n\" '()))))))",
            "<0.43.0>",
            "lfe> (! greeter (tuple 'greet 'shell))",
            "#(message 'greet 'shell)",
            "lfe> (flush)",
            "(FLUSH GREETINGS, SHELL!)",
        ],
    ),
];

immutable LfeCommandDoc[] lfeObjectCommandDocs = [
    LfeCommandDoc("(resolve path)", "Resolve a dotted module path."),
    LfeCommandDoc("(bind name obj)", "Bind a reference into the current environment."),
    LfeCommandDoc("(unbind name)", "Remove a bound reference."),
    LfeCommandDoc("(fields obj)", "List available fields for the object."),
    LfeCommandDoc("(methods obj)", "List callable methods on the object."),
    LfeCommandDoc("(call obj method args...)", "Invoke a method with the provided arguments."),
    LfeCommandDoc("(clone obj)", "Clone an object."),
    LfeCommandDoc("(extend obj fields)", "Extend object with new fields."),
    LfeCommandDoc("(detach parent name)", "Detach a named child."),
    LfeCommandDoc("(getParent obj)", "Return parent reference."),
    LfeCommandDoc("(getChildren obj)", "Return child identifiers."),
    LfeCommandDoc("(sandbox obj)", "Place object into sandbox mode."),
    LfeCommandDoc("(isIsolated obj)", "Check isolation flag."),
    LfeCommandDoc("(seal obj)", "Seal object against modification."),
    LfeCommandDoc("(verify obj)", "Verify object integrity."),
];
