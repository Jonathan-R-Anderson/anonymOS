"""Human-Computer Interaction: designing for the person, not the demo.

WHERE THE OUTLINE CAME FROM
---------------------------
The topic sequence is the conventional HCI syllabus — mental models, usability,
design principles, research methods, prototyping, evaluation, accessibility and
design ethics. A standard syllabus rather than anyone's authorship. Every lesson
below is written for this site.

Where the course cites established work it names it and describes it in its own
words: Norman's affordances and signifiers, Nielsen's heuristics, Fitts's law,
Miller on working memory. These are attributed ideas, not borrowed text.

WHY THERE ARE NO CODE EXERCISES
-------------------------------
HCI's exercises are observational — watch somebody use a thing, count the steps,
find the error case. A regex cannot check any of that, and inventing a coding
task to have something clickable would misrepresent what the discipline is. The
chapters end with things to go and look at instead.
"""

REFERENCE = "https://csplusplus.com/hci"

BOOK = {
    "slug": "hci",
    "title": "HCI",
    "reference": REFERENCE,
    "reference_name": "csplusplus.com/hci",
    "provenance": (
        "Written for this site, following the conventional HCI syllabus. "
        "Established work is attributed where it is used. Another treatment of "
        "the same material:"
    ),
    "subtitle": "Human-Computer Interaction: why things are hard to use, and what to do.",
    "blurb": (
        "Twelve chapters on designing for people: how they form models of a "
        "system, why they make errors, how to find out what they actually do, "
        "and how to tell whether your design works before you ship it."
    ),
    "parts": [
        {
            "title": "How people work",
            "blurb": "The constraints you are designing around.",
            "chapters": [
                {
                    "slug": "hci-mental-models",
                    "title": "Mental models",
                    "summary": "People act on the story they have built, not on your architecture.",
                    "body": """
Everyone using a system carries a MENTAL MODEL of it: a rough internal story of
what it does and how. It is usually wrong in detail, and it is what they act on
regardless.

Three models sit in tension:

- The DESIGN model — how the designer thinks it works.
- The SYSTEM image — what the interface actually communicates.
- The USER model — what the person concludes from that.

The designer never talks to the user directly; they only ever talk through the
system image. When a user is confused, the fault is nearly always in that middle
layer, not in the user.

The classic example is the thermostat. Many people believe turning it to 30
heats the room faster, on a mental model of a valve or a tap. It does not — it
is a threshold, not a rate. That belief is entirely reasonable given what the
interface shows, and it costs real money in real houses.

The practical instruction: when somebody misuses your system, do not ask why
they were careless. Ask what the interface led them to believe, because that
belief is a fact about your design.
""",
                    "checks": [
                        "Whose fault is it when a mental model is wrong, and why?",
                        "Describe something you have used where your model was wrong for a while.",
                    ],
                },
                {
                    "slug": "hci-memory-attention",
                    "title": "Memory, attention and error",
                    "summary": "The limits that make interfaces hard, and how to design around them.",
                    "body": """
Working memory holds only a few items at once — Miller's famous estimate was
around seven, and later work suggests fewer, closer to four. Anything requiring
someone to hold six things in their head while doing something else will produce
errors, and they will not be careless ones.

The design response is RECOGNITION OVER RECALL. Showing options is far easier
than making somebody remember them. This is why a menu beats a command you must
remember, and why asking a user to retype a code from another screen is a
design failure rather than a small inconvenience.

Attention is single-threaded for anything demanding. An interruption during a
multi-step task loses the state, which is why forms should preserve what was
typed when something goes wrong. Losing a half-finished form to a validation
error is the most reliably infuriating experience on the web.

Errors come in two kinds, and they need different fixes:

- SLIPS — the intention was right, the action went wrong. Clicking the wrong
  adjacent button. Fixed by design: spacing, size, confirmation on destructive
  actions.
- MISTAKES — the action was carried out correctly and the intention was wrong.
  A wrong mental model. Fixed by better feedback and clearer models, not by
  bigger buttons.

Treating a mistake as a slip produces an interface that nags without helping.
""",
                    "checks": [
                        "What is the difference between a slip and a mistake?",
                        "Why is recognition easier than recall, and where does that change a design?",
                    ],
                },
                {
                    "slug": "hci-fitts",
                    "title": "Fitts's law and physical interaction",
                    "summary": "Targets, distance, and why the corners are special.",
                    "body": """
Fitts's law says the time to hit a target depends on its distance and its size:
far and small is slow, near and large is fast. It is one of the few genuinely
predictive laws in interface design.

Its consequences are concrete:

- Make important controls bigger. Not for emphasis — for speed and accuracy.
- Put related controls near where the pointer already is. A menu that appears
  under the cursor beats one across the screen.
- Screen EDGES and CORNERS are effectively infinite targets: the pointer stops
  there, so you cannot overshoot. This is why a menu bar pinned to the top edge
  is faster to hit than one a few pixels below it, and why corners are prime
  real estate.
- Touch targets need a minimum size — roughly 44 by 44 points — because a
  fingertip is far less precise than a cursor and it covers what it is
  selecting.

The related trap is putting a destructive action adjacent to a common one. Speed
and proximity are the same property; a Delete beside a Save will be hit by
accident, and the fix is distance or an undo rather than a confirmation dialogue
people learn to dismiss.
""",
                    "checks": [
                        "Why is a control at the very edge of the screen faster to hit?",
                        "What is wrong with placing Delete next to Save?",
                    ],
                },
            ],
        },
        {
            "title": "Principles",
            "blurb": "The vocabulary for saying what is wrong.",
            "chapters": [
                {
                    "slug": "hci-affordances",
                    "title": "Affordances, signifiers and constraints",
                    "summary": "What a thing can do, what it says it can do, and what it prevents.",
                    "body": """
Don Norman's vocabulary, and it is worth using precisely:

- An AFFORDANCE is what an object makes possible. A handle affords pulling.
- A SIGNIFIER is what tells you so. A "PUSH" sign, or the visual style of a
  button.
- A CONSTRAINT prevents the wrong action. A plug that only fits one way.
- A MAPPING is the relationship between control and effect. Stove knobs
  arranged like the burners.

The famous case is a door with a flat plate on the pull side. The affordance and
the signifier disagree, so people fail — and they blame themselves, which is the
part Norman was most interested in.

Software has this constantly. Flat design removed many signifiers in the name of
cleanliness: text that might be a button, an icon whose meaning is guessable at
best. Something clickable should look clickable, and the aesthetic argument
against that is a bad trade.

Constraints are underused and are the strongest tool available. Disabling an
impossible option, or a date picker that cannot select the past, prevents the
error rather than reporting it. A prevented error costs nothing; a reported one
costs attention, recovery and confidence.
""",
                    "checks": [
                        "What is the difference between an affordance and a signifier?",
                        "Why is a constraint better than a validation message?",
                    ],
                },
                {
                    "slug": "hci-heuristics",
                    "title": "Usability heuristics",
                    "summary": "Nielsen's ten, as a checklist you can actually apply.",
                    "body": """
Jakob Nielsen's heuristics are the standard evaluation vocabulary. Paraphrased,
they ask:

- Does the system show its current state?
- Does it use the user's language rather than internal jargon?
- Can the user get out of somewhere they did not mean to be?
- Is it consistent with itself and with platform conventions?
- Does it prevent errors rather than only reporting them?
- Does it show options instead of requiring recall?
- Are there accelerators for experienced users without confusing new ones?
- Is anything on screen that does not need to be?
- Do error messages say what went wrong and what to do?
- Is help available where it is needed?

Their value is not as a scoring rubric. It is that they give you WORDS for a
vague sense that something is wrong. "This feels bad" is not actionable; "there
is no visible system status during a thirty-second upload" is.

A heuristic evaluation is several people going through independently and then
pooling findings. Independently matters: the first person's opinion anchors
everybody else's if you do it together, and three independent evaluators find
substantially more than three who conferred.
""",
                    "checks": [
                        "Why evaluate independently before pooling findings?",
                        "Rewrite \"Error 0x8007\" as a message that satisfies the error heuristic.",
                    ],
                },
                {
                    "slug": "hci-feedback",
                    "title": "Feedback and system status",
                    "summary": "Silence is the worst response an interface can give.",
                    "body": """
Every action needs a response, and the required kind depends on how long it
takes. The rough thresholds are well established:

- Under 0.1 second — feels instantaneous. No indicator needed.
- Up to about 1 second — noticeable, but thought is not interrupted. A subtle
  cue is enough.
- Up to about 10 seconds — attention wanders. Show a progress indicator, and a
  determinate one if you can.
- Beyond that — let them do something else, and tell them when it is finished.

The unforgivable case is silence. A button that appears to do nothing gets
pressed again, which is how duplicate payments happen. Disable it on first press
and show that something is happening.

Progress bars should be honest. One that sits at 99% teaches people that the
whole indicator is a lie, and after that they cannot judge anything. If you
genuinely do not know the duration, an indeterminate spinner with a description
of what is happening beats a fabricated percentage.

Feedback also covers success. An action that completes with no acknowledgement
leaves people wondering, and they check — which costs them more than the message
would have.
""",
                    "checks": [
                        "What happens when a button gives no feedback, and what does that cost?",
                        "Why is a dishonest progress bar worse than no percentage at all?",
                    ],
                },
            ],
        },
        {
            "title": "Finding out",
            "blurb": "Research, because you are not the user.",
            "chapters": [
                {
                    "slug": "hci-user-research",
                    "title": "User research",
                    "summary": "Asking, watching, and which one to believe.",
                    "body": """
The foundational fact of the discipline: YOU ARE NOT THE USER. You know where
everything is, you know what the words mean, and you built your own mental
model. None of that transfers.

Methods, and what each is good for:

- INTERVIEWS — understanding goals and context. Good for why, unreliable for
  what: people describe an idealised version of their behaviour, without
  intending to mislead.
- OBSERVATION — watching real work. The gold standard, because it reveals the
  workarounds people have stopped noticing they perform.
- SURVEYS — scale, once you already know what to ask. Useless for discovery,
  because you can only ask about what you thought of.
- ANALYTICS — what happened, at scale, with no explanation of why.

The rule worth carrying: WATCH WHAT PEOPLE DO, NOT WHAT THEY SAY THEY DO. The
gap is not dishonesty; memory is reconstructive and everyone rationalises.

Leading questions destroy data. "Was that easy?" gets yes. "Tell me what you
were expecting to happen there" gets something real. Silence is a technique —
wait, and people fill it with the thing they were hesitating over.

Personas and scenarios summarise research findings. Built from data they are
useful; invented in a meeting they are stereotypes with a photograph on them.
""",
                    "checks": [
                        "Why are surveys poor for discovery?",
                        "Rewrite \"Did you find that easy?\" as a non-leading question.",
                    ],
                },
                {
                    "slug": "hci-prototyping",
                    "title": "Prototyping",
                    "summary": "Being wrong cheaply and early.",
                    "body": """
A prototype exists to answer a question before the answer becomes expensive.
Fidelity should match the question:

- PAPER — sketches. Answers "is this the right flow?" in an afternoon.
- WIREFRAMES — structure and hierarchy without visual design.
- INTERACTIVE MOCKUPS — clickable, answering questions about navigation.
- HIGH FIDELITY — looks real, answers questions about visual design and detail.

Low fidelity has an advantage beyond speed, and it is the important one: people
critique a sketch honestly and are polite about something that looks finished.
Showing a polished mockup gets you compliments; showing a sketch gets you the
truth.

WIZARD OF OZ prototyping fakes the hard part — a human behind the curtain
answering what will eventually be an algorithm. It tests whether the experience
is worth building before you build the difficult half.

The failure to avoid is prototype creep: the throwaway that becomes production
because it demos well. Decide before you start whether this is a question or a
foundation, because those are built differently and confusing them produces a
codebase nobody can defend.
""",
                    "checks": [
                        "Why does a rough sketch get more honest feedback than a polished mockup?",
                        "What question is a Wizard of Oz prototype answering?",
                    ],
                },
                {
                    "slug": "hci-usability-testing",
                    "title": "Usability testing",
                    "summary": "Five people, real tasks, and keeping quiet.",
                    "body": """
Usability testing is watching somebody attempt a real task with your interface
while you say as little as possible.

How to run one:

- Give a TASK, not instructions. "Buy a blue shirt in your size" — never "click
  the search box, then type".
- Ask them to think aloud. It is unnatural and it works.
- Do not help. The silence is uncomfortable and it is the data. Every rescue
  destroys the finding you came for.
- Watch where they look, where they hesitate, and what they say just before they
  give up.

Nielsen's well-known finding is that around five participants surface the great
majority of usability problems, because the same problems recur immediately. So
run small tests often rather than one large study late — five people before
building beats fifty afterwards.

Measure both: TASK COMPLETION and time, plus what people say. When those two
disagree, believe the behaviour.

The hardest discipline is not defending your design. Explaining what they should
have done contaminates the test and teaches you nothing. If it needs explaining,
that IS the result.
""",
                    "checks": [
                        "Why is helping a participant during a test destructive?",
                        "Why does testing five people find most of the problems?",
                    ],
                },
            ],
        },
        {
            "title": "Responsibility",
            "blurb": "Design as something done TO people.",
            "chapters": [
                {
                    "slug": "hci-accessibility",
                    "title": "Accessibility and inclusive design",
                    "summary": "Designing for the range of people who actually exist.",
                    "body": """
Around one in five people has a disability. Designing only for the unimpaired
median excludes them, and in most jurisdictions it is also unlawful for public
services.

The categories to design against:

- VISUAL — blindness, low vision, colour blindness. Needs screen reader support,
  sufficient contrast, and never using colour as the only signal.
- MOTOR — needs keyboard operability, generous targets, no time limits that
  cannot be extended.
- AUDITORY — needs captions and transcripts.
- COGNITIVE — needs plain language, consistent layout, and forgiving errors.

INCLUSIVE DESIGN reframes it usefully: impairment is often situational and
temporary. Someone with a broken arm, holding a baby, or on a phone in bright
sun has the same needs as someone with a permanent condition. The curb cut was
built for wheelchairs and is used by everybody with a pram, a suitcase or a
delivery trolley.

That is the honest argument. Not "it helps everyone" as a slogan to make
accessibility palatable — but as an observation that the constraints are more
common than the categories suggest, and designing to the median means designing
for nobody in particular.

Involve disabled users in testing. Automated checkers find perhaps a third of
real problems and cannot tell you whether something makes sense.
""",
                    "checks": [
                        "What does 'situational impairment' mean, with an example?",
                        "Why is an automated accessibility checker insufficient?",
                    ],
                },
                {
                    "slug": "hci-dark-patterns",
                    "title": "Dark patterns and persuasion",
                    "summary": "Interfaces designed to work against the person using them.",
                    "body": """
A dark pattern is an interface deliberately built to make somebody do what they
did not intend. The named ones:

- ROACH MOTEL — trivial to sign up, deliberately hard to cancel.
- CONFIRMSHAMING — the decline option worded to shame: "No thanks, I don't want
  to save money".
- MISDIRECTION — visual emphasis pulling toward the choice that benefits the
  business.
- SNEAK INTO BASKET — items added without a clear action.
- FORCED CONTINUITY — a free trial that charges silently, with no reminder.
- PRIVACY ZUCKERING — sharing more than intended, through defaults and confusing
  controls.

These work. That is the uncomfortable part: they are not incompetence, they are
craft aimed at the user rather than for them. Everything in this course — mental
models, attention limits, defaults, Fitts's law — can be pointed either way.

Defaults are the strongest lever. Most people never change one, so a default is
a decision you are making on behalf of nearly all your users. Choosing the one
that serves you rather than them is a choice, made deliberately, whatever the
meeting called it.

The test worth applying: would you be comfortable explaining this design to the
person it is aimed at? If the answer is no, that is the finding.
""",
                    "checks": [
                        "Why is a default setting an ethical decision?",
                        "Name a dark pattern you have personally been caught by.",
                    ],
                },
                {
                    "slug": "hci-practice",
                    "title": "Putting it into practice",
                    "summary": "What to do on Monday.",
                    "body": """
The whole course, reduced to things you can actually do:

- Watch one person use what you built, and say nothing. It is the single highest
  value hour available, and almost nobody spends it.
- Write the error messages before the happy path. They are where the design is
  really tested, and doing them last means doing them badly.
- Put your mouse away and Tab through your interface.
- Check contrast with a tool rather than an opinion.
- Count the steps to the most common task. Then remove one.
- Ask what happens on a slow connection, on a small screen, and when the request
  fails. Those are the majority of real sessions, not the edge case.

Design is iterative and never finished; it is improved. The most useful habit is
noticing your own friction — the moment you hesitate, misread a label, or click
the wrong thing. You have just found a usability problem in somebody else's
product, and the same one exists in yours.

Where to go next: Norman's "The Design of Everyday Things" for the principles,
Krug's "Don't Make Me Think" for the web specifically, and the WCAG guidelines
for accessibility as a reference rather than a read-through.
""",
                    "checks": [
                        "What is the highest-value hour you can spend on a design?",
                        "Why write error messages first rather than last?",
                    ],
                },
            ],
        },
    ],
}
