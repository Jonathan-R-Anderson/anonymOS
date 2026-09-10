"""Web Design: HTML, CSS, and building pages that work for everyone.

WHERE THE OUTLINE CAME FROM
---------------------------
The topic sequence is the conventional one for an introductory web course —
document structure, semantic HTML, the box model, layout, responsive design,
accessibility, forms — which is a standard syllabus rather than anyone's
authorship. Every lesson, exercise and solution here is written for this site.

THE OPINION THIS COURSE HAS
---------------------------
Accessibility is not a final chapter. It appears in the structure lesson, the
image lesson, the colour lesson and the form lesson, because that is where the
decisions are actually made — a page is not made accessible at the end, it is
either built that way or rebuilt.

The same goes for semantics. A page of divs and a page of landmarks look
identical and are not the same page, and the difference only shows up for
somebody using a screen reader, a keyboard, or a search engine.

No frameworks. Bootstrap and Tailwind are worth learning and they are not worth
learning first: they hide the box model, and someone who never met it cannot
debug it.
"""

REFERENCE = "https://csplusplus.com/webdesign"

BOOK = {
    "slug": "webdesign",
    "title": "Web Design",
    "reference": REFERENCE,
    "reference_name": "csplusplus.com/webdesign",
    "provenance": (
        "Written for this site, following the conventional sequence for an "
        "introductory web design course. Another treatment of the same material:"
    ),
    "subtitle": "HTML and CSS, built to work for everyone from the start.",
    "blurb": (
        "Twelve lessons from a first document to a responsive, accessible page. "
        "No frameworks — the box model and the cascade first, because those are "
        "what you debug at two in the morning."
    ),
    "parts": [
        {
            "title": "Structure",
            "blurb": "HTML: what the page IS, before how it looks.",
            "chapters": [
                {
                    "slug": "wd-first-page",
                    "title": "A first HTML document",
                    "summary": "The boilerplate, and what each line is for.",
                    "body": """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>My page</title>
      </head>
      <body>
        <h1>Hello</h1>
      </body>
    </html>

Every line earns its place:

- `<!DOCTYPE html>` puts the browser in standards mode. Without it you get a
  quirks mode that emulates 1999, and your CSS behaves strangely for no visible
  reason.
- `lang="en"` tells screen readers which pronunciation to use and search engines
  which language this is. One attribute, real benefit.
- `charset="utf-8"` must come early, or accented characters and emoji arrive as
  mojibake.
- The viewport meta is what makes a page usable on a phone. Without it, mobile
  browsers pretend to be 980px wide and shrink everything.
- `<title>` is the tab, the bookmark and the search result.

An element is `<tag attribute="value">content</tag>`. Some are VOID and have no
closing tag: `<img>`, `<br>`, `<meta>`, `<input>`.

Head is metadata; body is what is shown. Nothing in the head appears on the page
and everything in it matters.
""",
                    "task": "Write a complete HTML5 document with a lang attribute, utf-8 charset, the viewport meta, a title, and an h1 in the body.",
                    "starter": "<!DOCTYPE html>\n",
                    "solution": "<!DOCTYPE html>\n<html lang=\"en\">\n  <head>\n    <meta charset=\"utf-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    <title>My page</title>\n  </head>\n  <body>\n    <h1>Hello</h1>\n  </body>\n</html>\n",
                    "validators": [
                        {"pattern": r"<!DOCTYPE\s+html>", "hint": "Start with `<!DOCTYPE html>` or the browser uses quirks mode."},
                        {"pattern": r"<html[^>]*lang\s*=", "hint": "Add `lang=\"en\"` to the html element."},
                        {"pattern": r"charset\s*=\s*[\"']?utf-8", "hint": "Include `<meta charset=\"utf-8\">`."},
                        {"pattern": r"name\s*=\s*[\"']viewport", "hint": "Include the viewport meta, or the page will be unusable on a phone."},
                        {"pattern": r"<title>", "hint": "Give the document a `<title>`."},
                        {"pattern": r"<h1>", "hint": "Put an `<h1>` in the body."},
                    ],
                },
                {
                    "slug": "wd-semantics",
                    "title": "Semantic HTML",
                    "summary": "Choosing elements by meaning, not by appearance.",
                    "body": """
A `<div>` means nothing. A `<nav>` means "this is navigation", and that meaning
is what assistive technology, search engines and reader modes act on.

The landmark elements:

    <header>   <nav>   <main>   <article>   <section>   <aside>   <footer>

`<main>` should appear once, and a screen reader user can jump straight to it —
skipping the navigation they have already heard on every other page.

Headings `<h1>` to `<h6>` form an OUTLINE. Choose them by level, never by size;
size is CSS's job. Skipping from `<h1>` to `<h3>` breaks the outline that people
navigate by, and "it looked right" is not a reason.

Other elements with real meaning:

- `<button>` for something that acts; `<a href>` for somewhere that goes. A div
  with a click handler is neither: it is not focusable, does not respond to
  Enter or Space, and is invisible to a screen reader.
- `<ul>`/`<ol>` for lists, so "list of six items" is announced.
- `<strong>` and `<em>` for importance and emphasis; `<b>` and `<i>` are purely
  visual.
- `<time datetime="2026-08-02">` so a machine can read the date.

The test: strip all the CSS. If the page still makes sense read top to bottom,
the structure is right.
""",
                    "task": "Write a page body using header, nav, main and footer landmarks, with an h1 inside main and a list of two links inside nav.",
                    "starter": "<body>\n\n</body>\n",
                    "solution": "<body>\n  <header>\n    <nav>\n      <ul>\n        <li><a href=\"/\">Home</a></li>\n        <li><a href=\"/about\">About</a></li>\n      </ul>\n    </nav>\n  </header>\n  <main>\n    <h1>Welcome</h1>\n  </main>\n  <footer>\n    <p>&copy; 2026</p>\n  </footer>\n</body>\n",
                    "validators": [
                        {"pattern": r"<header>", "hint": "Use a `<header>` landmark."},
                        {"pattern": r"<nav>", "hint": "Wrap the links in `<nav>`."},
                        {"pattern": r"<main>", "hint": "Use `<main>` for the primary content — screen readers jump to it."},
                        {"pattern": r"<footer>", "hint": "Add a `<footer>`."},
                        {"pattern": r"<ul>[\s\S]*<li>", "hint": "Put the nav links in a `<ul>` of `<li>` items."},
                    ],
                },
                {
                    "slug": "wd-links-images",
                    "title": "Links, images and alt text",
                    "summary": "The two elements that carry the web, and the attribute people skip.",
                    "body": """
    <a href="/about">About us</a>
    <a href="https://example.com" target="_blank" rel="noopener noreferrer">External</a>
    <img src="cat.jpg" alt="A tabby cat asleep on a keyboard" width="400" height="300">

Link text must make sense alone. Screen reader users can list every link on a
page, and a list reading "click here, click here, read more" is useless. Write
"Read our privacy policy", not "click here".

`target="_blank"` needs `rel="noopener"` — without it the opened page gets a
reference back to yours and can redirect it. `noreferrer` additionally withholds
where the click came from.

ALT TEXT is not optional and not decoration:

- Describe the FUNCTION, not the picture. For a logo that links home, the alt is
  "Home", not "company logo".
- If the image is purely decorative, use `alt=""` — empty, but present. That
  tells a screen reader to skip it. Omitting the attribute makes it read the
  filename instead, which is worse than nothing.
- Do not start with "image of". The screen reader already says that.

`width` and `height` attributes let the browser reserve space before the image
loads, which stops the page jumping around as things arrive — a small attribute
that fixes a genuinely annoying problem.
""",
                    "task": "Write an image with meaningful alt text and dimensions, plus an external link opened in a new tab safely.",
                    "starter": "<figure>\n\n</figure>\n",
                    "solution": "<figure>\n  <img src=\"cat.jpg\" alt=\"A tabby cat asleep on a keyboard\" width=\"400\" height=\"300\">\n  <figcaption>\n    See <a href=\"https://example.com\" target=\"_blank\" rel=\"noopener noreferrer\">the full gallery</a>.\n  </figcaption>\n</figure>\n",
                    "validators": [
                        {"pattern": r"<img[^>]*alt\s*=\s*[\"'][^\"']{5,}", "hint": "Give the image descriptive alt text, not an empty or missing attribute."},
                        {"pattern": r"<img[^>]*width\s*=", "hint": "Add width and height so the browser reserves space and the page stops jumping."},
                        {"pattern": r"target\s*=\s*[\"']_blank", "hint": "Open the external link with `target=\"_blank\"`."},
                        {"pattern": r"rel\s*=\s*[\"'][^\"']*noopener", "hint": "Add `rel=\"noopener noreferrer\"` — without it the new page can redirect yours."},
                    ],
                },
            ],
        },
        {
            "title": "CSS",
            "blurb": "Appearance, and the two models that explain everything.",
            "chapters": [
                {
                    "slug": "wd-selectors",
                    "title": "Selectors and the cascade",
                    "summary": "Which rule wins, and why !important is a confession.",
                    "body": """
    p { color: navy; }                /* element */
    .warning { color: red; }          /* class */
    #header { height: 60px; }         /* id */
    nav a:hover { text-decoration: underline; }

When two rules target the same element, three things decide the winner, in
order:

1. SPECIFICITY. Ids beat classes beat elements. Count them: an id is worth more
   than any number of classes.
2. ORDER. Among equally specific rules, the last one wins.
3. `!important` overrides all of it, which is why reaching for it usually means
   the specificity has got out of hand rather than that you needed it.

INHERITANCE is separate: some properties (colour, font) pass to children,
others (border, padding) do not.

The practical advice that follows: style with CLASSES. Ids are so specific they
are hard to override, and element selectors are so broad they catch things you
did not mean. A flat list of single-class rules is far easier to reason about
than a deep tower of nested selectors, and it is why naming conventions like BEM
exist.

Custom properties give you variables:

    :root { --brand: #0055aa; }
    .button { background: var(--brand); }

They cascade and can be changed per-section or per-theme, which is what makes a
dark mode a handful of lines rather than a second stylesheet.
""",
                    "task": "Write CSS defining a --brand custom property on :root, a .button class using it, and a hover state.",
                    "starter": "/* Custom property, class, hover */\n",
                    "solution": ":root {\n  --brand: #0055aa;\n}\n\n.button {\n  background: var(--brand);\n  color: white;\n  padding: 8px 16px;\n}\n\n.button:hover {\n  background: #003d7a;\n}\n",
                    "validators": [
                        {"pattern": r":root\s*\{", "hint": "Define the custom property on `:root`."},
                        {"pattern": r"--\w+\s*:", "hint": "Declare a custom property, e.g. `--brand: #0055aa;`."},
                        {"pattern": r"var\s*\(\s*--", "hint": "Use it with `var(--brand)`."},
                        {"pattern": r":hover", "hint": "Add a `:hover` state."},
                    ],
                },
                {
                    "slug": "wd-box-model",
                    "title": "The box model",
                    "summary": "The one concept that explains most layout confusion.",
                    "body": """
Every element is a box with four layers, inside out:

    content -> padding -> border -> margin

By default, `width` sets the CONTENT width only. So a box with `width: 300px`,
`padding: 20px` and `border: 1px` actually occupies 342px, and your three
300px columns do not fit in 900px.

The fix, which practically every stylesheet now starts with:

    *, *::before, *::after { box-sizing: border-box; }

Now `width` includes padding and border, and the number you wrote is the number
you get. There is no reason not to do this.

MARGIN COLLAPSE is the other surprise: vertical margins between siblings do not
add, they collapse to the larger of the two. A 20px and a 30px margin give 30px,
not 50. Horizontal margins never collapse, and neither do vertical ones inside a
flex or grid container — which is one reason modern layout uses `gap` instead.

`display` decides the box's behaviour: `block` takes full width and stacks,
`inline` flows with text and ignores width and vertical margins, `inline-block`
flows but accepts dimensions, `none` removes it entirely — and `none` is not the
same as `visibility: hidden`, which leaves the space behind.
""",
                    "task": "Write CSS applying border-box sizing to everything, and a .card class with padding, a border and a fixed width.",
                    "starter": "/* Fix the box model first. */\n",
                    "solution": "*, *::before, *::after {\n  box-sizing: border-box;\n}\n\n.card {\n  width: 300px;\n  padding: 20px;\n  border: 1px solid #ccc;\n  border-radius: 8px;\n}\n",
                    "validators": [
                        {"pattern": r"box-sizing\s*:\s*border-box", "hint": "Set `box-sizing: border-box` so width means what you expect."},
                        {"pattern": r"\*", "hint": "Apply it to everything with the `*` selector."},
                        {"pattern": r"\.card\s*\{", "hint": "Define a `.card` class."},
                        {"pattern": r"padding\s*:", "hint": "Give the card padding."},
                        {"pattern": r"border\s*:", "hint": "Give the card a border."},
                    ],
                },
                {
                    "slug": "wd-flexbox",
                    "title": "Flexbox",
                    "summary": "Laying things out in one direction.",
                    "body": """
    .row {
      display: flex;
      justify-content: space-between;   /* along the main axis */
      align-items: center;              /* across it */
      gap: 16px;
    }

Flexbox works in ONE dimension — a row or a column. `flex-direction` chooses
which, and that choice swaps what the two alignment properties mean:
`justify-content` always works along the main axis and `align-items` across it,
so in a column they trade places. Internalising that is most of learning
flexbox.

`gap` puts space between items without margins on the items themselves, which
avoids the awkward "every item except the last" rule that margins require.

On the children:

    flex: 1;          /* grow to fill available space, share equally */
    flex: 0 0 200px;  /* do not grow, do not shrink, be 200px */

`flex-wrap: wrap` lets items move to a new line rather than squashing, and it is
the difference between a layout that degrades on a narrow screen and one that
becomes unreadable.

Reach for flexbox when you have a row of things — a nav bar, a card footer, a
form row. When you have both rows AND columns to control, that is Grid.
""",
                    "task": "Write a .nav class using flexbox to space items apart, centre them vertically, and add a gap.",
                    "starter": ".nav {\n\n}\n",
                    "solution": ".nav {\n  display: flex;\n  justify-content: space-between;\n  align-items: center;\n  gap: 16px;\n  flex-wrap: wrap;\n}\n",
                    "validators": [
                        {"pattern": r"display\s*:\s*flex", "hint": "Set `display: flex`."},
                        {"pattern": r"justify-content\s*:", "hint": "Use `justify-content` to space items along the row."},
                        {"pattern": r"align-items\s*:", "hint": "Use `align-items: center` to centre them across the row."},
                        {"pattern": r"gap\s*:", "hint": "Use `gap` rather than margins on the children."},
                    ],
                },
                {
                    "slug": "wd-grid",
                    "title": "CSS Grid",
                    "summary": "Two dimensions, and the one line that replaces media queries.",
                    "body": """
    .grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 20px;
    }

`fr` is a fraction of the free space, so `1fr 2fr` gives one part and two parts.
`repeat(3, 1fr)` is three equal columns.

The single most useful line in modern CSS:

    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));

That means "as many columns as fit, each at least 250px, sharing the space
equally". The layout reflows from four columns to one as the window narrows,
with no media queries at all. It is worth writing out until it is muscle memory.

Items can span:

    .feature { grid-column: span 2; }

Grid is two-dimensional; flexbox is one. The rule of thumb: Grid for the page
skeleton and for anything with both rows and columns, flexbox for the contents
of a single row or column. They compose — a grid cell containing a flex row is
extremely common and entirely normal.
""",
                    "task": "Write a .cards class using grid with responsive auto-fit columns of at least 250px and a gap.",
                    "starter": ".cards {\n\n}\n",
                    "solution": ".cards {\n  display: grid;\n  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));\n  gap: 20px;\n}\n",
                    "validators": [
                        {"pattern": r"display\s*:\s*grid", "hint": "Set `display: grid`."},
                        {"pattern": r"grid-template-columns\s*:", "hint": "Define the columns with `grid-template-columns`."},
                        {"pattern": r"auto-fit|auto-fill", "hint": "Use `repeat(auto-fit, ...)` so the count adapts to the width."},
                        {"pattern": r"minmax\s*\(", "hint": "Use `minmax(250px, 1fr)` for the column size."},
                    ],
                },
            ],
        },
        {
            "title": "Making it work everywhere",
            "blurb": "Screens of every size, and people of every ability.",
            "chapters": [
                {
                    "slug": "wd-responsive",
                    "title": "Responsive design",
                    "summary": "Mobile first, and letting the content decide.",
                    "body": """
Write the narrow layout as the default, then add complexity as space allows:

    .grid { display: grid; gap: 16px; }

    @media (min-width: 600px) {
      .grid { grid-template-columns: 1fr 1fr; }
    }

MOBILE FIRST means `min-width` queries rather than `max-width`. The reason is
not fashion: the base styles are the simplest ones, so the least capable device
does the least work, and each query only ever adds.

Choose breakpoints where YOUR content breaks, not at device sizes. Widen the
window until the layout looks wrong and put a breakpoint there. Device-based
breakpoints go stale every time somebody releases a phone.

Units matter:

- `rem` for type and spacing — it scales with the user's font size setting,
  which people with low vision actually change. `px` ignores them.
- `%`, `fr`, `vw` for widths.
- `max-width` on text: about 65 characters per line is where reading comfort
  sits, and a full-width paragraph on a wide monitor is genuinely hard to read.

Images need `max-width: 100%; height: auto;` or they will overflow their
container on a narrow screen and give the whole page a horizontal scrollbar.
""",
                    "task": "Write mobile-first CSS: a single column by default, two columns above 600px, and images that never overflow.",
                    "starter": "/* Narrow first. */\n",
                    "solution": "img {\n  max-width: 100%;\n  height: auto;\n}\n\n.grid {\n  display: grid;\n  gap: 16px;\n}\n\n@media (min-width: 600px) {\n  .grid {\n    grid-template-columns: 1fr 1fr;\n  }\n}\n",
                    "validators": [
                        {"pattern": r"max-width\s*:\s*100%", "hint": "Give images `max-width: 100%` so they never overflow."},
                        {"pattern": r"@media\s*\(\s*min-width", "hint": "Use a `min-width` media query — that is what mobile-first means."},
                        {"pattern": r"grid-template-columns\s*:", "hint": "Add the second column inside the media query."},
                    ],
                },
                {
                    "slug": "wd-accessibility",
                    "title": "Accessibility",
                    "summary": "The checks that catch most of it.",
                    "body": """
Accessibility is mostly a consequence of decisions made earlier — semantic
elements, real alt text, a sensible heading outline. What is left is specific
and checkable.

COLOUR CONTRAST. Body text needs a contrast ratio of at least 4.5:1 against its
background; large text needs 3:1. Grey-on-white placeholder text usually fails.
And colour must never be the ONLY signal — a red border on an invalid field is
invisible to a colour-blind user without an error message beside it.

KEYBOARD. Everything clickable must be reachable with Tab and operable with
Enter or Space. Use `<button>` and `<a>` rather than divs and this is free.
Never remove the focus outline without replacing it: `outline: none` is the
single most damaging line in web design, because it leaves keyboard users with
no idea where they are.

Test it yourself: put the mouse away and Tab through the page.

MOTION. `@media (prefers-reduced-motion: reduce)` lets you turn animations off
for people who get motion sickness from them. Three lines.

ARIA exists for what HTML cannot express — but the first rule of ARIA is not to
use it if a native element does the job. A `<button>` beats
`<div role="button" tabindex="0">` in every respect.
""",
                    "task": "Write CSS providing a visible focus style and honouring prefers-reduced-motion.",
                    "starter": "/* Never leave keyboard users lost. */\n",
                    "solution": ":focus-visible {\n  outline: 3px solid #0055aa;\n  outline-offset: 2px;\n}\n\n@media (prefers-reduced-motion: reduce) {\n  *, *::before, *::after {\n    animation-duration: 0.01ms !important;\n    transition-duration: 0.01ms !important;\n  }\n}\n",
                    "validators": [
                        {"pattern": r":focus(-visible)?", "hint": "Style `:focus-visible` so keyboard users can see where they are."},
                        {"pattern": r"outline\s*:", "hint": "Provide a visible outline — never just remove it."},
                        {"pattern": r"prefers-reduced-motion", "hint": "Add a `prefers-reduced-motion` media query."},
                    ],
                },
                {
                    "slug": "wd-forms",
                    "title": "Forms",
                    "summary": "The most-used and worst-built part of most sites.",
                    "body": """
    <label for="email">Email address</label>
    <input type="email" id="email" name="email" required autocomplete="email">

Every input needs a `<label>` with a matching `for` and `id`. This is not
decorative: it makes the label clickable, which enlarges the tap target, and it
is what a screen reader announces. A placeholder is NOT a label — it disappears
when typing starts, exactly when a user needs to check what the field was.

Use the right `type`. `email`, `tel`, `url`, `number` and `date` bring the right
mobile keyboard and free validation. `autocomplete` lets the browser fill known
values, which is faster and reduces mistakes.

Group related controls with `<fieldset>` and `<legend>` — essential for radio
buttons, where the question itself is otherwise never announced.

Validation:

- Client-side validation is a courtesy. It is for fast feedback, and it is
  trivially bypassed.
- Server-side validation is the actual control. Anything the browser checked
  must be checked again on the server, because a request need never come from
  your form at all.

Error messages should say what to do. "Invalid input" is useless; "Enter a date
in the past" is not. Put the message next to the field, in text, and do not rely
on colour to carry it.
""",
                    "task": "Write a form field with a proper label, the right input type, an id/for pair, required and autocomplete.",
                    "starter": "<form>\n\n</form>\n",
                    "solution": "<form>\n  <label for=\"email\">Email address</label>\n  <input type=\"email\" id=\"email\" name=\"email\" required autocomplete=\"email\">\n  <button type=\"submit\">Sign up</button>\n</form>\n",
                    "validators": [
                        {"pattern": r"<label[^>]*for\s*=\s*[\"'](\w+)", "hint": "Add a `<label for=\"...\">` — a placeholder is not a label."},
                        {"pattern": r"type\s*=\s*[\"']email", "hint": "Use `type=\"email\"` for the right keyboard and free validation."},
                        {"pattern": r"id\s*=\s*[\"']email", "hint": "The input's `id` must match the label's `for`."},
                        {"pattern": r"required", "hint": "Mark it `required`."},
                        {"pattern": r"autocomplete\s*=", "hint": "Add `autocomplete=\"email\"` so the browser can fill it."},
                    ],
                },
                {
                    "slug": "wd-performance",
                    "title": "Performance and publishing",
                    "summary": "Making it fast, and putting it somewhere.",
                    "body": """
Most slow pages are slow for the same few reasons.

IMAGES are almost always the largest thing on a page. Serve them at the size
they are displayed rather than scaling a 4000px photo down in the browser, use
modern formats (WebP, AVIF), and add `loading="lazy"` to anything below the
fold.

FONTS block rendering. Every custom font is a download before text appears; use
`font-display: swap` so text shows immediately in a fallback, and limit yourself
to the weights you actually use.

Minify CSS and JavaScript for production, and serve compressed. Defer scripts
that are not needed for first paint — a `<script>` in the head without `defer`
stops the parser dead.

The layout-shift problem: always give images and embeds explicit dimensions, or
the page jumps as they load and people click the wrong thing.

To publish, you need somewhere to put files and a domain pointing at it. Static
hosting is free or nearly free at small scale. Use HTTPS — it is free, and
browsers now mark plain HTTP as insecure.

Then test on a real phone, on a slow connection. A site that is fast on your
laptop over fibre is not evidence about anything.
""",
                    "checks": [
                        "Why does a script in the head without `defer` slow down rendering?",
                        "What causes layout shift, and what one attribute prevents most of it?",
                    ],
                },
            ],
        },
    ],
}
