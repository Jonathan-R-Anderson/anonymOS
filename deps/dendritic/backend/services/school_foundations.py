"""Foundations: how a computer actually works. No programming.

WHERE THE OUTLINE CAME FROM
---------------------------
The topic sequence is the conventional one for a computing-foundations course —
hardware, binary representation, storage, the operating system, files, networks
and the web. A standard syllabus rather than anyone's authorship. Every lesson
here is written for this site.

WHAT THIS COURSE IS FOR, AND WHY IT HAS NO CODE
------------------------------------------------
This is the course for somebody who has never been told what any of it is. It
answers "what is inside the box", "what is the difference between memory and
storage", "what happens when I open a file" and "what actually travels when I
load a page".

Deliberately no programming. Intro Programming and Intro Python are next door
and assume you know what a file and a process are; this one supplies that. A
foundations course that starts with variables is a programming course with a
misleading name.
"""

REFERENCE = "https://csplusplus.com/foundations"

BOOK = {
    "slug": "foundations",
    "title": "Foundations",
    "reference": REFERENCE,
    "reference_name": "csplusplus.com/foundations",
    "provenance": (
        "Written for this site, following the conventional sequence for a "
        "computing foundations course. Another treatment of the same material:"
    ),
    "subtitle": "What a computer is, what is inside it, and how it talks to others.",
    "blurb": (
        "Twelve chapters for somebody starting from nothing. No programming — "
        "this is the course that explains what a file, a process and a network "
        "are, so the programming courses next door make sense."
    ),
    "parts": [
        {
            "title": "The machine",
            "blurb": "What is actually inside the box.",
            "chapters": [
                {
                    "slug": "fd-what-is-a-computer",
                    "title": "What a computer is",
                    "summary": "Input, processing, storage, output — and why that list is enough.",
                    "body": """
A computer takes input, processes it according to stored instructions, keeps
things, and produces output. Every computer does exactly this, from a washing
machine controller to a data centre.

The idea that makes it general-purpose is the STORED PROGRAM: the instructions
live in memory alongside the data, so changing what the machine does means
loading different instructions rather than rewiring it. That is why one device
can be a calculator, a camera and a telephone.

The parts:

- CPU — executes instructions.
- Memory (RAM) — the working space, holding what is running right now.
- Storage — the permanent shelf.
- Input and output devices — keyboard, screen, network, sensors.
- The bus — the wiring they all talk over.

Hardware is the physical parts; software is the instructions. The distinction
matters because they fail differently: hardware wears out and breaks, software
does exactly what it was told, forever, including the wrong thing.

There is nothing mysterious in the box. It is a machine that does simple
operations extremely quickly and never gets bored — and everything else is
built out of that.
""",
                    "checks": [
                        "What does 'stored program' mean, and why does it matter?",
                        "Name the four things every computer does.",
                    ],
                },
                {
                    "slug": "fd-cpu",
                    "title": "The processor",
                    "summary": "Fetch, decode, execute — a few billion times a second.",
                    "body": """
The CPU repeats one cycle:

- FETCH the next instruction from memory.
- DECODE what it means.
- EXECUTE it.

Then again. A modern processor does this a few billion times per second, and the
instructions are tiny: add two numbers, compare two values, copy a value, jump
somewhere else. Everything you have ever used is built from operations at that
level.

Terms you will meet:

- CLOCK SPEED, in gigahertz — cycles per second. Comparable only within a
  processor family; a faster clock elsewhere can do less per cycle.
- CORES — effectively several processors on one chip, able to work genuinely
  simultaneously.
- CACHE — a small, very fast memory on the chip holding recently used data,
  because fetching from RAM is slow by CPU standards.

The gap that shapes everything: a CPU can do an operation in well under a
nanosecond, RAM takes tens of nanoseconds, an SSD takes tens of microseconds, and
a network request takes milliseconds. Each step is orders of magnitude slower
than the last, and most of computer design is arranging not to wait.
""",
                    "checks": [
                        "What are the three steps of the instruction cycle?",
                        "Why does a processor have cache?",
                    ],
                },
                {
                    "slug": "fd-memory-storage",
                    "title": "Memory versus storage",
                    "summary": "The distinction that confuses more beginners than any other.",
                    "body": """
They are not the same thing and the words are used carelessly everywhere.

MEMORY (RAM) is the working space. Fast, limited, and VOLATILE — switch the
power off and it is gone. What is open right now lives here.

STORAGE is the permanent shelf: SSD or hard disk. Slower, much larger, and it
survives being switched off.

The kitchen analogy is the one that sticks: memory is the counter you work on,
storage is the cupboards. A bigger counter lets you work on more things at once;
bigger cupboards let you keep more. They fix different problems, and buying the
wrong one is a common and expensive mistake.

This is why unsaved work is lost when the power fails: it was on the counter and
never put away. Saving copies from memory to storage.

It is also why a machine slows to a crawl when memory fills. The operating
system starts moving things to storage to make room — swapping — and storage is
thousands of times slower, so everything crawls.

Capacities: a byte is one character, a kilobyte a thousand, then megabyte,
gigabyte, terabyte, each about a thousand times the last.
""",
                    "checks": [
                        "Why is unsaved work lost in a power cut?",
                        "You have too many tabs open and everything is slow. More memory or more storage?",
                    ],
                },
                {
                    "slug": "fd-devices",
                    "title": "Input, output and peripherals",
                    "summary": "How the machine meets the world.",
                    "body": """
Input brings data in: keyboards, mice, touchscreens, microphones, cameras,
sensors, and the network. Output sends it back: screens, speakers, printers,
motors, and again the network.

Some devices do both — a touchscreen, a network card, a storage drive. Storage
is the interesting case: it is input when read and output when written, which is
why it is often listed separately.

DRIVERS are the software that lets the operating system talk to a specific piece
of hardware. It is why a new printer sometimes needs an install, and why very old
hardware stops working after an update — not because the hardware failed, but
because nobody maintained the driver.

Ports and connectors — USB, HDMI, Ethernet — are the physical agreements. USB
became universal precisely because it removed the previous situation of a
different socket for every device.

EMBEDDED computers are the ones nobody calls computers: in a car, a thermostat, a
lift. Vastly more numerous than the visible sort, usually doing one job forever,
and frequently never updated — which is why they turn up so often in security
incidents.
""",
                    "checks": [
                        "Give an example of a device that is both input and output.",
                        "Why can a system update stop old hardware from working?",
                    ],
                },
            ],
        },
        {
            "title": "Data",
            "blurb": "How everything becomes numbers.",
            "chapters": [
                {
                    "slug": "fd-binary",
                    "title": "Binary",
                    "summary": "Two digits, because a switch has two positions.",
                    "body": """
Computers store everything as bits — a 0 or a 1 — because a circuit reliably
tells two states apart. Ten distinct voltage levels would be error-prone; two
are not.

Reading binary is positional, exactly like ordinary decimal:

    1 0 1 1  =  8 + 0 + 2 + 1  =  11
    8 4 2 1

Each position is twice the one to its right. To convert the other way, subtract
the largest power of two that fits and repeat.

A BIT is one digit. A BYTE is eight of them, giving 256 possible values — which
is why so many limits in computing are 256, or 65,536, or 4 billion. They are 2⁸,
2¹⁶ and 2³².

The general rule: n bits give 2ⁿ combinations. That single formula answers most
"how many can there be" questions in computing — how many colours, how many
addresses, how many characters.

HEXADECIMAL (base 16, using 0-9 then A-F) exists because long binary strings are
unreadable. One hex digit is exactly four bits, so `1111 0000` becomes `F0`. It
is shorthand, not a different kind of number.
""",
                    "checks": [
                        "What is 1101 in decimal?",
                        "How many different values fit in two bytes?",
                    ],
                },
                {
                    "slug": "fd-representing",
                    "title": "Text, pictures and sound",
                    "summary": "Same trick, three times: agree on a mapping.",
                    "body": """
Once you can store numbers, you can store anything — provided everyone agrees
what the numbers mean.

TEXT. A character encoding maps characters to numbers. ASCII covered 128
characters, enough for English. Unicode replaced it with a number for
essentially every writing system, which is why a document can hold Arabic,
Chinese and emoji at once. When you see text as `Ã©` instead of `é`, two
programs disagreed about the encoding.

PICTURES. An image is a grid of PIXELS, each storing amounts of red, green and
blue — usually one byte each, giving about 16.7 million colours. Resolution is
how many pixels; more means more detail and a bigger file. Doubling width and
height quadruples the size.

SOUND. A wave is measured at rapid intervals — SAMPLING — and each measurement
stored as a number. More samples per second and more bits per sample mean more
faithful audio and a larger file.

The pattern is identical each time: take something continuous, chop it into
discrete pieces, store each piece as a number. What falls between the pieces is
lost, and choosing how finely to chop is the only real decision.
""",
                    "checks": [
                        "What causes text to appear as strange symbols?",
                        "What is lost when sound is digitised?",
                    ],
                },
                {
                    "slug": "fd-files",
                    "title": "Files, formats and folders",
                    "summary": "What a file actually is, and what an extension is not.",
                    "body": """
A file is a named sequence of bytes on storage. That is genuinely all it is. The
FORMAT is the agreement about what those bytes mean, and it is what lets one
program read what another wrote.

The extension — `.jpg`, `.txt`, `.pdf` — is a hint to the operating system about
which program to open it with. It is part of the NAME, not part of the contents.
Renaming a photo to `.txt` does not change a single byte; it just confuses the
computer about what to open. This is worth knowing because it also means an
extension cannot be trusted: a file called `invoice.pdf` may be something else
entirely, which is a standard trick in malicious email.

Broadly, files are TEXT (readable as characters, like `.txt`, `.csv`, `.html`) or
BINARY (anything else — images, video, programs). Opening a binary file in a text
editor produces nonsense because you are interpreting it with the wrong
agreement.

FOLDERS organise files into a tree. A PATH is the route through it. An ABSOLUTE
path starts from the root; a RELATIVE path starts from wherever you are.

And the thing everyone learns the hard way: a file existing in one place is not
a backup. A backup is a copy somewhere else, that you have tested restoring.
""",
                    "checks": [
                        "Does renaming a file's extension change its contents?",
                        "Why is a second copy on the same drive not a backup?",
                    ],
                },
                {
                    "slug": "fd-compression",
                    "title": "Compression",
                    "summary": "Making files smaller, and what it costs.",
                    "body": """
Compression re-encodes data to take less space, exploiting the fact that real
data repeats itself.

LOSSLESS keeps everything: the original comes back exactly. ZIP files and PNG
images work this way. The simplest example is replacing runs — `AAAAABBB`
becomes `5A3B`. Note that on data with no repetition this makes the file BIGGER,
because you have added counts and saved nothing.

LOSSY throws information away permanently to save much more space. JPEG photos
and MP3 audio discard detail chosen to be hard for people to notice.

Which to use is a requirement, not a preference:

- A document, a spreadsheet, a program → lossless. One changed byte is a
  different number or a broken program.
- A photograph, music, video → lossy is normal, and the saving is enormous.

Two things worth knowing. Repeatedly saving a lossy file degrades it further
each time — which is why an image passed around a group chat eventually looks
like soup. And no compression method can shrink every possible file; if it
shrinks some, it must enlarge others. That is arithmetic, not a limitation
somebody will eventually engineer away.
""",
                    "checks": [
                        "Why does a photo shared repeatedly get worse?",
                        "When would compression make a file larger?",
                    ],
                },
            ],
        },
        {
            "title": "Software and networks",
            "blurb": "What runs, and what it talks to.",
            "chapters": [
                {
                    "slug": "fd-operating-system",
                    "title": "The operating system",
                    "summary": "The program that runs the other programs.",
                    "body": """
The operating system — Windows, macOS, Linux, Android, iOS — sits between
hardware and everything else, and does four jobs:

- MANAGES THE PROCESSOR. Many programs appear to run at once. On a single core
  the OS switches between them thousands of times a second, fast enough to look
  simultaneous.
- MANAGES MEMORY. Each program gets its own space and cannot read another's,
  which is why one crashing program does not take the rest with it.
- MANAGES FILES. Programs ask the OS to read a file; they never touch the disk.
- MANAGES DEVICES, through drivers.

A PROCESS is a running program. The same program run twice is two processes,
independent of one another. Task Manager or Activity Monitor lists them, and
"not responding" means a process has stopped answering the OS while still
holding its window.

The OS also enforces PERMISSIONS: which user may read which file, which programs
may run. That is the foundation everything else in security is built on — a
system where any program can read any file has nothing left to defend.

Booting is the sequence from power-on to usable: firmware checks the hardware,
finds the OS on storage, and loads it into memory.
""",
                    "checks": [
                        "How can more programs run at once than there are cores?",
                        "Why does one program crashing not usually crash the others?",
                    ],
                },
                {
                    "slug": "fd-software",
                    "title": "Software, apps and updates",
                    "summary": "Where programs come from and why they keep changing.",
                    "body": """
Software divides into SYSTEM software (the OS and its utilities) and APPLICATION
software (what you use to do things).

Programs are written in a language people can read and then translated into
instructions the processor executes. That translation is why you download an
application built for your operating system specifically: the same program
compiled for Windows will not run on a Mac.

Licensing decides what you may do with it:

- Proprietary — you buy or subscribe to permission to use it, under an
  agreement you accepted by clicking.
- Open source — the source is published and you may study, modify and share it,
  under stated conditions. Free here means freedom rather than price, though it
  is very often both.

UPDATES matter more than they seem. Most attacks exploit a flaw that was fixed
months earlier in an update nobody installed. Deferring updates indefinitely is
the single most common self-inflicted security problem.

Where you get software matters too. Official stores and vendor sites check what
they distribute; a search result offering the same program for free is a
standard way to receive something extra with it.
""",
                    "checks": [
                        "Why won't a Windows program run on a Mac?",
                        "Why are updates a security matter rather than a nuisance?",
                    ],
                },
                {
                    "slug": "fd-networks",
                    "title": "Networks",
                    "summary": "Two computers, a wire, and some agreements.",
                    "body": """
A network is computing devices connected so they can exchange data. Two on a
desk is a network; so is the internet.

Data crosses it in PACKETS — small chunks, each carrying its destination. They
travel independently, possibly by different routes, and are reassembled at the
far end. If one goes missing it is sent again. This is why a connection degrades
gracefully rather than simply stopping.

Every device has an IP ADDRESS identifying it. ROUTERS forward packets toward
their destination, hop by hop, each knowing only the next step rather than the
whole route.

PROTOCOLS are the agreements that let devices built by strangers interoperate.
Nobody owns them, which is exactly why the system works at all.

Two words routinely confused:

- BANDWIDTH — how much data per second the connection carries.
- LATENCY — how long before the first data arrives.

They are independent. A satellite link has huge bandwidth and terrible latency,
which is why it is fine for downloading a film and miserable for a video call.

Wired connections are faster and more reliable; wireless trades that for
convenience and is affected by distance, walls and other people's networks.
""",
                    "checks": [
                        "What is the difference between bandwidth and latency?",
                        "Why does a network get slower rather than simply failing?",
                    ],
                },
                {
                    "slug": "fd-web",
                    "title": "The internet and the web",
                    "summary": "Not the same thing, and what happens when you press Enter.",
                    "body": """
The INTERNET is the global network. The WEB is one service running on it —
linked pages fetched over HTTP. Email, video calls and game traffic also use the
internet and are not the web. The web runs on the internet in the way a train
service runs on rails.

What happens when you type an address and press Enter:

- Your device asks DNS to turn the name into an IP address.
- It opens a connection to that address.
- It sends an HTTP request for the page.
- The server replies with HTML, which references images, stylesheets and scripts.
- Your browser requests each of those and assembles the result.

That is dozens of requests for one page, which is why pages load in pieces.

HTTPS is HTTP inside encryption. It means two things: nobody between you and the
server can read the traffic, and the server proved its identity with a
certificate. The padlock says the connection is private — it says nothing about
whether the site is honest.

A URL has parts worth being able to read: the protocol, the DOMAIN, and the
path. The domain is the part that matters when checking a link, and it is the
part immediately before the first single slash — which is what phishing links
are constructed to disguise.
""",
                    "checks": [
                        "What is the difference between the internet and the web?",
                        "What does the padlock icon actually tell you?",
                    ],
                },
            ],
        },
    ],
}
