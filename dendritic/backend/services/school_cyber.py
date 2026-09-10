"""AP Cybersecurity: defending systems, and understanding what you defend against.

WHERE THE OUTLINE CAME FROM
---------------------------
The unit structure follows the College Board's AP Cybersecurity course
framework — foundations, systems and network security, data protection and
cryptography, threats and vulnerabilities, detection and response, and the legal
and ethical context. A syllabus is a published specification, not authorship.

Every lesson is written for this site. Nothing is taken from
csplusplus.com/apcyber or from any other course's materials.

WHAT THESE LESSONS DO AND DO NOT CONTAIN
----------------------------------------
Attacks are explained at the level needed to defend against them: what the
attacker is exploiting, what it looks like from the defender's side, and what
actually stops it. There are no working exploits, no payloads and no tooling
recipes here — not out of squeamishness, but because knowing that phishing
exploits trust and hurry is what changes behaviour, while a template for one
does not teach anything the defence chapter has not already covered.

The one habit this course is trying to leave behind: asking "what is this
protecting, from whom, and what does failure cost" before reaching for a
control.
"""

REFERENCE = "https://csplusplus.com/apcyber"

BOOK = {
    "slug": "cyber",
    "title": "AP Cybersecurity",
    "reference": REFERENCE,
    "reference_name": "csplusplus.com/apcyber",
    "provenance": (
        "Written for this site, following the College Board's AP Cybersecurity "
        "course framework. The lessons are ours; the unit structure is the "
        "course's. Another treatment of the same material:"
    ),
    "subtitle": "How systems are attacked, and what genuinely stops it.",
    "blurb": (
        "Six units on defending real systems: the CIA triad, networks, "
        "cryptography, the attacks that actually succeed, detection and "
        "response, and the law you are working inside. Written from the "
        "defender's chair."
    ),
    "parts": [
        {
            "title": "Foundations",
            "blurb": "What you are protecting, and from whom.",
            "chapters": [
                {
                    "slug": "cy-cia-triad",
                    "title": "The CIA triad",
                    "summary": "Three goals that pull against each other.",
                    "body": """
Security is usually described as three goals:

- CONFIDENTIALITY — only the right people can read it.
- INTEGRITY — it has not been altered, and you can tell.
- AVAILABILITY — the people who need it can reach it.

The useful part is that they CONFLICT. Encrypting everything and losing the key
protects confidentiality perfectly and destroys availability. Daily backups
protect availability and create more copies to keep confidential. Requiring
three approvals for a change protects integrity and slows response to an
incident.

So security is never "maximise all three". It is a set of deliberate trades,
made against a specific threat and a specific cost of failure.

Two additions you will meet: AUTHENTICITY (this really came from who it claims)
and NON-REPUDIATION (the sender cannot later deny sending it). Digital
signatures provide both.

The question to ask about any control is not "is this more secure" but "which of
the three does this buy, which does it cost, and is that trade right here". A
hospital and a newspaper answer it differently, and both are correct.
""",
                    "checks": [
                        "Give an example of a control that improves confidentiality and harms availability.",
                        "Which part of the triad does a ransomware attack primarily destroy?",
                    ],
                },
                {
                    "slug": "cy-threat-actors",
                    "title": "Threat actors and threat modelling",
                    "summary": "Who is actually coming for this system.",
                    "body": """
Defences are only meaningful against a specific adversary. The usual categories,
ordered roughly by capability:

- Opportunists running automated scans. They do not know who you are; they found
  a port. Patching and not exposing services stops nearly all of them.
- Insiders — employees or contractors, malicious or simply careless. They are
  already past the perimeter, which is why the perimeter is not a plan.
- Organised criminals, motivated by money. Ransomware and fraud.
- Hacktivists, motivated by attention.
- State actors, with time, budget and patience. Realistically undeterrable by an
  ordinary organisation; the goal becomes detection and limiting damage.

THREAT MODELLING is the discipline of asking four questions before designing
anything:

- What are we building?
- What can go wrong?
- What are we going to do about it?
- Did we do a good job?

The failure this prevents is spending heavily on a threat you do not face while
leaving open the one you do. Most organisations are attacked by the first
category and defend against the fifth.
""",
                    "checks": [
                        "Why does an insider threat make perimeter defence insufficient?",
                        "What are the four threat-modelling questions?",
                    ],
                },
                {
                    "slug": "cy-access-control",
                    "title": "Authentication, authorisation and least privilege",
                    "summary": "Proving who you are, and being given only what you need.",
                    "body": """
Three separate things, routinely confused:

- AUTHENTICATION — proving who you are.
- AUTHORISATION — what you are then permitted to do.
- ACCOUNTING — the record of what you did.

Authentication factors come in three kinds: something you KNOW (password),
something you HAVE (a phone, a hardware key), something you ARE (fingerprint).
Multi-factor means factors of DIFFERENT kinds — a password plus a security
question is still one kind, and adds much less than it appears to.

Not all second factors are equal. SMS codes are phishable and vulnerable to SIM
swapping; app-generated codes are better; hardware keys using WebAuthn are best,
because they check the site's identity and therefore cannot be relayed to a fake
one.

LEAST PRIVILEGE is the principle that does the most work: give every account the
minimum access needed, for the minimum time. It does not prevent compromise — it
limits what a compromise reaches. Most damaging breaches involve an account with
far more access than its job required.

Role-based access control implements this by attaching permissions to roles
rather than to people, so access changes when someone's job does.
""",
                    "checks": [
                        "Why is a password plus a security question not really two factors?",
                        "What does least privilege limit — the breach, or its blast radius?",
                    ],
                },
            ],
        },
        {
            "title": "Systems and networks",
            "blurb": "Where the attack surface actually is.",
            "chapters": [
                {
                    "slug": "cy-network-basics",
                    "title": "Networks from a defender's view",
                    "summary": "Ports, protocols, and what each one exposes.",
                    "body": """
Every open port is a service, and every service is code that accepts input from
strangers. The defender's first question about any machine is simply: what is
listening, and does it need to be?

The protocols that matter here:

- TCP builds a reliable ordered stream; UDP does not, and its connectionless
  nature makes it the workhorse of amplification attacks.
- DNS resolves names. It was designed without authentication, which is why
  spoofing and cache poisoning are possible and why DNSSEC exists.
- HTTP is plaintext; HTTPS wraps it in TLS.
- ARP resolves addresses on a local network, also without authentication, which
  is the basis of local traffic interception.

The pattern worth noticing: the internet's core protocols were designed among
mutually trusting researchers, and authentication was added later, in layers,
where it could be. Most network attacks exploit that original trust rather than
any bug.

SEGMENTATION is the defence with the best return. Splitting a network so that a
compromised laptop cannot reach the payroll server converts a catastrophe into
an incident.
""",
                    "checks": [
                        "Why are DNS and ARP spoofable by design rather than by defect?",
                        "What does network segmentation change about a compromise?",
                    ],
                },
                {
                    "slug": "cy-hardening",
                    "title": "Hardening systems",
                    "summary": "The unglamorous measures that prevent most incidents.",
                    "body": """
Nearly all successful attacks exploit something known and unfixed. The boring
controls are the effective ones:

- PATCHING. Most exploited vulnerabilities have had a fix available for months.
  The hard part is inventory — you cannot patch what you do not know you run.
- REMOVE WHAT IS UNUSED. Every installed service is attack surface. The most
  reliable way to secure something is not to run it.
- DEFAULT CREDENTIALS. Devices shipped with a known username and password are
  found by automated scanning within hours of being exposed.
- CONFIGURATION. Verbose errors that reveal software versions, directory
  listings, debug endpoints left enabled — each hands an attacker reconnaissance
  for free.
- ENCRYPT AT REST. A stolen laptop with full-disk encryption is a lost asset;
  without it, it is a data breach.

DEFENCE IN DEPTH is the organising idea: assume any single control fails, and
make sure something else is still in the way. Not because any one control is
weak, but because the one you were most confident about is the one that will be
bypassed.
""",
                    "checks": [
                        "Why is asset inventory a prerequisite for patching?",
                        "What does defence in depth assume about your best control?",
                    ],
                },
            ],
        },
        {
            "title": "Cryptography",
            "blurb": "The maths that works, and the implementations that do not.",
            "chapters": [
                {
                    "slug": "cy-crypto-basics",
                    "title": "Symmetric and asymmetric encryption",
                    "summary": "Two schemes, and why every real system uses both.",
                    "body": """
SYMMETRIC — one key encrypts and decrypts. Fast, suitable for bulk data (AES is
the standard). Its problem is distribution: both parties need the same key, and
getting it to them safely is the original difficulty.

ASYMMETRIC — a key pair. What the public key encrypts, only the private key
decrypts. This solves distribution: publish one half and strangers can send you
secrets with no prior arrangement. It is far slower, so it is not used for bulk.

Real systems combine them. TLS uses asymmetric cryptography to agree a
symmetric session key, then uses that for the actual traffic — the strength of
one and the speed of the other.

HASHING is not encryption. A hash is one-way and has no key; there is nothing to
decrypt. It is used for integrity checking and for storing passwords.

Kerckhoffs's principle underlies all of it: a system must remain secure even
when everything about it except the key is public. Security through obscurity
fails because the obscurity always ends, usually at the worst moment. Never
design your own cipher; use the reviewed ones.
""",
                    "checks": [
                        "Why does TLS use both symmetric and asymmetric cryptography?",
                        "Why is 'nobody knows how our system works' not a security property?",
                    ],
                },
                {
                    "slug": "cy-hashing-passwords",
                    "title": "Hashing, salting and storing passwords",
                    "summary": "How to hold a secret you must never be able to read.",
                    "body": """
A password database should be unreadable even to the people running it. That is
achieved by storing a HASH rather than the password: verify by hashing what is
typed and comparing.

Plain hashing is not enough, for two reasons:

- Identical passwords produce identical hashes, so an attacker sees who shares
  one, and precomputed tables reverse common passwords instantly.
- Fast hashes are fast for the attacker too. A GPU tries billions of SHA-256
  guesses per second.

The fixes:

- SALT — a unique random value per user, stored alongside and hashed with the
  password. Identical passwords now produce different hashes, and precomputed
  tables become useless.
- A SLOW, memory-hard hash designed for the purpose: bcrypt, scrypt, Argon2.
  Deliberately expensive, tuned so verification takes a noticeable fraction of a
  second and brute force becomes impractical.

The corollary for users is that password LENGTH beats complexity, and reuse is
the real danger: a breach at one site becomes credential stuffing everywhere
else. A password manager solves reuse better than any rule about symbols.
""",
                    "checks": [
                        "What does a salt prevent that a plain hash does not?",
                        "Why is a deliberately slow hash function the right choice here?",
                    ],
                },
                {
                    "slug": "cy-certificates",
                    "title": "Certificates and trust",
                    "summary": "Knowing whose key you are encrypting to.",
                    "body": """
Encryption is worthless if you encrypted to the attacker. A public key alone
proves nothing about whose it is.

A CERTIFICATE binds a public key to an identity, signed by a CERTIFICATE
AUTHORITY that your device already trusts. The chain runs from a root CA in your
operating system's trust store, through intermediates, to the site's
certificate.

This is the web's weak point as well as its foundation:

- Any trusted CA can issue a certificate for any domain. Hundreds are trusted by
  default, and a compromised or coerced one can impersonate anything. Certificate
  Transparency logs exist so mis-issuance becomes publicly visible.
- Organisations often install their own root CA on managed devices, which lets
  them decrypt employee HTTPS traffic legitimately. The padlock means the
  connection is encrypted to whoever holds that certificate — not that nobody is
  reading it.

What a browser warning actually means is that the identity could not be
verified, and clicking through it is precisely the case the whole system exists
to prevent.
""",
                    "checks": [
                        "What does the padlock icon actually guarantee, and what does it not?",
                        "Why is 'any CA can issue for any domain' a structural weakness?",
                    ],
                },
            ],
        },
        {
            "title": "Threats and vulnerabilities",
            "blurb": "What actually succeeds, in the order it actually succeeds.",
            "chapters": [
                {
                    "slug": "cy-social-engineering",
                    "title": "Social engineering",
                    "summary": "The attack that beats every technical control.",
                    "body": """
Most breaches begin with a person, not a bug. Social engineering exploits normal
human behaviour rather than software.

The levers are consistent: AUTHORITY (a message appearing to be from a
director), URGENCY (an account closing in one hour), FEAR, and HELPFULNESS
(holding a door, or resetting a password for a colleague who sounds stressed).

Forms you should recognise:

- Phishing — mass deceptive messages.
- Spear phishing — targeted, using real details about you. Far harder to spot,
  and the details are usually public.
- Pretexting — an invented scenario that makes the request reasonable.
- Baiting and tailgating — physical equivalents.

What works as defence is NOT "be more careful":

- Verification through a separate channel. Not by replying, not by the number in
  the message.
- Process that removes urgency as a lever: payment changes always take a
  callback, no exceptions, so nobody has to make a judgement under pressure.
- Phishing-resistant MFA — hardware keys check the site's identity, so a stolen
  code cannot be relayed.
- A culture where reporting a mistake quickly is rewarded. Punishment buys
  silence, and silence is what turns an incident into a catastrophe.
""",
                    "checks": [
                        "Why is 'train people to be careful' a weak defence on its own?",
                        "Why does punishing people who click make an organisation less safe?",
                    ],
                },
                {
                    "slug": "cy-malware",
                    "title": "Malware",
                    "summary": "Categories by behaviour, and why antivirus is not enough.",
                    "body": """
Categorised by how it spreads and what it does:

- Virus — attaches to a program and spreads when that program runs.
- Worm — spreads by itself across a network, needing no user action.
- Trojan — something the user installs willingly, believing it is useful.
- Ransomware — encrypts data and demands payment. An availability and
  increasingly a confidentiality attack, since operators now steal data first
  and threaten to publish.
- Spyware and keyloggers — capture what you do.
- Rootkit — hides its own presence from the operating system.
- Botnet — many compromised machines under one controller.

Antivirus recognises what it has been taught about, which is why it is a layer
and not a plan. Modern defence adds behavioural detection: not "is this file
known bad" but "why is a document editor encrypting a thousand files".

Against ransomware specifically, BACKUPS are the control that decides the
outcome — and only if they are tested, and offline or immutable. Backups
reachable from the compromised network get encrypted too, which is discovered at
the worst possible moment.
""",
                    "checks": [
                        "What is the difference between a virus and a worm?",
                        "Why must a ransomware backup be offline or immutable?",
                    ],
                },
                {
                    "slug": "cy-app-vulns",
                    "title": "Application vulnerabilities",
                    "summary": "One root cause, wearing several costumes.",
                    "body": """
Most application vulnerabilities are the same mistake: DATA SUPPLIED BY A USER
IS TREATED AS INSTRUCTIONS.

- Injection (SQL and otherwise) — input ends up in a query that the database
  then executes as commands. The fix is parameterised queries, which send code
  and data separately so the data can never become code. Escaping by hand is the
  approach that keeps failing.
- Cross-site scripting — input is echoed into a page and the browser runs it as
  script. Fixed by encoding output for its context, plus a Content Security
  Policy.
- Broken access control — the server trusts the client about who you are or what
  you may see. Changing an id in a URL and getting somebody else's record. The
  fix is checking authorisation on the server for every request, every time.
- Insecure deserialisation, path traversal, SSRF — same root, different sink.

Two habits cover most of it: never build a command or query by concatenating
input, and never trust a check performed on the client, because the client is
under the attacker's control.
""",
                    "checks": [
                        "What single mistake underlies injection and XSS alike?",
                        "Why is a validation check in the browser not a security control?",
                    ],
                },
            ],
        },
        {
            "title": "Detection and response",
            "blurb": "Assuming it already happened.",
            "chapters": [
                {
                    "slug": "cy-detection",
                    "title": "Logging, monitoring and detection",
                    "summary": "You cannot respond to what you never saw.",
                    "body": """
Prevention fails eventually. Detection decides whether that is an incident or a
disaster, and the gap between compromise and discovery is often measured in
months.

What makes detection possible:

- LOGGING, centralised. Logs on a compromised machine are logs an attacker can
  edit; shipping them elsewhere immediately is the point.
- Synchronised clocks, or you cannot reconstruct an order of events across
  machines.
- BASELINES. Detection is largely "this is not normal", which requires knowing
  what normal is. A login at 3am matters only if logins at 3am are unusual here.
- Alerting that a human can actually act on. A system generating a thousand
  alerts a day generates zero attention, and alert fatigue is a documented cause
  of missed breaches.

IDS/IPS detect or block known-bad patterns. SIEM aggregates logs and correlates
across sources — the value is seeing that one failed login on each of forty
machines is one attack rather than forty non-events.

The metric worth caring about is dwell time: how long an attacker was present
before discovery. Everything above exists to shrink it.
""",
                    "checks": [
                        "Why must logs be shipped off the machine that produces them?",
                        "Why is a very sensitive alerting system sometimes worse than a quieter one?",
                    ],
                },
                {
                    "slug": "cy-incident-response",
                    "title": "Incident response",
                    "summary": "What to do, in what order, decided beforehand.",
                    "body": """
The standard phases:

- PREPARATION — the plan, the contacts, the practice. Done in advance or not at
  all.
- IDENTIFICATION — is this an incident, and what is its scope?
- CONTAINMENT — stop the spread. Short-term isolation first, then a longer-term
  fix.
- ERADICATION — remove the attacker's access, including persistence you have not
  found yet.
- RECOVERY — restore service, monitoring closely for their return.
- LESSONS LEARNED — the phase that gets skipped and matters most.

Judgements that are much easier made beforehand:

- Pulling the network cable stops the spread and destroys volatile evidence. If
  you may need to prosecute, that ordering matters.
- Rebuilding is more reliable than cleaning. A machine you are not sure about is
  a machine you do not trust.
- Rotate credentials that could have been captured, including service accounts
  nobody remembers.

The post-incident review should be blameless. The purpose is finding what let it
happen, and a review looking for someone to fire finds a scapegoat instead of a
cause.
""",
                    "checks": [
                        "Why does pulling the network cable involve a trade-off?",
                        "Why must a post-incident review be blameless to be useful?",
                    ],
                },
            ],
        },
        {
            "title": "Law, ethics and people",
            "blurb": "The context you are operating inside.",
            "chapters": [
                {
                    "slug": "cy-law-ethics",
                    "title": "Law, authorisation and disclosure",
                    "summary": "The line, and which side of it you are on.",
                    "body": """
The distinction that matters more than any technique: AUTHORISATION. Testing a
system you have written permission to test is security work. The identical
actions without it are a crime in most jurisdictions, and "I was only looking"
is not a defence.

Written scope, agreed in advance, is what separates the two. It states which
systems, which techniques, which hours, and who to call when something breaks.

RESPONSIBLE DISCLOSURE is the convention when you find a flaw in something that
is not yours: report it privately, give a reasonable window to fix it, then
publish. It balances the users' interest in a fix against their interest in
knowing. Many organisations run bug bounties that formalise this and grant
permission in advance — read the scope before touching anything.

Relevant law includes computer misuse statutes, data protection regimes such as
GDPR and HIPAA, and breach notification duties with deadlines measured in days.

And the ethical question the technical answer never settles: a control that is
legal and effective can still be wrong — pervasive employee monitoring,
say. Asking who bears the cost of a security decision is part of the job.
""",
                    "checks": [
                        "What single factor separates penetration testing from a crime?",
                        "What is responsible disclosure balancing?",
                    ],
                },
                {
                    "slug": "cy-careers",
                    "title": "Working in security",
                    "summary": "The roles, and what the work is actually like.",
                    "body": """
The field divides roughly into:

- BLUE TEAM — defence. SOC analysts, incident responders, engineers. Where most
  of the jobs are, and where most of the value is.
- RED TEAM — authorised offence. Penetration testers, exploit researchers.
  Smaller, and more glamorous than it is common.
- PURPLE — the two working together deliberately, which is where both improve
  fastest.
- GOVERNANCE, RISK AND COMPLIANCE — policy, audit, regulation. Unfashionable,
  and frequently the function with the most actual influence.
- APPLICATION SECURITY, cryptography, forensics, threat intelligence.

What the work is really like, as against the portrayal: a great deal of reading
logs, writing documentation, patching, and persuading people. The intellectual
core is adversarial thinking — asking how something could be abused rather than
whether it works — and that is a habit anyone can build.

The most useful foundations are unglamorous: know how networks and operating
systems actually work, be able to script, and be able to write clearly. A
finding nobody understands does not get fixed, which makes writing a security
skill rather than a soft one.
""",
                    "checks": [
                        "Which team do most security jobs sit on?",
                        "Why is writing clearly a security skill rather than an optional extra?",
                    ],
                },
            ],
        },
    ],
}
