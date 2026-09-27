"""What a submission contains, per kind. One definition, three consumers.

The form renders from this, the validator checks against it, and the payload is
built from it. Three hand-maintained copies of a field list is how a form grows a
question whose answer nothing stores, or a validator that rejects something the
form never asked for -- and on an intake form the second one means a person
retypes their account of being assaulted because a required field was invisible.

WHY KINDS DIFFER IN REQUIREMENTS AND NOT IN MACHINERY
-----------------------------------------------------
A civil-rights report asks for a name and an email because somebody wants their
case worked and worked cases need a way back to the complainant. A press tip must
be submittable with NOTHING -- the person sending it is often the person at risk,
and every required field is a reason to close the tab.

That is the only real difference between them, so it lives here as `required`
rather than in two intake stacks.

WHAT IS *NOT* HERE
------------------
Evidence files. They are not payload fields -- they are streamed to storage,
scanned, scrubbed and referenced by digest, so they have their own path. A field
list is the wrong shape for something that never fits in a form value.
"""

# --- classification --------------------------------------------------------

# (value, label). Values are stable identifiers stored in the index; labels are
# display text and may be reworded without a migration.
CATEGORIES = (
    ("discrimination", "Discrimination"),
    ("unlawful_search", "Unlawful search or seizure"),
    ("excessive_force", "Excessive use of force"),
    ("unlawful_arrest", "Unlawful arrest or detention"),
    ("due_process", "Due-process violation"),
    ("free_speech", "Freedom of speech or expression"),
    ("free_assembly", "Freedom of assembly"),
    ("free_religion", "Freedom of religion"),
    ("voting_rights", "Voting or election rights"),
    ("employment", "Employment discrimination"),
    ("housing", "Housing discrimination"),
    ("education", "Education-related discrimination"),
    ("disability", "Disability discrimination"),
    ("privacy", "Privacy violation"),
    ("retaliation", "Retaliation"),
    ("police_misconduct", "Police misconduct"),
    ("prison_misconduct", "Prison or jail misconduct"),
    ("other", "Other"),
)

CATEGORY_VALUES = tuple(value for value, _ in CATEGORIES)


# Who the submitter says is responsible. "Unknown" is a first-class answer, not a
# fallback: a person who was stopped by someone they could not identify has given
# a complete account, and forcing a guess would put a fabricated attribution into
# a record that may be read years later as though they had asserted it.
ENTITY_TYPES = (
    ("government", "A government entity, agency, official or law-enforcement body"),
    ("private", "A private business, organisation, employer or institution"),
    ("individual", "A private individual"),
    ("unknown", "Unknown or unsure"),
)

ENTITY_TYPE_VALUES = tuple(value for value, _ in ENTITY_TYPES)


CONTACT_METHODS = (
    ("email", "Email"),
    ("phone", "Phone"),
    ("none", "Do not contact me"),
)

CONTACT_METHOD_VALUES = tuple(value for value, _ in CONTACT_METHODS)


# --- fields ----------------------------------------------------------------

class Field(object):
    """One question.

    `sensitive` marks a field whose value must never be echoed back in an error
    page, written to a log, or copied into the index. It is not decoration --
    `validate` uses it to decide what may appear in a message.
    """

    __slots__ = ("name", "label", "kind", "help", "sensitive", "max_length",
                 "choices", "rows")

    def __init__(self, name, label, kind="text", help=None, sensitive=False,
                 max_length=500, choices=None, rows=None):
        self.name = name
        self.label = label
        self.kind = kind          # text | textarea | date | time | select | checkboxes
        self.help = help
        self.sensitive = sensitive
        self.max_length = max_length
        self.choices = choices
        self.rows = rows


# Kept modest deliberately: a description long enough to matter is a few
# thousand characters, and a cap in the megabytes is a denial-of-service surface
# rather than a generosity.
LONG = 20000


CONTACT_FIELDS = (
    Field("full_name", "Your full name", sensitive=True, max_length=200),
    Field("email", "Email address", kind="email", sensitive=True, max_length=254),
    Field("phone", "Phone number (optional)", sensitive=True, max_length=64),
    Field("preferred_contact", "How should we reach you?", kind="select",
          choices=CONTACT_METHODS,
          help="Choose “Do not contact me” if being contacted would put "
               "you at risk. We will still review what you send."),
)

INCIDENT_FIELDS = (
    Field("incident_date", "Date this happened", kind="date"),
    Field("incident_time", "Approximate time (optional)", kind="time"),
    Field("location", "Where it happened", sensitive=True,
          help="A street, building or place — as precise as you are "
               "comfortable being."),
    Field("city", "City or town", sensitive=True, max_length=120),
    Field("state", "State or province", max_length=120),
    Field("country", "Country", max_length=120),
    Field("description", "What happened?", kind="textarea", sensitive=True,
          max_length=LONG, rows=10,
          help="In your own words, in whatever order makes sense. Facts you saw "
               "or heard yourself are the most useful."),
    Field("rights_basis", "Why do you believe your civil rights were violated?",
          kind="textarea", sensitive=True, max_length=LONG, rows=5,
          help="You do not need to cite a law. Say what feels wrong about how "
               "you were treated."),
    Field("entity_responsible", "Who was responsible?", sensitive=True,
          help="A department, company, or person, as best you know."),
    Field("entity_type", "Are they…", kind="select", choices=ENTITY_TYPES),
    Field("people_involved", "Names or titles of people involved, if known",
          kind="textarea", sensitive=True, max_length=5000, rows=3,
          help="Badge numbers, job titles or descriptions are useful if you do "
               "not have names."),
    Field("organisations_involved",
          "Agencies, companies, organisations or institutions involved",
          kind="textarea", sensitive=True, max_length=5000, rows=3),
    Field("witnesses", "Witnesses (optional)", kind="textarea", sensitive=True,
          max_length=5000, rows=3,
          help="Only include someone else’s details if you believe they "
               "would want you to."),
)

TIP_FIELDS = (
    Field("description", "What do you want us to know?", kind="textarea",
          sensitive=True, max_length=LONG, rows=10),
    Field("why_it_matters", "Why does it matter?", kind="textarea",
          sensitive=True, max_length=LONG, rows=4),
    Field("entity_responsible", "Who or what is this about?", sensitive=True),
    Field("email", "Email address (optional)", kind="email", sensitive=True,
          max_length=254,
          help="Only if you want it. Your reference number lets you come back "
               "without giving us any way to identify you."),
)

CONTEXT_FIELD = Field(
    "additional_context", "Anything else", kind="textarea", sensitive=True,
    max_length=LONG, rows=6,
    help="Anything the questions above did not cover.")


# The four acknowledgements. Placeholder wording pending legal review -- see the
# roadmap. Stored with the payload so a submission records what the person was
# actually shown, not what the current template happens to say.
ACKNOWLEDGEMENTS = (
    ("accurate",
     "The information I am submitting is accurate to the best of my knowledge."),
    ("may_contact",
     "I understand Syndichan may contact me about this report."),
    ("no_representation",
     "I understand that submitting this form does not create an "
     "attorney-client relationship and does not guarantee legal "
     "representation."),
    ("may_not_investigate",
     "I understand Syndichan may be unable to investigate every submission."),
)

ACKNOWLEDGEMENT_KEYS = tuple(key for key, _ in ACKNOWLEDGEMENTS)


# --- per-kind assembly -----------------------------------------------------

KIND_CIVIL_RIGHTS = "civil_rights"
KIND_NEWS_TIP = "news_tip"


SCHEMAS = {
    KIND_CIVIL_RIGHTS: {
        "version": 1,
        "sections": (
            ("Your contact details", CONTACT_FIELDS),
            ("What happened", INCIDENT_FIELDS),
            ("Anything else", (CONTEXT_FIELD,)),
        ),
        # A worked case needs a way back to the person and an account of what
        # happened. Everything else is optional, including the categories.
        "required": ("full_name", "email", "description", "incident_date"),
        "categories": True,
        "acknowledgements": ACKNOWLEDGEMENT_KEYS,
    },
    KIND_NEWS_TIP: {
        "version": 1,
        "sections": (
            ("Your tip", TIP_FIELDS),
            ("Anything else", (CONTEXT_FIELD,)),
        ),
        # Deliberately just the tip itself. No name, no email, no slip -- see
        # the module docstring.
        "required": ("description",),
        "categories": False,
        "acknowledgements": ("accurate",),
    },
}


def schema_for(kind):
    if kind not in SCHEMAS:
        raise KeyError("unknown report kind: %r" % kind)
    return SCHEMAS[kind]


def fields_for(kind):
    """Every field of a kind, flattened."""
    out = []
    for _, fields in schema_for(kind)["sections"]:
        out.extend(fields)
    return out


def field_map(kind):
    return {field.name: field for field in fields_for(kind)}


class ValidationError(Exception):
    """Field name -> message. Messages never quote what was submitted."""

    def __init__(self, errors):
        self.errors = errors
        super(ValidationError, self).__init__("%d field(s) invalid" % len(errors))


def validate(kind, values, categories=(), acknowledgements=()):
    """Check a submission. Returns the cleaned payload dict, or raises.

    Messages describe the PROBLEM and never echo the value. An error page is
    rendered, cached by intermediaries and sometimes logged, and quoting a
    complainant's description back into one is a way for it to escape the
    encryption everything else here exists to provide.
    """
    schema = schema_for(kind)
    fields = field_map(kind)
    errors = {}
    cleaned = {}

    for name, field in fields.items():
        raw = (values.get(name) or "").strip()
        if not raw:
            continue
        if len(raw) > field.max_length:
            errors[name] = "This is longer than the %d characters we can accept." \
                % field.max_length
            continue
        if field.kind == "select":
            allowed = [value for value, _ in (field.choices or ())]
            if raw not in allowed:
                errors[name] = "Choose one of the listed options."
                continue
        if field.kind == "email" and ("@" not in raw or raw.startswith("@")
                                      or raw.endswith("@")):
            errors[name] = "That does not look like an email address."
            continue
        cleaned[name] = raw

    for name in schema["required"]:
        if not cleaned.get(name):
            label = fields[name].label if name in fields else name
            errors.setdefault(name, "%s is needed before we can accept this." % label)

    chosen = [c for c in categories if c in CATEGORY_VALUES]
    if schema["categories"] and not chosen:
        errors.setdefault("categories", "Choose at least one category. Pick "
                                        "“Other” if none fit.")

    missing_ack = [key for key in schema["acknowledgements"]
                   if key not in acknowledgements]
    if missing_ack:
        errors.setdefault("acknowledgements",
                          "Please confirm each statement before submitting.")

    if errors:
        raise ValidationError(errors)

    return {
        "kind": kind,
        "schema_version": schema["version"],
        "fields": cleaned,
        "categories": chosen,
        # Recorded as the text that was actually shown, so a later reader knows
        # what the person agreed to rather than what the template says today.
        "acknowledgements": {key: text for key, text in ACKNOWLEDGEMENTS
                             if key in schema["acknowledgements"]},
    }
