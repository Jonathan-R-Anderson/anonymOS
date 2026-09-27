"""Memorable names for lab machines.

A machine called `vulhub-1panel-cve-2024-39907` is a catalogue entry, not
something anyone says out loud. Two people comparing notes need a handle, and a
CVE number is exactly the thing nobody remembers — so every machine gets an
adjective-and-animal codename in the style Docker gives containers: Funky
Beaver, Brisk Otter, Candid Heron.

The product and CVE do not go away; they move to the subtitle, where they are
still searchable and still the thing you cite in a writeup. What changes is
which of the two is the name.

Assignment is DETERMINISTIC from the slug, so the same machine gets the same
name on any deployment, in any order, without a database. It is nevertheless
stored once on the row, because the name is how people refer to a machine and a
name that could shift under a wordlist edit is not a name.
"""

import hashlib

ADJECTIVES = (
    "admiring adoring affable agile amber amusing ardent artful bashful blissful",
    "bold boundless brave brisk bubbly candid charming cheerful clever compassionate",
    "competent confident cosmic crafty dapper daring dazzling determined devoted",
    "distracted dreamy eager ecstatic elastic elated elegant eloquent epic exuberant",
    "fearless fervent festive flamboyant focused friendly frosty funky gallant gentle",
    "gifted gleaming glorious golden gracious grand groovy hardcore heuristic hopeful",
    "hungry infallible inspiring intrepid jolly jovial keen kind laughing lively",
    "loving lucid magical majestic mellow merry mighty modest musing mystifying",
    "naughty nervous nifty nimble nostalgic objective optimistic peaceful pedantic",
    "pensive plucky practical priceless quirky quizzical radiant recursing relaxed",
    "reverent romantic sassy scrappy serene sharp silly sleepy smooth snappy",
    "solar sparkling spirited stoic strange stupefied suspicious sweet tender thirsty",
    "trusting unruffled upbeat vibrant vigilant vigorous voyaging wandering wizardly",
    "wonderful youthful zealous zen",
)

ANIMALS = (
    "adder albatross alpaca badger barnacle basilisk bison bittern bobcat bullfrog",
    "camel capybara caracal cassowary catfish chameleon cheetah chinchilla civet cobra",
    "condor cougar coyote crane cricket crocodile crow cuttlefish dingo dormouse",
    "dragonfly duckling eagle echidna eel egret elk ermine falcon fennec",
    "ferret finch firefly flamingo fossa gannet gazelle gecko gerbil gibbon",
    "giraffe goshawk grouse guanaco gull hamster hare harrier hedgehog heron",
    "hornbill hyena ibex ibis iguana impala jackal jaguar jay jellyfish",
    "jerboa kakapo kestrel kingfisher kite koala kudu lapwing lemming lemur",
    "leopard limpet lizard llama lobster loris lynx macaw magpie mallard",
    "manatee mandrill mantis marmot marten meerkat mink mole mongoose moorhen",
    "moose narwhal newt nightjar numbat ocelot octopus okapi opossum orca",
    "oryx osprey otter owl panther pangolin parrot pelican penguin petrel",
    "pheasant pigeon pika platypus plover polecat porcupine possum puffin puma",
    "quail quokka quoll rabbit raccoon raven reindeer rhino roadrunner rook",
    "salamander sandpiper seahorse seal serval shearwater shrew shrike siskin skink",
    "skua sloth snipe sparrow squid squirrel starling stingray stoat stork",
    "swallow swift tamarin tapir tarsier teal tern thrush tiger toucan",
    "turtle urchin vicuna viper vole vulture wallaby walrus warbler weasel",
    "whimbrel wolverine wombat woodpecker wren yak zebra zebu",
)


def _flatten(rows):
    out = []
    for row in rows:
        out.extend(row.split())
    return tuple(out)


_ADJECTIVES = _flatten(ADJECTIVES)
_ANIMALS = _flatten(ANIMALS)


def wordlist_size():
    """How many distinct names exist. Reported so an operator can see the
    headroom rather than discover it when names start repeating."""
    return len(_ADJECTIVES) * len(_ANIMALS)


def codename_for(slug, taken=()):
    """A stable codename for a slug, avoiding any already in `taken`.

    The slug is hashed rather than counted, so a machine's name does not depend
    on how many were added before it. Collisions walk forward through the pair
    space by a stride derived from the same hash: a fixed +1 would cluster every
    colliding slug onto consecutive animals of one adjective, which reads as a
    bug even when it is not.
    """
    taken = {str(name).strip().lower() for name in taken if name}
    digest = hashlib.sha256(("syndichan-lab:" + str(slug or "")).encode("utf-8")).digest()
    span = wordlist_size()
    start = int.from_bytes(digest[:8], "big") % span
    # Odd stride, coprime with the span's factors often enough in practice; the
    # loop below is bounded by the span either way so it always terminates.
    stride = (int.from_bytes(digest[8:16], "big") % (span - 1)) | 1

    for step in range(span):
        index = (start + step * stride) % span
        name = "%s %s" % (
            _ADJECTIVES[index // len(_ANIMALS)].capitalize(),
            _ANIMALS[index % len(_ANIMALS)].capitalize(),
        )
        if name.lower() not in taken:
            return name

    # Every pair is spoken for. Suffixing is ugly, and being ugly is the point:
    # it is visible, so somebody adds words to the list rather than the site
    # quietly handing two machines the same name.
    base = "%s %s" % (
        _ADJECTIVES[start // len(_ANIMALS)].capitalize(),
        _ANIMALS[start % len(_ANIMALS)].capitalize(),
    )
    suffix = 2
    while ("%s %d" % (base, suffix)).lower() in taken:
        suffix += 1
    return "%s %d" % (base, suffix)
