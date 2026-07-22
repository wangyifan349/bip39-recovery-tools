#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Offline recovery for a Bitcoin wallet whose BIP39 word order is correct but zero, one, or two words may be wrong.

Features:
- Interactive input only; no mnemonic or address command-line arguments.
- Accepts words separated by spaces, English commas, or Chinese commas.
- Supports 12 and 24 English BIP39 words.
- The official 2048-word English BIP39 list is embedded in this file.
- Rejects structurally unreasonable input before candidate generation.
- Performs the BIP39 checksum before seed/address derivation.
- Verifies candidates against one known Bitcoin address.
- Does not save results, logs, checkpoints, or mnemonic data to disk.
- Shows live total, checked, remaining, completion, speed, and estimated time.
- Prints exact runtime counters and keeps the screen open for 9999 seconds.

Required package:
    python -m pip install bip-utils==2.12.1
"""

from __future__ import annotations

import getpass
import hashlib
import math
import re
import sys
import time
import unicodedata
from collections import Counter

sys.dont_write_bytecode = True                                      # Do not create .pyc cache files.

from bip_utils import (                                             # Standard BIP39/BIP32 wallet derivation.
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    Bip86,
    Bip86Coins,
)

BIP39_WORDS = """
abandon
ability
able
about
above
absent
absorb
abstract
absurd
abuse
access
accident
account
accuse
achieve
acid
acoustic
acquire
across
act
action
actor
actress
actual
adapt
add
addict
address
adjust
admit
adult
advance
advice
aerobic
affair
afford
afraid
again
age
agent
agree
ahead
aim
air
airport
aisle
alarm
album
alcohol
alert
alien
all
alley
allow
almost
alone
alpha
already
also
alter
always
amateur
amazing
among
amount
amused
analyst
anchor
ancient
anger
angle
angry
animal
ankle
announce
annual
another
answer
antenna
antique
anxiety
any
apart
apology
appear
apple
approve
april
arch
arctic
area
arena
argue
arm
armed
armor
army
around
arrange
arrest
arrive
arrow
art
artefact
artist
artwork
ask
aspect
assault
asset
assist
assume
asthma
athlete
atom
attack
attend
attitude
attract
auction
audit
august
aunt
author
auto
autumn
average
avocado
avoid
awake
aware
away
awesome
awful
awkward
axis
baby
bachelor
bacon
badge
bag
balance
balcony
ball
bamboo
banana
banner
bar
barely
bargain
barrel
base
basic
basket
battle
beach
bean
beauty
because
become
beef
before
begin
behave
behind
believe
below
belt
bench
benefit
best
betray
better
between
beyond
bicycle
bid
bike
bind
biology
bird
birth
bitter
black
blade
blame
blanket
blast
bleak
bless
blind
blood
blossom
blouse
blue
blur
blush
board
boat
body
boil
bomb
bone
bonus
book
boost
border
boring
borrow
boss
bottom
bounce
box
boy
bracket
brain
brand
brass
brave
bread
breeze
brick
bridge
brief
bright
bring
brisk
broccoli
broken
bronze
broom
brother
brown
brush
bubble
buddy
budget
buffalo
build
bulb
bulk
bullet
bundle
bunker
burden
burger
burst
bus
business
busy
butter
buyer
buzz
cabbage
cabin
cable
cactus
cage
cake
call
calm
camera
camp
can
canal
cancel
candy
cannon
canoe
canvas
canyon
capable
capital
captain
car
carbon
card
cargo
carpet
carry
cart
case
cash
casino
castle
casual
cat
catalog
catch
category
cattle
caught
cause
caution
cave
ceiling
celery
cement
census
century
cereal
certain
chair
chalk
champion
change
chaos
chapter
charge
chase
chat
cheap
check
cheese
chef
cherry
chest
chicken
chief
child
chimney
choice
choose
chronic
chuckle
chunk
churn
cigar
cinnamon
circle
citizen
city
civil
claim
clap
clarify
claw
clay
clean
clerk
clever
click
client
cliff
climb
clinic
clip
clock
clog
close
cloth
cloud
clown
club
clump
cluster
clutch
coach
coast
coconut
code
coffee
coil
coin
collect
color
column
combine
come
comfort
comic
common
company
concert
conduct
confirm
congress
connect
consider
control
convince
cook
cool
copper
copy
coral
core
corn
correct
cost
cotton
couch
country
couple
course
cousin
cover
coyote
crack
cradle
craft
cram
crane
crash
crater
crawl
crazy
cream
credit
creek
crew
cricket
crime
crisp
critic
crop
cross
crouch
crowd
crucial
cruel
cruise
crumble
crunch
crush
cry
crystal
cube
culture
cup
cupboard
curious
current
curtain
curve
cushion
custom
cute
cycle
dad
damage
damp
dance
danger
daring
dash
daughter
dawn
day
deal
debate
debris
decade
december
decide
decline
decorate
decrease
deer
defense
define
defy
degree
delay
deliver
demand
demise
denial
dentist
deny
depart
depend
deposit
depth
deputy
derive
describe
desert
design
desk
despair
destroy
detail
detect
develop
device
devote
diagram
dial
diamond
diary
dice
diesel
diet
differ
digital
dignity
dilemma
dinner
dinosaur
direct
dirt
disagree
discover
disease
dish
dismiss
disorder
display
distance
divert
divide
divorce
dizzy
doctor
document
dog
doll
dolphin
domain
donate
donkey
donor
door
dose
double
dove
draft
dragon
drama
drastic
draw
dream
dress
drift
drill
drink
drip
drive
drop
drum
dry
duck
dumb
dune
during
dust
dutch
duty
dwarf
dynamic
eager
eagle
early
earn
earth
easily
east
easy
echo
ecology
economy
edge
edit
educate
effort
egg
eight
either
elbow
elder
electric
elegant
element
elephant
elevator
elite
else
embark
embody
embrace
emerge
emotion
employ
empower
empty
enable
enact
end
endless
endorse
enemy
energy
enforce
engage
engine
enhance
enjoy
enlist
enough
enrich
enroll
ensure
enter
entire
entry
envelope
episode
equal
equip
era
erase
erode
erosion
error
erupt
escape
essay
essence
estate
eternal
ethics
evidence
evil
evoke
evolve
exact
example
excess
exchange
excite
exclude
excuse
execute
exercise
exhaust
exhibit
exile
exist
exit
exotic
expand
expect
expire
explain
expose
express
extend
extra
eye
eyebrow
fabric
face
faculty
fade
faint
faith
fall
false
fame
family
famous
fan
fancy
fantasy
farm
fashion
fat
fatal
father
fatigue
fault
favorite
feature
february
federal
fee
feed
feel
female
fence
festival
fetch
fever
few
fiber
fiction
field
figure
file
film
filter
final
find
fine
finger
finish
fire
firm
first
fiscal
fish
fit
fitness
fix
flag
flame
flash
flat
flavor
flee
flight
flip
float
flock
floor
flower
fluid
flush
fly
foam
focus
fog
foil
fold
follow
food
foot
force
forest
forget
fork
fortune
forum
forward
fossil
foster
found
fox
fragile
frame
frequent
fresh
friend
fringe
frog
front
frost
frown
frozen
fruit
fuel
fun
funny
furnace
fury
future
gadget
gain
galaxy
gallery
game
gap
garage
garbage
garden
garlic
garment
gas
gasp
gate
gather
gauge
gaze
general
genius
genre
gentle
genuine
gesture
ghost
giant
gift
giggle
ginger
giraffe
girl
give
glad
glance
glare
glass
glide
glimpse
globe
gloom
glory
glove
glow
glue
goat
goddess
gold
good
goose
gorilla
gospel
gossip
govern
gown
grab
grace
grain
grant
grape
grass
gravity
great
green
grid
grief
grit
grocery
group
grow
grunt
guard
guess
guide
guilt
guitar
gun
gym
habit
hair
half
hammer
hamster
hand
happy
harbor
hard
harsh
harvest
hat
have
hawk
hazard
head
health
heart
heavy
hedgehog
height
hello
helmet
help
hen
hero
hidden
high
hill
hint
hip
hire
history
hobby
hockey
hold
hole
holiday
hollow
home
honey
hood
hope
horn
horror
horse
hospital
host
hotel
hour
hover
hub
huge
human
humble
humor
hundred
hungry
hunt
hurdle
hurry
hurt
husband
hybrid
ice
icon
idea
identify
idle
ignore
ill
illegal
illness
image
imitate
immense
immune
impact
impose
improve
impulse
inch
include
income
increase
index
indicate
indoor
industry
infant
inflict
inform
inhale
inherit
initial
inject
injury
inmate
inner
innocent
input
inquiry
insane
insect
inside
inspire
install
intact
interest
into
invest
invite
involve
iron
island
isolate
issue
item
ivory
jacket
jaguar
jar
jazz
jealous
jeans
jelly
jewel
job
join
joke
journey
joy
judge
juice
jump
jungle
junior
junk
just
kangaroo
keen
keep
ketchup
key
kick
kid
kidney
kind
kingdom
kiss
kit
kitchen
kite
kitten
kiwi
knee
knife
knock
know
lab
label
labor
ladder
lady
lake
lamp
language
laptop
large
later
latin
laugh
laundry
lava
law
lawn
lawsuit
layer
lazy
leader
leaf
learn
leave
lecture
left
leg
legal
legend
leisure
lemon
lend
length
lens
leopard
lesson
letter
level
liar
liberty
library
license
life
lift
light
like
limb
limit
link
lion
liquid
list
little
live
lizard
load
loan
lobster
local
lock
logic
lonely
long
loop
lottery
loud
lounge
love
loyal
lucky
luggage
lumber
lunar
lunch
luxury
lyrics
machine
mad
magic
magnet
maid
mail
main
major
make
mammal
man
manage
mandate
mango
mansion
manual
maple
marble
march
margin
marine
market
marriage
mask
mass
master
match
material
math
matrix
matter
maximum
maze
meadow
mean
measure
meat
mechanic
medal
media
melody
melt
member
memory
mention
menu
mercy
merge
merit
merry
mesh
message
metal
method
middle
midnight
milk
million
mimic
mind
minimum
minor
minute
miracle
mirror
misery
miss
mistake
mix
mixed
mixture
mobile
model
modify
mom
moment
monitor
monkey
monster
month
moon
moral
more
morning
mosquito
mother
motion
motor
mountain
mouse
move
movie
much
muffin
mule
multiply
muscle
museum
mushroom
music
must
mutual
myself
mystery
myth
naive
name
napkin
narrow
nasty
nation
nature
near
neck
need
negative
neglect
neither
nephew
nerve
nest
net
network
neutral
never
news
next
nice
night
noble
noise
nominee
noodle
normal
north
nose
notable
note
nothing
notice
novel
now
nuclear
number
nurse
nut
oak
obey
object
oblige
obscure
observe
obtain
obvious
occur
ocean
october
odor
off
offer
office
often
oil
okay
old
olive
olympic
omit
once
one
onion
online
only
open
opera
opinion
oppose
option
orange
orbit
orchard
order
ordinary
organ
orient
original
orphan
ostrich
other
outdoor
outer
output
outside
oval
oven
over
own
owner
oxygen
oyster
ozone
pact
paddle
page
pair
palace
palm
panda
panel
panic
panther
paper
parade
parent
park
parrot
party
pass
patch
path
patient
patrol
pattern
pause
pave
payment
peace
peanut
pear
peasant
pelican
pen
penalty
pencil
people
pepper
perfect
permit
person
pet
phone
photo
phrase
physical
piano
picnic
picture
piece
pig
pigeon
pill
pilot
pink
pioneer
pipe
pistol
pitch
pizza
place
planet
plastic
plate
play
please
pledge
pluck
plug
plunge
poem
poet
point
polar
pole
police
pond
pony
pool
popular
portion
position
possible
post
potato
pottery
poverty
powder
power
practice
praise
predict
prefer
prepare
present
pretty
prevent
price
pride
primary
print
priority
prison
private
prize
problem
process
produce
profit
program
project
promote
proof
property
prosper
protect
proud
provide
public
pudding
pull
pulp
pulse
pumpkin
punch
pupil
puppy
purchase
purity
purpose
purse
push
put
puzzle
pyramid
quality
quantum
quarter
question
quick
quit
quiz
quote
rabbit
raccoon
race
rack
radar
radio
rail
rain
raise
rally
ramp
ranch
random
range
rapid
rare
rate
rather
raven
raw
razor
ready
real
reason
rebel
rebuild
recall
receive
recipe
record
recycle
reduce
reflect
reform
refuse
region
regret
regular
reject
relax
release
relief
rely
remain
remember
remind
remove
render
renew
rent
reopen
repair
repeat
replace
report
require
rescue
resemble
resist
resource
response
result
retire
retreat
return
reunion
reveal
review
reward
rhythm
rib
ribbon
rice
rich
ride
ridge
rifle
right
rigid
ring
riot
ripple
risk
ritual
rival
river
road
roast
robot
robust
rocket
romance
roof
rookie
room
rose
rotate
rough
round
route
royal
rubber
rude
rug
rule
run
runway
rural
sad
saddle
sadness
safe
sail
salad
salmon
salon
salt
salute
same
sample
sand
satisfy
satoshi
sauce
sausage
save
say
scale
scan
scare
scatter
scene
scheme
school
science
scissors
scorpion
scout
scrap
screen
script
scrub
sea
search
season
seat
second
secret
section
security
seed
seek
segment
select
sell
seminar
senior
sense
sentence
series
service
session
settle
setup
seven
shadow
shaft
shallow
share
shed
shell
sheriff
shield
shift
shine
ship
shiver
shock
shoe
shoot
shop
short
shoulder
shove
shrimp
shrug
shuffle
shy
sibling
sick
side
siege
sight
sign
silent
silk
silly
silver
similar
simple
since
sing
siren
sister
situate
six
size
skate
sketch
ski
skill
skin
skirt
skull
slab
slam
sleep
slender
slice
slide
slight
slim
slogan
slot
slow
slush
small
smart
smile
smoke
smooth
snack
snake
snap
sniff
snow
soap
soccer
social
sock
soda
soft
solar
soldier
solid
solution
solve
someone
song
soon
sorry
sort
soul
sound
soup
source
south
space
spare
spatial
spawn
speak
special
speed
spell
spend
sphere
spice
spider
spike
spin
spirit
split
spoil
sponsor
spoon
sport
spot
spray
spread
spring
spy
square
squeeze
squirrel
stable
stadium
staff
stage
stairs
stamp
stand
start
state
stay
steak
steel
stem
step
stereo
stick
still
sting
stock
stomach
stone
stool
story
stove
strategy
street
strike
strong
struggle
student
stuff
stumble
style
subject
submit
subway
success
such
sudden
suffer
sugar
suggest
suit
summer
sun
sunny
sunset
super
supply
supreme
sure
surface
surge
surprise
surround
survey
suspect
sustain
swallow
swamp
swap
swarm
swear
sweet
swift
swim
swing
switch
sword
symbol
symptom
syrup
system
table
tackle
tag
tail
talent
talk
tank
tape
target
task
taste
tattoo
taxi
teach
team
tell
ten
tenant
tennis
tent
term
test
text
thank
that
theme
then
theory
there
they
thing
this
thought
three
thrive
throw
thumb
thunder
ticket
tide
tiger
tilt
timber
time
tiny
tip
tired
tissue
title
toast
tobacco
today
toddler
toe
together
toilet
token
tomato
tomorrow
tone
tongue
tonight
tool
tooth
top
topic
topple
torch
tornado
tortoise
toss
total
tourist
toward
tower
town
toy
track
trade
traffic
tragic
train
transfer
trap
trash
travel
tray
treat
tree
trend
trial
tribe
trick
trigger
trim
trip
trophy
trouble
truck
true
truly
trumpet
trust
truth
try
tube
tuition
tumble
tuna
tunnel
turkey
turn
turtle
twelve
twenty
twice
twin
twist
two
type
typical
ugly
umbrella
unable
unaware
uncle
uncover
under
undo
unfair
unfold
unhappy
uniform
unique
unit
universe
unknown
unlock
until
unusual
unveil
update
upgrade
uphold
upon
upper
upset
urban
urge
usage
use
used
useful
useless
usual
utility
vacant
vacuum
vague
valid
valley
valve
van
vanish
vapor
various
vast
vault
vehicle
velvet
vendor
venture
venue
verb
verify
version
very
vessel
veteran
viable
vibrant
vicious
victory
video
view
village
vintage
violin
virtual
virus
visa
visit
visual
vital
vivid
vocal
voice
void
volcano
volume
vote
voyage
wage
wagon
wait
walk
wall
walnut
want
warfare
warm
warrior
wash
wasp
waste
water
wave
way
wealth
weapon
wear
weasel
weather
web
wedding
weekend
weird
welcome
west
wet
whale
what
wheat
wheel
when
where
whip
whisper
wide
width
wife
wild
will
win
window
wine
wing
wink
winner
winter
wire
wisdom
wise
wish
witness
wolf
woman
wonder
wood
wool
word
work
world
worry
worth
wrap
wreck
wrestle
wrist
write
wrong
yard
year
yellow
you
young
youth
zebra
zero
zone
zoo
""".split()                                                        # Embedded official English BIP39 word list.

WORD_TO_INDEX = {word: index for index, word in enumerate(BIP39_WORDS)}


# ============================== Configuration ==============================

REFRESH_INTERVAL = 0.75                                             # Refresh one progress line, not the whole screen.
HOLD_SECONDS = 9999                                                 # Keep the terminal window visible after completion.
SUPPORTED_WORD_COUNTS = (12, 24)
MAX_WRONG_WORDS = 2

SCAN_LOCATIONS = (
    (Bip44Changes.CHAIN_EXT, 0, 0, "external address 0"),
    (Bip44Changes.CHAIN_EXT, 0, 1, "external address 1"),
    (Bip44Changes.CHAIN_INT, 1, 0, "internal address 0"),
    (Bip44Changes.CHAIN_INT, 1, 1, "internal address 1"),
)


# ============================== Validation and recovery ==============================

def analyze_input_words(words: list[str]) -> tuple[bool, list[int], str]:
    """Check whether the input is suitable for a one-word or two-word repair."""
    if len(words) not in SUPPORTED_WORD_COUNTS:
        return False, [], f"Expected 12 or 24 words; received {len(words)}."

    malformed_positions = [
        position
        for position, word in enumerate(words)
        if not re.fullmatch(r"[a-z]+", word)
    ]

    if malformed_positions:
        displayed = ", ".join(str(position + 1) for position in malformed_positions)
        return False, [], f"Non-English-letter input at word position(s): {displayed}."

    unknown_positions = [
        position
        for position, word in enumerate(words)
        if word not in WORD_TO_INDEX
    ]

    if len(unknown_positions) > MAX_WRONG_WORDS:
        displayed = ", ".join(str(position + 1) for position in unknown_positions)
        return (
            False,
            unknown_positions,
            f"More than two words are outside the BIP39 list: positions {displayed}.",
        )

    return True, unknown_positions, ""


def checksum_is_valid(word_indices: list[int]) -> bool:
    """Reject invalid BIP39 candidates before expensive seed/address derivation."""
    checksum_bit_count = len(word_indices) // 3
    entropy_bit_count = len(word_indices) * 11 - checksum_bit_count
    combined_value = 0

    for word_index in word_indices:
        if word_index < 0 or word_index >= 2048:
            return False                                             # Candidate word is not a valid BIP39 index.
        combined_value = (combined_value << 11) | word_index

    checksum_mask = (1 << checksum_bit_count) - 1
    actual_checksum = combined_value & checksum_mask
    entropy_value = combined_value >> checksum_bit_count
    entropy_bytes = entropy_value.to_bytes(entropy_bit_count // 8, "big")
    expected_checksum = hashlib.sha256(entropy_bytes).digest()[0] >> (8 - checksum_bit_count)

    return actual_checksum == expected_checksum


def select_wallet_standard(target_address: str) -> dict:
    """Use the address prefix to avoid deriving unrelated wallet standards."""
    lowered = target_address.lower()

    if target_address.startswith("1"):
        return {"name": "BIP44", "purpose": 44, "class": Bip44, "coin": Bip44Coins.BITCOIN}
    if target_address.startswith("3"):
        return {"name": "BIP49", "purpose": 49, "class": Bip49, "coin": Bip49Coins.BITCOIN}
    if lowered.startswith("bc1q"):
        return {"name": "BIP84", "purpose": 84, "class": Bip84, "coin": Bip84Coins.BITCOIN}
    if lowered.startswith("bc1p"):
        return {"name": "BIP86", "purpose": 86, "class": Bip86, "coin": Bip86Coins.BITCOIN}

    if target_address.startswith(("m", "n", "2")) or lowered.startswith("tb1"):
        raise ValueError("Testnet addresses are not supported.")

    raise ValueError("Unsupported Bitcoin mainnet address prefix.")


def compare_candidate(
    word_indices: list[int],
    passphrase: str,
    target_address: str,
    standard: dict,
) -> tuple[dict | None, int]:
    """Compare one checksum-valid mnemonic against the four configured paths."""
    mnemonic = " ".join(BIP39_WORDS[index] for index in word_indices)
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    wallet = standard["class"].FromSeed(seed, standard["coin"])
    account = wallet.Purpose().Coin().Account(0)
    target_for_compare = (
        target_address.lower()
        if target_address.lower().startswith("bc1")
        else target_address
    )
    comparison_count = 0

    for change_type, change_index, address_index, description in SCAN_LOCATIONS:
        generated_address = (
            account
            .Change(change_type)
            .AddressIndex(address_index)
            .PublicKey()
            .ToAddress()
        )
        comparison_count += 1

        generated_for_compare = (
            generated_address.lower()
            if generated_address.lower().startswith("bc1")
            else generated_address
        )

        if generated_for_compare == target_for_compare:
            return {
                "mnemonic": mnemonic,
                "standard": standard["name"],
                "path": (
                    f"m/{standard['purpose']}'/0'/0'/"
                    f"{change_index}/{address_index}"
                ),
                "location": description,
                "address": generated_address,
            }, comparison_count

    return None, comparison_count


def format_eta(seconds: float) -> str:
    """Keep the progress line compact."""
    if seconds <= 0:
        return "calculating"
    if seconds >= 31_556_952:
        return f"{seconds / 31_556_952:,.2f}y"
    if seconds >= 86_400:
        return f"{seconds / 86_400:,.2f}d"

    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    remaining_seconds = int(seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{remaining_seconds:02d}"


def generate_candidates(
    base_indices: list[int | None],
    one_word_positions: list[int],
    two_word_positions: list[tuple[int, int]],
):
    """Yield the original, one-word repairs, and two-word repairs in that order."""
    candidate = [index if index is not None else 0 for index in base_indices]

    if all(index is not None for index in base_indices):
        yield 0, candidate                                             # Check the supplied mnemonic first.

    for position in one_word_positions:
        original_index = base_indices[position]

        for replacement_index in range(2048):
            if original_index is not None and replacement_index == original_index:
                continue

            candidate[position] = replacement_index
            yield 1, candidate

        candidate[position] = original_index if original_index is not None else 0

    for first_position, second_position in two_word_positions:
        first_original = base_indices[first_position]
        second_original = base_indices[second_position]

        for first_replacement in range(2048):
            if first_original is not None and first_replacement == first_original:
                continue

            candidate[first_position] = first_replacement

            for second_replacement in range(2048):
                if second_original is not None and second_replacement == second_original:
                    continue

                candidate[second_position] = second_replacement
                yield 2, candidate

        candidate[first_position] = first_original if first_original is not None else 0
        candidate[second_position] = second_original if second_original is not None else 0


# ============================== Main program ==============================

def main() -> None:
    previous_line_width = 0

    print("Offline BIP39 wrong-word recovery - Bitcoin mainnet only")
    print("This mode assumes the word order is correct and zero, one, or two words are wrong.")
    print("Nothing is saved to disk. Mnemonic and passphrase input are visible on screen.\n")

    raw_words = input("Enter 12 or 24 BIP39 words in their current order: ")
    normalized_input = unicodedata.normalize("NFKD", raw_words).strip().lower()
    input_words = [word for word in re.split(r"[\s,，]+", normalized_input) if word]

    reasonable, unknown_positions, reason = analyze_input_words(input_words)

    if not reasonable:
        raise ValueError(reason)                                      # Stop before requesting or deriving anything else.

    if unknown_positions:
        displayed_positions = ", ".join(str(position + 1) for position in unknown_positions)
        print(f"Words outside the BIP39 list detected at position(s): {displayed_positions}")
        print("The search will force replacements at those positions.")
    else:
        print("Every supplied word is in the BIP39 list; the wrong position(s) are unknown.")

    passphrase = unicodedata.normalize(
        "NFKD",
        input("Enter the optional BIP39 passphrase (press Enter if none): "),
    )
    target_address = input("Enter a known Bitcoin mainnet address: ").strip()
    standard = select_wallet_standard(target_address)

    base_indices = [
        WORD_TO_INDEX[word] if word in WORD_TO_INDEX else None
        for word in input_words
    ]
    word_count = len(base_indices)
    all_positions = list(range(word_count))
    unknown_count = len(unknown_positions)

    if unknown_count == 0:
        one_word_positions = all_positions
        two_word_positions = [
            (first, second)
            for first in range(word_count)
            for second in range(first + 1, word_count)
        ]
    elif unknown_count == 1:
        known_bad_position = unknown_positions[0]
        one_word_positions = [known_bad_position]
        two_word_positions = [
            (min(known_bad_position, other), max(known_bad_position, other))
            for other in all_positions
            if other != known_bad_position
        ]
    else:
        one_word_positions = []
        two_word_positions = [
            (min(unknown_positions), max(unknown_positions))
        ]

    def replacement_count(position: int) -> int:
        return 2048 if base_indices[position] is None else 2047

    original_total = 1 if unknown_count == 0 else 0
    one_word_total = sum(
        replacement_count(position)
        for position in one_word_positions
    )
    two_word_total = sum(
        replacement_count(first) * replacement_count(second)
        for first, second in two_word_positions
    )
    total_candidates = original_total + one_word_total + two_word_total
    checksum_bit_count = word_count // 3
    expected_checksum_valid = total_candidates / (1 << checksum_bit_count)

    print("\nSearch configuration")
    print(f"Words: {word_count} | Address standard selected: {standard['name']}")
    print(f"Original candidate: {original_total:,}")
    print(f"One-word replacement candidates: {one_word_total:,}")
    print(f"Two-word replacement candidates: {two_word_total:,}")
    print(f"Exact total candidates: {total_candidates:,}")
    print(f"Expected checksum-valid candidates: about {expected_checksum_valid:,.0f}")
    print(f"Address paths per checksum-valid candidate: {len(SCAN_LOCATIONS)}")
    print("Paths: external 0, external 1, internal 0, internal 1\n")

    checked_count = 0
    checksum_valid_count = 0
    address_comparison_count = 0
    current_error_count = 0
    result = None
    start_time = time.monotonic()
    last_refresh_time = start_time

    for error_count, candidate_indices in generate_candidates(
        base_indices,
        one_word_positions,
        two_word_positions,
    ):
        current_error_count = error_count
        checked_count += 1

        if checksum_is_valid(candidate_indices):
            checksum_valid_count += 1
            candidate_result, comparisons = compare_candidate(
                candidate_indices,
                passphrase,
                target_address,
                standard,
            )
            address_comparison_count += comparisons

            if candidate_result is not None:
                candidate_result["error_count"] = error_count
                result = candidate_result
                break

        current_time = time.monotonic()

        if current_time - last_refresh_time >= REFRESH_INTERVAL:
            elapsed_seconds = current_time - start_time
            speed = checked_count / elapsed_seconds if elapsed_seconds else 0.0
            remaining_count = total_candidates - checked_count
            completion = checked_count * 100 / total_candidates
            eta = format_eta(remaining_count / speed) if speed else "calculating"

            progress = (
                f"Stage {error_count}-word | "
                f"Checked {checked_count:,}/{total_candidates:,} | "
                f"Left {remaining_count:,} | {completion:.8f}% | "
                f"Checksum {checksum_valid_count:,} | "
                f"Address tests {address_comparison_count:,} | "
                f"{speed:,.0f}/s | ETA {eta}"
            )

            line_width = max(previous_line_width, len(progress))
            sys.stdout.write("\r" + progress.ljust(line_width))
            sys.stdout.flush()
            previous_line_width = line_width
            last_refresh_time = current_time

    if previous_line_width:
        sys.stdout.write("\r" + (" " * previous_line_width) + "\r")
        sys.stdout.flush()

    elapsed_seconds = time.monotonic() - start_time
    speed = checked_count / elapsed_seconds if elapsed_seconds else 0.0
    remaining_count = total_candidates - checked_count
    completion = checked_count * 100 / total_candidates

    print("Detailed final report")
    print(f"Status: {'MATCH FOUND' if result else 'FULL SEARCH COMPLETED - NO MATCH'}")
    print(f"Last search stage: {current_error_count}-word replacement")
    print(f"Total candidates: {total_candidates:,}")
    print(f"Checked candidates: {checked_count:,}")
    print(f"Remaining candidates: {remaining_count:,}")
    print(f"Completion: {completion:.12f}%")
    print(f"Checksum-valid candidates: {checksum_valid_count:,}")
    print(f"Address comparisons: {address_comparison_count:,}")
    print(f"Elapsed seconds: {elapsed_seconds:,.3f}")
    print(f"Average candidate speed: {speed:,.3f}/second")

    if result:
        recovered_words = result["mnemonic"].split()
        changes = [
            (position + 1, input_words[position], recovered_words[position])
            for position in range(word_count)
            if input_words[position] != recovered_words[position]
        ]

        print("\nRecovered mnemonic:")
        print(result["mnemonic"])
        print(f"Corrected word count: {result['error_count']}")

        for position, old_word, new_word in changes:
            print(f"Position {position}: {old_word} -> {new_word}")

        print(f"Detected standard: {result['standard']}")
        print(f"Matched path: {result['path']}")
        print(f"Matched location: {result['location']}")
        print(f"Matched address: {result['address']}")
        print("Move funds to a newly generated wallet after recovery.")
    else:
        print("No candidate matched the supplied address.")
        print("Check the word order, passphrase, account number, and derivation path.")

    print(f"\nThe program will remain open for {HOLD_SECONDS} seconds.")
    print("Press Ctrl+C to close earlier.")

    try:
        time.sleep(HOLD_SECONDS)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSearch interrupted by user.")
    except Exception as error:
        print(f"\nFatal error: {type(error).__name__}: {error}")
        print(f"The program will remain open for {HOLD_SECONDS} seconds.")

        try:
            time.sleep(HOLD_SECONDS)
        except KeyboardInterrupt:
            pass
