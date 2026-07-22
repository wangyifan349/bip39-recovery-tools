#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
用于恢复本人 Bitcoin 钱包的离线工具：BIP39 助记词顺序正确，但可能有 0、1 或 2 个词错误。

功能：
- 仅使用交互式输入，不通过命令行参数传递助记词或地址。
- 支持空格、英文逗号或中文逗号分隔助记词。
- 支持 12 或 24 个英文 BIP39 单词。
- 文件内嵌标准英文 BIP39 2048 词表。
- 在生成候选前拒绝结构明显不合理的输入。
- 在生成种子和派生地址前先执行 BIP39 checksum。
- 使用一个已知 Bitcoin 地址验证候选结果。
- 不主动把结果、日志、断点或助记词数据写入磁盘。
- 实时显示总量、已检查、剩余量、完成度、速度和预计时间。
- 输出准确运行计数，并在结束后保持窗口 9999 秒。

所需依赖：
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

sys.dont_write_bytecode = True                                      # 不创建 .pyc 字节码缓存文件。

from bip_utils import (                                             # 标准 BIP39/BIP32 钱包派生库。
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
""".split()                                                        # 内嵌标准英文 BIP39 词表。

WORD_TO_INDEX = {word: index for index, word in enumerate(BIP39_WORDS)}


# ============================== 配置区 ==============================

REFRESH_INTERVAL = 0.75                                             # 只刷新一行进度，不反复刷屏。
HOLD_SECONDS = 9999                                                 # 完成后保持终端窗口可见。
SUPPORTED_WORD_COUNTS = (12, 24)
MAX_WRONG_WORDS = 2

SCAN_LOCATIONS = (
    (Bip44Changes.CHAIN_EXT, 0, 0, "外部地址 0"),
    (Bip44Changes.CHAIN_EXT, 0, 1, "外部地址 1"),
    (Bip44Changes.CHAIN_INT, 1, 0, "内部地址 0"),
    (Bip44Changes.CHAIN_INT, 1, 1, "内部地址 1"),
)


# ============================== 输入校验与恢复 ==============================

def analyze_input_words(words: list[str]) -> tuple[bool, list[int], str]:
    """检查输入是否适合进行一个词或两个词修复。"""
    if len(words) not in SUPPORTED_WORD_COUNTS:
        return False, [], f"应输入 12 或 24 个词，实际收到 {len(words)}."

    malformed_positions = [
        position
        for position, word in enumerate(words)
        if not re.fullmatch(r"[a-z]+", word)
    ]

    if malformed_positions:
        displayed = ", ".join(str(position + 1) for position in malformed_positions)
        return False, [], f"以下助记词位置包含非英文字母：{displayed}."

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
            f"超过两个词不在 BIP39 词表中，位置：{displayed}.",
        )

    return True, unknown_positions, ""


def checksum_is_valid(word_indices: list[int]) -> bool:
    """在昂贵的种子和地址派生前拒绝无效 BIP39 候选。"""
    checksum_bit_count = len(word_indices) // 3
    entropy_bit_count = len(word_indices) * 11 - checksum_bit_count
    combined_value = 0

    for word_index in word_indices:
        if word_index < 0 or word_index >= 2048:
            return False                                             # 候选词不是有效的 BIP39 索引。
        combined_value = (combined_value << 11) | word_index

    checksum_mask = (1 << checksum_bit_count) - 1
    actual_checksum = combined_value & checksum_mask
    entropy_value = combined_value >> checksum_bit_count
    entropy_bytes = entropy_value.to_bytes(entropy_bit_count // 8, "big")
    expected_checksum = hashlib.sha256(entropy_bytes).digest()[0] >> (8 - checksum_bit_count)

    return actual_checksum == expected_checksum


def select_wallet_standard(target_address: str) -> dict:
    """根据地址前缀选择标准，避免派生无关钱包类型。"""
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
        raise ValueError("本版本不支持测试网地址。")

    raise ValueError("不支持的 Bitcoin 主网地址前缀。")


def compare_candidate(
    word_indices: list[int],
    passphrase: str,
    target_address: str,
    standard: dict,
) -> tuple[dict | None, int]:
    """把一个 checksum 有效助记词与四条已配置路径进行比较。"""
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
    """保持进度行简短。"""
    if seconds <= 0:
        return "计算中"
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
    """依次生成原始候选、一个词修复和两个词修复候选。"""
    candidate = [index if index is not None else 0 for index in base_indices]

    if all(index is not None for index in base_indices):
        yield 0, candidate                                             # 先检查用户原始输入的助记词。

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


# ============================== 主程序 ==============================

def main() -> None:
    previous_line_width = 0

    print("离线 BIP39 错词恢复——仅支持 Bitcoin 主网")
    print("本模式假设助记词顺序正确，但可能有 0、1 或 2 个词错误。")
    print("程序不会主动写入磁盘，助记词和 passphrase 输入会显示在屏幕上。\n")

    raw_words = input("请按当前顺序输入 12 或 24 个 BIP39 单词：")
    normalized_input = unicodedata.normalize("NFKD", raw_words).strip().lower()
    input_words = [word for word in re.split(r"[\s,，]+", normalized_input) if word]

    reasonable, unknown_positions, reason = analyze_input_words(input_words)

    if not reasonable:
        raise ValueError(reason)                                      # 在继续询问或派生任何内容前停止。

    if unknown_positions:
        displayed_positions = ", ".join(str(position + 1) for position in unknown_positions)
        print(f"检测到不在 BIP39 词表中的位置：{displayed_positions}")
        print("搜索将强制替换这些位置。")
    else:
        print("输入的所有词都在 BIP39 词表中，错误位置未知。")

    passphrase = unicodedata.normalize(
        "NFKD",
        input("请输入可选 BIP39 passphrase（没有则直接回车）："),
    )
    target_address = input("请输入一个已知的 Bitcoin 主网地址：").strip()
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

    print("\n搜索配置")
    print(f"助记词数量：{word_count} | 已选择地址标准：{standard['name']}")
    print(f"原始候选：{original_total:,}")
    print(f"一个词替换候选：{one_word_total:,}")
    print(f"两个词替换候选：{two_word_total:,}")
    print(f"准确候选总数：{total_candidates:,}")
    print(f"预计 checksum 有效候选约：{expected_checksum_valid:,.0f}")
    print(f"每个 checksum 有效候选检查的地址路径数：{len(SCAN_LOCATIONS)}")
    print("路径：外部地址 0、外部地址 1、内部地址 0、内部地址 1\n")

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
            eta = format_eta(remaining_count / speed) if speed else "计算中"

            progress = (
                f"阶段 {error_count} 个错词 | "
                f"已检查 {checked_count:,}/{total_candidates:,} | "
                f"剩余 {remaining_count:,} | {completion:.8f}% | "
                f"checksum有效 {checksum_valid_count:,} | "
                f"地址对比 {address_comparison_count:,} | "
                f"{speed:,.0f}/秒 | 预计剩余 {eta}"
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

    print("详细最终报告")
    print(f"状态：{'已找到匹配' if result else '已完成全部搜索——未找到匹配'}")
    print(f"最后搜索阶段：{current_error_count} 个词替换")
    print(f"候选总数：{total_candidates:,}")
    print(f"已检查候选：{checked_count:,}")
    print(f"剩余候选：{remaining_count:,}")
    print(f"完成度：{completion:.12f}%")
    print(f"checksum 有效候选：{checksum_valid_count:,}")
    print(f"地址对比次数：{address_comparison_count:,}")
    print(f"耗时秒数：{elapsed_seconds:,.3f}")
    print(f"平均候选速度：{speed:,.3f}/秒")

    if result:
        recovered_words = result["mnemonic"].split()
        changes = [
            (position + 1, input_words[position], recovered_words[position])
            for position in range(word_count)
            if input_words[position] != recovered_words[position]
        ]

        print("\n恢复出的助记词：")
        print(result["mnemonic"])
        print(f"纠正的单词数量：{result['error_count']}")

        for position, old_word, new_word in changes:
            print(f"位置 {position}: {old_word} -> {new_word}")

        print(f"检测到的标准：{result['standard']}")
        print(f"匹配的派生路径：{result['path']}")
        print(f"匹配的位置：{result['location']}")
        print(f"匹配的地址：{result['address']}")
        print("恢复后请把资产转移到全新生成的钱包。")
    else:
        print("没有候选匹配所提供的地址。")
        print("请检查单词顺序、passphrase、account 编号和派生路径。")

    print(f"\n程序将在结束后保持打开 {HOLD_SECONDS} 秒。")
    print("可按 Ctrl+C 提前关闭。")

    try:
        time.sleep(HOLD_SECONDS)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断了搜索。")
    except Exception as error:
        print(f"\n严重错误：{type(error).__name__}: {error}")
        print(f"程序将在结束后保持打开 {HOLD_SECONDS} 秒。")

        try:
            time.sleep(HOLD_SECONDS)
        except KeyboardInterrupt:
            pass
