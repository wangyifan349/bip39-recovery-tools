#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
用于恢复本人 Bitcoin 钱包的离线 BIP39 助记词顺序工具。

功能：
- 仅使用交互式输入，不通过命令行参数传递助记词或地址。
- 支持空格、英文逗号或中文逗号分隔助记词。
- 支持 12、18、24 个英文 BIP39 单词。
- 文件内嵌标准英文 BIP39 2048 词表。
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

REFRESH_INTERVAL = 0.75                                             # 进度刷新间隔，单位为秒。
HOLD_SECONDS = 9999                                                 # 程序结束后保持终端窗口打开。
SUPPORTED_WORD_COUNTS = (12, 18, 24)

WALLET_STANDARDS = (
    {
        "name": "BIP44",
        "purpose": 44,
        "wallet_class": Bip44,
        "coin": Bip44Coins.BITCOIN,
    },
    {
        "name": "BIP49",
        "purpose": 49,
        "wallet_class": Bip49,
        "coin": Bip49Coins.BITCOIN,
    },
    {
        "name": "BIP84",
        "purpose": 84,
        "wallet_class": Bip84,
        "coin": Bip84Coins.BITCOIN,
    },
    {
        "name": "BIP86",
        "purpose": 86,
        "wallet_class": Bip86,
        "coin": Bip86Coins.BITCOIN,
    },
)

SCAN_LOCATIONS = (
    {
        "change_type": Bip44Changes.CHAIN_EXT,
        "change_index": 0,
        "address_index": 0,
        "description": "外部地址 0",
    },
    {
        "change_type": Bip44Changes.CHAIN_EXT,
        "change_index": 0,
        "address_index": 1,
        "description": "外部地址 1",
    },
    {
        "change_type": Bip44Changes.CHAIN_INT,
        "change_index": 1,
        "address_index": 0,
        "description": "内部地址 0",
    },
    {
        "change_type": Bip44Changes.CHAIN_INT,
        "change_index": 1,
        "address_index": 1,
        "description": "内部地址 1",
    },
)


# ============================== 核心算法 ==============================

def checksum_is_valid(word_indices: list[int]) -> bool:
    """当 12/18/24 词候选具有有效 BIP39 checksum 时返回 True。"""
    checksum_bit_count = len(word_indices) // 3
    entropy_bit_count = len(word_indices) * 11 - checksum_bit_count
    combined_bits = 0

    for word_index in word_indices:
        combined_bits = (combined_bits << 11) | word_index

    checksum_mask = (1 << checksum_bit_count) - 1
    actual_checksum = combined_bits & checksum_mask
    entropy_value = combined_bits >> checksum_bit_count
    entropy_bytes = entropy_value.to_bytes(entropy_bit_count // 8, "big")
    expected_checksum = hashlib.sha256(entropy_bytes).digest()[0] >> (8 - checksum_bit_count)

    return actual_checksum == expected_checksum


def next_permutation(values: list[int]) -> bool:
    """把列表修改为下一个不重复的字典序排列。"""
    pivot = len(values) - 2

    while pivot >= 0 and values[pivot] >= values[pivot + 1]:
        pivot -= 1

    if pivot < 0:
        return False

    successor = len(values) - 1

    while values[successor] <= values[pivot]:
        successor -= 1

    values[pivot], values[successor] = values[successor], values[pivot]
    values[pivot + 1:] = reversed(values[pivot + 1:])

    return True


def format_eta(seconds: float) -> str:
    """把预计剩余时间格式化为简短文本。"""
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


def check_candidate(mnemonic: str, passphrase: str, target_address: str):
    """为一个助记词派生并比较全部已配置的主网地址。"""
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    target_for_compare = target_address.lower() if target_address.lower().startswith("bc1") else target_address
    comparison_count = 0

    for standard in WALLET_STANDARDS:
        wallet = standard["wallet_class"].FromSeed(seed, standard["coin"])
        account = wallet.Purpose().Coin().Account(0)

        for location in SCAN_LOCATIONS:
            generated_address = (
                account
                .Change(location["change_type"])
                .AddressIndex(location["address_index"])
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
                path = (
                    f"m/{standard['purpose']}'/0'/0'/"
                    f"{location['change_index']}/{location['address_index']}"
                )

                return {
                    "mnemonic": mnemonic,
                    "standard": standard["name"],
                    "path": path,
                    "address": generated_address,
                    "comparisons": comparison_count,
                }

    return {
        "mnemonic": None,
        "standard": None,
        "path": None,
        "address": None,
        "comparisons": comparison_count,
    }


# ============================== 主程序 ==============================

def main() -> None:
    previous_line_width = 0

    print("离线 BIP39 助记词顺序恢复——仅支持 Bitcoin 主网")
    print("仅用于恢复你本人拥有或已获得明确授权的钱包。")
    print("程序不会主动写入磁盘，进度会在终端同一行刷新。")
    print("警告：助记词和 passphrase 输入会显示在屏幕上。\n")

    raw_words = input("请输入顺序混乱的 BIP39 助记词（空格或逗号分隔）：")
    normalized_input = unicodedata.normalize("NFKD", raw_words).strip().lower()
    words = [word for word in re.split(r"[\s,，]+", normalized_input) if word]

    if len(words) not in SUPPORTED_WORD_COUNTS:
        allowed_counts = ", ".join(str(count) for count in SUPPORTED_WORD_COUNTS)
        raise ValueError(
            f"应输入 {allowed_counts} 个词，实际收到 {len(words)} 个。"
        )

    unknown_words = sorted({word for word in words if word not in WORD_TO_INDEX})

    if unknown_words:
        raise ValueError(
            "以下单词不在内嵌英文 BIP39 词表中："
            + ", ".join(unknown_words)
        )

    passphrase = unicodedata.normalize(
        "NFKD",
        input("请输入可选 BIP39 passphrase（没有则直接回车）："),
    )

    target_address = input("请输入一个已知的 Bitcoin 主网地址：").strip()
    target_lower = target_address.lower()

    if target_address.startswith(("m", "n", "2")) or target_lower.startswith("tb1"):
        raise ValueError("本版本不支持测试网地址。")

    if not (
        target_address.startswith(("1", "3"))
        or target_lower.startswith("bc1")
    ):
        raise ValueError("不支持的 Bitcoin 主网地址前缀。")

    word_indices = sorted(WORD_TO_INDEX[word] for word in words)

    total_permutations = math.factorial(len(word_indices))

    for repeated_count in Counter(word_indices).values():
        total_permutations //= math.factorial(repeated_count)

    checksum_bit_count = len(word_indices) // 3
    estimated_valid_candidates = total_permutations / (1 << checksum_bit_count)
    comparisons_per_valid_candidate = len(WALLET_STANDARDS) * len(SCAN_LOCATIONS)

    print("\n搜索配置")
    print(f"助记词数量：{len(word_indices)}")
    print(f"不重复排列总数：{total_permutations:,}")
    print(f"预计 checksum 有效候选数：{estimated_valid_candidates:,.0f}")
    print(f"每个有效候选检查的地址路径数：{comparisons_per_valid_candidate}")
    print("标准：BIP44、BIP49、BIP84、BIP86")
    print("位置：外部地址 0、外部地址 1、内部地址 0、内部地址 1\n")

    checked_count = 0
    valid_checksum_count = 0
    address_comparison_count = 0
    result = None

    start_time = time.monotonic()
    last_refresh_time = start_time

    while True:
        checked_count += 1

        if checksum_is_valid(word_indices):
            valid_checksum_count += 1
            mnemonic = " ".join(BIP39_WORDS[index] for index in word_indices)
            candidate_result = check_candidate(mnemonic, passphrase, target_address)
            address_comparison_count += candidate_result["comparisons"]

            if candidate_result["mnemonic"] is not None:
                result = candidate_result
                break

        current_time = time.monotonic()

        if current_time - last_refresh_time >= REFRESH_INTERVAL:
            elapsed_seconds = current_time - start_time
            speed = checked_count / elapsed_seconds if elapsed_seconds else 0.0
            remaining_count = total_permutations - checked_count
            completion_percent = checked_count * 100 / total_permutations
            eta = format_eta(remaining_count / speed) if speed else "计算中"

            progress_text = (
                f"已检查 {checked_count:,}/{total_permutations:,} | "
                f"剩余 {remaining_count:,} | "
                f"{completion_percent:.8f}% | "
                f"checksum有效 {valid_checksum_count:,} | "
                f"地址对比 {address_comparison_count:,} | "
                f"{speed:,.0f}/秒 | 预计剩余 {eta}"
            )

            line_width = max(previous_line_width, len(progress_text))
            sys.stdout.write("\r" + progress_text.ljust(line_width))
            sys.stdout.flush()

            previous_line_width = line_width
            last_refresh_time = current_time

        if not next_permutation(word_indices):
            break

    if previous_line_width:
        sys.stdout.write("\r" + (" " * previous_line_width) + "\r")
        sys.stdout.flush()

    elapsed_seconds = time.monotonic() - start_time
    speed = checked_count / elapsed_seconds if elapsed_seconds else 0.0
    remaining_count = total_permutations - checked_count
    completion_percent = checked_count * 100 / total_permutations

    print("详细最终报告")
    print(f"状态：{'已找到匹配' if result else '已完成全部搜索——未找到匹配'}")
    print(f"排列总数：{total_permutations:,}")
    print(f"已检查 permutations: {checked_count:,}")
    print(f"剩余排列：{remaining_count:,}")
    print(f"完成度：{completion_percent:.12f}%")
    print(f"checksum 有效候选：{valid_checksum_count:,}")
    print(f"地址对比次数：{address_comparison_count:,}")
    print(f"耗时秒数：{elapsed_seconds:,.3f}")
    print(f"平均速度：{speed:,.3f} 个排列/秒")

    if result:
        print("\n恢复出的助记词：")
        print(result["mnemonic"])
        print(f"检测到的标准：{result['standard']}")
        print(f"匹配的派生路径：{result['path']}")
        print(f"匹配的地址：{result['address']}")
        print("恢复后请把资产转移到全新生成的钱包。")
    else:
        print("没有候选匹配已配置的 16 条主网路径。")
        print("请检查 passphrase、地址、account 编号或派生路径。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断了搜索。")
    except Exception as error:
        print(f"\n严重错误：{type(error).__name__}: {error}")

    print(f"\n程序将在结束后保持打开 {HOLD_SECONDS} 秒。")
    print("可按 Ctrl+C 提前关闭。")

    try:
        time.sleep(HOLD_SECONDS)
    except KeyboardInterrupt:
        pass
