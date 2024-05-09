
import random

uppercase_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
lowercase_letters = uppercase_letters.lower()
digits = "0123456789"
all_symbols = "()[],.:=@#%&+-/?*"

upper, lower, nums, sym = True, False, True, False

all = ""

if upper:
    all += uppercase_letters
if lower:
    all  += lowercase_letters
if  nums:
    all += digits
if sym:
    all += all_symbols

length = 20
amount = 10

for x in range(amount):
    password = "".join(random.sample(all, length))
    print(password)