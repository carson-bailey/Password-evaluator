# Password-evaluator
# Password Entropy Evaluator

A small, dependency-free web tool that scores a password by its **entropy** — how much randomness it actually contains — rather than just checking a few arbitrary rules like "has a number." It also estimates how long the password would realistically survive against a few different kinds of attacks.

Try it live: open `index.html` in a browser, or host it with GitHub Pages (see below).

## How it works

1. **Character pool.** The tool looks at which character classes are present — lowercase, uppercase, digits, symbols, or extended/unicode characters — and adds up the pool size (e.g. lowercase + digits = 36 possible characters per position).
2. **Raw entropy.** Entropy in bits is calculated as:

   ```
   bits = length × log2(pool size)
   ```

   This is the standard way to estimate how many attempts, in the worst case, a brute-force attacker would need.
3. **Pattern penalties.** Raw entropy overstates real-world strength, because humans don't pick characters randomly. The tool subtracts bits for:
   - Matching a list of extremely common passwords
   - Sequential runs (`abcd`, `4321`)
   - Keyboard-adjacent sequences (`qwerty`, `asdf`)
   - Repeated characters (`aaa`, `111`)
   - Repeated short blocks (`abcabcabc`)
4. **Crack-time estimates.** The adjusted entropy is converted into an estimated number of guesses (half the keyspace, the average case) and divided by four illustrative guessing rates: a rate-limited online login, an unthrottled online login, an offline attack against a slow hash like bcrypt, and an offline attack against a fast hash on GPU hardware.

Nothing is sent anywhere — all of this runs client-side in `script.js`.

## Rating scale

| Entropy (adjusted) | Rating      |
|---------------------|-------------|
| < 28 bits           | Very weak   |
| 28–35 bits          | Weak        |
| 36–59 bits          | Fair        |
| 60–79 bits          | Strong      |
| ≥ 80 bits           | Very strong |

