# ============================
# Part 2: Code Obfuscation Challenge
# ============================

# ---------- Original Code ----------
def fibonacci(n):
    """Original Fibonacci function using recursion"""
    if n <= 1:
        return n
    else:
        return fibonacci(n-1) + fibonacci(n-2)

print("Original Fibonacci (n=5):", fibonacci(5))


# ---------- Manually Obfuscated Code ----------
def x(a):
    """Manually obfuscated version: variables and function names changed"""
    if a <= 1:
        return a
    else:
        return x(a-1) + x(a-2)

print("Manually Obfuscated Fibonacci (n=5):", x(5))


# ---------- Automatically Obfuscated Simulation ----------
# Simulating automatic obfuscation by minifying and renaming
# (Typically done using tools like pyminifier or online services)

def q(_):return _ if _<=1 else q(_-1)+q(_-2)

print("Auto-Obfuscated Simulation (n=5):", q(5))


# ---------- Explanation ----------
"""
Manual Obfuscation:
- Function name changed from 'fibonacci' to 'x'
- Parameter name 'n' changed to 'a'
- Preserves logic but hides meaning

Automatic Obfuscation (Simulated):
- Function renamed to 'q'
- Parameter renamed to '_'
- Entire logic compressed to a single line

Purpose:
- Obfuscation protects code from reverse engineering.
- Manual obfuscation reduces readability by changing identifiers.
- Automatic tools also reduce formatting, spacing, and naming clarity.
"""
