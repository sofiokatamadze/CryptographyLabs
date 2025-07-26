import random

def simulate_zkp(trials=20, knows_password=True):
    success_count = 0
    for _ in range(trials):
        path_entered = random.choice(['A', 'B'])
        challenge = random.choice(['A', 'B'])

        if knows_password:
            # Honest prover always succeeds
            success = True
        else:
            # Malicious prover succeeds only by guessing correctly
            success = path_entered == challenge

        if success:
            success_count += 1

    probability = success_count / trials
    print(f"Successful responses: {success_count}/{trials} "
          f"({probability*100:.2f}% success rate)")

# Honest prover
print("Honest Prover (knows password):")
simulate_zkp(trials=20, knows_password=True)

# Malicious prover
print("\nMalicious Prover (does NOT know password):")
simulate_zkp(trials=20, knows_password=False)