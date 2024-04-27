from sage.all import *
import multiprocessing

# Define secp256k1 curve parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
E = EllipticCurve(GF(p), [a, b])

# Define base point and public key
G_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G = E.lift_x(G_x, all=True)[0]  # Extract the first element
pub_key_x = 0x2dfn234fjfxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
pub_key_y = 0x23r4fwd2dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
pub_key = E((pub_key_x, pub_key_y))

# Define parameters for index calculus attack
B = 2**16  # Smoothness bound
M = 2**20  # Maximum number of relations to collect
num_processes = multiprocessing.cpu_count()  # Number of CPU cores for parallel processing

# Define helper functions
def generate_smooth_numbers(B):
    smooth_numbers = []
    for i in range(2, B+1):
        if is_prime(i):
            smooth_numbers.append(i)
    return smooth_numbers

def generate_relations(pub_key, G, smooth_numbers, M):
    relations = []
    k = 0
    while len(relations) < M:
        k += 1
        Q = k * pub_key
        r = discrete_log(Q, G, operation='+')
        if r is not None and r > 0:
            r_factors = factor(r)
            if all(factor in smooth_numbers for factor in r_factors):
                relations.append((Q, r))
        if k % 10000 == 0:  # Print progress every 10000 iterations
            print(f"Generated {len(relations)} relations out of {M} ({(len(relations) / M)*100:.2f}% complete)")
    return relations

def solve_linear_systems(relations, smooth_numbers):
    A = matrix(GF(2), len(smooth_numbers), len(relations))
    b = vector(GF(2), len(smooth_numbers))
    for i, (Q, r) in enumerate(relations):
        for j, factor in enumerate(smooth_numbers):
            if r % factor == 0:
                A[j, i] = 1
                r //= factor
        b[i] = r
    x = A.block_wiedemann_solver(b)
    return x

# Main function to perform index calculus attack
def index_calculus_attack(pub_key, G, B, M, num_processes):
    print("Generating smooth numbers...")
    smooth_numbers = generate_smooth_numbers(B)
    print("Generating relations...")
    relations = generate_relations(pub_key, G, smooth_numbers, M)
    
    print("Starting parallel processing...")
    pool = multiprocessing.Pool(num_processes)
    chunk_size = len(relations) // num_processes
    results = []
    for i in range(num_processes):
        chunk = relations[i * chunk_size: (i + 1) * chunk_size]
        results.append(pool.apply_async(solve_linear_systems, args=(chunk, smooth_numbers)))
    pool.close()
    pool.join()
    
    print("Combining results...")
    x = vector(GF(2), len(smooth_numbers))
    for res in results:
        x += res.get()
    private_key = CRT(smooth_numbers)(x)
    return private_key

# Perform the advanced index calculus attack
print("Starting advanced index calculus attack...")
private_key = index_calculus_attack(pub_key, G, B, M, num_processes)
print("Private Key:", private_key)
