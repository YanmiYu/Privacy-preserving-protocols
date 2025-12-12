# Private Set-Membership Test Protocol

A Python implementation of the Private Set-Membership Test protocol using Paillier homomorphic encryption. This protocol allows a client to check if a private query is contained in a server's dataset without revealing the query to the server or learning the server's dataset elements.

## Overview

The protocol allows a client to check if a private query `c` is contained in a server's dataset `S = {s1, s2, ..., sn}` without:
- The server learning the client's query `c`
- The client learning any elements of `S` (except the membership result)

## Protocol Description

1. **Offline Phase (Server)**: The server pre-computes polynomial coefficients from its dataset `S`:
   - Constructs polynomial `PS(x) = (x-s1)(x-s2)...(x-sn)` in standard form
   - Expands to `PS(x) = a_n*x^n + a_{n-1}*x^{n-1} + ... + a_1*x + a_0`

2. **Online Phase**:
   - **Client**: Generates Paillier key pair `(pk, sk)`, encrypts query `c` and its powers `c, c^2, ..., c^n`, sends `pk` and encrypted powers to server
   - **Server**: Homomorphically evaluates `PS(c)` using only addition and scalar multiplication:
     - Computes `Epk(a_k * c^k)` for each term using homomorphic scalar multiplication
     - Aggregates terms using homomorphic addition: `Epk(PS(c))`
     - Blinds result with random factor `r`: `R = Epk(r * PS(c))`
     - Returns `R` to client
   - **Client**: Decrypts `R`; if result is 0, concludes `c ∈ S`, otherwise `c ∉ S`

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```python
from private_set_membership import run_protocol

# Server's private dataset
server_dataset = [5, 10, 15, 20, 25]

# Client's private query
client_query = 15

# Run protocol
is_member, info = run_protocol(client_query, server_dataset)

print(f"Query {client_query} is {'in' if is_member else 'not in'} the dataset")
```

### Using Classes Directly

```python
from private_set_membership import Client, Server

# Initialize
client = Client()
server = Server([5, 10, 15, 20, 25])

# Client generates keys
public_key = client.generate_keys()

# Client encrypts query
encrypted_powers = client.encrypt_query(15, server.n)

# Server evaluates polynomial
encrypted_result = server.evaluate_polynomial_homomorphic(
    public_key, encrypted_powers
)

# Server blinds result
blinded_result = server.blind_and_return(encrypted_result)

# Client decrypts and checks
decrypted = client.decrypt_result(blinded_result)
is_member = client.check_membership(decrypted)
```

### Running Demo

```bash
python demo.py
```

Or run the built-in demo:

```bash
python private_set_membership.py
```

## Files

- `private_set_membership.py`: Main implementation with `Client` and `Server` classes
- `demo.py`: Demo script with various test cases
- `requirements.txt`: Python dependencies

## Security Notes

- The implementation uses Paillier encryption which provides semantic security (IND-CPA)
- The blinding factor prevents the client from learning `PS(c)` when `c ∉ S`
- The protocol is secure against honest-but-curious adversaries
- Note: Large values of `c` or `n` may cause integer overflow when computing powers. For production use, consider using modular arithmetic or bignum libraries.

## Dependencies

- `phe`: Python Paillier Homomorphic Encryption library
- `numpy`: Used internally by `phe` for mathematical operations

## Limitations

- Integer values only (no floating point support)
- Performance degrades with large datasets (polynomial degree)
- Set size `n` is revealed to the client (can be masked with padding)

## References

- Paillier, P. (1999). Public-key cryptosystems based on composite degree residuosity classes.
- The protocol is based on polynomial evaluation with homomorphic encryption as described in the assignment.

## GitHub Repository

[Link to your public GitHub repository](https://github.com/yourusername/your-repo)

