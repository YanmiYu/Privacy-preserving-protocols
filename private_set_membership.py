"""
Private Set-Membership Test Protocol Implementation

This module implements a privacy-preserving protocol for checking set membership
using additively homomorphic encryption (Paillier cryptosystem).

The protocol allows a client to check if a private query c is contained in a
server's dataset S without revealing c to the server or learning any elements
of S (except the membership result).
"""

import random
from typing import List, Tuple
from phe import paillier


class Client:
    """
    Client side of the Private Set-Membership Test protocol.
    
    The client wants to check if its private query c is in the server's set S
    without revealing c to the server.
    """
    
    def __init__(self):
        """Initialize the client with no keys (keys generated during protocol)."""
        self.public_key = None
        self.private_key = None
    
    def generate_keys(self, key_length: int = 1024) -> paillier.PaillierPublicKey:
        """
        Generate a key pair for Paillier encryption.
        
        Args:
            key_length: Bit length of the key (default: 1024)
            
        Returns:
            The public key to be sent to the server
        """
        self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=key_length)
        return self.public_key
    
    def encrypt_query(self, c: int, n: int) -> List[paillier.EncryptedNumber]:
        """
        Encrypt the query c and all necessary powers c^k for k in [1, n].
        
        Args:
            c: The private query value
            n: The degree of the polynomial (size of server's set)
            
        Returns:
            List of encrypted values [Epk(c), Epk(c^2), ..., Epk(c^n)]
        """
        if self.public_key is None:
            raise ValueError("Keys must be generated first. Call generate_keys()")
        
        encrypted_powers = []
        current_power = 1
        
        for k in range(1, n + 1):
            current_power = current_power * c  # Compute c^k
            encrypted_powers.append(self.public_key.encrypt(current_power))
        
        return encrypted_powers
    
    def decrypt_result(self, encrypted_result: paillier.EncryptedNumber) -> int:
        """
        Decrypt the result from the server.
        
        Args:
            encrypted_result: The blinded encrypted result from the server
            
        Returns:
            The decrypted integer value
        """
        if self.private_key is None:
            raise ValueError("Private key not available")
        
        return self.private_key.decrypt(encrypted_result)
    
    def check_membership(self, decrypted_result: int) -> bool:
        """
        Check if the query c is in the server's set based on decrypted result.
        
        Args:
            decrypted_result: The decrypted value from the server
            
        Returns:
            True if c ∈ S (result is 0), False otherwise
        """
        return decrypted_result == 0


class Server:
    """
    Server side of the Private Set-Membership Test protocol.
    
    The server holds a private dataset S and can check membership queries
    without learning the client's query or revealing elements of S.
    """
    
    def __init__(self, dataset: List[int]):
        """
        Initialize the server with a dataset.
        
        Args:
            dataset: The server's private set S = {s1, s2, ..., sn}
        """
        self.dataset = list(set(dataset))  # Remove duplicates and convert to list
        self.n = len(self.dataset)
        self.coefficients = self._compute_polynomial_coefficients()
    
    def _compute_polynomial_coefficients(self) -> List[int]:
        """
        Compute the coefficients of the polynomial PS(x) = (x-s1)(x-s2)...(x-sn)
        in standard form: PS(x) = a_n*x^n + a_{n-1}*x^{n-1} + ... + a_1*x + a_0
        
        Uses Vieta's formulas to compute coefficients from roots.
        
        Returns:
            List of coefficients [a_n, a_{n-1}, ..., a_1, a_0]
            where a_n = 1 (leading coefficient)
        """
        if self.n == 0:
            return [1]  # Empty polynomial: PS(x) = 1
        
        # Initialize coefficients: start with polynomial (x - s1)
        # For (x - s1), coefficients are [1, -s1]
        coeffs = [1, -self.dataset[0]]
        
        # Multiply by (x - s_i) for each remaining element
        for s_i in self.dataset[1:]:
            # Multiply current polynomial by (x - s_i)
            # If current poly is a_n*x^n + ... + a_0, then
            # (a_n*x^n + ... + a_0) * (x - s_i) = a_n*x^{n+1} + ... + (a_0)*(-s_i)
            new_coeffs = [0] * (len(coeffs) + 1)
            
            # Multiply by x: shift coefficients
            for i in range(len(coeffs)):
                new_coeffs[i] = coeffs[i]
            
            # Multiply by -s_i: scale and add
            for i in range(len(coeffs)):
                new_coeffs[i + 1] += coeffs[i] * (-s_i)
            
            coeffs = new_coeffs
        
        return coeffs
    
    def evaluate_polynomial_homomorphic(
        self,
        public_key: paillier.PaillierPublicKey,
        encrypted_powers: List[paillier.EncryptedNumber]
    ) -> paillier.EncryptedNumber:
        """
        Evaluate PS(c) homomorphically using encrypted powers of c.
        
        Computes Epk(PS(c)) = Epk(a_n*c^n + a_{n-1}*c^{n-1} + ... + a_1*c + a_0)
        
        Args:
            public_key: The client's public key
            encrypted_powers: List [Epk(c), Epk(c^2), ..., Epk(c^n)]
            
        Returns:
            Encrypted result Epk(PS(c))
        """
        if len(encrypted_powers) != self.n:
            raise ValueError(
                f"Expected {self.n} encrypted powers, got {len(encrypted_powers)}"
            )
        
        # Start with the constant term a_0
        # Epk(a_0) = encrypt a_0 directly
        result = public_key.encrypt(self.coefficients[-1])
        
        # Add each term a_k * c^k for k from 1 to n
        # Epk(a_k * c^k) = (Epk(c^k))^a_k (homomorphic scalar multiplication)
        for k in range(1, self.n + 1):
            coeff_index = self.n - k  # a_n is at index 0, a_1 is at index n-1
            a_k = self.coefficients[coeff_index]
            
            if a_k != 0:
                # Compute Epk(a_k * c^k) = (Epk(c^k))^a_k
                encrypted_term = encrypted_powers[k - 1] * a_k
                # Add to result: Epk(result + a_k*c^k)
                result = result + encrypted_term
        
        return result
    
    def blind_and_return(
        self,
        encrypted_result: paillier.EncryptedNumber,
        max_blinding_factor: int = 1000
    ) -> paillier.EncryptedNumber:
        """
        Blind the encrypted result with a random non-zero factor.
        
        Computes R = Epk(r * PS(c)) where r is a random non-zero integer.
        This prevents the client from learning PS(c) when c ∉ S.
        
        Args:
            encrypted_result: Epk(PS(c))
            max_blinding_factor: Maximum value for the random blinding factor
            
        Returns:
            Blinded encrypted result Epk(r * PS(c))
        """
        # Generate random non-zero blinding factor
        r = random.randint(1, max_blinding_factor)
        
        # Compute Epk(r * PS(c)) = (Epk(PS(c)))^r
        blinded_result = encrypted_result * r
        
        return blinded_result


def run_protocol(
    client_query: int,
    server_dataset: List[int],
    key_length: int = 1024
) -> Tuple[bool, dict]:
    """
    Run the complete Private Set-Membership Test protocol.
    
    Args:
        client_query: The client's private query c
        server_dataset: The server's private dataset S
        key_length: Bit length for Paillier keys
        
    Returns:
        Tuple of (membership_result, protocol_info)
        where protocol_info contains details about the protocol execution
    """
    # Initialize parties
    client = Client()
    server = Server(server_dataset)
    
    # Step 1: Client generates keys
    public_key = client.generate_keys(key_length)
    
    # Step 2: Client encrypts query and powers
    encrypted_powers = client.encrypt_query(client_query, server.n)
    
    # Step 3: Server evaluates polynomial homomorphically
    encrypted_polynomial_value = server.evaluate_polynomial_homomorphic(
        public_key, encrypted_powers
    )
    
    # Step 4: Server blinds the result
    blinded_result = server.blind_and_return(encrypted_polynomial_value)
    
    # Step 5: Client decrypts and checks membership
    decrypted_result = client.decrypt_result(blinded_result)
    is_member = client.check_membership(decrypted_result)
    
    protocol_info = {
        'query': client_query,
        'dataset_size': len(server_dataset),
        'polynomial_degree': server.n,
        'coefficients': server.coefficients,
        'decrypted_result': decrypted_result,
        'is_member': is_member,
        'actual_membership': client_query in server_dataset
    }
    
    return is_member, protocol_info


if __name__ == "__main__":
    # Example usage
    print("Private Set-Membership Test Protocol Demo")
    print("=" * 50)
    
    # Test case 1: Query is in the set
    print("\nTest 1: Query is IN the set")
    server_set = [5, 10, 15, 20, 25]
    query = 15
    result, info = run_protocol(query, server_set)
    print(f"Server dataset: {server_set}")
    print(f"Client query: {query}")
    print(f"Protocol result: {'Member' if result else 'Not a member'}")
    print(f"Actual membership: {'Member' if info['actual_membership'] else 'Not a member'}")
    print(f"Decrypted result: {info['decrypted_result']}")
    print(f"✓ Correct!" if result == info['actual_membership'] else "✗ Incorrect!")
    
    # Test case 2: Query is NOT in the set
    print("\nTest 2: Query is NOT in the set")
    query = 30
    result, info = run_protocol(query, server_set)
    print(f"Server dataset: {server_set}")
    print(f"Client query: {query}")
    print(f"Protocol result: {'Member' if result else 'Not a member'}")
    print(f"Actual membership: {'Member' if info['actual_membership'] else 'Not a member'}")
    print(f"Decrypted result: {info['decrypted_result']} (blinded, non-zero)")
    print(f"✓ Correct!" if result == info['actual_membership'] else "✗ Incorrect!")
    
    # Test case 3: Larger set
    print("\nTest 3: Larger set")
    server_set = list(range(1, 21))  # [1, 2, ..., 20]
    query = 10
    result, info = run_protocol(query, server_set)
    print(f"Server dataset size: {len(server_set)}")
    print(f"Client query: {query}")
    print(f"Protocol result: {'Member' if result else 'Not a member'}")
    print(f"Actual membership: {'Member' if info['actual_membership'] else 'Not a member'}")
    print(f"✓ Correct!" if result == info['actual_membership'] else "✗ Incorrect!")

