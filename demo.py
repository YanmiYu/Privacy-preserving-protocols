"""
Demo script for Private Set-Membership Test Protocol

This script demonstrates the protocol with various test cases.
"""

from private_set_membership import run_protocol


def print_test_result(test_name: str, query: int, dataset: list, expected: bool):
    """Run a test case and print the results."""
    print(f"\n{'='*60}")
    print(f"Test: {test_name}")
    print(f"{'='*60}")
    print(f"Server dataset: {dataset}")
    print(f"Dataset size: {len(dataset)}")
    print(f"Client query: {query}")
    
    result, info = run_protocol(query, dataset)
    
    print(f"\nProtocol execution:")
    print(f"  - Polynomial degree: {info['polynomial_degree']}")
    print(f"  - Decrypted result: {info['decrypted_result']}")
    print(f"  - Protocol says: {'Member' if result else 'Not a member'}")
    print(f"  - Actually is member: {info['actual_membership']}")
    
    if result == info['actual_membership']:
        print(f"\n✓ Test PASSED: Protocol correctly identified membership")
    else:
        print(f"\n✗ Test FAILED: Protocol result does not match actual membership")
    
    return result == info['actual_membership']


def main():
    """Run all demo test cases."""
    print("="*60)
    print("Private Set-Membership Test Protocol - Demo")
    print("="*60)
    
    test_results = []
    
    # Test 1: Small set, query is member
    test_results.append(
        print_test_result(
            "Small set - Query IS a member",
            query=5,
            dataset=[1, 3, 5, 7, 9],
            expected=True
        )
    )
    
    # Test 2: Small set, query is not member
    test_results.append(
        print_test_result(
            "Small set - Query is NOT a member",
            query=4,
            dataset=[1, 3, 5, 7, 9],
            expected=False
        )
    )
    
    # Test 3: Medium set
    test_results.append(
        print_test_result(
            "Medium set - Query is member",
            query=15,
            dataset=list(range(10, 21)),
            expected=True
        )
    )
    
    # Test 4: Larger set
    test_results.append(
        print_test_result(
            "Larger set - Query is member",
            query=50,
            dataset=list(range(1, 101)),
            expected=True
        )
    )
    
    # Test 5: Query not in larger set
    test_results.append(
        print_test_result(
            "Larger set - Query is NOT a member",
            query=150,
            dataset=list(range(1, 101)),
            expected=False
        )
    )
    
    # Test 6: Single element set
    test_results.append(
        print_test_result(
            "Single element set - Query is member",
            query=42,
            dataset=[42],
            expected=True
        )
    )
    
    # Test 7: Single element set - not member
    test_results.append(
        print_test_result(
            "Single element set - Query is NOT a member",
            query=43,
            dataset=[42],
            expected=False
        )
    )
    
    # Summary
    print(f"\n{'='*60}")
    print("Summary")
    print(f"{'='*60}")
    passed = sum(test_results)
    total = len(test_results)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed!")
    else:
        print(f"✗ {total - passed} test(s) failed")


if __name__ == "__main__":
    main()

