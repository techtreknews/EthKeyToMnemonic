from bip_utils import Bip39MnemonicGenerator

def eth_private_key_to_mnemonic(private_key_hex):
    # Remove the '0x' prefix if present
    if private_key_hex.startswith('0x'):
        private_key_hex = private_key_hex[2:]

    # Check if the private key hex is valid (should be 64 hex characters, which equals 256 bits)
    if len(private_key_hex) != 64 or not all (c in '0123456789abcdefABCDEF' for c in private_key_hex):
        raise ValueError("Invalid Ethereum private key format")
    
    # Convert hex private key to bytes
    private_key_hex = bytes.fromhex(private_key_hex)

    # Ensure we only use 128 bits (16 bytes) of entropy for a 12-word mnemonic
    entropy_bytes = private_key_hex[:16] # Using the first 128 bits of the private key

    # Create an instance of Bip39MnemonicGenerator
    mnemonic_generator = Bip39MnemonicGenerator()

    # Generate a mnemonic from the private key bytes using BIG-39 standard
    mnemonic = mnemonic_generator.FromEntropy(entropy_bytes)

    return mnemonic

# Example Usage
private_key_hex = ""
mnemonic_phrase = eth_private_key_to_mnemonic(private_key_hex)
print("12-Word Mnemonic Phrase:",mnemonic_phrase)