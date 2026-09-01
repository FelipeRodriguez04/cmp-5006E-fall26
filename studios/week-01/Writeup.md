1. 
python3 test_cipher.py
  ok  encrypt/decrypt round-trips on 3 keys
  ok  frequency_guess_key is a valid 1-to-1 mapping (23 symbols)
  ok  confidentiality collapsed on 12/12 English ciphertexts — recovered without the key (that is the lesson)
  ok  non-English plaintext held: only 9% recovered — the assumption is what breaks the cipher, not the algorithm

all 4 tests pass

python3 starter.py    
SECURITY THROUGH OBSCURITY IS THE RELIANCE ON SECRECY OF DESIGN AS THE MAIN METHOD
OF PROVIDING SECURITY FOR A SYSTEM. A SYSTEM RELYING ON OBSCURITY MAY HAVE REAL
SECURITY VULNERABILITIES, BUT ITS OWNERS OR DESIGNERS BELIEVE THAT IF THE FLAWS
ARE NOT KNOWN THEN ATTACKERS WILL BE UNLIKELY TO FIND THEM. KERCKHOFFS ARGUED ...

recovered 100% of characters WITHOUT the key

2. 
The attack assumed that the plaintext was ordinary English and it preserved recognizable English single-letter and bigram frequency patterns after substitution.

3. 

Plaintext:  HELLO, MY NAME IS FELIPE
Defense: One time pad
My defense guarantees that attackers cannot decypher the message as English frequency will not provide a partial key, also there is not any bigrams under the condition that the key used will remain secret. The cost is that it requires securely generating, distributing, and storing a key as long as every message, and each key can be used only once.

4. 

Plaintext: HELLO PEOPLE  
Ciphertext: QDPPA RDARPD
Frequency guess: IETTA OEAOTE
Accuracy: 27.3% (only letters)

Frequency analysis failed because small samples do not follow the expected distribution of letters in ordinary English. In this short message, E and L occur equally often, causing the algorithm to map some ciphertext symbols to the wrong plaintext letters. 