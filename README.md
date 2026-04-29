# Blockchain-Project
In this project you will create a small blockchain system. The goal is to demonstrate understanding of core blockchain concepts (hash-linked blocks, transactions, validation, and a simple consensus rule) and to practice security engineering discipline: designing first, implementing to spec, and validating that the implementation matches the design.

You will submit three deliverables:

1) Design document
2) Implementation (code + README)
3) Validation report (tests + evidence + design-to-code traceability)

Important: Implementation may be assisted by generative AI tools. Because of this, grading emphasizes the quality of the design and the quality of the validation.


How to run:
- java Blockchain.java
- java Blockchain.java test (validation tests)
    
Demo Script:
- java Blockchain.java demo (same as original)
    
Assumptions and Limitations:
- Requires java 9+
- Uses SHA-256; User must be registered
- Genesis block (1st block) has a nonce of 0
- Fork resolution uses longest valid chain
- All classes are static nested classes inside Blockchain.java
