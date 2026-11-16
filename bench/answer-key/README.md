# Answer key

Every fixture here has a correct grade that is known before the scanner runs.
run_key.py scans each one and prints HIT or MISS, then a score.

Run it from the repo root:

    python3 bench/answer-key/run_key.py

    HIT  open_noauth expect MEDIUM 1f exit0 got MEDIUM 1f exit0
    HIT  closed_401 expect INCONCLUSIVE 0f exit5 got INCONCLUSIVE 0f exit5
    HIT  closed_oauth expect PASS 0f exit5 got PASS 0f exit5
    HIT  html_page expect INCONCLUSIVE 0f exit5 got INCONCLUSIVE 0f exit5

    ANSWER KEY 4 hit 0 miss

The point is that the grade is not the scanner grading itself. A page server
that is not MCP gets the same verdict as a closed server: no findings and no
clean bill. A miss is a defect in the scanner, not in the key.
