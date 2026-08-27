# CloakDB Terminal Demo Tape (VHS)
# Render using: vhs demo.tape

Output assets/demo.gif

Set Shell "bash"
Set FontSize 14
Set FontFamily "JetBrains Mono"
Set Width 1280
Set Height 820
Set LetterSpacing 0
Set LineHeight 1.2
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

# Initial pause
Sleep 1s

# 1. Scan SQL dump for PII
Type "cloakdb scan examples/sample_postgres.sql"
Enter
Sleep 3.5s

# 2. Preview masking transformations
Type "cloakdb preview -c examples/cloakdb.example.yaml -i examples/sample_postgres.sql"
Enter
Sleep 4s

# 3. Stream and mask using 4 parallel workers
Type "cloakdb apply -c examples/cloakdb.example.yaml -i examples/sample_postgres.sql -o masked.sql --workers 4"
Enter
Sleep 3.5s

# 4. In-memory throughput benchmark
Type "cloakdb bench --rows 10000"
Enter
Sleep 4s