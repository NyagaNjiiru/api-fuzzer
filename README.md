```markdown
# API Fuzzing & Hardening Toolkit

Low-level API fuzzer in Rust.  
Generates malformed requests to test system resilience:  
- Bad JSON structures  
- Oversized payloads  
- Replayed timestamps  

### Build & Run
```bash
cargo run -- fuzz --url https://target-api.com
