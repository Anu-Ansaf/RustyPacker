use rustpacker::polymorph::{BuildSeed, Polymorph};

#[test]
fn same_seed_same_idents() {
    let mut a = Polymorph::from_seed(BuildSeed(0xDEADBEEF));
    let mut b = Polymorph::from_seed(BuildSeed(0xDEADBEEF));
    for _ in 0..16 {
        assert_eq!(a.random_ident("fn"), b.random_ident("fn"));
    }
}

#[test]
fn different_seeds_different_idents() {
    let mut a = Polymorph::from_seed(BuildSeed(1));
    let mut b = Polymorph::from_seed(BuildSeed(2));
    let a_ids: Vec<_> = (0..16).map(|_| a.random_ident("fn")).collect();
    let b_ids: Vec<_> = (0..16).map(|_| b.random_ident("fn")).collect();
    assert_ne!(a_ids, b_ids);
}

#[test]
fn random_ident_is_valid_rust_ident() {
    let mut p = Polymorph::from_seed(BuildSeed(42));
    for _ in 0..256 {
        let id = p.random_ident("x");
        let first = id.chars().next().unwrap();
        assert!(first.is_ascii_lowercase() || first == '_', "ident: {id}");
        assert!(id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "ident: {id}");
    }
}

#[test]
fn random_ident_no_reserved_words() {
    let mut p = Polymorph::from_seed(BuildSeed(42));
    for _ in 0..1024 {
        let id = p.random_ident("x");
        assert!(!matches!(id.as_str(),
            "fn" | "let" | "mut" | "pub" | "use" | "mod" | "as" | "if" | "in" |
            "for" | "while" | "loop" | "match" | "ref" | "self" | "Self" | "super" |
            "type" | "trait" | "impl" | "struct" | "enum" | "where" | "true" | "false" |
            "static" | "const" | "extern" | "unsafe" | "move" | "box" | "do" | "yield"
        ));
    }
}

#[test]
fn random_ident_unique_within_polymorph() {
    let mut p = Polymorph::from_seed(BuildSeed(42));
    let mut seen = std::collections::HashSet::new();
    for _ in 0..512 {
        let id = p.random_ident("x");
        assert!(seen.insert(id.clone()), "duplicate ident: {id}");
    }
}

#[test]
fn jitter_within_range() {
    let mut p = Polymorph::from_seed(BuildSeed(7));
    for _ in 0..256 {
        let j = p.jitter(200, 25);
        assert!(j >= 150 && j <= 250, "jitter out of range: {j}");
        assert_eq!(j % 25, 0, "jitter not quantised to 25ms: {j}");
    }
}

#[test]
fn xor_bytes_literal_roundtrip() {
    let p = Polymorph::from_seed(BuildSeed(99));
    let lit = p.xor_bytes_literal(b"hello\0", 0x42);
    // Format: "[0x.., 0x.., ...]"
    assert!(lit.starts_with('[') && lit.ends_with(']'));
    assert_eq!(lit.matches(", ").count(), 5);  // 6 bytes -> 5 commas
}

#[test]
fn pick_is_deterministic() {
    let mut a = Polymorph::from_seed(BuildSeed(123));
    let mut b = Polymorph::from_seed(BuildSeed(123));
    let choices = ["red", "green", "blue", "yellow"];
    for _ in 0..32 {
        assert_eq!(a.pick(&choices), b.pick(&choices));
    }
}
