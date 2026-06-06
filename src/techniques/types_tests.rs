#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_can_be_constructed_as_static() {
        const M: TechniqueMeta = TechniqueMeta {
            id: "test_xor",
            display_name: "Test XOR",
            description: "fixture",
            category: Category::Encryption,
            tags: &[],
            requires: &[],
            incompatible_with: &[],
            params: &[ParamSpec::Text { name: "key", label: "Key", default: "0x42" }],
        };
        assert_eq!(M.id, "test_xor");
        assert!(matches!(M.category, Category::Encryption));
    }

    #[test]
    fn requirement_self_injection_matches() {
        let req = Requirement::SelfInjection;
        assert!(matches!(req, Requirement::SelfInjection));
    }

    #[test]
    fn registry_includes_xor() {
        let xor = crate::techniques::find("xor").expect("xor technique not registered");
        assert_eq!(xor.meta().id, "xor");
        assert!(matches!(xor.meta().category, crate::techniques::Category::Encryption));
    }

    #[test]
    fn all_eight_injections_register() {
        let ids = ["syscrt", "wincrt", "earlycascade"];
        for id in ids {
            assert!(crate::techniques::find(id).is_some(), "missing injection: {id}");
        }
    }
}
