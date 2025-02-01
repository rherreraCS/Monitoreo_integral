rule TestRule {
    strings:
        $my_text_string = "malicious_string"
        $my_hex_string = { E2 34 A1 C8 }
    condition:
        $my_text_string or $my_hex_string
}
