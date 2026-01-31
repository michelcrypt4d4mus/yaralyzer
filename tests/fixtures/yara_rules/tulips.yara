rule Will_There_Be_Tulips {
    meta:
        author = "The Yaralyzer"
    strings:
        $tulip_to_tulip = /tulip.{1,2500}tulip/
    condition:
        $tulip_to_tulip
}

rule There_Will_Be_No_Tulips {
    meta:
        author = "The Yaralyzer"
    strings:
        $tulip = {60 71 65 8d fd cd 8b 4b}
    condition:
        $tulip
}

rule There_Will_Be_Hex_Tulips {
    meta:
        author = "The Yaralyzer"
    strings:
        $che_vi_e_tanta = {63 68 65 20 76 69 20 c3 a8 20 74 61 6e 74 61}
    condition:
        $che_vi_e_tanta
}
