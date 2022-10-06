rule Will_There_Be_Tulips {
    meta:
        author = "The Yaralyzer"
    strings:
        $tulip_to_tulip = /tulip.{1,2500}tulip/
    condition:
        $tulip_to_tulip
}

rule There_Will_Be_Tulips {
    meta:
        author = "The Yaralyzer"
    strings:
        $tulip = {60 71 65 8d fd cd 8b 4b}
    condition:
        $tulip
}
