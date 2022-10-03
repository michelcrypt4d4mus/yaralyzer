rule Will_There_Be_Tulips {
    meta:
        author = "The Yaralyzer"
    strings:
        $tulip_to_tulip = /tulip.{1,2500}tulip/
    condition:
        $tulip_to_tulip
}
