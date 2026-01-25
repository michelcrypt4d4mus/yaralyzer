rule BlackHole_v2 : PDF {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
        weight = 3

    strings:
        $magic = { 25 50 44 46 }
        $content = "Index[5 1 7 1 9 4 23 4 50"
    condition:
        $magic in (0..1024) and $content
}
