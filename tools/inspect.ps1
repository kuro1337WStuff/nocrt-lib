param([string]$Path)
$b = [IO.File]::ReadAllBytes($Path)
function R32($o) { [BitConverter]::ToUInt32($b, $o) }
function R16($o) { [BitConverter]::ToUInt16($b, $o) }
function Off($rva) {
    for ($i = 0; $i -lt $nsec; $i++) {
        $e = $sec + $i * 40
        $va = R32 ($e + 12); $rs = R32 ($e + 16); $rp = R32 ($e + 20)
        if ($rva -ge $va -and $rva -lt $va + $rs) { return $rp + ($rva - $va) }
    }
    return $rva
}
$lf = R32 0x3C
$opt = $lf + 24
$nsec = R16 ($lf + 4 + 2)
$optsize = R16 ($lf + 4 + 16)
$sec = $opt + $optsize
Write-Output ("file=" + $Path)
for ($i = 0; $i -lt $nsec; $i++) {
    $e = $sec + $i * 40
    $name = [Text.Encoding]::ASCII.GetString($b, $e, 8).TrimEnd([char]0)
    $vs = R32 ($e + 8); $rs = R32 ($e + 16); $ch = R32 ($e + 36)
    Write-Output ("section {0} vsize=0x{1:X} rawsize=0x{2:X} chars=0x{3:X}" -f $name, $vs, $rs, $ch)
}
Write-Output ("SizeOfImage=0x{0:X} SizeOfHeaders=0x{1:X}" -f (R32 ($opt + 56)), (R32 ($opt + 60)))
$dd = $opt + 112
$exrva = R32 $dd
if ($exrva -ne 0) {
    $ex = Off $exrva
    $nn = R32 ($ex + 24)
    $af = Off (R32 ($ex + 28))
    $an = Off (R32 ($ex + 32))
    $ao = Off (R32 ($ex + 36))
    for ($i = 0; $i -lt $nn; $i++) {
        $no = Off (R32 ($an + $i * 4))
        $s = ''
        for ($j = 0; $j -lt 40 -and $b[$no + $j] -ne 0; $j++) { $s += [char]$b[$no + $j] }
        $ord = R16 ($ao + $i * 2)
        $rva = R32 ($af + $ord * 4)
        Write-Output ("export {0} rva=0x{1:X}" -f $s, $rva)
    }
}
Write-Output ("AddressOfEntryPoint=0x{0:X}" -f (R32 ($opt + 16)))
