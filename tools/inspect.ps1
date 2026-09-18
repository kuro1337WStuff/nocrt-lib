param([string]$Path)
$b = [IO.File]::ReadAllBytes($Path)
function R32($o) { [BitConverter]::ToUInt32($b, $o) }
function R16($o) { [BitConverter]::ToUInt16($b, $o) }
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
