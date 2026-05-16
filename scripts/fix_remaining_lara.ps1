# Fix all .h header files: //  lara -> //  DSPloit
$hFiles = Get-ChildItem -Path "d:\Backup\Personal\Hp\iPhone\DSPloit\lara" -Recurse -Filter "*.h"
foreach ($file in $hFiles) {
    $content = Get-Content $file.FullName -Raw -Encoding UTF8
    if ($content -match '//  lara') {
        $newContent = $content -replace '//  lara', '//  DSPloit'
        [System.IO.File]::WriteAllText($file.FullName, $newContent)
        Write-Output "Fixed header: $($file.Name)"
    }
}

# Fix ipabuild.sh
$ipabuild = "d:\Backup\Personal\Hp\iPhone\DSPloit\scripts\ipabuild.sh"
if (Test-Path $ipabuild) {
    $content = Get-Content $ipabuild -Raw -Encoding UTF8
    $content = $content -replace 'APPLICATION_NAME=lara', 'APPLICATION_NAME=dsploit'
    [System.IO.File]::WriteAllText($ipabuild, $content)
    Write-Output "Fixed: ipabuild.sh"
}

Write-Output "Done!"
