$files = Get-ChildItem -Path "d:\Backup\Personal\Hp\iPhone\DSPloit\lara" -Recurse -Filter "*.swift"
foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw -Encoding UTF8
    if ($content -match '//  lara') {
        $newContent = $content -replace '//  lara', '//  DSPloit'
        [System.IO.File]::WriteAllText($file.FullName, $newContent)
        Write-Output "Fixed: $($file.FullName)"
    }
}
Write-Output "Done fixing lara headers"
