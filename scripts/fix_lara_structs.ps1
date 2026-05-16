# Fix LaraIconTheme -> DSPIconTheme, LaraThemedIcon -> DSPThemedIcon, etc.
# Also fix the storage path and UserDefaults keys
$files = @(
    "d:\Backup\Personal\Hp\iPhone\DSPloit\lara\classes\IconThemeManager.swift",
    "d:\Backup\Personal\Hp\iPhone\DSPloit\lara\views\tweaks\broken\darkboard\DarkBoardView.swift"
)
foreach ($file in $files) {
    $content = Get-Content $file -Raw -Encoding UTF8
    $content = $content -replace 'LaraIconTheme', 'DSPIconTheme'
    $content = $content -replace 'LaraThemedIcon', 'DSPThemedIcon'
    $content = $content -replace 'LaraThemedApp', 'DSPThemedApp'
    $content = $content -replace 'LaraAppIconChange', 'DSPAppIconChange'
    $content = $content -replace '\.DO-NOT-DELETE-lara/', '.DO-NOT-DELETE-dsploit/'
    $content = $content -replace '"lara\.iconThemes\.selectedThemes"', '"dsploit.iconThemes.selectedThemes"'
    $content = $content -replace '"lara\.iconThemes\.iconOverrides"', '"dsploit.iconThemes.iconOverrides"'
    $content = $content -replace '"lara\.iconThemes\.pendingFixup"', '"dsploit.iconThemes.pendingFixup"'
    [System.IO.File]::WriteAllText($file, $content)
    Write-Output "Fixed: $file"
}
Write-Output "Done fixing Lara struct names"
