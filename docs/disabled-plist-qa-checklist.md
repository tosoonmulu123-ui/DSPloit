# disabled.plist QA checklist

## Scope
- Target file: `/var/db/com.apple.xpc.launchd/disabled.plist`
- Validate behavior when edited content is smaller, equal, and larger than original file.
- Validate both file manager editor flow and custom overwrite flow.

## Preconditions
- Exploit path initialized.
- VFS initialized.
- Device has a recoverable backup strategy before changing launchd-related files.

## Test cases
1. **Baseline read**
   - Open target in file viewer/editor.
   - Confirm file can be read and parsed before edits.

2. **Save with larger payload**
   - Add valid plist keys so resulting XML is larger than original.
   - Save from editor flow.
   - Expected: save succeeds and read-back content matches exact edited text.

3. **Save with smaller payload**
   - Remove keys so file shrinks.
   - Save from editor flow.
   - Expected: save succeeds and read-back content matches exact edited text.

4. **Custom overwrite with larger source**
   - Prepare source plist larger than target.
   - Use custom overwrite view to write into target path.
   - Expected: operation succeeds via growth-safe path.

5. **Failure message quality**
   - Force a write error (invalid source path or unreadable source).
   - Expected: UI/log reports actionable message, not generic silent failure.

6. **Post-write integrity**
   - Re-open target and compare against expected content.
   - Confirm size and content are correct after each case.

## Regression checks
- Font overwrite still works.
- Card image/pass rewrite still works.
- Whitelist patch path still reports detailed fallback status.
