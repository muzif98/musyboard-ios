# Installing MusyBoard on iOS

> No part of this guide has been tested end to end on a real iPhone yet.
> Action names in Shortcuts vary slightly between iOS versions and device
> languages: the steps describe the mechanism; pick the closest action if a name
> does not match exactly.

## 1. Scriptable

Install **Scriptable** (by Simon B. Støvring) from the App Store. Open it once
and close it: this creates its local folder.

## 2. Files

Put these files in Scriptable's **local** folder (in the Files app: *On My
iPhone → Scriptable*, **never** *iCloud Drive → Scriptable*, or the private key
would sync to Apple's servers):

- `MusyBoard.js` from `scriptable/`;
- `musyboard_wasm.wasm` from `dist/`, with **exactly this name** (the script
  looks for it by name). To build it yourself, see the README.

> **The private key is stored in clear inside `config.json`.** It stays in
> Scriptable's sandbox and iOS encrypts it at rest, but a **device backup**
> (iCloud or computer) carries it as it is. Scriptable cannot exclude a file
> from backups. Keep this in mind before using it for anything serious.

The script saves its state in a recoverable way: during an update
`config.json.new` and `config.json.bak` may appear temporarily. **Do not delete
them by hand**: on the next start the script picks the most recent valid copy if
a save was interrupted.

## 3. First run

In Scriptable, create a new script named `MusyBoard`, paste `MusyBoard.js` and
run it. It offers to generate an identity: accept, then copy your identity card
and send it to your Android contact.

## 4. Shortcuts

Scriptable's **"Run Script"** action passes its parameter to the script as
`args.shortcutParameter`, and the script returns a result with
`Script.setShortcutOutput(...)`.

`MusyBoard.js` recognises the intent from a marker at the start of the text
(`MB_DECRYPT:` or `MB_ENCRYPT:`) added by the Shortcut itself, so the two
Shortcuts stay two distinct actions rather than one that guesses what to do.
Their names are up to you.

### Decrypt

1. Shortcuts app → new Shortcut, e.g. "Decrypt MusyBoard".
2. Add a **Text** action: type `MB_DECRYPT:`, then insert the **Shortcut
   Input** variable right after it.
3. Add **Run Script** → Scriptable → script "MusyBoard", with the text from
   step 2 as input.
4. Add **Show Result** (or **Show Notification**) with the output of Run
   Script.
5. In the Shortcut's details, enable **Show in Share Sheet**, accepted type
   **Text**. It now appears in the share menu of other apps.

### Encrypt

1. New Shortcut, e.g. "Encrypt with MusyBoard".
2. Add **Ask for Input** (prompt: text to encrypt) with the **Clipboard**
   variable as default value: the field starts filled if you just copied
   something, and stays editable.
3. Add a **Text** action: `MB_ENCRYPT:` followed by the answer from step 2.
4. Add **Run Script** → Scriptable → "MusyBoard", input = the text from step 3.
5. Add **Copy to Clipboard** with the output of Run Script.

## 5. End-to-end check (on a real iPhone)

1. Generate the identity and exchange identity cards with a real Android device
   (or with `kc` from [musyboard-core](https://github.com/muzif98/musyboard-core)
   on a computer).
2. Encrypt a message on Android and decrypt it on iOS from the share sheet, and
   the other way round.
3. Quit Scriptable completely, reopen it, and check that a conversation already
   started keeps working (rehydration from `config.json`).
4. Burn a conversation and check that the old keys disappear from
   `config.json`.
5. In airplane mode, check that everything keeps working (no network).
6. In the Files app, check that `config.json` and `musyboard_wasm.wasm` are only
   under *On My iPhone*, never under *iCloud Drive*.
