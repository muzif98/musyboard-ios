// Tests for the header shown above a decrypted message, OUTSIDE Scriptable.
// Loaded after MusyBoard.js, like the other test files.
//
// Why it has a test: this checks not cryptography but **what the user is told
// about it**, where two project decisions become visible or stay dead letters.
//
// K6: a group message must never show an author, and must say that the author
// cannot be established. K1 condition 2: it must say that a group has no
// forward secrecy. A one-to-one message does have a proven author (decryption
// proves it), and hiding it throws away the only anti-MITM signal.

let iPassati = 0;
let iFalliti = 0;

function iCheck(nome, ok) {
  if (ok) {
    iPassati++;
  } else {
    iFalliti++;
    print("FALLITO: " + nome);
  }
}

// `intestazioneMittente` asks wasm for the fingerprint when there is no label:
// replaced here, since no module is loaded.
fingerprintOf = function () {
  return "abcd efgh ijkl mnop qrst uvwx";
};

function daGruppo(destinatari) {
  return {
    tag: "message",
    gruppo: true,
    destinatari: destinatari,
    sender: new Uint8Array(32),
    senderStatus: { kind: "known", verified: true, label: "Marco" },
  };
}

function aDue(senderStatus) {
  return {
    tag: "message",
    gruppo: false,
    destinatari: 1,
    sender: new Uint8Array(32),
    senderStatus: senderStatus,
  };
}

print("--- intestazione del messaggio decifrato ---");

const gruppo = intestazioneMittente(daGruppo(5));
iCheck("gruppo: non nomina il mittente", gruppo.join(" ").indexOf("Marco") === -1);
iCheck("gruppo: dice che e' un gruppo", gruppo[0].indexOf("gruppo") !== -1);
iCheck("gruppo: dice quante persone", gruppo[1].indexOf("5") !== -1);
iCheck("gruppo: dice che l'autore non e' stabilibile", gruppo[1].indexOf("stabilibile") !== -1);
iCheck("gruppo: dice che non c'e' forward secrecy", gruppo[1].indexOf("forward secrecy") !== -1);

const verificato = intestazioneMittente(aDue({ kind: "known", verified: true, label: "Anna" }));
iCheck("a due verificato: nomina chi ha scritto", verificato[0].indexOf("Anna") !== -1);
iCheck("a due verificato: lo dice", verificato[0].indexOf("persona") !== -1);

const nonVerificato = intestazioneMittente(aDue({ kind: "known", verified: false, label: "Anna" }));
iCheck("a due non verificato: nomina chi ha scritto", nonVerificato[0].indexOf("Anna") !== -1);
iCheck("a due non verificato: non dice 'confrontato'", nonVerificato[0].indexOf("confrontato") === -1);
iCheck("a due non verificato: avverte", nonVerificato[1].indexOf("in mezzo") !== -1);

const senzaNome = intestazioneMittente(aDue({ kind: "known", verified: false, label: null }));
iCheck("senza etichetta: mostra l'impronta", senzaNome[0].indexOf("abcd") !== -1);

const nuovo = intestazioneMittente(aDue({ kind: "new" }));
iCheck("mai visto: lo dice", nuovo[0].indexOf("mai visto") !== -1);
iCheck("mai visto: mostra l'impronta da confrontare", nuovo[1].indexOf("abcd") !== -1);

const mio = intestazioneMittente({
  tag: "ownMessage",
  recipient: new Uint8Array(32),
  recipientLabel: "Giuseppe",
});
iCheck("proprio messaggio: dice che l'hai scritto tu", mio[0].indexOf("tu") !== -1);
iCheck("proprio messaggio: dice a chi", mio[1].indexOf("Giuseppe") !== -1);

print("");
print(iPassati + " passati, " + iFalliti + " falliti");
if (iFalliti > 0) {
  throw new Error(iFalliti + " test sull'interfaccia falliti");
}
