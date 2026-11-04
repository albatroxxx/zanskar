# How the console speaks

The console is for people who know what a target, a policy and a session are. It says less. The
documentation (the guide on the site, the ADRs, the release notes) is where words go.

## The rules

1. **A name says what it is; a description exists only for what the name does not carry** — a
   consequence, a security nuance, a format — and is one short clause. *Check for new versions*
   needs "Daily; nothing is sent." (the privacy fact). *Approving asks for a code* needs nothing.
   "Terminal output is indexed beside the commands, up to 5,000 lines a recording, so reviewers
   can find it" was cut to "Off empties the index." A page or card heading never gets a lead that
   restates it: "Who hears of what, without the console open…" under *Notifications* went.
2. **No mechanism narration.** Not "a custom image, for a private registry mirror, is pinned by
   digest" but "a custom image is pinned by digest". Not "so reviewers can find it".
3. **No "is recorded" and "is logged" captions.** They sat on nearly every page. The audit log
   records everything regardless; the person is told once, by the login banner, which the
   operator words. It has no default text, only an example in the field ("every session is
   recorded and may be reviewed"), so an empty banner tells nobody; the 1.18.1 notes say so.
4. **A title that is ambiguous to the owner is wrong.** "Search what sessions printed" under
   *Recordings* read as desktop video to them; it is "Index terminal output".
5. **Four tiles a row, and never an invented one.** When a row needs a fourth box, use something
   that existed; a tile made to fill the row ("Sign-in providers failing") was removed. A tile's
   colour is its state; no icon beside a progress bar to say what its colour already says.
6. **Neutral glyphs only.** Icons are shapes, not brands (a trademark decision); the aria-label
   keeps the words. Buttons are verbs: Test, Edit, Remove, Allow, Open, Request.
7. **A form hint is a format, not an essay.** "587 STARTTLS, 465 TLS", "ldaps://host:636 or
   ldap://host:389 with StartTLS", "Comma-separated". A dialog body states the consequence of the
   button in one sentence.
8. **Buttons are never inside a sentence.** They sit on an `.actions` row of their own; facts sit
   in a `.kv` key–value list. (A `span.actions` inside a paragraph is `display: flex` and breaks
   the line — the Email server block did exactly that.)
9. **One notice, not a sprinkle.** Something the person must know at the moment of acting is
   said there, once (the install-settings dialog warns that the proxy must stop first); nothing is
   repeated on every page it might apply to.
10. **The palette is the project's.** Warm neutrals with one ultramarine accent, as the tokens in
    `web/src/styles/base.css` define; no navy-and-teal "AI look"; the selected sidebar item is its
    soft background and accent text, with no bar beside it. New UI uses the tokens, not colours.

## Before shipping copy

Read every new title, description, lead, hint and dialog against the rules above, and against the
page it sits on. If a sentence can go without the control losing its meaning, it goes. Then
screenshot the page from the local mock; the owner reviews the picture, not the diff.
