# Public status readability implementation plan

**Goal:** Apply the public-page improvements approved in chat on 2026-11-05.
**Architecture:** Reuse Django presentation adapters and shared domain templates. Keep public DTOs free of diagnostics and secrets; derive allowlisted public explanations during presentation. Keep automatic refresh on read pages, deferring drafts and active interactions.
**Tech stack:** Django templates, Python, native CSS and JavaScript.
**Spec:** User-approved review points 1–12 in this conversation.

## Constraints

- No next-check date or displayed timezone on the public page.
- Use “Successful checks”; distinguish page refresh time from saved check time.
- Preserve gaps, owner isolation, native navigation and public read-only behavior.
- Remove auto-refresh switches from owner and public headers; refresh remains on.
- Preserve existing uncommitted changes, including password settings.
- Investigate absent VirusTotal results; do not invent successful verdicts.

## Tasks

- [x] Add regression coverage for safe missing-report explanations, check grouping, gaps and always-on refresh.
- [x] Update presentation adapters: relative-first public timestamps, page render timestamp, check groups, gap intervals and recent response-time means (15 minutes, 1 hour, 1 day).
- [x] Update templates and styles: readable summaries, neutral gap legend, tooltips, domain emphasis, subtle expanded state and quieter check separators.
- [x] Update chart controls for touch and arrow-key point navigation; defer automatic reload while a chart tooltip is open.
- [x] Update translations and user documentation, run Python/JS/lint checks.
- [x] Inspect desktop/mobile light/dark rendering and verify local container runtime after rebuild if needed.

## Review focus

- Unknown measurements never count as downtime or success.
- Public text is allowlisted; raw provider messages and metrics never enter HTML/DTOs.
- Group sorting keeps severe/overdue checks first without changing verdicts.
- Stored “refresh=off” no longer disables refresh; edits and open live activity remain protected.
- Empty data, narrow screens, keyboard focus and chart gaps remain usable.

## Follow-up requirements

- Saved results become stale only after three effective polling intervals; actual scheduling keeps one interval. Explicit failures and missing results remain immediate.
- Replace the maximum response time with exact sample means for the last 15 minutes, 1 hour and 1 day. These windows are independent of the graph period.

## Final visual corrections

- Restore the supplied compact flat checklist: two columns on desktop, one on phones, no category headings or verbose visible notes. Keep actual status handling and hover details.
- Remove the visible instruction paragraph below the chart; preserve chart interactions and gap shading.
- Render the three response-time means in one inline “Average: 15 min: …, 1 hour: …, 1 day: …” summary, with natural wrapping on narrow screens.
