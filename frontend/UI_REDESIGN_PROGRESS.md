# UI Redesign Progress

## Design system
- Tokens and shared styles: frontend/src/index.css
- Fonts: Space Grotesk (headings), Inter (body), JetBrains Mono (data)
- Reference images: frontend/design-reference/
- Skill: .agent/skills/frontend-design/SKILL.md

## Status
- [x] Steps 1-3: audit, design system, app shell (WorkspaceShell)
- [x] Batch A: Login/Register (AuthPage), Dashboard (DashboardHome)
- [x] Batch B: SubmissionIntake, SubmissionsList, SubmissionDetail, FindingsPanel
- [x] Batch C: Semantic search, Network Settings
- [x] Batch D: Stage 2 and Stage 3 screens
  - [x] D1: MemoryNetwork.css, Analytics.css, CentralAdmin.css (CSS-only restyle)
  - [x] D2: Analytics.css network-context state styling & early-warning/risk-band styling (CSS-only)
- [x] Step 5: polish

## Rules
Presentation only. Nothing outside frontend/src. Keep routes, props, API calls, hooks, form field names, test IDs and aria-labels unchanged.