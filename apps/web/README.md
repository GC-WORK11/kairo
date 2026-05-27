# Kairo Web Dashboard

Real-time risk intelligence dashboard for the Kairo project.

## Setup

```bash
cd apps/web
bun install
bun dev
```

Open [http://localhost:3000](http://localhost:3000) to view the dashboard.

## Build

```bash
bun run build
```

## Pages

- `/` - Overview dashboard with stats, charts, and recent checks
- `/checks` - Full audit trail of all Kairo decisions
- `/policies` - Organization policy management
- `/packages` - Package risk overview and advisories
- `/audit` - Complete audit log of all actions
