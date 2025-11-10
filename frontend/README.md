# SecureChain AI - Frontend

Modern Next.js frontend for the SecureChain AI platform - an AI-powered software supply chain security analysis system.

## Features

- 🎨 **Modern UI**: Built with Next.js 15, React 19, and shadcn/ui
- 📊 **Dashboard**: Real-time security posture overview
- 🔍 **Scan Management**: Create and monitor security scans
- 🛡️ **Vulnerability Analysis**: Detailed vulnerability tables with filtering
- 🤖 **AI Integration**: Run AI agents for prioritization and remediation
- 📱 **Responsive Design**: Mobile-friendly interface
- ⚡ **Real-time Updates**: Automatic polling for running scans
- 🎯 **Type-Safe**: Full TypeScript coverage

## Tech Stack

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **UI Components**: shadcn/ui + Radix UI
- **Data Fetching**: TanStack Query (React Query)
- **Icons**: Lucide React
- **Charts**: Recharts

## Prerequisites

- Node.js 18+ (recommended: 20+)
- npm, yarn, or pnpm
- Running backend API (see `../backend/README.md`)

## Installation

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Configure Environment

Create `.env.local` file:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000/api
```

### 3. Start Development Server

```bash
npm run dev
```

The application will be available at `http://localhost:3000`.

## Project Structure

```
frontend/
├── app/                      # Next.js App Router
│   ├── layout.tsx           # Root layout with providers
│   ├── page.tsx             # Dashboard page
│   ├── globals.css          # Global styles
│   ├── scans/               # Scans pages
│   │   ├── page.tsx         # Scans list
│   │   └── [id]/page.tsx    # Scan details
│   └── analysis/            # AI analysis pages
│       └── page.tsx         # Analysis interface
├── components/              # React components
│   ├── ui/                  # shadcn/ui components
│   │   ├── button.tsx
│   │   ├── card.tsx
│   │   ├── dialog.tsx
│   │   ├── table.tsx
│   │   └── ...
│   ├── navigation.tsx       # Main navigation
│   ├── scan-form.tsx        # Scan creation form
│   └── vulnerability-table.tsx  # Vulnerability display
├── lib/                     # Utilities
│   ├── api-client.ts        # Backend API client
│   ├── types.ts             # TypeScript types
│   ├── utils.ts             # Helper functions
│   └── providers.tsx        # React Query provider
├── next.config.ts           # Next.js configuration
├── tailwind.config.ts       # Tailwind CSS configuration
├── tsconfig.json            # TypeScript configuration
└── package.json             # Dependencies
```

## Available Scripts

```bash
# Development
npm run dev          # Start dev server (http://localhost:3000)

# Production
npm run build        # Build for production
npm start            # Start production server

# Code Quality
npm run lint         # Run ESLint
```

## Key Features

### 1. Dashboard

- **Security Metrics**: Total scans, vulnerabilities, critical issues
- **Recent Activity**: Latest scan results
- **Quick Actions**: Direct links to scans and analysis

### 2. Scan Management

#### Create New Scan

Supports 5 scan types:

- **Git Repository**: Scan source code repositories
- **Container Image**: Scan Docker containers
- **Virtual Machine**: Scan VM images
- **SBOM**: Analyze Software Bill of Materials
- **Kubernetes**: Scan K8s manifests

#### Scan List

- Filter by status (all, completed, running, pending, failed)
- Real-time status updates
- Severity badges and counts
- Quick navigation to details

#### Scan Details

- Comprehensive scan information
- Real-time progress updates (auto-polling)
- Vulnerability breakdown by severity
- Interactive vulnerability table

### 3. Vulnerability Table

Features:

- **Search**: Filter by CVE ID or package name
- **Severity Filter**: Filter by CRITICAL, HIGH, MEDIUM, LOW
- **CVE Links**: Direct links to NVD database
- **EPSS Scores**: Exploitation probability with prediction badges
- **CVSS Scores**: Industry-standard severity scores

### 4. AI Analysis

Three AI agents available:

#### Prioritization Agent

- Risk-based vulnerability scoring
- EPSS integration
- Business impact assessment
- Actionable recommendations

#### Supply Chain Agent

- Cross-scan analysis
- Dependency mapping
- Common vulnerability identification
- Consolidated remediation

#### Remediation Agent

- Step-by-step instructions
- Upgrade commands
- Testing procedures
- Rollback plans

## API Integration

### API Client

The frontend uses a type-safe API client (`lib/api-client.ts`):

```typescript
import { apiClient } from "@/lib/api-client";

// Fetch scans
const scans = await apiClient.listScans({ limit: 10 });

// Get scan details
const scan = await apiClient.getScan(scanId);

// Create new scan
const response = await apiClient.triggerScan({
  scan_type: "container",
  target: "nginx:latest",
});

// Get vulnerabilities
const vulnerabilities = await apiClient.getScanVulnerabilities(scanId);

// Run AI analysis
const analysis = await apiClient.analyzeScan({
  scan_id: scanId,
  agents: ["prioritization"],
});
```

### React Query Integration

All API calls use TanStack Query for:

- Automatic caching
- Background refetching
- Real-time updates
- Loading states
- Error handling

Example:

```typescript
const { data, isLoading, error } = useQuery({
  queryKey: ["scans", scanId],
  queryFn: () => apiClient.getScan(scanId),
  refetchInterval: 3000, // Poll every 3 seconds for running scans
});
```

## Styling Guide

### Tailwind CSS

The project uses Tailwind CSS with custom theme configuration:

```tsx
// Primary colors
className="bg-primary text-primary-foreground"

// Severity colors
className="text-red-600 bg-red-50"  // Critical
className="text-orange-600 bg-orange-50"  // High
className="text-yellow-600 bg-yellow-50"  // Medium
className="text-blue-600 bg-blue-50"  // Low
```

### shadcn/ui Components

All UI components follow shadcn/ui patterns:

```tsx
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

<Card>
  <CardHeader>
    <CardTitle>Title</CardTitle>
  </CardHeader>
  <CardContent>
    <Button>Click Me</Button>
  </CardContent>
</Card>;
```

## Type Safety

### TypeScript Types

All backend types are defined in `lib/types.ts`:

```typescript
export interface Scan {
  id: string;
  scan_type: ScanType;
  target: string;
  status: ScanStatus;
  vulnerability_count: number;
  // ...
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  severity: string;
  cvss_score?: number;
  epss_score?: number;
  // ...
}
```

## Deployment

### Build for Production

```bash
npm run build
npm start
```

### Environment Variables

Production environment:

```bash
NEXT_PUBLIC_API_URL=https://api.your-domain.com/api
```

### Docker Deployment

```dockerfile
FROM node:20-alpine AS base

# Install dependencies
FROM base AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Build application
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# Run application
FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

EXPOSE 3000
CMD ["node", "server.js"]
```

### Vercel Deployment

The project is optimized for Vercel deployment:

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel
```

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Performance

- **Lighthouse Score**: 90+ (Performance, Accessibility, Best Practices)
- **First Contentful Paint**: < 1.5s
- **Time to Interactive**: < 3.5s

## Contributing

1. Follow TypeScript best practices
2. Use shadcn/ui components
3. Implement proper error handling
4. Add loading states for async operations
5. Test on multiple browsers
6. Ensure mobile responsiveness

## Troubleshooting

### API Connection Issues

```bash
# Check backend is running
curl http://localhost:8000/health

# Verify API URL in .env.local
cat .env.local
```

### Build Errors

```bash
# Clear cache and rebuild
rm -rf .next
npm run build
```

### Type Errors

```bash
# Check TypeScript
npx tsc --noEmit
```

## License

Part of the SecureChain AI platform.
