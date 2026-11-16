# Deeprisk Frontend

The Deeprisk frontend is a React-based web dashboard for exploring software supply-chain security scans, dependency relationships, vulnerability findings, remediation information, and scan history.

## Technology Stack

- React 19
- Vite
- JavaScript (ES Modules)
- React Router
- Axios
- Recharts
- Cytoscape
- 3D Force Graph
- Three.js
- Oxlint

## Getting Started

### Prerequisites

- Node.js and npm
- Deeprisk backend running locally

### Installation

Run `npm ci` inside the frontend directory to install dependencies.

### Development

Run `npm run dev` to start the development server.

### Production Build

Run `npm run build` to create the production build.

### Preview

Run `npm run preview` to preview the production build.

## Backend Configuration

The frontend communicates with the Deeprisk backend API.

Set `VITE_API_BASE_URL` when a custom backend URL is required.

If not configured, the API client defaults to `http://127.0.0.1:8000`.

## Project Structure

- public/: Static assets and branding
- src/api/: Backend API client
- src/components/: Reusable components
- src/pages/: Dashboard pages
- src/assets/: Frontend assets

For complete backend setup, architecture, API documentation, and testing instructions, refer to the root README.md.
