# Threat Detection Frontend

A modern web application for analyzing binary files and detecting malware threats.

## Features

- File upload with drag-and-drop support
- Real-time analysis status
- Detailed PE header parsing results
- YARA rule match detection
- Section-level entropy analysis
- Threat classification and risk scoring
- Packed binary detection

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm run dev
```

The application will be available at `http://localhost:3000`

## Backend Configuration

The frontend expects the backend API to be running at `http://localhost:8080`. Make sure your Spring Boot backend is running before using the frontend.

## Usage

1. Click the upload area or drag a binary file (.exe, .dll, .sys)
2. Click "Analyze File" to submit for analysis
3. View comprehensive analysis results including:
   - File classification (clean/suspicious/malicious)
   - ML risk score
   - YARA rule matches
   - PE header information
   - Section details with entropy analysis
   - Packer detection

## Technology Stack

- React 18
- TypeScript
- Vite
- Tailwind CSS
- Axios
