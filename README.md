<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/212de002-0644-4bea-8dd4-830cc6304da7

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `VITE_GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Run the React dashboard with the FastAPI model service

Open two terminals at the repository root. In the first, install the Python
dependencies and start the API on port 8000:

```bash
python -m pip install -r cyberworld/requirements.txt
python -m uvicorn cyberworld.backend.api:app --host 127.0.0.1 --port 8000 --reload
```

In the second, start the React dashboard:

```bash
npm install
npm run dev
```

The Vite script in this repository runs on `http://localhost:3000` (the API
also permits the standard Vite port `http://localhost:5173`). The dashboard is
offline-first by default: [`src/App.tsx`](src/App.tsx) sets
`USE_BACKEND_API = false`, so it continues to use the deterministic simulator.
Set that flag to `true` to send the current sequence to `http://localhost:8000`.
If the API is unavailable, the API client automatically returns to the existing
TypeScript simulator path.

Check the running service with:

```bash
curl http://127.0.0.1:8000/api/health
```
