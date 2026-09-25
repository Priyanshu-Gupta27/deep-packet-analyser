# Frontend

The browser UI is a dependency-free HTML, CSS, and JavaScript application served by FastAPI from the same origin as its API.

## Views

- **Upload:** drag-and-drop or file selection, file details, PCAP/PCAPNG guidance, client-side size checks, and real upload progress followed by an indeterminate analysis stage.
- **Overview:** API-derived summary cards, protocol donut, traffic-by-second chart, top source and destination addresses, and top port appearances.
- **Packets:** server-paginated Wireshark-inspired table with search, protocol/IP/port filters, sorting, clear filters, and a packet metadata panel.
- **Flows:** directional five-tuple records returned by FastAPI.
- **Protocols:** packet counts and shares calculated from the backend protocol summary. Protocol byte counts show unavailable because the API does not expose them.
- **About:** architecture and parser limitations.

All data shown for an analysis comes from `/api/analyses/{id}` or `/api/analyses/{id}/packets`. The browser requests one packet page at a time, caches the last query result, and aborts stale page requests when filters change. Charts are native SVG; there are no chart or icon dependencies.

## Local verification

From the repository root:

```powershell
node --check frontend\app.js
```

Start the FastAPI service as described in the root README. The service serves `index.html` at `/`, assets at `/static/`, and analysis deep links at `/analysis/{analysis_id}`. PCAPNG, IPv6, and TCP stream reassembly are not supported by the current parser. Browser live capture is not implemented.
