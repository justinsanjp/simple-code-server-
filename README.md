Justin's Simple Code Server
Current version V1.0 Beta

A tiny, self-contained Python file server with a VS-Code-like in-browser editor and Discord OAuth authentication.
It lets authorized Discord users browse, preview, download and edit files on the host machine (with configurable permissions).

Quick: this repository contains a single-file HTTP server (e.g. server.py) — drop it into a folder you want to serve, configure a few environment variables and run.

Features

Discord OAuth2 login (identify scope) for authentication

Per-user permission model stored in a local SQLite DB

Permissions: browse, preview, download, upload, admin

VS Code-style Single Page App (Monaco editor) for editing text files in-browser

Tree explorer with icons, file size display and lazy folder loading

File upload endpoint (multipart/form-data)

API endpoints for listing/reading/saving files (/api/list, /api/read, /api/save)

Single-file, minimal dependency server (stdlib + optional python-dotenv)

Safe path resolution preventing escaping the configured ROOT

Cookie-based session signing (HMAC + SHA256)
