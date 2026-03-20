# Basalt - Networking

A networking layer for the Basalt project.

## Architecture

Consists of a single container. This will be the only container within the main Basalt server with external access. All communications flow through this container. It acts as a security layer, performing rate limiting, CORS, etc.
