# Web server

Wormway answering like a fresh Nginx: a welcome page at `/` and `/index.html`, and a 404 page for
every other request. The pages are fixed responses of two routes in `wormway.toml`, with
`Content-Type: text/html`, so the example needs no files besides the configuration.

## Run it

It listens on port 80, which needs root. From the repository root, build Wormway and run it with
sudo (`sudo cargo run` would leave files owned by root in `target/`):

```sh
cargo build -p wormway
sudo target/debug/wormway run -c examples/web-server/wormway.toml
```

Then, in another terminal:

```sh
curl -i http://127.0.0.1/            # 200, the welcome page
curl -i http://127.0.0.1/missing     # 404, the error page
```

Or open <http://127.0.0.1/> in a browser. Each request gets a line in the format of Nginx on
standard output.

The settings come from the file (`config.source = "file"`): edit it and send SIGHUP to apply the
changes without a restart, as with `nginx -s reload`:

```sh
sudo kill -HUP $(pgrep -f "wormway run -c examples/web-server/wormway.toml")
```

Wormway also starts its Admin API and dashboard on `127.0.0.1:9872`, and keeps its database and
the Admin API token in `data/` next to the configuration, owned by root when it runs with sudo.
