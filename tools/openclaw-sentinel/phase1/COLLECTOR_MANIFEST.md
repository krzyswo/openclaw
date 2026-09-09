# Phase 1 Collector Manifest

Validated collector version: `1.1.0`

Validated SHA-256:

```text
6bd077d4d73bc01712e517aabc08197da71d16876b35cbeaaf34f9c1639c4785
```

The validated collector is the local `openclaw-sentinel-discovery.sh` used for the successful Phase 1 run.

The generated runtime reports are intentionally not stored in this public repository because they can contain LAN inventory, public IP information, service exposure and SSH activity.

Before committing a collector copy, verify it with:

```bash
bash -n openclaw-sentinel-discovery.sh
sha256sum openclaw-sentinel-discovery.sh
```

Expected version marker:

```text
VERSION="1.1.0"
```
