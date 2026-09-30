# Vendored Wheels for Live ISO Offline Build

These pre-downloaded wheels are staged into the Debian Bookworm live ISO build environment (`/opt/s0/vendor`) during `auto/build.sh` and installed by `config/hooks/live/9000-s0.hook.chroot`.

Debian 12 Bookworm ships with `python3-pydantic` v1.10.4-1, whereas `src/s0/web/app.py` requires Pydantic v2 (`ConfigDict`, `field_validator`).
Because live-build runs offline without external network access, these wheels satisfy the dependency reproducibly:

- `annotated_types-0.7.0-py3-none-any.whl`
- `pydantic-2.9.2-py3-none-any.whl`
- `pydantic_core-2.23.4-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`
- `typing_extensions-4.16.0-py3-none-any.whl`
