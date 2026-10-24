"""The implementation behind artifact-tools' four tasks (grep, jq, sql, slice).

Nothing in this package imports the capability SDK: each task function takes
the SDK's `ctx` as a parameter and uses only `ctx.artifacts`, `ctx.workdir`,
`ctx.input_artifacts` and `ctx.log`. That keeps the models importable from
`scripts/export_schemas.py`, which runs where the SDK is the vendored one.
"""
