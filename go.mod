module github.com/penrush/penrush

go 1.26

// Pin the build toolchain so reproducible builds have a single fixed input
// (architecture §H.1). The Go team's reproducibility guarantee is that a build's
// "only relevant input being its source" (go.dev/blog/rebuild) — pinning the
// toolchain removes the compiler version as a hidden variable across the
// two-runner byte-identical verification job.
toolchain go1.26.4
