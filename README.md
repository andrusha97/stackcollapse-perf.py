stackcollapse-perf.py
=====================
A simple replacement for `perf script report stackcollapse` or `stackcollapse-perf.pl` (from Flamegraph)
that supports inlined functions. It's useful for profiling programs in C++,
because they usually have tons of inlined code.

This script is supposed to be used to build [flamegraphs](https://github.com/brendangregg/FlameGraph).

How to use
==========
```
perf record -F 99 -p 1234 -g -- sleep 60
perf script --inline | ./stackcollapse-perf.py | /path/to/flamegraph.pl > graph.svg
```

You will need a recent perf that supports `--inline`:
```
git clone https://github.com/torvalds/linux.git
cd linux/tools/perf
make
```
