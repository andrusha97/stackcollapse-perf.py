#!/usr/bin/env python
# encoding: utf-8

# Script to collapse perf samples that supports inlined functions.
#
# Usage: perf script --inline | ./stackcollapse-perf.py [options] | /path/to/flamegraph.pl > flamegraph.svg
# Use ./stackcollapse-perf.py -h to list available options.


# Parse stacktraces in format:
#
# process_name 11562 2585167.735943:          5 cycles:uppp:
#         ffffffff8168e0ec irq_return ([kernel.kallsyms])
#                    7da0b _int_malloc (/usr/lib64/libc-2.17.so)
#                    8010b malloc (/usr/lib64/libc-2.17.so)
#                    5f647 operator new (/usr/lib/gcc/x86_64-redhat-linux/4.9.2/libstdc++.so.6.0.20)
#                    c37a8 std::string::_Rep::_S_create (/usr/lib/gcc/x86_64-redhat-linux/4.9.2/libstdc++.so.6.0.20)
#                    30aec std::vector<std::string, std::allocator<std::string> >::_M_initialize_dispatch<boost::transform_iterator<boost::algorithm::detail::copy_iterator_rangeF<std::string, __gnu_cxx::__normal_iterator<char*, std::string> >, boost::algorithm::split_iterator<__gnu_cxx::__normal_iterator<char*, std::string> >, boost::use_default, boost::use_default> > (/path/to/binary)
#                          std::string::_S_construct<__gnu_cxx::__normal_iterator<char*, std::string> >
#                          std::string::_S_construct_aux<__gnu_cxx::__normal_iterator<char*, std::string> >
#                          std::string::_S_construct<__gnu_cxx::__normal_iterator<char*, std::string> >
#                          std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string<__gnu_cxx::__normal_iterator<char*, std::string> >
#                          boost::copy_range<std::string, boost::iterator_range<__gnu_cxx::__normal_iterator<char*, std::string> > >
#                          boost::algorithm::detail::copy_iterator_rangeF<std::string, __gnu_cxx::__normal_iterator<char*, std::string> >::operator()
#                          boost::transform_iterator<boost::algorithm::detail::copy_iterator_rangeF<std::string, __gnu_cxx::__normal_iterator<char*, std::string> >, boost::algorithm::split_iterator<__gnu_cxx::__normal_iterator<char*, std::string> >, boost::use_default, boost::use_default>::dereference
#                          boost::iterator_core_access::dereference<boost::transform_iterator<boost::algorithm::detail::copy_iterator_rangeF<std::string, __gnu_cxx::__normal_iterator<char*, std::string> >, boost::algorithm::split_iterator<__gnu_cxx::__normal_iterator<char*, std::string> >, boost::use_default, boost::use_default> >
#                          boost::iterator_facade<boost::transform_iterator<boost::algorithm::detail::copy_iterator_rangeF<std::string, __gnu_cxx::__normal_iterator<char*, std::string> >, boost::algorithm::split_iterator<__gnu_cxx::__normal_iterator<char*, std::string> >, boost::use_default, boost::use_default>, std::string, boost::forward_traversal_tag, std::string, long>::operator*
#                          std::vector<std::string, std::allocator<std::string> >::_M_range_initialize<boost::transform_iterator<boost::algorithm::detail::copy_iterator_rangeF<std::string, __gnu_cxx::__normal_iterator<char*, std::string> >, boost::algorithm::split_iterator<__gnu_cxx::__normal_iterator<char*, std::string> >, boost::use_default, boost::use_default> >
#                          std::vector<std::string, std::allocator<std::string> >::_M_initialize_dispatch<boost::transform_iterator<boost::algorithm::detail::copy_iterator_rangeF<std::string, __gnu_cxx::__normal_iterator<char*, std::string> >, boost::algorithm::split_iterator<__gnu_cxx::__normal_iterator<char*, std::string> >, boost::use_default, boost::use_default> >
#                    31117 some_function (/path/to/binary)
#                    ...
#
# Here inlined frames are listed under their "real" stackframe.
# Note that the last function in the list is the one from the stackframe header.


import argparse
import re
import sys


class Trace:
    def __init__(self):
        self.frames = []
        self.event = None
        self.process = None

    def escape_frame(self, frame):
        return frame.strip().replace(";", ":").replace("\n", "_")

    def to_string(self):
        result = [self.process] if self.process else []
        result += list(reversed(self.frames))
        return ";".join(self.escape_frame(f) for f in result)


class PerfParser:
    process_matcher = re.compile(r"^(\S.*)\s+(\d+)(?:/(\d+))?\s+.*(\d+).(\d+):")
    event_matcher = re.compile(r".*\s(\S+):\s*$")
    stackframe_matcher = re.compile(r"^\s*[0-9a-fA-F]+\s+(.+)\s+\(.*\)$")

    def __init__(self, event_filter, include_pid, include_tid):
        self.event_filter = event_filter
        self.include_pid = include_pid
        self.include_tid = include_tid
        self.starting_trace = True
        self.last_frame = None
        self.current_trace = Trace()
        self.folded = dict()

    def result(self):
        self.finish_trace()
        return self.folded

    def process_line(self, line):
        if len(line.strip()) == 0:
            self.finish_trace()
            return

        # Handle the start of a stacktrace.
        if self.starting_trace:
            self.starting_trace = False
            self.current_trace.process, self.current_trace.event = self.parse_trace_start(line)

            if not self.event_filter:
                self.event_filter = {self.current_trace.event}

            return

        frame_match = PerfParser.stackframe_matcher.match(line.strip())

        # If it's not a line of format 'd34db33f printf (/usr/bin/glibc.so)' then it's an inlined function.
        if frame_match is None:
            self.last_frame = None
            self.current_trace.frames.append(line)
            return

        # It's a stackframe header.
        if self.last_frame:
            self.current_trace.frames.append(self.last_frame)

        self.last_frame = frame_match.group(1)

    def finish_trace(self):
        self.starting_trace = True

        if self.last_frame:
            self.current_trace.frames.append(self.last_frame)
            self.last_frame = None

        if self.current_trace.event in self.event_filter:
            trace_string = self.current_trace.to_string()

            if trace_string:
                if not self.folded.has_key(trace_string):
                    self.folded[trace_string] = 0

                self.folded[trace_string] += 1

        self.current_trace = Trace()

    def parse_trace_start(self, line):
        process_name = None
        event = None

        process_match = PerfParser.process_matcher.match(line)

        if process_match:
            process_name = process_match.group(1)

            if (self.include_pid or self.include_tid) and process_match.group(2):
                process_name += "-" + process_match.group(2)

            if self.include_tid and process_match.group(3):
                process_name += "/" + process_match.group(3)

        event_match = PerfParser.event_matcher.match(line)

        if event_match:
            event = event_match.group(1)

        return (process_name, event)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--event-filter", nargs = "*", type = str, help = "Events to process. If not specified then events of the type of the first event will be processed.")
    argparser.add_argument("--include-pid", action = "store_true", help = "Include pid in process names.")
    argparser.add_argument("--include-tid", action = "store_true", help = "Include pid and tid in process names.")
    args = argparser.parse_args()

    parser = PerfParser(set(args.event_filter or []), args.include_pid or False, args.include_tid or False)

    for line in sys.stdin:
        parser.process_line(line)

    traces = parser.result()

    for k in sorted(traces.iterkeys()):
        print k, traces[k]
