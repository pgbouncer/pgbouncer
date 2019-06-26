#!/usr/bin/env python

from pandocfilters import toJSONFilter, walk, Str, Header


def caps(key, value, fmt, meta):
    if key == "Str":
        return Str(value.upper())


def manify(key, value, fmt, meta):
    if key == "Header":
        # drop level-1 header
        if value[0] == 1:
            return []

        # decrease level of all headers by 1
        value[0] -= 1

        # convert level-1 headers to uppercase
        if value[0] == 1:
            return Header(*walk(value, caps, fmt, meta))


if __name__ == "__main__":
    toJSONFilter(manify)
