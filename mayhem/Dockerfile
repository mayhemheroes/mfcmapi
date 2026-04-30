# Mayhem Dockerfile for mfcmapi
#
# Upstream mfcmapi is a Windows-only MFC/MAPI application that cannot be
# built natively on Linux. Mayhem runs Linux containers, so we build a
# narrow, self-contained Linux harness (mayhem/harness.cpp) that targets
# the binaryParser machinery shared by every SmartView parser. This gives
# us a deployable libFuzzer binary on Mayhem while we investigate broader
# coverage via mingw-w64 / Wine in a follow-up.

FROM --platform=linux/amd64 ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY mayhem/harness.cpp /src/harness.cpp

RUN mkdir -p /out

# Build a libFuzzer-instrumented binary. AddressSanitizer is enabled to
# catch out-of-bounds reads/writes the parser would otherwise mask.
RUN clang++ \
        -std=c++17 \
        -O1 -g \
        -fsanitize=fuzzer,address \
        -fno-omit-frame-pointer \
        -o /out/mfcmapi-fuzz \
        /src/harness.cpp

FROM --platform=linux/amd64 ubuntu:22.04

# Runtime sanitizer support
RUN apt-get update && apt-get install -y --no-install-recommends \
        libstdc++6 \
        && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/mfcmapi-fuzz /mfcmapi-fuzz

ENTRYPOINT ["/mfcmapi-fuzz"]
